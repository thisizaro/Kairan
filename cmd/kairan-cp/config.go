package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"kairan/internal/cp/api"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/obs"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// maxConfigBytes bounds the config file (a cp.json of a few thousand
// enrollments is well under it).
const maxConfigBytes = 1 << 20

const (
	maxJSONDepth   = 8
	maxTenants     = 1000
	maxEnrollments = 100000
	maxAdminKeys   = 16
	maxMaxPolls    = 1000000
	maxSeconds     = 24 * 60 * 60

	defaultDwell = 60 * time.Second
	defaultStale = 30
	defaultLost  = 120
)

// cliError is a message for the person running the program, in both
// languages. It never holds a config value, a token or a key.
type cliError struct{ en, ja string }

func (e *cliError) Error() string { return e.en }

func msg(en, ja string) *cliError { return &cliError{en: en, ja: ja} }

// config is the validated control plane configuration.
type config struct {
	Listen, MetricsListen, DataDir string
	LogLevel                       slog.Level
	AllowPlaintext                 bool
	Certificate                    *tls.Certificate // nil when plaintext
	Dwell                          time.Duration
	Thresholds                     fleet.Thresholds
	MaxPolls                       int
	AdminKeys                      map[wire.ID]trust.Root
	Proxies                        map[wire.ID]api.Enrollment
}

type rawConfig struct {
	Listen         string               `json:"listen"`
	MetricsListen  string               `json:"metrics_listen"`
	DataDir        string               `json:"data_dir"`
	LogLevel       string               `json:"log_level"`
	AllowPlaintext bool                 `json:"allow_plaintext"`
	TLSCertFile    string               `json:"tls_cert_file"`
	TLSKeyFile     string               `json:"tls_key_file"`
	DwellSeconds   *int64               `json:"canary_dwell_seconds"`
	StaleSeconds   *int64               `json:"stale_seconds"`
	LostSeconds    *int64               `json:"lost_seconds"`
	MaxPolls       *int64               `json:"max_polls"`
	Tenants        map[string]rawTenant `json:"tenants"`
	Enrollments    []rawEnrollment      `json:"enrollments"`
}

type rawTenant struct {
	Threshold int64    `json:"threshold"`
	AdminKeys []string `json:"admin_keys"`
}

type rawEnrollment struct {
	ProxyID     string `json:"proxy_id"`
	Tenant      string `json:"tenant"`
	Group       string `json:"group"`
	TokenSHA256 string `json:"token_sha256"`
}

// loadConfig reads and validates the config file at path. Only a regular
// file is read, without waiting on a FIFO.
func loadConfig(path string) (*config, *cliError) {
	b, cerr := readSmallFile(path, maxConfigBytes, "config file", "設定ファイル", "config file is too large", "設定ファイルが大きすぎます")
	if cerr != nil {
		return nil, cerr
	}
	return parseConfig(b)
}

// readSmallFile opens path without blocking, insists on a regular file and
// reads at most limit bytes. what/whatJa name the file in the messages; the
// last two strings are the "too large" messages.
func readSmallFile(path string, limit int, what, whatJa, tooBig, tooBigJa string) ([]byte, *cliError) {
	b, err := openRegular(path, limit)
	if err != nil {
		switch {
		case errors.Is(err, errNotRegular):
			return nil, msg(what+": not a regular file", whatJa+": 通常のファイルではありません")
		case errors.Is(err, errTooBig):
			return nil, msg(tooBig, tooBigJa)
		}
		reason := err.Error()
		var pe *os.PathError
		if errors.As(err, &pe) {
			reason = pe.Err.Error()
		}
		return nil, msg(what+": "+reason, whatJa+": "+reason)
	}
	return b, nil
}

var (
	errNotRegular = errors.New("not a regular file")
	errTooBig     = errors.New("file too large")
)

// openRegular reads a regular file of at most limit bytes. The open does not
// block (a FIFO is refused, not waited on); the type, mode and size are taken
// from the open descriptor, so nothing can be swapped in after the check.
func openRegular(path string, limit int) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errTooBig
	}
	return b, nil
}

// parseConfig decodes and validates a config file's bytes. It refuses, in
// this order: bad JSON shape (nesting, repeated or upper-case field names,
// private key material), unknown fields and wrong types, then the values.
func parseConfig(data []byte) (*config, *cliError) {
	if len(data) > maxConfigBytes {
		return nil, msg("config file is too large", "設定ファイルが大きすぎます")
	}
	if cerr := scanJSON(data); cerr != nil {
		return nil, cerr
	}
	var raw rawConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		var te *json.UnmarshalTypeError
		switch {
		case errors.As(err, &te):
			f := short(te.Field)
			return nil, msg(f+" has the wrong type", f+" の型が正しくありません")
		case strings.HasPrefix(err.Error(), "json: unknown field "):
			f := short(strings.Trim(strings.TrimPrefix(err.Error(), "json: unknown field "), `"`))
			return nil, msg("unknown field: "+f, "未知のフィールドです: "+f)
		}
		return nil, msg("config file is not valid JSON", "設定ファイルが正しい JSON ではありません")
	}
	return validate(raw)
}

func short(s string) string {
	if len(s) > 40 {
		s = strings.ToValidUTF8(s[:40], "") + "..."
	}
	return s
}

// scanJSON walks the token stream, so that it can see what json.Unmarshal
// hides: repeated field names, field names that differ only by case, and
// nesting. It also refuses private key material wherever it appears.
func scanJSON(data []byte) *cliError {
	notJSON := msg("config file is not valid JSON", "設定ファイルが正しい JSON ではありません")
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return notJSON
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return msg("config file must be a JSON object", "設定ファイルは JSON オブジェクトでなければなりません")
	}
	type frame struct {
		obj         bool
		wantKey     bool
		keys        map[string]bool
		pending     string
		tenantNames bool // the keys of "tenants" are tenant names, not field names
	}
	stack := []frame{{obj: true, wantKey: true, keys: map[string]bool{}}}
	for len(stack) > 0 {
		tok, err := dec.Token()
		if err != nil {
			return notJSON
		}
		top := &stack[len(stack)-1]
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				if len(stack) >= maxJSONDepth {
					return msg("config file is nested too deeply", "設定ファイルの入れ子が深すぎます")
				}
				f := frame{obj: v == '{', wantKey: v == '{'}
				if f.obj {
					f.keys = map[string]bool{}
					f.tenantNames = len(stack) == 1 && top.pending == "tenants"
				}
				stack = append(stack, f)
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].obj {
				stack[len(stack)-1].wantKey = true
			}
		case string:
			if top.obj && top.wantKey {
				if top.keys[v] {
					f := short(v)
					return msg("config file repeats a field: "+f, "設定ファイルに重複したフィールドがあります: "+f)
				}
				top.keys[v] = true
				top.pending, top.wantKey = v, false
				if !top.tenantNames {
					if v != strings.ToLower(v) {
						f := short(v)
						return msg("field names must be lower case: "+f, "フィールド名は小文字でなければなりません: "+f)
					}
					if privateName(v) {
						return privateMaterial()
					}
				}
				continue
			}
			if privateValue(v) {
				return privateMaterial()
			}
			if top.obj {
				top.wantKey = true
			}
		default:
			if top.obj {
				top.wantKey = true
			}
		}
	}
	if _, err := dec.Token(); err != io.EOF {
		return msg("config file has data after the JSON object", "設定ファイルの JSON オブジェクトの後ろにデータがあります")
	}
	return nil
}

func privateMaterial() *cliError {
	return msg("config file holds private key material; it may hold public keys only (generate keys with kairanctl keygen and keep the private key on the admin's machine)",
		"設定ファイルに秘密鍵の情報があります。公開鍵だけを書いてください (鍵は kairanctl keygen で作り、秘密鍵は管理者のマシンに置きます)")
}

func privateName(k string) bool {
	for _, w := range []string{"seed", "private", "secret", "privkey"} {
		if strings.Contains(k, w) {
			return true
		}
	}
	return false
}

// privateValue spots a PEM block or an ed25519 private key (seed and public
// key, 64 bytes) written as 128 hex characters.
func privateValue(v string) bool {
	if strings.Contains(v, "-----BEGIN") || strings.Contains(v, "PRIVATE KEY") {
		return true
	}
	return len(v) == 128 && isHex(v)
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func isLowerHex64(s string) bool {
	return len(s) == 64 && isHex(s) && s == strings.ToLower(s)
}

func hostPortOK(s string) (port string, ok bool) {
	_, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", false
	}
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return "", false
	}
	return p, true
}

func validate(raw rawConfig) (*config, *cliError) {
	cfg := &config{
		AllowPlaintext: raw.AllowPlaintext,
		MaxPolls:       api.DefaultMaxPolls,
		Dwell:          defaultDwell,
		AdminKeys:      map[wire.ID]trust.Root{},
		Proxies:        map[wire.ID]api.Enrollment{},
	}

	// listeners, paths, log level
	switch {
	case strings.TrimSpace(raw.Listen) == "":
		return nil, msg("listen is required", "listen は必須です")
	}
	lport, ok := hostPortOK(raw.Listen)
	if !ok {
		return nil, msg("listen must look like host:port", "listen は host:port の形式で指定してください")
	}
	cfg.Listen = raw.Listen
	if raw.MetricsListen != "" {
		mport, ok := hostPortOK(raw.MetricsListen)
		if !ok {
			return nil, msg("metrics_listen must look like host:port", "metrics_listen は host:port の形式で指定してください")
		}
		if raw.MetricsListen == raw.Listen && mport != "0" && lport != "0" {
			return nil, msg("metrics_listen must differ from listen", "metrics_listen は listen と異なる必要があります")
		}
		cfg.MetricsListen = raw.MetricsListen
	}
	if strings.TrimSpace(raw.DataDir) == "" {
		return nil, msg("data_dir is required", "data_dir は必須です")
	}
	cfg.DataDir = raw.DataDir
	lvl, err := obs.ParseLevel(raw.LogLevel)
	if err != nil {
		return nil, msg("log_level must be debug, info, warn or error", "log_level は debug、info、warn、error のいずれかです")
	}
	cfg.LogLevel = lvl

	// TLS
	hasCert, hasKey := raw.TLSCertFile != "", raw.TLSKeyFile != ""
	switch {
	case hasCert != hasKey:
		return nil, msg("tls_cert_file and tls_key_file go together", "tls_cert_file と tls_key_file は両方を指定してください")
	case hasCert && raw.AllowPlaintext:
		return nil, msg("allow_plaintext cannot be combined with tls_cert_file", "allow_plaintext は tls_cert_file と同時に指定できません")
	case !hasCert && !raw.AllowPlaintext:
		return nil, msg("no TLS: set tls_cert_file and tls_key_file, or allow_plaintext for a demo",
			"TLS がありません。tls_cert_file と tls_key_file を指定するか、デモ用に allow_plaintext を指定してください")
	}
	if hasCert {
		c, err := tls.LoadX509KeyPair(raw.TLSCertFile, raw.TLSKeyFile)
		if err != nil {
			return nil, msg("cannot load the TLS certificate and key", "TLS 証明書と鍵を読み込めません")
		}
		cfg.Certificate = &c
	}

	// numbers
	if raw.DwellSeconds != nil {
		n := *raw.DwellSeconds
		if n < 1 || n > int64(rollout.MaxDwell/time.Second) {
			return nil, msg("canary_dwell_seconds must be 1 to "+strconv.Itoa(int(rollout.MaxDwell/time.Second)),
				"canary_dwell_seconds は 1 から "+strconv.Itoa(int(rollout.MaxDwell/time.Second))+" の間で指定してください")
		}
		cfg.Dwell = time.Duration(n) * time.Second
	}
	stale, lost := int64(defaultStale), int64(defaultLost)
	if raw.StaleSeconds != nil {
		stale = *raw.StaleSeconds
		if stale < 1 || stale > maxSeconds {
			return nil, msg("stale_seconds must be 1 to 86400", "stale_seconds は 1 から 86400 の間で指定してください")
		}
	}
	if raw.LostSeconds != nil {
		lost = *raw.LostSeconds
		if lost < 1 || lost > maxSeconds {
			return nil, msg("lost_seconds must be 1 to 86400", "lost_seconds は 1 から 86400 の間で指定してください")
		}
	}
	if lost < stale {
		return nil, msg("lost_seconds must not be less than stale_seconds", "lost_seconds は stale_seconds 以上でなければなりません")
	}
	cfg.Thresholds = fleet.Thresholds{Stale: time.Duration(stale) * time.Second, Lost: time.Duration(lost) * time.Second}
	if raw.MaxPolls != nil {
		n := *raw.MaxPolls
		if n < 1 || n > maxMaxPolls {
			return nil, msg("max_polls must be 1 to "+strconv.Itoa(maxMaxPolls), "max_polls は 1 から "+strconv.Itoa(maxMaxPolls)+" の間で指定してください")
		}
		cfg.MaxPolls = int(n)
	}

	// tenants and their trust floor
	if len(raw.Tenants) == 0 {
		return nil, msg("tenants is required", "tenants は必須です")
	}
	if len(raw.Tenants) > maxTenants {
		return nil, msg("too many tenants", "テナントが多すぎます")
	}
	names := make([]string, 0, len(raw.Tenants))
	for n := range raw.Tenants {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		id := wire.ID(n)
		if !id.Valid() {
			return nil, msg("a tenant name in tenants is not a valid ID", "tenants のテナント名が有効な ID ではありません")
		}
		root, cerr := tenantRoot(id, raw.Tenants[n])
		if cerr != nil {
			return nil, cerr
		}
		cfg.AdminKeys[id] = root
	}

	// enrollments
	if len(raw.Enrollments) > maxEnrollments {
		return nil, msg("too many enrollments", "enrollments が多すぎます")
	}
	seen := map[[sha256.Size]byte]int{}
	for i, e := range raw.Enrollments {
		at := "enrollments[" + strconv.Itoa(i) + "]"
		fail := func(en, ja string) (*config, *cliError) { return nil, msg(at+": "+en, at+": "+ja) }
		pid, tid, gid := wire.ID(e.ProxyID), wire.ID(e.Tenant), wire.ID(e.Group)
		switch {
		case !pid.Valid():
			return fail("proxy_id is missing or not a valid ID", "proxy_id がないか、有効な ID ではありません")
		case e.Tenant == "" || !tid.Valid():
			return fail("tenant is missing or not a valid ID", "tenant がないか、有効な ID ではありません")
		}
		if _, ok := cfg.AdminKeys[tid]; !ok {
			return fail("tenant is not listed in tenants", "tenant が tenants に載っていません")
		}
		if !gid.Valid() {
			return fail("group is missing or not a valid ID", "group がないか、有効な ID ではありません")
		}
		if _, dup := cfg.Proxies[pid]; dup {
			return fail("proxy_id is already enrolled", "proxy_id はすでに登録されています")
		}
		if !isLowerHex64(e.TokenSHA256) {
			return fail("token_sha256 must be 64 lower-case hex characters (the SHA-256 of the proxy token, not the token)",
				"token_sha256 は 64 文字の小文字 16 進数 (トークン本体ではなく、その SHA-256) でなければなりません")
		}
		var d [sha256.Size]byte
		if _, err := hex.Decode(d[:], []byte(e.TokenSHA256)); err != nil {
			return fail("token_sha256 must be 64 lower-case hex characters", "token_sha256 は 64 文字の小文字 16 進数でなければなりません")
		}
		switch {
		case d == sha256.Sum256(nil):
			return fail("token_sha256 is the digest of the empty token", "token_sha256 が空のトークンのダイジェストです")
		case d == [sha256.Size]byte{}:
			return fail("token_sha256 is all zeros", "token_sha256 がすべて 0 です")
		}
		if j, dup := seen[d]; dup {
			return fail("token_sha256 is the same as enrollments["+strconv.Itoa(j)+"]; every proxy needs its own token",
				"token_sha256 が enrollments["+strconv.Itoa(j)+"] と同じです。プロキシごとに別のトークンが必要です")
		}
		seen[d] = i
		cfg.Proxies[pid] = api.Enrollment{Tenant: tid, Group: gid, TokenDigest: d}
	}
	return cfg, nil
}

// tenantRoot builds the trust root of one tenant. The floor (threshold of at
// least 2, at most the number of keys) is the one trust.Verify enforces.
func tenantRoot(id wire.ID, t rawTenant) (trust.Root, *cliError) {
	at := "tenant " + string(id) + ": "
	fail := func(en, ja string) (trust.Root, *cliError) { return trust.Root{}, msg(at+en, at+ja) }
	if len(t.AdminKeys) > maxAdminKeys {
		return fail("too many admin_keys (at most 16)", "admin_keys が多すぎます (最大 16)")
	}
	pubs := make([]ed25519.PublicKey, 0, len(t.AdminKeys))
	have := map[string]bool{}
	for _, k := range t.AdminKeys {
		if !isLowerHex64(k) {
			return fail("each admin key must be 64 lower-case hex characters (an ed25519 public key)",
				"admin_keys の各鍵は 64 文字の小文字 16 進数 (ed25519 公開鍵) でなければなりません")
		}
		if have[k] {
			return fail("an admin key is listed twice", "同じ管理鍵が 2 回載っています")
		}
		have[k] = true
		b, _ := hex.DecodeString(k)
		pubs = append(pubs, ed25519.PublicKey(b))
	}
	// A seed pasted next to its own public key: the key list holds a secret.
	for _, k := range t.AdminKeys {
		b, _ := hex.DecodeString(k)
		pub := ed25519.NewKeyFromSeed(b).Public().(ed25519.PublicKey)
		if have[hex.EncodeToString(pub)] {
			return trust.Root{}, privateMaterial()
		}
	}
	if t.Threshold < 2 || t.Threshold > int64(len(pubs)) {
		return fail("threshold must be at least 2 and at most the number of admin_keys",
			"threshold は 2 以上、admin_keys の数以下でなければなりません")
	}
	keys := make(map[wire.Hash]ed25519.PublicKey, len(pubs))
	for _, p := range pubs {
		keys[trust.KeyID(p)] = p
	}
	return trust.Root{Tenant: id, Keys: keys, Threshold: int(t.Threshold)}, nil
}
