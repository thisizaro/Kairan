package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	"kairan/internal/proxy/state"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

const (
	// DefaultSkew is the expiry tolerance when the config does not say. The
	// ceiling is trust.MaxSkew (5m, M-D33).
	DefaultSkew = 2 * time.Minute

	maxConfigBytes = 64 << 10
	maxTrustedKeys = 16 // an envelope holds at most wire.MaxSignatures; a few spare for rotation
	maxJSONDepth   = 8
)

// Config is the proxy's local configuration (ARCHITECTURE section 10,
// cmd/kairan-proxy). The trust root lives here and nowhere else: a policy is
// accepted only if signed by Threshold distinct keys listed in trusted_keys.
// A config that cannot be fully checked is an error and the proxy does not
// start (fail closed).
type Config struct {
	Tenant         wire.ID
	ProxyID        wire.ID
	CP             *url.URL
	Token          string
	Root           trust.Root
	Skew           time.Duration
	Listen         string
	MetricsListen  string // "" = no local self view and metrics listener (P-09)
	Upstream       *url.URL
	APIKeys        map[string]string // API key -> role
	DataDir        string
	SafeMode       state.SafeMode
	CAFile         string
	AllowPlaintext bool
}

// fileConfig is the JSON shape. Every field name is exact lowercase; unknown,
// duplicate and case-variant keys are rejected before decoding.
type fileConfig struct {
	Tenant         *string           `json:"tenant"`
	ProxyID        *string           `json:"proxy_id"`
	CPURL          *string           `json:"cp_url"`
	Token          *string           `json:"token"`
	TrustedKeys    []string          `json:"trusted_keys"`
	Threshold      *int              `json:"threshold"`
	Skew           *string           `json:"skew"`
	Listen         *string           `json:"listen"`
	MetricsListen  *string           `json:"metrics_listen"`
	Upstream       *string           `json:"upstream"`
	APIKeys        map[string]string `json:"api_keys"`
	DataDir        *string           `json:"data_dir"`
	SafeMode       *string           `json:"safe_mode"`
	CAFile         *string           `json:"ca_file"`
	AllowPlaintext *bool             `json:"allow_plaintext"`
}

var knownFields = map[string]bool{
	"tenant": true, "proxy_id": true, "cp_url": true, "token": true, "trusted_keys": true,
	"threshold": true, "skew": true, "listen": true, "metrics_listen": true, "upstream": true, "api_keys": true,
	"data_dir": true, "safe_mode": true, "ca_file": true, "allow_plaintext": true,
}

// LoadConfig reads and checks the config file. The file must be a regular
// file of at most 64 KiB; it is opened without blocking so a FIFO cannot hang
// startup.
func LoadConfig(path string) (*Config, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, osUsageMsg("config: cannot open the file", "設定: ファイルを開けません", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, osUsageMsg("config: cannot read the file", "設定: ファイルを読めません", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, usageMsg("config: not a regular file", "設定: 通常のファイルではありません")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, osUsageMsg("config: cannot read the file", "設定: ファイルを読めません", err)
	}
	return ParseConfig(data)
}

// ParseConfig checks the JSON text of a config. Errors name the field and the
// problem; they never repeat a value, so a token or key cannot reach a log.
func ParseConfig(data []byte) (*Config, error) {
	if len(data) > maxConfigBytes {
		return nil, usageMsg("config: too large", "設定: ファイルが大きすぎます")
	}
	if err := checkObjectKeys(data); err != nil {
		return nil, err
	}
	var fc fileConfig
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fc); err != nil {
		return nil, usageMsg("config: not valid JSON of the expected shape (a field has the wrong type)",
			"設定: 期待する形の JSON ではありません (型が正しくない項目があります)")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, usageMsg("config: data after the JSON object", "設定: JSON オブジェクトの後ろに余分なデータがあります")
	}
	return fc.check()
}

func (fc *fileConfig) check() (*Config, error) {
	bad := func(field, why, whyJa string) (*Config, error) {
		return nil, usageMsg("config: "+field+": "+why, "設定: "+field+": "+whyJa)
	}
	c := &Config{}

	if fc.Tenant == nil || !wire.ID(*fc.Tenant).Valid() {
		return bad("tenant", "required, 1-63 characters of a-z 0-9 -", "必須です。a-z 0-9 - の 1〜63 文字")
	}
	c.Tenant = wire.ID(*fc.Tenant)
	if fc.ProxyID == nil || !wire.ID(*fc.ProxyID).Valid() {
		return bad("proxy_id", "required, 1-63 characters of a-z 0-9 -", "必須です。a-z 0-9 - の 1〜63 文字")
	}
	c.ProxyID = wire.ID(*fc.ProxyID)
	if fc.Token == nil || *fc.Token == "" {
		return bad("token", "required", "必須です")
	}
	c.Token = *fc.Token
	if fc.AllowPlaintext != nil {
		c.AllowPlaintext = *fc.AllowPlaintext
	}

	if fc.CPURL == nil {
		return bad("cp_url", "required", "必須です")
	}
	cp, perr := parseURL(*fc.CPURL)
	if perr != nil {
		return bad("cp_url", perr.en, perr.ja)
	}
	switch {
	case cp.Scheme == "https":
	case cp.Scheme == "http" && c.AllowPlaintext:
	case cp.Scheme == "http":
		return bad("cp_url", "http needs allow_plaintext: true (demo only); use https", "http には allow_plaintext: true が必要です (デモ専用)。https を使ってください")
	default:
		return bad("cp_url", "must be an https URL", "https の URL にしてください")
	}
	c.CP = cp

	// Trust root: hex ed25519 public keys, distinct, threshold of at least 2
	// and at most the number of keys (M-D33).
	if len(fc.TrustedKeys) == 0 || len(fc.TrustedKeys) > maxTrustedKeys {
		return bad("trusted_keys", "required, 1 to "+strconv.Itoa(maxTrustedKeys)+" hex public keys", "必須です。16 進数の公開鍵を 1〜"+strconv.Itoa(maxTrustedKeys)+" 個")
	}
	keys := make(map[wire.Hash]ed25519.PublicKey, len(fc.TrustedKeys))
	for _, h := range fc.TrustedKeys {
		raw, err := hex.DecodeString(h)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return bad("trusted_keys", "each item must be a public key in 64 hex characters", "各項目は 64 文字の 16 進数の公開鍵にしてください")
		}
		id := trust.KeyID(raw)
		if _, dup := keys[id]; dup {
			return bad("trusted_keys", "the same key is listed twice", "同じ鍵が 2 回書かれています")
		}
		keys[id] = ed25519.PublicKey(raw)
	}
	if fc.Threshold == nil {
		return bad("threshold", "required (at least 2)", "必須です (2 以上)")
	}
	if *fc.Threshold < 2 {
		return bad("threshold", "must be at least 2: no single key may approve a policy", "2 以上にしてください。1 つの鍵だけではポリシーを承認できません")
	}
	if *fc.Threshold > len(keys) {
		return bad("threshold", "is higher than the number of trusted_keys", "trusted_keys の数より大きくできません")
	}
	c.Root = trust.Root{Tenant: c.Tenant, Keys: keys, Threshold: *fc.Threshold}

	c.Skew = DefaultSkew
	if fc.Skew != nil {
		d, err := time.ParseDuration(*fc.Skew)
		if err != nil {
			return bad("skew", "not a duration such as 2m", "2m のような期間ではありません")
		}
		if d < 0 || d > trust.MaxSkew {
			return bad("skew", "must be between 0 and 5m", "0 から 5m の間にしてください")
		}
		c.Skew = d
	}

	c.SafeMode = state.ReadOnly
	if fc.SafeMode != nil {
		switch state.SafeMode(*fc.SafeMode) {
		case state.ReadOnly, state.DenyAll:
			c.SafeMode = state.SafeMode(*fc.SafeMode)
		default:
			return bad("safe_mode", "must be read_only or deny_all", "read_only か deny_all にしてください")
		}
	}

	if fc.Listen == nil {
		return bad("listen", "required, host:port", "必須です。host:port の形式")
	}
	_, port, err := net.SplitHostPort(*fc.Listen)
	if err != nil {
		return bad("listen", "must be host:port", "host:port の形式にしてください")
	}
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return bad("listen", "port must be a number from 0 to 65535", "ポートは 0 から 65535 の数にしてください")
	}
	c.Listen = *fc.Listen

	if fc.MetricsListen != nil {
		_, port, err := net.SplitHostPort(*fc.MetricsListen)
		if err != nil {
			return bad("metrics_listen", "must be host:port", "host:port の形式にしてください")
		}
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return bad("metrics_listen", "port must be a number from 0 to 65535", "ポートは 0 から 65535 の数にしてください")
		}
		if *fc.MetricsListen == c.Listen && n != 0 {
			return bad("metrics_listen", "must differ from listen", "listen と別のアドレスにしてください")
		}
		c.MetricsListen = *fc.MetricsListen
	}

	if fc.Upstream == nil {
		return bad("upstream", "required", "必須です")
	}
	up, perr := parseURL(*fc.Upstream)
	if perr != nil {
		return bad("upstream", perr.en, perr.ja)
	}
	if up.Scheme != "http" && up.Scheme != "https" {
		return bad("upstream", "must be an http or https URL", "http か https の URL にしてください")
	}
	c.Upstream = up

	if len(fc.APIKeys) == 0 {
		return bad("api_keys", "required, an object of API key to role", "必須です。API キーからロールへのオブジェクト")
	}
	for k, role := range fc.APIKeys {
		if k == "" || !printable(k) || !wire.ID(role).Valid() {
			return bad("api_keys", "keys must be non-empty without spaces or control characters; roles must be IDs (1-63 of a-z, 0-9, -)", "キーは空でなく、空白や制御文字を含めないでください。ロールは ID (a-z 0-9 - の 1〜63 文字) にしてください")
		}
	}
	c.APIKeys = fc.APIKeys

	if fc.DataDir == nil || *fc.DataDir == "" {
		return bad("data_dir", "required", "必須です")
	}
	c.DataDir = *fc.DataDir
	if fc.CAFile != nil {
		c.CAFile = *fc.CAFile
	}
	return c, nil
}

// parseURL accepts an absolute URL with a host and no credentials, query or
// fragment.
func parseURL(s string) (*url.URL, *cliError) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return nil, msg("must be an absolute URL with a host", "ホストを含む絶対 URL にしてください")
	}
	if u.User != nil {
		return nil, msg("must not contain a user name or password", "ユーザー名やパスワードを含めないでください")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return nil, msg("must not contain a query or fragment", "クエリやフラグメントを含めないでください")
	}
	return u, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// TestOnlyKeys is how many of the trusted keys are repo fixture keys (M-D37).
func (c *Config) TestOnlyKeys() int {
	n := 0
	for id := range c.Root.Keys {
		if testOnlyKeyIDs[id] {
			n++
		}
	}
	return n
}

// testOnlyKeyIDs are the key IDs of test/fixtures/TEST-ONLY-*.pub. Their
// private seeds are public, so a proxy that trusts one is not protected
// (M-D37, M-D39). A unit test keeps this list equal to the fixtures.
var testOnlyKeyIDs = map[wire.Hash]bool{
	"95f9872ca090c9dda41fb865ba7383733c7872c0a79b88199b8e12e9932eb9de": true, // admin-a
	"df6c781ac3afa442f0e0c798f9640f3fa0047675f7e7e293c2d21246c6302567": true, // admin-b
	"70bfe9d759c1231a68c7d879e2f50a20d6f209396546fdefcab1a4937f955959": true, // admin-c
	"cabfa839574735c3e9293da0a5fd677b9e7381486541ca059a876182844ea6f0": true, // outsider
}

// checkObjectKeys walks the JSON once and rejects what encoding/json would
// quietly accept: a duplicate key at any object level, a top-level key that is
// not spelled exactly as a known field (case variants), more than one value,
// and nesting deeper than maxJSONDepth. It checks structure only.
func checkObjectKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return usageMsg("config: must be a JSON object", "設定: JSON オブジェクトにしてください")
	}
	if err := walkObject(dec, 1, true); err != nil {
		return err
	}
	return nil
}

func walkObject(dec *json.Decoder, depth int, top bool) error {
	if depth > maxJSONDepth {
		return usageMsg("config: nested too deeply", "設定: 入れ子が深すぎます")
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
		}
		key, ok := kt.(string)
		if !ok {
			return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
		}
		if seen[key] {
			return usageMsg("config: duplicate key (a field appears twice)", "設定: キーが重複しています (同じ項目が 2 回あります)")
		}
		seen[key] = true
		if top && !knownFields[key] {
			return usageMsg("config: unknown field "+safeKey(key), "設定: 未知の項目です: "+safeKey(key))
		}
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
	}
	return nil
}

func walkValue(dec *json.Decoder, depth int) error {
	tok, err := dec.Token()
	if err != nil {
		return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		return walkObject(dec, depth+1, false)
	case '[':
		if depth+1 > maxJSONDepth {
			return usageMsg("config: nested too deeply", "設定: 入れ子が深すぎます")
		}
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return usageMsg("config: not valid JSON", "設定: 正しい JSON ではありません")
		}
	}
	return nil
}

// safeKey shortens and escapes a field name for an error message. Field names
// are not secrets, but they can hold anything in a hostile file.
func safeKey(k string) string {
	if len(k) > 32 {
		k = k[:32]
	}
	return esc(k)
}
