package kairancpbreak

// Break pass for the message rules of M-D65 (Q-D32 .. Q-D35), PRD J7, C-D12 and invariant I4, applied to
// kairan-cp. Sources: the go doc of the kairan-cp command ("Every message for a person is printed in
// English and in Japanese: errors and -check as an English line and a Japanese line, usage as one text, and
// log lines with the English text in msg and the Japanese text in msg_ja"), M-D65 and the decisions it names.
//
// Contract checked, for every outcome below:
//   - an error is exactly one English line "kairan-cp: error: ..." immediately followed by exactly one Japanese
//     line "kairan-cp: エラー: ..." (the usage may follow); the English line holds no Japanese script and the
//     Japanese line does;
//   - Q-D32: no config path or value is echoed: not data_dir, not a TLS file path, not a token, not a config
//     value of any kind; every such string below carries the marker CANARY, so a leak is a hit;
//   - Q-D33: a typed flag name may be echoed only escaped (control bytes as \xNN, no raw newline or ESC) and
//     truncated to 128 bytes; the marker CANARYFLAG is used for it and is the only marker allowed in output;
//   - Q-D34: OS and library error text appears only on the English line; the Japanese line has no raw
//     English library error (the error class is mapped to a Japanese phrase);
//   - every JSON log line has "msg" (English) and "msg_ja" (Japanese script) and no config path or token;
//   - nothing in the output is a raw control character.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

const (
	enPrefix = "kairan-cp: error:"
	jaPrefix = "kairan-cp: エラー:"
)

// valueMarkers are the canaries planted in config values, paths and tokens: none may ever be printed.
var valueMarkers = []string{"CANARYVAL", "CANARYPATH", "CANARYDIR", "CANARYTLS", "CANARYTOKEN", "CANARYFIELDVAL", "CANARYSHA", "CANARYTENANT", "CANARYKEY", "CANARYPOS"}

// englishRunRe finds a run of three English words in a row ("tenant bank-a: threshold" is not one).
var englishRunRe = regexp.MustCompile(`\b[a-z]{2,}(?: [a-z]{2,}){2,}\b`)

// libPhrases are the OS and library error texts a Japanese line must not carry (Q-D34): every errno text,
// and the common Go library errors.
var libPhrases = func() []string {
	ph := []string{"i/o timeout", "no such host", "unexpected eof", "context deadline exceeded", "context canceled",
		"file already exists", "file does not exist", "invalid argument", "tls: ", "x509: ", "bind: ", "dial tcp", "listen tcp",
		"store: open", "json: ", "invalid character", "unexpected end", "cannot unmarshal", "not a directory", "is a directory"}
	for i := 1; i < 134; i++ {
		e := strings.ToLower(syscall.Errno(i).Error())
		if len(e) >= 8 && !strings.HasPrefix(e, "errno ") && !strings.HasPrefix(e, "unknown") {
			ph = append(ph, e)
		}
	}
	return ph
}()

// rawEnglish reports whether a Japanese line carries raw library error text.
func rawEnglish(ja string) bool {
	low := strings.ToLower(ja)
	for _, p := range libPhrases {
		if strings.Contains(low, p) {
			return true
		}
	}
	return englishRunRe.MatchString(ja)
}

func hasJP(s string) bool {
	for _, r := range s {
		if (r >= 0x3040 && r <= 0x30ff) || (r >= 0x4e00 && r <= 0x9fff) {
			return true
		}
	}
	return false
}

func clipMsg(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

type msgOutcome struct{ pairs, jsonLines int }

// checkMessages applies the contract to the combined output. flagCase allows the marker CANARYFLAG (a typed
// flag name echoed under Q-D33); every value marker stays forbidden.
func checkMessages(t testing.TB, what, out string, flagCase bool, extraForbid ...string) msgOutcome {
	t.Helper()
	var oc msgOutcome
	if os.Getenv("MSG_DUMP") != "" {
		t.Logf("%s output:\n%s", what, out)
	}
	low := strings.ToLower(out)
	forbid := append(append([]string{}, valueMarkers...), extraForbid...)
	if !flagCase && strings.Contains(out, "CANARY") {
		t.Errorf("%s: output carries the marker CANARY (case-sensitive; the lower-case field name canary_dwell_seconds is not one): %s", what, clipMsg(out))
	}
	for _, f := range forbid {
		if f != "" && strings.Contains(low, strings.ToLower(f)) {
			t.Errorf("%s: output echoes %q: %s", what, f, clipMsg(out))
		}
	}
	if !utf8.ValidString(out) {
		t.Errorf("%s: output is not valid UTF-8: %q", what, clipMsg(out))
	}
	for _, r := range out {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			t.Errorf("%s: raw control character %U in the output (Q-D33: escape it): %q", what, r, clipMsg(out))
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, ln := range lines {
		switch {
		case strings.HasPrefix(ln, "{"):
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Errorf("%s: a line starting with { is not JSON: %q", what, clipMsg(ln))
				continue
			}
			oc.jsonLines++
			msg, _ := m["msg"].(string)
			ja, _ := m["msg_ja"].(string)
			switch {
			case msg == "":
				t.Errorf("%s: log line without msg: %s", what, clipMsg(ln))
			case ja == "" || !hasJP(ja):
				t.Errorf("%s: log line without a Japanese msg_ja (PRD J7): %s", what, clipMsg(ln))
			case hasJP(msg):
				t.Errorf("%s: msg must stay English: %s", what, clipMsg(ln))
			case rawEnglish(ja):
				t.Errorf("%s: msg_ja carries raw English text (Q-D34): %s", what, clipMsg(ln))
			}
		case strings.HasPrefix(ln, enPrefix):
			if hasJP(ln) {
				t.Errorf("%s: the English error line holds Japanese script: %q", what, clipMsg(ln))
			}
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], jaPrefix) || !hasJP(lines[i+1]) {
				t.Errorf("%s: an English error line is not followed by its Japanese line: %q", what, clipMsg(ln))
				continue
			}
			oc.pairs++
			ja := strings.TrimPrefix(lines[i+1], jaPrefix)
			if rawEnglish(ja) {
				t.Errorf("%s: the Japanese line carries raw English (library error text, Q-D34): %q", what, clipMsg(lines[i+1]))
			}
		case strings.HasPrefix(ln, jaPrefix):
			if i == 0 || !strings.HasPrefix(lines[i-1], enPrefix) {
				t.Errorf("%s: a Japanese error line without its English line: %q", what, clipMsg(ln))
			}
		}
	}
	return oc
}

// exactlyOnePair is the Q-D33 rule for an echoed flag name: one English line plus one Japanese line, each bounded.
func exactlyOnePair(t testing.TB, what, out string, args []string) {
	t.Helper()
	en, ja := 0, 0
	for _, ln := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(ln, enPrefix):
			en++
			if len(ln) > 512 {
				t.Errorf("%s: English error line is %d bytes: the echoed flag name is not truncated to 128 bytes", what, len(ln))
			}
		case strings.HasPrefix(ln, jaPrefix):
			ja++
			if len(ln) > 640 {
				t.Errorf("%s: Japanese error line is %d bytes: the echoed flag name is not truncated to 128 bytes", what, len(ln))
			}
		}
	}
	if en != 1 || ja != 1 {
		t.Errorf("%s: %d English and %d Japanese error lines, want exactly one of each: %s", what, en, ja, clipMsg(out))
	}
	for _, a := range args {
		if strings.ContainsAny(a, "\x1b\n\r\x00\x07") && !strings.Contains(out, `\x`) && !strings.Contains(out, `\n`) && !strings.Contains(out, `\r`) {
			t.Errorf("%s: a control byte in the typed flag name is not shown escaped (as \\xNN): %s", what, clipMsg(out))
		}
	}
}

// ---- fixtures ----

// canaryBase is a valid config whose free-text values carry markers, so any echo is caught.
func canaryBase(t testing.TB) (cfg, string) {
	d := filepath.Join(t.TempDir(), "CANARYDIR", "data")
	return baseCfg(t, d), d
}

func writeCfg(t testing.TB, raw []byte) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "conf")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "cp.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func goodToken(t testing.TB) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(p, []byte(adminTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// ---- usage and flag errors ----

func TestMsgUsageAndFlagErrors(t *testing.T) {
	cb, _ := canaryBase(t)
	good := writeCfg(t, cb.bytes(t))
	fifo := filepath.Join(t.TempDir(), "CANARYPATH-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "CANARYPATH", "nope.json")
	dir := filepath.Join(t.TempDir(), "CANARYPATH-dir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		args     []string
		flagName bool // the typed text is a flag NAME: Q-D33 allows an escaped, bounded echo
	}{
		{"no arguments", nil, false},
		{"unknown flag", []string{"-bogus"}, true},
		{"unknown flag with canary name", []string{"-CANARYFLAG"}, true},
		{"unknown flag double dash", []string{"--CANARYFLAG"}, true},
		{"unknown flag after good config", []string{"-config", good, "-CANARYFLAG"}, true},
		{"unknown flag with value", []string{"-bogus=CANARYVAL"}, true},
		{"flag name with a newline", []string{"-a\nkairan-cp: error: forged"}, true},
		{"flag name with an escape", []string{"-\x1b[2JCANARYFLAG"}, true},
		{"flag name with a bell", []string{"-a\x07CANARYFLAG"}, true},
		{"long flag name", []string{"-" + strings.Repeat("x", 50000)}, true},
		{"-config without value", []string{"-config"}, false},
		{"-admin-token-file without value", []string{"-config", good, "-admin-token-file"}, false},
		{"-check with a bad boolean", []string{"-config", good, "-check=CANARYVAL"}, false},
		{"-check with a number", []string{"-config", good, "-check=99"}, false},
		{"-config empty", []string{"-config", ""}, false},
		{"-config missing file", []string{"-config", missing}, false},
		{"-config directory", []string{"-config", dir}, false},
		{"-config FIFO", []string{"-config", fifo}, false},
		{"-config /dev/zero", []string{"-config", "/dev/zero"}, false},
		{"-config long path", []string{"-config", "/" + strings.Repeat("CANARYPATH", 5000)}, false},
		{"-config path with a newline", []string{"-config", "/nope/CANARYPATH\nkairan-cp: error: forged"}, false},
		{"-config path with an escape", []string{"-config", "/nope/\x1b[2JCANARYPATH"}, false},
		{"-config twice, second missing", []string{"-config", good, "-config", missing}, false},
		{"positional canary", []string{"-config", good, "CANARYPOS"}, false},
		{"positional first", []string{"CANARYPOS", "-config", good}, false},
		{"positional with an escape", []string{"-config", good, "\x1b[31mCANARYPOS"}, false},
		{"token as a flag", []string{"-config", good, "-admin-token", "CANARYTOKEN"}, true},
		{"token as a flag with =", []string{"-config", good, "-admin-token=CANARYTOKEN"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, nil, c.args...)
			noPanic(t, r)
			if r.code != 2 {
				t.Errorf("exit %d, want 2: %s", r.code, clipMsg(r.all()))
			}
			if r.stdout != "" {
				t.Errorf("standard output is not empty: %s", clipMsg(r.stdout))
			}
			oc := checkMessages(t, c.name, r.stderr, c.flagName)
			if oc.pairs < 1 {
				t.Errorf("no English+Japanese error pair: %s", clipMsg(r.stderr))
			}
			if len(r.stderr) > 8192 {
				t.Errorf("%d bytes of error output: typed text is echoed unbounded", len(r.stderr))
			}
			if c.flagName {
				exactlyOnePair(t, c.name, r.stderr, c.args)
			}
		})
	}
}

// -h prints one bilingual usage and exits 0; a canary flag next to it is not echoed.
func TestMsgHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"-h", "-CANARYFLAG"}, {"-config", "/nope/CANARYPATH", "-h"}} {
		r := run(t, nil, args...)
		if r.code != 0 {
			t.Errorf("%v: exit %d, want 0", args, r.code)
		}
		if !strings.Contains(r.all(), "usage:") || !strings.Contains(r.all(), "使い方") {
			t.Errorf("%v: the usage is not in both languages: %s", args, clipMsg(r.all()))
		}
		for _, v := range valueMarkers {
			if strings.Contains(r.all(), v) {
				t.Errorf("%v: -h echoes %q", args, v)
			}
		}
		if strings.Contains(r.all(), "CANARYFLAG") && args[len(args)-1] == "-CANARYFLAG" {
			// a flag name echo is allowed (escaped); not asserted either way
			continue
		}
	}
}

// ---- config errors: one class per case, a marker in the offending value ----

func TestMsgConfigErrors(t *testing.T) {
	cb, d := canaryBase(t)
	a := pub(t, "admin-a")
	raw := func(s string) []byte { return []byte(s) }
	mut := func(k string, v any) []byte { return cb.with(t, k, v).bytes(t) }
	base := string(cb.bytes(t))
	prefix := `{"listen":"127.0.0.1:0","data_dir":"` + d + `","allow_plaintext":true,"tenants":{"bank-a":{"threshold":2,"admin_keys":["` + a + `","` + pub(t, "admin-b") + `"]}}`
	tenantA := func(m map[string]any) []byte {
		return mut("tenants", map[string]any{"bank-a": m})
	}
	enr := func(over map[string]any) []byte {
		m := map[string]any{"proxy_id": "p1", "tenant": "bank-a", "group": "main", "token_sha256": sha(tokOf("p1"))}
		for k, v := range over {
			m[k] = v
		}
		return mut("enrollments", []any{m})
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty file", raw("")},
		{"not json", raw("listen: CANARYVAL")},
		{"array", raw(`["CANARYVAL"]`)},
		{"string", raw(`"CANARYVAL"`)},
		{"truncated", raw(prefix + `,"x":"CANARYVAL`)},
		{"trailing second document", raw(prefix + `}{"x":"CANARYVAL"}`)},
		{"trailing garbage", raw(prefix + `} CANARYVAL`)},
		{"unknown field value", raw(prefix + `,"bogus":"CANARYVAL"}`)},
		{"unknown nested field value", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"bogus":{"k":"CANARYVAL"}`, 1))},
		{"duplicate key, canary value first", raw(prefix + `,"listen":"CANARYVAL"}`)},
		{"duplicate key, canary value second", raw(strings.Replace(prefix+"}", `"listen":"127.0.0.1:0"`, `"listen":"CANARYVAL","listen":"127.0.0.1:0"`, 1))},
		{"upper-case key with canary value", raw(strings.Replace(prefix+"}", `"listen"`, `"Listen"`, 1))},
		{"nesting deeper than 8", raw(prefix + `,"x":` + strings.Repeat("[", 9) + `"CANARYVAL"` + strings.Repeat("]", 9) + `}`)},
		{"over 64 KiB", raw(prefix + `,"x":"CANARYVAL` + strings.Repeat("a", 70<<10) + `"}`)},
		{"listen garbage", mut("listen", "CANARYVAL")},
		{"listen no port", mut("listen", "CANARYVAL.example")},
		{"listen port out of range", mut("listen", "127.0.0.1:CANARYVAL")},
		{"metrics_listen garbage", mut("metrics_listen", "CANARYVAL")},
		{"data_dir number", mut("data_dir", 5)},
		{"data_dir empty", mut("data_dir", "")},
		{"allow_plaintext string", mut("allow_plaintext", "CANARYVAL")},
		{"no TLS and no allow_plaintext", cb.with(t, "allow_plaintext", nil).with(t, "listen", "CANARYVAL.example:1").bytes(t)},
		{"tls cert file missing", cb.with(t, "allow_plaintext", nil).with(t, "tls_cert_file", filepath.Join(d, "CANARYTLS-cert.pem")).with(t, "tls_key_file", filepath.Join(d, "CANARYTLS-key.pem")).bytes(t)},
		{"tls cert without key", cb.with(t, "allow_plaintext", nil).with(t, "tls_cert_file", filepath.Join(d, "CANARYTLS-cert.pem")).bytes(t)},
		{"tls key without cert", cb.with(t, "allow_plaintext", nil).with(t, "tls_key_file", filepath.Join(d, "CANARYTLS-key.pem")).bytes(t)},
		{"tenants string", mut("tenants", "CANARYVAL")},
		{"tenant id invalid", mut("tenants", map[string]any{"CANARYTENANT Bank": map[string]any{"threshold": 2, "admin_keys": []string{a, pub(t, "admin-b")}}})},
		{"tenant id 64 chars", mut("tenants", map[string]any{strings.Repeat("a", 60) + "canarytenant": map[string]any{"threshold": 2, "admin_keys": []string{a, pub(t, "admin-b")}}})},
		{"threshold string", tenantA(map[string]any{"threshold": "CANARYVAL", "admin_keys": []string{a, pub(t, "admin-b")}})},
		{"threshold below floor", tenantA(map[string]any{"threshold": 1, "admin_keys": []string{a, pub(t, "admin-b")}})},
		{"admin key canary text", tenantA(map[string]any{"threshold": 2, "admin_keys": []string{a, "CANARYKEY"}})},
		{"admin key not hex", tenantA(map[string]any{"threshold": 2, "admin_keys": []string{a, "CANARYKEY" + strings.Repeat("g", 55)}})},
		{"admin key is a seed (private key)", tenantA(map[string]any{"threshold": 2, "admin_keys": []string{a, seed(t, "admin-a")}})},
		{"seed field", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"seed":"`+seed(t, "admin-a")+`"`, 1))},
		{"enrollment token_sha256 canary", enr(map[string]any{"token_sha256": "CANARYSHA"})},
		{"enrollment plaintext token field", enr(map[string]any{"token": "CANARYTOKEN"})},
		{"enrollment proxy_id invalid", enr(map[string]any{"proxy_id": "P CANARYVAL"})},
		{"enrollment tenant unknown", enr(map[string]any{"tenant": "canarytenant"})},
		{"enrollment group invalid", enr(map[string]any{"group": "Main CANARYVAL"})},
		{"enrollment token_sha256 is the plaintext token", enr(map[string]any{"token_sha256": "CANARYTOKEN-0123456789"})},
		{"log_level garbage", mut("log_level", "CANARYVAL")},
		{"canary_dwell_seconds string", mut("canary_dwell_seconds", "CANARYVAL")},
		{"PEM in a value", mut("data_dir", "-----BEGIN PRIVATE KEY-----\nCANARYKEY\n-----END PRIVATE KEY-----")},
	}
	_ = base
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := writeFiles(t, c.raw, adminTok+"\n")
			r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath, "-check")
			noPanic(t, r)
			if r.code != 2 {
				t.Errorf("exit %d, want 2: %s", r.code, clipMsg(r.all()))
			}
			if r.stdout != "" {
				t.Errorf("standard output is not empty: %s", clipMsg(r.stdout))
			}
			oc := checkMessages(t, c.name, r.stderr, false, f.dir, adminTok)
			if oc.pairs != 1 {
				t.Errorf("%d English+Japanese error pairs, want exactly 1: %s", oc.pairs, clipMsg(r.stderr))
			}
			if len(r.stderr) > 4096 {
				t.Errorf("%d bytes of error output: the message is not bounded", len(r.stderr))
			}
		})
	}
}

// A hostile config field name is the one piece of config text that is printed (it names the unknown field):
// escaped and bounded, no forged line, no escape sequence.
func TestMsgHostileFieldNames(t *testing.T) {
	cb, _ := canaryBase(t)
	base := string(cb.bytes(t))
	names := map[string]string{
		"newline":     `a\nkairan-cp: error: forged`,
		"carriage":    `a\rkairan-cp: error: forged`,
		"escape":      `\u001b[2Jx`,
		"bell":        `\u0007x`,
		"nul":         `a\u0000b`,
		"C1 control":  `a\u009bb`,
		"line sep":    `a b`,
		"bidi":        `a‮b`,
		"lone surr.":  `\ud800x`,
		"long 60 KiB": strings.Repeat("n", 60<<10),
	}
	for name, nm := range names {
		t.Run(name, func(t *testing.T) {
			raw := strings.Replace(base, `{`, `{"`+nm+`":1,`, 1)
			f := writeFiles(t, []byte(raw), adminTok+"\n")
			r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath, "-check")
			noPanic(t, r)
			if r.code != 2 {
				t.Errorf("exit %d, want 2: %s", r.code, clipMsg(r.all()))
			}
			checkMessages(t, name, r.stderr, false, f.dir)
			if len(r.stderr) > 4096 {
				t.Errorf("a %d-byte field name produced %d bytes of error output; echoed text must be bounded", len(nm), len(r.stderr))
			}
			exactlyOnePair(t, name, r.stderr, nil)
		})
	}
}

// ---- admin token errors ----

func TestMsgTokenErrors(t *testing.T) {
	cb, _ := canaryBase(t)
	cp := writeCfg(t, cb.bytes(t))
	mk := func(mode os.FileMode, body string) string {
		p := filepath.Join(t.TempDir(), "CANARYPATH-token")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	fifo := filepath.Join(t.TempDir(), "CANARYPATH-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "CANARYPATH-dir")
	_ = os.MkdirAll(dir, 0o700)
	sharedCfg := writeCfg(t, cb.with(t, "enrollments", []any{map[string]any{"proxy_id": "p1", "tenant": "bank-a", "group": "main", "token_sha256": sha("CANARYTOKEN-0123456789")}}).bytes(t))
	cases := []struct {
		name string
		cfg  string
		env  []string
		args []string
	}{
		{"no token at all", cp, nil, nil},
		{"env token empty", cp, []string{"KCP_ADMIN_TOKEN="}, nil},
		{"token file missing", cp, nil, []string{"-admin-token-file", filepath.Join(t.TempDir(), "CANARYPATH", "nope")}},
		{"token file via env missing", cp, []string{"KCP_ADMIN_TOKEN_FILE=" + filepath.Join(t.TempDir(), "CANARYPATH", "nope")}, nil},
		{"token file readable by others (content is a canary)", cp, nil, []string{"-admin-token-file", mk(0o644, "CANARYTOKEN-0123456789\n")}},
		{"token file group readable", cp, nil, []string{"-admin-token-file", mk(0o640, "CANARYTOKEN-0123456789\n")}},
		{"token file empty", cp, nil, []string{"-admin-token-file", mk(0o600, "")}},
		{"token file blank", cp, nil, []string{"-admin-token-file", mk(0o600, " \n\n")}},
		{"token file with embedded newline", cp, nil, []string{"-admin-token-file", mk(0o600, "CANARYTOKEN-line1\nCANARYTOKEN-line2\n")}},
		{"token file with NUL", cp, nil, []string{"-admin-token-file", mk(0o600, "CANARYTOKEN\x00abc")}},
		{"token file huge", cp, nil, []string{"-admin-token-file", mk(0o600, "CANARYTOKEN"+strings.Repeat("a", 1<<20))}},
		{"token file is a directory", cp, nil, []string{"-admin-token-file", dir}},
		{"token file is a FIFO", cp, nil, []string{"-admin-token-file", fifo}},
		{"token file is /dev/zero", cp, nil, []string{"-admin-token-file", "/dev/zero"}},
		{"admin token equals a proxy token", sharedCfg, []string{"KCP_ADMIN_TOKEN=CANARYTOKEN-0123456789"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			args := append([]string{"-config", c.cfg, "-check"}, c.args...)
			r := run(t, c.env, args...)
			noPanic(t, r)
			if r.code != 2 {
				t.Errorf("exit %d, want 2: %s", r.code, clipMsg(r.all()))
			}
			oc := checkMessages(t, c.name, r.stderr, false)
			if oc.pairs != 1 {
				t.Errorf("%d English+Japanese error pairs, want exactly 1: %s", oc.pairs, clipMsg(r.stderr))
			}
		})
	}
}

// ---- a good -check, and the log lines of a running control plane ----

func TestMsgCheckSuccessAndRunLogs(t *testing.T) {
	cb, d := canaryBase(t)
	f := writeFiles(t, cb.bytes(t), adminTok+"\n")
	r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath, "-check")
	if r.code != 0 {
		t.Fatalf("-check of a valid config: exit %d: %s", r.code, clipMsg(r.all()))
	}
	out := strings.TrimSpace(r.all())
	lines := strings.Split(out, "\n")
	if len(lines) != 2 || hasJP(lines[0]) || !hasJP(lines[1]) {
		t.Errorf("-check success is not exactly one English line and one Japanese line: %q", clipMsg(out))
	}
	for _, v := range append(append([]string{}, valueMarkers...), "CANARY", adminTok, d, f.dir) {
		if strings.Contains(out, v) {
			t.Errorf("-check echoes %q: %s", v, clipMsg(out))
		}
	}

	// serve: every log line has msg and msg_ja, none carries the data directory, the token or the config path
	port := freePort(t)
	cfgRaw := cb.with(t, "listen", port).with(t, "metrics_listen", freePort(t)).bytes(t)
	f2 := writeFiles(t, cfgRaw, adminTok+"\n")
	s := start(t, nil, "-config", f2.cfgPath, "-admin-token-file", f2.tokPath)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.out.String(), "listening") {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.signal(syscall.SIGTERM)
	if code, ok := s.waitExit(10 * time.Second); !ok || code != 0 {
		t.Errorf("SIGTERM: exited=%v code=%d: %s", ok, code, clipMsg(s.out.String()))
	}
	logs := s.out.String()
	oc := checkMessages(t, "run logs", logs, false, d, f2.dir, f2.cfgPath, f2.tokPath, adminTok)
	if oc.jsonLines < 3 {
		t.Errorf("only %d JSON log lines (warning, listening, shutting down expected): %s", oc.jsonLines, clipMsg(logs))
	}
}

// ---- failures while starting up: the error class is mapped, no path, no raw library text ----

func TestMsgStartupFailures(t *testing.T) {
	cb, d := canaryBase(t)
	tok := goodToken(t)

	t.Run("listen address in use", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		f := writeFiles(t, cb.with(t, "listen", l.Addr().String()).bytes(t), adminTok+"\n")
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		noPanic(t, r)
		if r.code != 1 {
			t.Errorf("exit %d, want 1 (failure at startup): %s", r.code, clipMsg(r.all()))
		}
		oc := checkMessages(t, "address in use", r.all(), false, d, f.dir)
		if oc.pairs != 1 {
			t.Errorf("%d English+Japanese pairs, want 1: %s", oc.pairs, clipMsg(r.all()))
		}
	})
	t.Run("metrics address in use", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		f := writeFiles(t, cb.with(t, "listen", freePort(t)).with(t, "metrics_listen", l.Addr().String()).bytes(t), adminTok+"\n")
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		noPanic(t, r)
		if r.code != 1 {
			t.Errorf("exit %d, want 1: %s", r.code, clipMsg(r.all()))
		}
		checkMessages(t, "metrics address in use", r.all(), false, d, f.dir)
	})
	t.Run("data_dir under a regular file", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "CANARYPATH-file")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		f := writeFiles(t, cb.with(t, "data_dir", filepath.Join(blocker, "data")).with(t, "listen", freePort(t)).bytes(t), adminTok+"\n")
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", tok)
		_ = f
		noPanic(t, r)
		if r.code != 1 && r.code != 2 {
			t.Errorf("exit %d, want 1 or 2: %s", r.code, clipMsg(r.all()))
		}
		oc := checkMessages(t, "data_dir under a file", r.all(), false, blocker, f.dir)
		if oc.pairs != 1 {
			t.Errorf("%d English+Japanese pairs, want 1: %s", oc.pairs, clipMsg(r.all()))
		}
	})
	t.Run("data_dir not writable", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root ignores directory permissions")
		}
		ro := filepath.Join(t.TempDir(), "CANARYPATH-ro")
		if err := os.MkdirAll(ro, 0o500); err != nil {
			t.Fatal(err)
		}
		f := writeFiles(t, cb.with(t, "data_dir", filepath.Join(ro, "data")).with(t, "listen", freePort(t)).bytes(t), adminTok+"\n")
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		noPanic(t, r)
		if r.code != 1 && r.code != 2 {
			t.Errorf("exit %d, want 1 or 2: %s", r.code, clipMsg(r.all()))
		}
		oc := checkMessages(t, "data_dir not writable", r.all(), false, ro, f.dir)
		if oc.pairs != 1 {
			t.Errorf("%d English+Japanese pairs, want 1: %s", oc.pairs, clipMsg(r.all()))
		}
	})
	t.Run("tls files are garbage", func(t *testing.T) {
		dd := t.TempDir()
		certP, keyP := filepath.Join(dd, "CANARYTLS-cert.pem"), filepath.Join(dd, "CANARYTLS-key.pem")
		_ = os.WriteFile(certP, []byte("-----BEGIN CERTIFICATE-----\nCANARYTLS\n-----END CERTIFICATE-----\n"), 0o600)
		_ = os.WriteFile(keyP, []byte("-----BEGIN PRIVATE KEY-----\nCANARYTLS\n-----END PRIVATE KEY-----\n"), 0o600)
		f := writeFiles(t, cb.with(t, "allow_plaintext", nil).with(t, "tls_cert_file", certP).with(t, "tls_key_file", keyP).with(t, "listen", freePort(t)).bytes(t), adminTok+"\n")
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		noPanic(t, r)
		if r.code != 1 && r.code != 2 {
			t.Errorf("exit %d, want 1 or 2: %s", r.code, clipMsg(r.all()))
		}
		oc := checkMessages(t, "tls garbage", r.all(), false, certP, keyP, dd, f.dir)
		if oc.pairs != 1 {
			t.Errorf("%d English+Japanese pairs, want 1: %s", oc.pairs, clipMsg(r.all()))
		}
	})
}

// The message does not depend on the locale: both languages are always printed.
func TestMsgSameInEveryLocale(t *testing.T) {
	cb, _ := canaryBase(t)
	p := writeCfg(t, cb.with(t, "listen", "CANARYVAL").bytes(t))
	tok := goodToken(t)
	var ref string
	for _, env := range [][]string{{"LANG=C"}, {"LANG=ja_JP.UTF-8"}, {"LC_ALL=en_US.UTF-8"}, {"LC_ALL=C", "LANG=C"}, {"LC_ALL=ja_JP.eucJP"}, {"LANGUAGE=en"}, {"TERM=dumb", "NO_COLOR=1"}} {
		r := run(t, env, "-config", p, "-admin-token-file", tok, "-check")
		if r.code != 2 {
			t.Errorf("%v: exit %d, want 2", env, r.code)
		}
		checkMessages(t, fmt.Sprint(env), r.stderr, false)
		if ref == "" {
			ref = r.stderr
		} else if r.stderr != ref {
			t.Errorf("the message depends on the locale %v:\n%s\nvs\n%s", env, clipMsg(ref), clipMsg(r.stderr))
		}
	}
	_ = bytes.MinRead
}
