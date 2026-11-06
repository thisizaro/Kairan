package kairanproxybreak

// Break pass for P-12 (PRD J7, M-D62): every kairan-proxy message for a person is in English and Japanese.
// Sources: the go doc of the kairan-proxy command (section "Messages are in English and Japanese", Config,
// Offline import, The data directory is locked, Exit status), PRD J7, invariant I4.
//
// Contract checked, for every outcome below:
//   - an error is an English line "kairan-proxy: error: ..." immediately followed by a Japanese line
//     "kairan-proxy: エラー: ..." that holds Japanese script; the English line holds none;
//   - the usage (-h, and after a bad command line) is in both languages, -h exits 0, all of it on standard error;
//   - every JSON log line has "msg" (English) and "msg_ja" (Japanese script), different from each other;
//   - "A message never holds a config value, a token, a key or bundle content" and nothing typed is echoed.
//     Every string below that could be echoed carries the marker CANARY; the output is searched for it,
//     case-insensitively, in raw text and in decoded JSON strings;
//   - nothing in the output is a raw control character (no terminal escape, no forged line).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"kairan/internal/wire"
)

// ---- the checker ----

// englishSentenceRe finds three or more lower-case English words in a row ("permission denied", "address
// already in use", "no such file or directory"): a Japanese line must not end in a raw library error.
var englishSentenceRe = regexp.MustCompile(`\b[a-z]{3,}(?: [a-z]{2,}){2,}\b|\b[a-z]{4,} [a-z]{4,}\b`)

var headingRe = regexp.MustCompile(`^\s+-\S+( [A-Za-z]+)?$`)

type msgStats struct {
	json, pairs int
}

// bilingual checks every line of out. forbid holds strings that must not appear (compared lower case).
func bilingual(t testing.TB, what, out string, forbid ...string) msgStats {
	t.Helper()
	var st msgStats
	if os.Getenv("MSG_DUMP") != "" {
		t.Logf("%s output:\n%s", what, out)
	}
	low := strings.ToLower(out)
	for _, f := range forbid {
		if f != "" && strings.Contains(low, strings.ToLower(f)) {
			t.Errorf("%s: output echoes %q: %s", what, f, clip(out))
		}
	}
	if !utf8.ValidString(out) {
		t.Errorf("%s: output is not valid UTF-8: %q", what, clip(out))
	}
	for _, r := range out {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			t.Errorf("%s: raw control character %U in the output (terminal escape or forged line): %q", what, r, clip(out))
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if out == "" {
		lines = nil
	}
	pending := false
	for i, ln := range lines {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if strings.HasPrefix(ln, "{") {
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Errorf("%s: a line starting with { is not JSON: %q", what, clip(ln))
				continue
			}
			st.json++
			msg, _ := m["msg"].(string)
			ja, _ := m["msg_ja"].(string)
			switch {
			case msg == "":
				t.Errorf("%s: log line without msg: %s", what, clip(ln))
			case ja == "":
				t.Errorf("%s: log line without msg_ja (PRD J7): %s", what, clip(ln))
			case !hasJP(ja):
				t.Errorf("%s: msg_ja holds no Japanese script: %s", what, clip(ln))
			case hasJP(msg):
				t.Errorf("%s: msg must stay English: %s", what, clip(ln))
			case msg == ja:
				t.Errorf("%s: msg_ja equals msg: %s", what, clip(ln))
			}
			walkStrings(m, func(s string) {
				for _, f := range forbid {
					if f != "" && strings.Contains(strings.ToLower(s), strings.ToLower(f)) {
						t.Errorf("%s: log field echoes %q: %s", what, f, clip(ln))
					}
				}
			})
			continue
		}
		if strings.HasPrefix(ln, "kairan-proxy: error:") {
			if i+1 >= len(lines) || !strings.HasPrefix(lines[i+1], "kairan-proxy: エラー:") || !hasJP(lines[i+1]) {
				t.Errorf("%s: an error line is not followed by its Japanese line: %q", what, clip(ln))
			} else {
				st.pairs++
			}
		}
		if strings.HasPrefix(ln, "kairan-proxy: エラー:") && (i == 0 || !strings.HasPrefix(lines[i-1], "kairan-proxy: error:")) {
			t.Errorf("%s: a Japanese error line without its English line: %q", what, clip(ln))
		}
		if headingRe.MatchString(ln) && !hasJP(ln) {
			continue // "  -config FILE": the flag heading is neither language
		}
		if !hasJP(ln) {
			if pending {
				t.Errorf("%s: English line %d has no Japanese partner after the previous English line: %q", what, i, clip(ln))
			}
			pending = true
		} else {
			if !pending {
				t.Errorf("%s: Japanese line %d has no English line before it: %q", what, i, clip(ln))
			}
			pending = false
		}
	}
	if pending {
		t.Errorf("%s: the last English line has no Japanese line: %s", what, clip(out))
	}
	return st
}

func walkStrings(v any, f func(string)) {
	switch x := v.(type) {
	case string:
		f(x)
	case []any:
		for _, e := range x {
			walkStrings(e, f)
		}
	case map[string]any:
		for k, e := range x {
			f(k)
			walkStrings(e, f)
		}
	}
}

func listenTCP() (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }

// splitRun is one run with separate standard output and standard error.
type splitRun struct {
	code        int
	stdout, err string
	ok          bool
}

func runSplit(t testing.TB, args []string, env []string, stdin string) splitRun {
	t.Helper()
	b := bin(t)
	cmd := exec.Command(b, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + cmd.Dir, "LANG=C"}, env...)
	var so, se lockedBuf
	cmd.Stdout, cmd.Stderr = &so, &se
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		return splitRun{cmd.ProcessState.ExitCode(), so.String(), se.String(), true}
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return splitRun{-1, so.String(), se.String(), false}
	}
}

func (r splitRun) mustExit(t testing.TB, want int) {
	t.Helper()
	if !r.ok {
		t.Fatalf("did not exit in 30 s: %s", clip(r.err))
	}
	if r.code != want {
		t.Errorf("exit %d, want %d: %s", r.code, want, clip(r.err))
	}
	if r.stdout != "" {
		t.Errorf("something on standard output (messages go to standard error): %s", clip(r.stdout))
	}
}

// canaryCfg is a valid config whose free-text values all carry CANARY, so any echo is caught.
func canaryCfg(t testing.TB) pcfg {
	d := filepath.Join(t.TempDir(), "CANARYDIR", "data")
	return baseCfg(t, d, "http://127.0.0.1:9/cp-CANARYCP", "http://127.0.0.1:9/mcp-CANARYUP", "127.0.0.1:0")
}

func cfgPath(t testing.TB, raw []byte) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "conf")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(d, "proxy.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var commonForbid = []string{"CANARY", token, keySales, keyIntrn, canary}

func pubs(t testing.TB) []string {
	return []string{key(t, "admin-a").pub, key(t, "admin-b").pub, key(t, "admin-c").pub, key(t, "outsider").pub}
}

func nonEmpty(s string) []string {
	var o []string
	for _, l := range strings.Split(s, "\n") {
		if strings.TrimSpace(l) != "" {
			o = append(o, l)
		}
	}
	return o
}

// ---- config errors ----

// Every config error class of TestConfigRejections, with a CANARY in the offending value: exit 2, English line,
// Japanese line, the value never echoed (command doc: "prints which field is wrong, never its value").
func TestMsgConfigErrors(t *testing.T) {
	a, b, c := key(t, "admin-a").pub, key(t, "admin-b").pub, key(t, "admin-c").pub
	g := canaryCfg(t)
	raw := func(s string) []byte { return []byte(s) }
	mut := func(k string, v any) []byte { return g.with(k, v).bytes() }
	base := string(g.bytes())
	keys := func(n int) []string {
		ks := []string{a, b, c, key(t, "outsider").pub}
		for len(ks) < n {
			ks = append(ks, strings.Repeat("0", 62)+string("0123456789abcdef"[len(ks)/16])+string("0123456789abcdef"[len(ks)%16]))
		}
		return ks[:n]
	}
	cases := []struct {
		name string
		raw  []byte
	}{
		{"empty file", raw("")},
		{"not json", raw("tenant: CANARY")},
		{"not json, secret-like word", raw("token: " + token)},
		{"array", raw(`["CANARY"]`)},
		{"null", raw("null")},
		{"string", raw(`"CANARY"`)},
		{"number", raw("5")},
		{"truncated", raw(base[:len(base)-5])},
		{"trailing second document", raw(base + `{"x":"CANARY"}`)},
		{"trailing garbage", raw(base + " CANARY")},
		{"BOM", append([]byte("\xef\xbb\xbf"), []byte(base)...)},
		{"NUL byte", raw(base + "\x00")},
		{"unknown field value", mut("bogus", "CANARY")},
		{"unknown field object value", mut("bogus", map[string]string{"k": "CANARY"})},
		{"duplicate top-level key", raw(strings.Replace(base, `"tenant":"bank-a"`, `"tenant":"bank-a","tenant":"CANARY"`, 1))},
		{"duplicate key, value canary first", raw(strings.Replace(base, `"tenant":"bank-a"`, `"tenant":"CANARY","tenant":"bank-a"`, 1))},
		{"upper-case key", raw(strings.Replace(base, `"tenant":"bank-a"`, `"Tenant":"CANARY"`, 1))},
		{"nesting deeper than 8", raw(strings.Replace(base, `{`, `{"x":`+strings.Repeat("[", 9)+`"CANARY"`+strings.Repeat("]", 9)+`,`, 1))},
		{"over 64 KiB", raw(strings.Replace(base, `{`, `{"x":"CANARY`+strings.Repeat("a", 70<<10)+`",`, 1))},
		{"missing tenant", mut("tenant", nil)},
		{"missing proxy_id", mut("proxy_id", nil)},
		{"missing cp_url", mut("cp_url", nil)},
		{"missing token", mut("token", nil)},
		{"missing trusted_keys", mut("trusted_keys", nil)},
		{"missing threshold", mut("threshold", nil)},
		{"missing listen", mut("listen", nil)},
		{"missing upstream", mut("upstream", nil)},
		{"missing api_keys", mut("api_keys", nil)},
		{"missing data_dir", mut("data_dir", nil)},
		{"tenant upper case", mut("tenant", "Bank-CANARY")},
		{"tenant empty", mut("tenant", "")},
		{"tenant 64 chars", mut("tenant", strings.Repeat("a", 60)+"canary")},
		{"tenant number", mut("tenant", 5)},
		{"tenant has newline", mut("tenant", "a\nkairan-proxy: error: CANARY")},
		{"tenant has escape", mut("tenant", "a\x1b[31mCANARY")},
		{"proxy_id invalid", mut("proxy_id", "p CANARY")},
		{"proxy_id empty", mut("proxy_id", "")},
		{"token empty", mut("token", "")},
		{"token number", mut("token", 5)},
		{"cp_url http without allow_plaintext", g.with("allow_plaintext", nil).with("cp_url", "http://cp.CANARY.example.test/CANARY").bytes()},
		{"cp_url allow_plaintext false", g.with("allow_plaintext", false).with("cp_url", "http://cp.CANARY.example.test").bytes()},
		{"cp_url ftp", mut("cp_url", "ftp://CANARY.example.test")},
		{"cp_url no scheme", mut("cp_url", "CANARY.example.test")},
		{"cp_url file", mut("cp_url", "file:///etc/CANARY")},
		{"cp_url with userinfo", mut("cp_url", "http://user:CANARY@cp.example.test")},
		{"cp_url empty", mut("cp_url", "")},
		{"cp_url number", mut("cp_url", 5)},
		{"allow_plaintext string", mut("allow_plaintext", "CANARY")},
		{"safe_mode unknown", mut("safe_mode", "CANARY")},
		{"safe_mode upper case", mut("safe_mode", "READ_ONLY_CANARY")},
		{"safe_mode empty", mut("safe_mode", "")},
		{"safe_mode number", mut("safe_mode", 1)},
		{"skew 5m1s", mut("skew", "5m1s")},
		{"skew 1h", mut("skew", "1h")},
		{"skew negative", mut("skew", "-1s")},
		{"skew garbage", mut("skew", "CANARY")},
		{"skew number", mut("skew", 120)},
		{"threshold 1", mut("threshold", 1)},
		{"threshold 0", mut("threshold", 0)},
		{"threshold above keys", mut("threshold", 4)},
		{"threshold float", mut("threshold", 2.5)},
		{"threshold string", mut("threshold", "CANARY")},
		{"threshold huge", raw(strings.Replace(base, `"threshold":2`, `"threshold":18446744073709551616`, 1))},
		{"one trusted key", g.with("trusted_keys", []string{a}).bytes()},
		{"no trusted keys", g.with("trusted_keys", []string{}).bytes()},
		{"duplicate trusted key", g.with("trusted_keys", []string{a, a, b}).bytes()},
		{"17 trusted keys", g.with("trusted_keys", keys(17)).bytes()},
		{"trusted key not hex", g.with("trusted_keys", []string{a, "CANARY" + strings.Repeat("g", 58)}).bytes()},
		{"trusted key short", g.with("trusted_keys", []string{a, b[:62]}).bytes()},
		{"trusted key long", g.with("trusted_keys", []string{a, b + "00"}).bytes()},
		{"trusted key CANARY text", g.with("trusted_keys", []string{a, "CANARY"}).bytes()},
		{"trusted key number", g.with("trusted_keys", []any{a, 5}).bytes()},
		{"trusted key null", g.with("trusted_keys", []any{a, nil}).bytes()},
		{"trusted_keys object", g.with("trusted_keys", map[string]any{"CANARY": 1}).bytes()},
		{"listen garbage", mut("listen", "CANARY")},
		{"listen no port", mut("listen", "CANARY.example")},
		{"listen port too big", mut("listen", "127.0.0.1:99999")},
		{"listen number", mut("listen", 80)},
		{"metrics_listen garbage", mut("metrics_listen", "CANARY")},
		{"metrics_listen equals listen", g.with("listen", "127.0.0.1:34567").with("metrics_listen", "127.0.0.1:34567").bytes()},
		{"upstream ftp", mut("upstream", "ftp://CANARY/y")},
		{"upstream no scheme", mut("upstream", "CANARY/y")},
		{"upstream empty", mut("upstream", "")},
		{"upstream with userinfo", mut("upstream", "http://user:CANARY@h/mcp")},
		{"api_keys empty", g.with("api_keys", map[string]string{}).bytes()},
		{"api_keys empty key", g.with("api_keys", map[string]string{"": "sales"}).bytes()},
		{"api_keys empty role", g.with("api_keys", map[string]string{keySales: ""}).bytes()},
		{"api_keys role invalid", g.with("api_keys", map[string]string{keySales: "Sales CANARY"}).bytes()},
		{"api_keys role number", g.with("api_keys", map[string]any{keySales: 5}).bytes()},
		{"api_keys array", g.with("api_keys", []string{keySales}).bytes()},
		{"api_keys duplicate key", raw(strings.Replace(base, `"api_keys":{`, `"api_keys":{"`+keySales+`":"intern",`, 1))},
		{"api_keys key with newline", g.with("api_keys", map[string]string{keySales + "\nCANARY": ""}).bytes()},
		{"data_dir empty", mut("data_dir", "")},
		{"data_dir number", mut("data_dir", 5)},
		{"ca_file missing", mut("ca_file", filepath.Join(t.TempDir(), "CANARYCA", "nope.pem"))},
		{"ca_file number", mut("ca_file", 5)},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			r := runSplit(t, []string{"-config", cfgPath(t, cs.raw)}, nil, "")
			r.mustExit(t, 2)
			st := bilingual(t, cs.name, r.err, commonForbid...)
			if st.pairs < 1 {
				t.Errorf("no English+Japanese error pair: %s", clip(r.err))
			}
			for _, secret := range pubs(t) {
				if strings.Contains(r.err, secret) {
					t.Errorf("a trusted public key is echoed")
				}
			}
		})
	}
}

// A hostile field name is the one piece of config text that is printed (it names the unknown field). It must
// be escaped and bounded: no forged line, no escape sequence, no 60 KiB error message.
func TestMsgHostileFieldNames(t *testing.T) {
	g := canaryCfg(t)
	base := string(g.bytes())
	names := map[string]string{
		"newline":     `a\nkairan-proxy: error: forged`,
		"carriage":    `a\rkairan-proxy: error: forged`,
		"escape":      `\u001b[2Jx`,
		"bell":        `\u0007x`,
		"nul":         `a\u0000b`,
		"C1 control":  `a\u009bb`,
		"line sep":    `a b`,
		"bidi":        "a\u202eb",
		"lone surr.":  `\ud800x`,
		"long 60 KiB": strings.Repeat("n", 60<<10),
	}
	for name, nm := range names {
		t.Run(name, func(t *testing.T) {
			raw := strings.Replace(base, `{`, `{"`+nm+`":1,`, 1)
			r := runSplit(t, []string{"-config", cfgPath(t, []byte(raw))}, nil, "")
			r.mustExit(t, 2)
			bilingual(t, name, r.err, commonForbid...)
			if len(r.err) > 4096 {
				t.Errorf("a %d-byte field name produced %d bytes of error output; echoed text must be bounded", len(nm), len(r.err))
			}
			errLines := 0
			for _, ln := range strings.Split(r.err, "\n") {
				if strings.HasPrefix(ln, "kairan-proxy: error:") {
					errLines++
				}
			}
			if errLines != 1 {
				t.Errorf("a hostile field name produced a forged or extra error line: %s", clip(r.err))
			}
		})
	}
}

// Both languages are always printed: the message does not depend on the locale.
func TestMsgSameInEveryLocale(t *testing.T) {
	g := canaryCfg(t).with("threshold", 1)
	p := cfgPath(t, g.bytes())
	var ref string
	for _, env := range [][]string{{"LANG=C"}, {"LANG=ja_JP.UTF-8"}, {"LC_ALL=en_US.UTF-8"}, {"LC_ALL=C", "LANG=C"}, {"LC_ALL=ja_JP.eucJP"}, {"LANGUAGE=en"}, {"TERM=dumb", "NO_COLOR=1"}} {
		r := runSplit(t, []string{"-config", p}, env, "")
		r.mustExit(t, 2)
		bilingual(t, strings.Join(env, " "), r.err, commonForbid...)
		if ref == "" {
			ref = r.err
		} else if r.err != ref {
			t.Errorf("the message depends on the locale %v (both languages are always printed):\n%s\nvs\n%s", env, clip(ref), clip(r.err))
		}
	}
}

// ---- usage and flag errors ----

// flagNameCases are the cases whose typed text is a flag NAME (M-D65, Q-D33 allows echoing it escaped and
// truncated to 128 bytes).
var flagNameCases = map[string]bool{
	"unknown flag": true, "unknown flag with canary name": true, "unknown flag double dash": true,
	"unknown flag after good config": true, "flag with a newline in its name": true,
	"flag with an escape in its name": true, "long flag name": true,
}

// checkEscapedBoundedEcho: exactly one English error line plus one Japanese error line (the usage is
// separate), no raw control byte (bilingual checks that too), a control byte of the typed name shown as
// \xNN, and each error line bounded (the name is cut at 128 bytes, so a line cannot grow with the input).
func checkEscapedBoundedEcho(t *testing.T, name, out string, args []string) {
	t.Helper()
	en, ja := 0, 0
	for _, ln := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(ln, "kairan-proxy: error:"):
			en++
			if len(ln) > 512 {
				t.Errorf("%s: English error line is %d bytes: the echoed name is not truncated to 128 bytes", name, len(ln))
			}
		case strings.HasPrefix(ln, "kairan-proxy: エラー:"):
			ja++
			if len(ln) > 640 {
				t.Errorf("%s: Japanese error line is %d bytes: the echoed name is not truncated", name, len(ln))
			}
		}
	}
	if en != 1 || ja != 1 {
		t.Errorf("%s: %d English and %d Japanese error lines, want exactly one of each: %s", name, en, ja, clip(out))
	}
	for _, a := range args {
		if strings.ContainsAny(a, "\x1b\n") && !strings.Contains(out, `\x1b`) && !strings.Contains(out, `\n`) && !strings.Contains(out, `\x0a`) {
			t.Errorf("%s: a control byte in the typed flag name is not shown escaped (as \\xNN): %s", name, clip(out))
		}
	}
}

func TestMsgUsageAndFlagErrors(t *testing.T) {
	good := cfgPath(t, canaryCfg(t).bytes())
	missing := filepath.Join(t.TempDir(), "CANARYPATH", "nope.json")
	fifo := filepath.Join(t.TempDir(), "CANARYFIFO")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	dirCanary := filepath.Join(t.TempDir(), "CANARYDIR2")
	if err := os.MkdirAll(dirCanary, 0o700); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		args  []string
		usage bool // a bad command line also prints the usage
	}{
		{"no arguments", nil, true},
		{"unknown flag", []string{"-bogus"}, true},
		{"unknown flag with canary name", []string{"-CANARYFLAG"}, true},
		{"unknown flag with canary value", []string{"-bogus=CANARYVAL"}, true},
		{"unknown flag double dash", []string{"--CANARYFLAG"}, true},
		{"unknown flag after good config", []string{"-config", good, "-CANARYFLAG"}, true},
		{"-config without value", []string{"-config"}, true},
		{"-config empty", []string{"-config", ""}, false},
		{"-config missing file (canary path)", []string{"-config", missing}, false},
		{"-config directory (canary path)", []string{"-config", dirCanary}, false},
		{"-config FIFO (canary path)", []string{"-config", fifo}, false},
		{"-config /dev/zero", []string{"-config", "/dev/zero"}, false},
		{"token as a flag", []string{"-config", good, "-token", token}, true},
		{"token as a flag with =", []string{"-config", good, "-token=" + token}, true},
		{"api key as a positional", []string{"-config", good, keySales}, true},
		{"canary positional", []string{"-config", good, "CANARYPOS"}, true},
		{"canary positional first", []string{"CANARYPOS", "-config", good}, true},
		{"-import without value", []string{"-config", good, "-import"}, true},
		{"-import without -config", []string{"-import", filepath.Join(t.TempDir(), "CANARYB.json")}, true},
		{"-config twice, second missing", []string{"-config", good, "-config", missing}, false},
		{"-import with extra", []string{"-config", good, "-import", missing, "CANARYPOS"}, true},
		{"flag with a newline in its name", []string{"-a\nkairan-proxy: error: forged"}, true},
		{"flag with an escape in its name", []string{"-\x1b[2JCANARY"}, true},
		{"argument with an escape", []string{"-config", good, "\x1b[31mCANARY"}, true},
		{"long flag name", []string{"-" + strings.Repeat("x", 50000)}, true},
		{"long path", []string{"-config", "/" + strings.Repeat("CANARY", 5000)}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runSplit(t, c.args, nil, "")
			if !r.ok {
				t.Fatalf("did not exit")
			}
			if r.code != 2 {
				t.Errorf("exit %d, want 2: %s", r.code, clip(r.err))
			}
			if r.stdout != "" {
				t.Errorf("standard output is not empty: %s", clip(r.stdout))
			}
			forbid := commonForbid
			if flagNameCases[c.name] {
				// M-D65 (Q-D33): a typed flag NAME may be echoed, but only escaped and bounded. The marker
				// CANARY inside the flag name itself is therefore allowed; every other secret and value stays forbidden.
				forbid = nil
				for _, f := range commonForbid {
					if f != "CANARY" {
						forbid = append(forbid, f)
					}
				}
				forbid = append(forbid, "CANARYDIR", "CANARYPATH", "CANARYFIFO", "CANARYPOS", "CANARYCP", "CANARYUP", "CANARYVAL")
			}
			st := bilingual(t, c.name, r.err, forbid...)
			if st.pairs < 1 {
				t.Errorf("no English+Japanese error pair: %s", clip(r.err))
			}
			if len(r.err) > 8192 {
				t.Errorf("%d bytes of error output: typed text is echoed unbounded", len(r.err))
			}
			if flagNameCases[c.name] {
				checkEscapedBoundedEcho(t, c.name, r.err, c.args)
			}
			if c.usage && (!strings.Contains(r.err, "usage:") || !strings.Contains(r.err, "使い方")) {
				t.Errorf("a bad command line must print the usage in both languages: %s", clip(r.err))
			}
		})
	}
}

// -h, -help and --help: exit 0, both languages, standard error only.
func TestMsgHelp(t *testing.T) {
	for _, args := range [][]string{{"-h"}, {"-help"}, {"--help"}, {"-h", "-config", "x"}, {"-config", "x", "-h"}, {"-h", "-import", "y"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			r := runSplit(t, args, nil, "")
			r.mustExit(t, 0)
			bilingual(t, "help", r.err, commonForbid...)
			for _, want := range []string{"-config", "-import", "usage", "使い方"} {
				if !strings.Contains(r.err, want) {
					t.Errorf("usage lacks %q: %s", want, clip(r.err))
				}
			}
			if strings.Contains(r.err, "kairan-proxy: error:") {
				t.Errorf("-h printed an error line: %s", clip(r.err))
			}
		})
	}
	t.Run("-h with a following bad flag does not echo it", func(t *testing.T) {
		r := runSplit(t, []string{"-h", "-CANARYFLAG"}, nil, "")
		if r.code != 0 && r.code != 2 {
			t.Errorf("exit %d", r.code)
		}
		bilingual(t, "help then bad flag", r.err, commonForbid...)
	})
	t.Run("every flag has an English then a Japanese description", func(t *testing.T) {
		r := runSplit(t, []string{"-h"}, nil, "")
		r.mustExit(t, 0)
		lines := strings.Split(r.err, "\n")
		n := 0
		for i, ln := range lines {
			if headingRe.MatchString(ln) {
				n++
				if i+2 >= len(lines) || hasJP(lines[i+1]) || !hasJP(lines[i+2]) {
					t.Errorf("flag %q lacks an English then a Japanese description", ln)
				}
			}
		}
		if n < 2 {
			t.Errorf("only %d flags listed: %s", n, clip(r.err))
		}
	})
}

// ---- the TEST-ONLY warning ----

func TestMsgTestOnlyWarning(t *testing.T) {
	t.Run("fixture keys: warning in both languages, keys not echoed", func(t *testing.T) {
		l := newLife(t, "")
		l.start("", nil, nil)
		out := l.p.out.String()
		bilingual(t, "TEST-ONLY", out, append(append([]string{}, commonForbid...), pubs(t)...)...)
		found := false
		for _, ln := range strings.Split(out, "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(ln), &m) != nil {
				continue
			}
			if msg, _ := m["msg"].(string); strings.Contains(msg, "TEST-ONLY") {
				found = true
				if lv, _ := m["level"].(string); lv != "WARN" && lv != "ERROR" {
					t.Errorf("the TEST-ONLY warning is level %q, want WARN or higher", lv)
				}
				if ja, _ := m["msg_ja"].(string); !hasJP(ja) {
					t.Errorf("Japanese part of the TEST-ONLY warning: %q", ja)
				}
				if m["test_only_keys"] == nil {
					t.Errorf("no count of test-only keys on the warning")
				}
			}
		}
		if !found {
			t.Errorf("no TEST-ONLY warning log line: %s", clip(out))
		}
		l.p.signal(syscall.SIGTERM)
		l.p.waitExit(10 * time.Second)
	})
	t.Run("one fixture key out of three", func(t *testing.T) {
		l := newLife(t, "")
		real1 := "ab" + strings.Repeat("12", 31)
		real2 := "cd" + strings.Repeat("34", 31)
		l.start("", func(c pcfg) pcfg { return c.with("trusted_keys", []string{key(t, "admin-a").pub, real1, real2}) }, nil)
		out := l.p.out.String()
		bilingual(t, "one fixture key", out, append(append([]string{}, commonForbid...), key(t, "admin-a").pub, real1, real2)...)
		if !strings.Contains(out, "TEST-ONLY") {
			t.Errorf("no warning when one trusted key is a fixture key: %s", clip(out))
		}
	})
	t.Run("the warning is bilingual for -import too", func(t *testing.T) {
		e := newImp(t)
		r := runSplit(t, []string{"-config", cfgPath(t, e.cfg.bytes()), "-import", e.bundle(envJSON(good(t, 1)))}, nil, "")
		r.mustExit(t, 0)
		bilingual(t, "import with fixture keys", r.err, append(append([]string{}, commonForbid...), pubs(t)...)...)
	})
}

// ---- -import outcomes ----

// A policy that carries a CANARY in every place it can: nothing from the bundle is printed.
func canaryPolicy(tn string, version uint64, issued, expires time.Time) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"canaryrole":{"canarytool.read_*":"R","canarytool.update":"W"}}}`,
		tn, version, issued.UTC().Format(time.RFC3339), expires.UTC().Format(time.RFC3339)))
}

func TestMsgImportOutcomes(t *testing.T) {
	now := time.Now()
	hour := time.Hour
	valid := func(v uint64) []byte { return canaryPolicy(tenant, v, now.Add(-hour), now.Add(24*hour)) }
	type bc struct {
		name string
		prep func(t *testing.T, e *imp) []byte // bundle bytes; may apply earlier versions
		code int
	}
	cases := []bc{
		{"applied", func(t *testing.T, e *imp) []byte { return envJSON(signedBy(t, valid(1), "admin-a", "admin-b")) }, 0},
		{"applied with three signatures", func(t *testing.T, e *imp) []byte {
			return envJSON(signedBy(t, valid(1), "admin-a", "admin-b", "admin-c"))
		}, 0},
		{"unsigned", func(t *testing.T, e *imp) []byte { return envJSON(envelopeOf(valid(1))) }, 1},
		{"one signature", func(t *testing.T, e *imp) []byte { return envJSON(signedBy(t, valid(1), "admin-a")) }, 1},
		{"outsider signature", func(t *testing.T, e *imp) []byte { return envJSON(signedBy(t, valid(1), "admin-a", "outsider")) }, 1},
		{"wrong tenant (canary tenant)", func(t *testing.T, e *imp) []byte {
			return envJSON(signedBy(t, canaryPolicy("tenant-canary-x", 1, now.Add(-hour), now.Add(24*hour)), "admin-a", "admin-b"))
		}, 1},
		{"old version", func(t *testing.T, e *imp) []byte {
			e.apply(signedBy(t, valid(5), "admin-a", "admin-b"))
			return envJSON(signedBy(t, valid(4), "admin-a", "admin-b"))
		}, 1},
		{"same version", func(t *testing.T, e *imp) []byte {
			e.apply(signedBy(t, valid(5), "admin-a", "admin-b"))
			return envJSON(signedBy(t, valid(5), "admin-a", "admin-b"))
		}, 1},
		{"expired", func(t *testing.T, e *imp) []byte {
			return envJSON(signedBy(t, canaryPolicy(tenant, 1, now.Add(-48*hour), now.Add(-24*hour)), "admin-a", "admin-b"))
		}, 1},
		{"payload is not a policy", func(t *testing.T, e *imp) []byte {
			return envJSON(signedBy(t, []byte(`{"tenant":"bank-a","canaryfield":"CANARY-PAYLOAD"}`), "admin-a", "admin-b"))
		}, 1},
		{"payload is garbage", func(t *testing.T, e *imp) []byte {
			return envJSON(signedBy(t, []byte("CANARY-PAYLOAD garbage"), "admin-a", "admin-b"))
		}, 1},
		{"wrong payload type", func(t *testing.T, e *imp) []byte {
			return envJSON(wire.Envelope{PayloadType: "application/CANARY", Payload: valid(1)})
		}, 1},
		{"not an envelope, canary object", func(t *testing.T, e *imp) []byte { return []byte(`{"CANARYKEY":"CANARY-VALUE"}`) }, 1},
		{"not JSON, canary text", func(t *testing.T, e *imp) []byte { return []byte("CANARY-BUNDLE-TEXT") }, 1},
		{"empty bundle", func(t *testing.T, e *imp) []byte { return []byte("") }, 1},
		{"array bundle", func(t *testing.T, e *imp) []byte { return []byte(`["CANARY"]`) }, 1},
		{"binary bundle", func(t *testing.T, e *imp) []byte { return []byte("\x00\x01\x02CANARY\xff\xfe") }, 1},
		{"escape sequences in the bundle", func(t *testing.T, e *imp) []byte {
			return []byte("\x1b[31mCANARY\x1b[0m\nkairan-proxy: error: forged")
		}, 1},
		{"trailing bytes after the envelope", func(t *testing.T, e *imp) []byte {
			return append(envJSON(signedBy(t, valid(1), "admin-a", "admin-b")), []byte(" CANARY")...)
		}, 1},
		{"flipped signature", func(t *testing.T, e *imp) []byte {
			env := signedBy(t, valid(1), "admin-a", "admin-b")
			env.Signatures[0].Sig[0] ^= 0xff
			return envJSON(env)
		}, 1},
		{"tampered payload after signing", func(t *testing.T, e *imp) []byte {
			env := signedBy(t, valid(1), "admin-a", "admin-b")
			env.Payload = bytes.Replace(env.Payload, []byte("canarytool"), []byte("canarytoo2"), 1)
			return envJSON(env)
		}, 1},
		{"nine signatures", func(t *testing.T, e *imp) []byte {
			env := signedBy(t, valid(1), "admin-a", "admin-b")
			for i := 0; i < 7; i++ {
				env.Signatures = append(env.Signatures, env.Signatures[0])
			}
			return envJSON(env)
		}, 1},
		{"oversize bundle", func(t *testing.T, e *imp) []byte { return bytes.Repeat([]byte("CANARY "), 400000) }, 1},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			e := newImp(t)
			e.cfg = e.cfg.with("data_dir", filepath.Join(filepath.Dir(e.dir), "CANARYDATA", "d"))
			e.dir = e.cfg["data_dir"].(string)
			b := cs.prep(t, e)
			bp := filepath.Join(t.TempDir(), "CANARYBUNDLE.json")
			if err := os.WriteFile(bp, b, 0o600); err != nil {
				t.Fatal(err)
			}
			r := runSplit(t, []string{"-config", cfgPath(t, e.cfg.bytes()), "-import", bp}, nil, "")
			r.mustExit(t, cs.code)
			forbid := append(append([]string{}, commonForbid...), pubs(t)...)
			forbid = append(forbid, "tenant-canary")
			var env wire.Envelope
			if json.Unmarshal(b, &env) == nil {
				for _, s := range env.Signatures {
					forbid = append(forbid, string(s.KeyID))
				}
				if len(env.Payload) > 0 && cs.code != 0 {
					// the hash of an applied policy is shown (the apply log and decisions carry it too); the
					// hash of a rejected bundle is bundle content that was never applied
					forbid = append(forbid, string(hashOf(env.Payload)))
				}
			}
			bilingual(t, cs.name, r.err, forbid...)
			lines := nonEmpty(r.err)
			if len(lines) == 0 {
				t.Fatalf("the import printed nothing: a person must see the result")
			}
			if !hasJP(r.err) {
				t.Errorf("no Japanese in the import result: %s", clip(r.err))
			}
			if cs.code == 0 && len(lines) < 2 {
				t.Errorf("success result is not two lines (English, Japanese): %q", lines)
			}
			if cs.code == 1 && strings.Count(r.err, "kairan-proxy: error:") < 1 {
				t.Errorf("a rejected bundle prints no 'kairan-proxy: error:' line: %s", clip(r.err))
			}
			if cs.code == 0 && strings.Contains(r.err, "kairan-proxy: error:") {
				t.Errorf("a successful import prints an error line: %s", clip(r.err))
			}
			if len(r.err) > 4096 {
				t.Errorf("%d bytes of import output", len(r.err))
			}
		})
	}
}

// Unreadable bundles: missing, directory, FIFO, device, symlink. The path is typed text.
func TestMsgImportUnreadableBundles(t *testing.T) {
	e := newImp(t)
	cfg := cfgPath(t, e.cfg.bytes())
	fifo := filepath.Join(t.TempDir(), "CANARYFIFO")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	d := filepath.Join(t.TempDir(), "CANARYDIR")
	os.MkdirAll(d, 0o700)
	link := filepath.Join(t.TempDir(), "CANARYLINK")
	os.Symlink("/etc/passwd", link)
	cases := map[string]string{
		"missing":        filepath.Join(t.TempDir(), "CANARYMISSING.json"),
		"directory":      d,
		"FIFO":           fifo,
		"/dev/zero":      "/dev/zero",
		"/dev/null":      "/dev/null",
		"symlink":        link,
		"escape in path": filepath.Join(t.TempDir(), "\x1b[2JCANARY"),
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			r := runSplit(t, []string{"-config", cfg, "-import", p}, nil, "")
			if !r.ok || r.code != 1 && r.code != 2 {
				t.Fatalf("exit %d ok=%v: %s", r.code, r.ok, clip(r.err))
			}
			if bilingual(t, name, r.err, commonForbid...).pairs < 1 {
				t.Errorf("no error pair: %s", clip(r.err))
			}
			if _, err := os.Stat(filepath.Join(e.dir, "policy.json")); err == nil {
				t.Errorf("a policy was stored from an unreadable bundle")
			}
		})
	}
}

// An import over a broken apply log recovers (reset) or refuses, and says so in both languages.
func TestMsgImportOverBrokenLog(t *testing.T) {
	for _, c := range brokenLogCases {
		t.Run(c.name, func(t *testing.T) {
			e := newImp(t)
			e.brokenAt(c.f)
			r := runSplit(t, []string{"-config", cfgPath(t, e.cfg.bytes()), "-import", e.bundle(envJSON(good(t, 3)))}, nil, "")
			r.mustExit(t, 0)
			bilingual(t, "reset import", r.err, append(append([]string{}, commonForbid...), pubs(t)...)...)
			if len(nonEmpty(r.err)) < 2 {
				t.Errorf("recovery result: %s", clip(r.err))
			}
			e2 := newImp(t)
			e2.brokenAt(c.f)
			r2 := runSplit(t, []string{"-config", cfgPath(t, e2.cfg.bytes()), "-import", e2.bundle(envJSON(good(t, 1)))}, nil, "")
			r2.mustExit(t, 1)
			if bilingual(t, "import refused over a broken log", r2.err, append(append([]string{}, commonForbid...), pubs(t)...)...).pairs < 1 {
				t.Errorf("no error pair: %s", clip(r2.err))
			}
		})
	}
}

// Golden fixtures: every rejection of cases.json by -import prints a bilingual result and none of the bundle.
func TestMsgImportGoldenRejections(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name string `json:"name"`
			File string `json:"file"`
			Have uint64 `json:"have"`
			Want string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range doc.Cases {
		if c.Want == "" {
			continue
		}
		n++
		t.Run(c.Name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", c.File))
			if err != nil {
				t.Fatal(err)
			}
			e := newImp(t)
			if c.Have > 0 {
				e.apply(good(t, c.Have))
			}
			forbid := append(append([]string{}, commonForbid...), pubs(t)...)
			var env wire.Envelope
			if json.Unmarshal(b, &env) == nil {
				for _, s := range env.Signatures {
					forbid = append(forbid, string(s.KeyID))
				}
			}
			r := runSplit(t, []string{"-config", cfgPath(t, e.cfg.bytes()), "-import", e.bundle(b)}, nil, "")
			r.mustExit(t, 1)
			if bilingual(t, c.Name, r.err, forbid...).pairs < 1 {
				t.Errorf("no error pair: %s", clip(r.err))
			}
		})
	}
	if n < 10 {
		t.Fatalf("only %d golden rejection cases", n)
	}
}

// Import with a bad config keeps both languages and echoes nothing.
func TestMsgImportBadConfigs(t *testing.T) {
	e := newImp(t)
	bp := e.bundle(envJSON(good(t, 1)))
	for name, c := range map[string]pcfg{
		"threshold 1":      e.cfg.with("threshold", 1),
		"skew over 5m":     e.cfg.with("skew", "6m"),
		"bad safe_mode":    e.cfg.with("safe_mode", "CANARY"),
		"bad key":          e.cfg.with("trusted_keys", []string{"CANARY", "yy"}),
		"missing data_dir": e.cfg.with("data_dir", nil),
	} {
		t.Run(name, func(t *testing.T) {
			r := runSplit(t, []string{"-config", cfgPath(t, c.bytes()), "-import", bp}, nil, "")
			r.mustExit(t, 2)
			if bilingual(t, name, r.err, commonForbid...).pairs < 1 {
				t.Errorf("no error pair: %s", clip(r.err))
			}
		})
	}
}

// ---- the data directory is in use ----

func TestMsgDataDirectoryInUse(t *testing.T) {
	l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	forbid := append(append([]string{}, commonForbid...), pubs(t)...)

	check := func(name string, r splitRun) {
		t.Helper()
		if !r.ok {
			t.Fatalf("%s: did not exit", name)
		}
		if r.code != 1 {
			t.Errorf("%s: exit %d, want 1: %s", name, r.code, clip(r.err))
		}
		if bilingual(t, name, r.err, forbid...).pairs < 1 {
			t.Errorf("%s: no error pair: %s", name, clip(r.err))
		}
		if !strings.Contains(r.err, "data directory is in use") {
			t.Errorf("%s: the documented words \"the data directory is in use\" are missing: %s", name, clip(r.err))
		}
		if !strings.Contains(r.err, "使用中") && !strings.Contains(r.err, "使われて") && !strings.Contains(r.err, "ロック") {
			t.Errorf("%s: the Japanese line does not say it is in use or locked: %s", name, clip(r.err))
		}
	}
	bp := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(bp, envJSON(good(t, 2)), 0o600)
	check("import beside a proxy", runSplit(t, []string{"-config", cfgPath(t, l.cfg.bytes()), "-import", bp}, nil, ""))
	c2 := l.cfg.with("listen", freePort(t))
	check("second proxy", runSplit(t, []string{"-config", cfgPath(t, c2.bytes())}, nil, ""))
	bilingual(t, "running proxy log", l.p.out.String(), forbid...)
	if !allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Errorf("the running proxy stopped enforcing")
	}
	l.stop()
}

// ---- startup failures ----

func TestMsgStartupFailures(t *testing.T) {
	cp := "http://127.0.0.1:9"
	up := "http://127.0.0.1:9/mcp-CANARYUP"
	forbid := append(append([]string{}, commonForbid...), pubs(t)...)
	run := func(t *testing.T, name string, c pcfg, wantCodes ...int) {
		t.Helper()
		r := runSplit(t, []string{"-config", cfgPath(t, c.bytes())}, nil, "")
		if !r.ok {
			t.Fatalf("did not exit")
		}
		okc := false
		for _, w := range wantCodes {
			okc = okc || r.code == w
		}
		if !okc {
			t.Errorf("exit %d, want one of %v: %s", r.code, wantCodes, clip(r.err))
		}
		fb := append([]string{}, forbid...)
		if d, ok := c["data_dir"].(string); ok {
			fb = append(fb, d)
		}
		if bilingual(t, name, r.err, fb...).pairs < 1 {
			t.Errorf("no English+Japanese error pair: %s", clip(r.err))
		}
	}
	t.Run("MCP port in use", func(t *testing.T) {
		l, err := listenTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		run(t, "port in use", baseCfg(t, filepath.Join(t.TempDir(), "CANARYD", "d"), cp, up, l.Addr().String()), 1)
	})
	t.Run("metrics port in use", func(t *testing.T) {
		l, err := listenTCP()
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		run(t, "metrics port in use", baseCfg(t, filepath.Join(t.TempDir(), "CANARYD", "d"), cp, up, freePort(t)).with("metrics_listen", l.Addr().String()), 1)
	})
	t.Run("decisions.log is a directory", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "CANARYD", "d")
		os.MkdirAll(filepath.Join(d, "decisions.log"), 0o700)
		run(t, "decisions.log directory", baseCfg(t, d, cp, up, freePort(t)), 1)
	})
	t.Run("decisions.log is a symlink", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "CANARYD", "d")
		os.MkdirAll(d, 0o700)
		os.Symlink(filepath.Join(t.TempDir(), "CANARYVICTIM"), filepath.Join(d, "decisions.log"))
		run(t, "decisions.log symlink", baseCfg(t, d, cp, up, freePort(t)), 1, 2)
	})
	t.Run("data_dir is a regular file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "CANARYFILE")
		os.WriteFile(f, []byte("x"), 0o600)
		run(t, "data_dir is a file", baseCfg(t, f, cp, up, freePort(t)), 1, 2)
	})
	t.Run("data_dir cannot be created", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "CANARYRO")
		os.MkdirAll(d, 0o700)
		os.Chmod(d, 0o500)
		defer os.Chmod(d, 0o700)
		if os.Geteuid() == 0 {
			t.Fatal("running as root: cannot test permission denial")
		}
		run(t, "data_dir cannot be created", baseCfg(t, filepath.Join(d, "sub", "data"), cp, up, freePort(t)), 1)
	})
	t.Run("ca_file missing", func(t *testing.T) {
		run(t, "ca_file missing", baseCfg(t, filepath.Join(t.TempDir(), "d"), cp, up, freePort(t)).with("ca_file", filepath.Join(t.TempDir(), "CANARYCA.pem")), 2)
	})
	t.Run("ca_file is not a certificate", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "CANARYCA.pem")
		os.WriteFile(f, []byte("CANARY not pem"), 0o600)
		run(t, "ca_file not PEM", baseCfg(t, filepath.Join(t.TempDir(), "d"), cp, up, freePort(t)).with("ca_file", f), 2)
	})
}

// ---- startup, shutdown, runtime warnings ----

func TestMsgStartupAndShutdown(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
			l.offer(1, "admin-a", "admin-b")
			l.start("", func(c pcfg) pcfg { return c.with("metrics_listen", freePort(t)) }, nil)
			l.waitAllowed()
			forbid := append(append([]string{}, commonForbid...), pubs(t)...)
			forbid = append(forbid, l.dir)
			started := l.p.out.String()
			st := bilingual(t, "startup", started, forbid...)
			if st.json < 3 {
				t.Errorf("only %d log lines at startup: %s", st.json, clip(started))
			}
			for _, want := range []string{"listening", "boot"} {
				if !strings.Contains(strings.ToLower(started), want) {
					t.Errorf("no %q line at startup: %s", want, clip(started))
				}
			}
			l.p.call(keySales, callBody("crm.read_contact", `{"x":"CANARY-ARG"}`))
			l.p.call(keySales, callBody("admin.shutdown", `{"x":"CANARY-ARG"}`))
			l.p.call("wrong-key-CANARY", callBody("crm.read_contact", `{}`))
			l.p.call("", "CANARY not json")
			l.p.signal(sig)
			code, ok := l.p.waitExit(10 * time.Second)
			if !ok || code != 0 {
				t.Fatalf("exit %d ok=%v", code, ok)
			}
			all := l.p.out.String()
			bilingual(t, "run and shutdown", all, forbid...)
			after := strings.TrimPrefix(all, started)
			if !strings.Contains(strings.ToLower(after), "shut") && !strings.Contains(strings.ToLower(after), "stop") {
				t.Errorf("no shutdown line after the signal: %s", clip(after))
			}
			if bilingual(t, "shutdown", after).json < 1 {
				t.Errorf("no log line at shutdown: %s", clip(after))
			}
		})
	}
}

// Rejected offers: the log says so in both languages and carries nothing of the offer.
func TestMsgRejectedOffers(t *testing.T) {
	l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
	l.offer(5, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	now := time.Now()
	two := func(doc []byte) wire.Envelope { return envelopeOf(doc, key(t, "admin-a"), key(t, "admin-b")) }
	bad := []wire.Envelope{
		envelopeOf(canaryPolicy(tenant, 6, now.Add(-time.Hour), now.Add(time.Hour))),
		envelopeOf(canaryPolicy(tenant, 6, now.Add(-time.Hour), now.Add(time.Hour)), key(t, "admin-a")),
		envelopeOf(canaryPolicy(tenant, 6, now.Add(-time.Hour), now.Add(time.Hour)), key(t, "admin-a"), key(t, "outsider")),
		two(canaryPolicy("tenant-canary-b", 6, now.Add(-time.Hour), now.Add(time.Hour))),
		two(canaryPolicy(tenant, 4, now.Add(-time.Hour), now.Add(time.Hour))),
		two(canaryPolicy(tenant, 5, now.Add(-time.Hour), now.Add(time.Hour))),
		two(canaryPolicy(tenant, 7, now.Add(-48*time.Hour), now.Add(-24*time.Hour))),
		two([]byte(`{"tenant":"bank-a","canaryfield":"CANARY-PAYLOAD"}`)),
		two([]byte("CANARY-PAYLOAD not json")),
		{PayloadType: "application/CANARY", Payload: canaryPolicy(tenant, 6, now.Add(-time.Hour), now.Add(time.Hour))},
	}
	idx := 0
	var imu sync.Mutex
	l.cp.mu.Lock()
	l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) {
		imu.Lock()
		defer imu.Unlock()
		e := bad[idx%len(bad)]
		idx++
		return e, true
	}
	l.cp.mu.Unlock()
	waitFor(t, "all bad offers seen", 60*time.Second, func() bool { imu.Lock(); defer imu.Unlock(); return idx >= len(bad)+1 })
	time.Sleep(500 * time.Millisecond)
	out := l.p.out.String()
	forbid := append(append([]string{}, commonForbid...), pubs(t)...)
	forbid = append(forbid, "tenant-canary", "canaryfield", "canarytool", "canaryrole", l.dir)
	for _, e := range bad {
		for _, s := range e.Signatures {
			forbid = append(forbid, string(s.KeyID))
		}
		if len(e.Payload) > 0 {
			forbid = append(forbid, string(hashOf(e.Payload)))
		}
	}
	bilingual(t, "rejected offers", out, forbid...)
	warn := 0
	for _, ln := range strings.Split(out, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && (m["level"] == "WARN" || m["level"] == "ERROR") && !strings.Contains(fmt.Sprint(m["msg"]), "TEST-ONLY") {
			warn++
		}
	}
	if warn < 1 {
		t.Errorf("no WARN line for %d rejected offers: %s", len(bad), clip(out))
	}
	l.stop()
}

// A boot over tampered files says tampered in both languages.
func TestMsgTamperedBoot(t *testing.T) {
	cases := []struct {
		name string
		do   func(t *testing.T, l *life)
	}{
		{"policy garbage", func(t *testing.T, l *life) { os.WriteFile(l.policyFile(), []byte("CANARY garbage"), 0o600) }},
		{"policy deleted", func(t *testing.T, l *life) { os.Remove(l.policyFile()) }},
		{"apply log garbage appended", func(t *testing.T, l *life) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, []byte("CANARY garbage\n")...), 0o600)
		}},
		{"apply log field edited", func(t *testing.T, l *life) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, bytes.Replace(b, []byte(`"to":1`), []byte(`"to":0`), 1), 0o600)
		}},
		{"apply log cut", func(t *testing.T, l *life) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)-5], 0o600)
		}},
		{"apply log binary", func(t *testing.T, l *life) {
			os.WriteFile(filepath.Join(l.dir, "apply.log"), []byte("\x00\x1b[31mCANARY\xff\n"), 0o600)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
			l.offer(1, "admin-a", "admin-b")
			l.start("", nil, nil)
			l.waitAllowed()
			l.stop()
			c.do(t, l)
			l2 := &life{t: t, dir: l.dir, cp: newCP(t), up: l.up}
			l2.start("http://"+freePort(t), nil, nil)
			l2.p.call(keySales, callBody("crm.read_contact", `{}`))
			l2.p.signal(syscall.SIGTERM)
			l2.p.waitExit(10 * time.Second)
			out := l2.p.out.String()
			forbid := append(append([]string{}, commonForbid...), pubs(t)...)
			forbid = append(forbid, l.dir)
			bilingual(t, c.name, out, forbid...)
			found := false
			for _, ln := range strings.Split(out, "\n") {
				var m map[string]any
				if json.Unmarshal([]byte(ln), &m) != nil {
					continue
				}
				if strings.Contains(strings.ToLower(fmt.Sprint(m["msg"])), "tamper") || m["state"] == "tampered" {
					found = true
				}
			}
			if !found {
				t.Errorf("no tamper log line: %s", clip(out))
			}
		})
	}
}

// clock_untrusted: a high-water mark ahead of the clock.
func TestMsgClockUntrusted(t *testing.T) {
	l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	l.stop()
	hw := filepath.Join(l.dir, "highwater")
	b, err := os.ReadFile(hw)
	if err != nil {
		t.Fatal(err)
	}
	cur, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	future := cur.Add(72 * time.Hour).UTC().Format(time.RFC3339Nano)
	os.WriteFile(hw, []byte(future+"\n"), 0o600)
	l2 := &life{t: t, dir: l.dir, cp: newCP(t), up: l.up}
	maddr := freePort(t)
	l2.start("http://"+freePort(t), func(c pcfg) pcfg { return c.with("metrics_listen", maddr) }, nil)
	waitDial(t, maddr)
	// the scenario is real: the proxy itself says its clock is untrusted
	if v, body := getSelf(t, maddr); !v.ClockUntrusted {
		t.Fatalf("a wall clock 72 h behind the high-water mark is not reported as clock_untrusted: %s", body)
	}
	l2.p.call(keySales, callBody("crm.update_deal", `{}`))
	time.Sleep(700 * time.Millisecond)
	l2.stop()
	out := l2.p.out.String()
	forbid := append(append([]string{}, commonForbid...), pubs(t)...)
	forbid = append(forbid, l.dir, future)
	bilingual(t, "clock_untrusted", out, forbid...)
	// The doc names the counter and the self view for clock_untrusted but no log line, so a missing line is not
	// asserted here (see change-request); a line that exists must be a warning and bilingual (checked above).
	for _, ln := range strings.Split(out, "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(ln), &m) == nil && strings.Contains(strings.ToLower(fmt.Sprint(m["msg"])), "clock") {
			if lv := fmt.Sprint(m["level"]); lv != "WARN" && lv != "ERROR" {
				t.Errorf("clock line is level %s", lv)
			}
		}
	}
	os.WriteFile(hw, []byte("CANARY garbage"), 0o600)
	l3 := &life{t: t, dir: l.dir, cp: newCP(t), up: l.up}
	l3.start("http://"+freePort(t), nil, nil)
	l3.stop()
	bilingual(t, "garbage high-water mark", l3.p.out.String(), forbid...)
}

// Expiry at run time: the safe-mode lines are bilingual.
func TestMsgExpiry(t *testing.T) {
	l := newLife(t, filepath.Join(t.TempDir(), "CANARYDATA", "d"))
	env := envelopeOf(policyDoc(tenant, 1, time.Now().Add(-time.Hour), time.Now().Add(3*time.Second)), key(t, "admin-a"), key(t, "admin-b"))
	l.cp.mu.Lock()
	l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) { return env, have < 1 }
	l.cp.mu.Unlock()
	l.start("", func(c pcfg) pcfg { return c.with("skew", "1s") }, nil)
	l.waitAllowed()
	l.cp.mu.Lock()
	l.cp.offer = nil
	l.cp.mu.Unlock()
	waitFor(t, "safe mode", 15*time.Second, func() bool {
		return !allowed(l.p.call(keySales, callBody("crm.update_deal", `{}`)))
	})
	time.Sleep(500 * time.Millisecond)
	l.stop()
	out := l.p.out.String()
	forbid := append(append([]string{}, commonForbid...), pubs(t)...)
	forbid = append(forbid, l.dir)
	bilingual(t, "expiry", out, forbid...)
	if !strings.Contains(strings.ToLower(out), "expir") && !strings.Contains(strings.ToLower(out), "safe") {
		t.Errorf("no expiry or safe-mode line: %s", clip(out))
	}
}

// A reset by the control plane: a newer valid policy over a broken log.
func TestMsgResetFromControlPlane(t *testing.T) {
	for _, c := range brokenLogCases {
		t.Run(c.name, func(t *testing.T) {
			e := newImp(t)
			e.cfg = e.cfg.with("data_dir", filepath.Join(filepath.Dir(e.dir), "CANARYDATA", "d"))
			e.dir = e.cfg["data_dir"].(string)
			e.brokenAt(c.f)
			l := &life{t: t, dir: e.dir, cp: newCP(t), up: newUpstream(t)}
			l.offer(3, "admin-a", "admin-b")
			l.start("", nil, nil)
			l.waitAllowed()
			time.Sleep(300 * time.Millisecond)
			l.stop()
			out := l.p.out.String()
			forbid := append(append([]string{}, commonForbid...), pubs(t)...)
			forbid = append(forbid, e.dir)
			bilingual(t, c.name, out, forbid...)
			found := false
			for _, ln := range strings.Split(out, "\n") {
				var m map[string]any
				if json.Unmarshal([]byte(ln), &m) == nil && strings.Contains(strings.ToLower(fmt.Sprint(m["msg"])), "reset") {
					found = true
				}
			}
			if !found {
				t.Errorf("no log line says the apply log was reset: %s", clip(out))
			}
		})
	}
}

// Fuzz target: whatever is in the config file, a config error stays bilingual, escaped and free of the marker.
func FuzzMsgConfigFile(f *testing.F) {
	g := baseCfg(f, filepath.Join(f.TempDir(), "d"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", "127.0.0.1:0").with("threshold", 1)
	f.Add(g.bytes())
	f.Add([]byte(`{"tenant":"CANARY"}`))
	f.Add([]byte("{\"a\\nb\":1}"))
	f.Add([]byte(`{"\u001b[2J":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			return
		}
		r := runSplit(t, []string{"-config", cfgPath(t, raw)}, nil, "")
		if r.ok && r.code == 2 {
			for _, ln := range strings.Split(r.err, "\n") {
				if strings.HasPrefix(ln, "kairan-proxy: error:") && hasJP(ln) {
					return // a field name typed in Japanese would look like a Japanese line to the checker
				}
			}
			bilingual(t, "fuzz", r.err)
		}
	})
}

// PRD J7 asks for a Japanese line, and a person reading it should not meet a raw Go library error in the middle
// of it. The docs say only "a Japanese line", so this is stricter than the documented minimum; it is a separate
// test so an Overseer ruling that the tail may stay English touches this test only.
func TestMsgJapaneseLineHoldsNoLibraryError(t *testing.T) {
	cp := "http://127.0.0.1:9"
	up := "http://127.0.0.1:9/mcp"
	busy, err := listenTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	ro := filepath.Join(t.TempDir(), "ro")
	os.MkdirAll(ro, 0o700)
	os.Chmod(ro, 0o500)
	defer os.Chmod(ro, 0o700)
	cases := []struct {
		name string
		args func(t *testing.T) []string
	}{
		{"config file missing", func(t *testing.T) []string {
			return []string{"-config", filepath.Join(t.TempDir(), "nope.json")}
		}},
		{"MCP port in use", func(t *testing.T) []string {
			return []string{"-config", cfgPath(t, baseCfg(t, filepath.Join(t.TempDir(), "d"), cp, up, busy.Addr().String()).bytes())}
		}},
		{"data_dir cannot be created", func(t *testing.T) []string {
			return []string{"-config", cfgPath(t, baseCfg(t, filepath.Join(ro, "sub", "d"), cp, up, freePort(t)).bytes())}
		}},
		{"ca_file missing", func(t *testing.T) []string {
			c := baseCfg(t, filepath.Join(t.TempDir(), "d"), cp, up, freePort(t)).with("ca_file", filepath.Join(t.TempDir(), "nope.pem"))
			return []string{"-config", cfgPath(t, c.bytes())}
		}},
		{"decisions.log is a symlink", func(t *testing.T) []string {
			d := filepath.Join(t.TempDir(), "d")
			os.MkdirAll(d, 0o700)
			os.Symlink(filepath.Join(t.TempDir(), "victim"), filepath.Join(d, "decisions.log"))
			return []string{"-config", cfgPath(t, baseCfg(t, d, cp, up, freePort(t)).bytes())}
		}},
		{"import bundle missing", func(t *testing.T) []string {
			c := baseCfg(t, filepath.Join(t.TempDir(), "d"), cp, up, freePort(t))
			return []string{"-config", cfgPath(t, c.bytes()), "-import", filepath.Join(t.TempDir(), "nope.json")}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := runSplit(t, c.args(t), nil, "")
			if !r.ok {
				t.Fatal("did not exit")
			}
			found := false
			for _, ln := range strings.Split(r.err, "\n") {
				if !strings.HasPrefix(ln, "kairan-proxy: エラー:") {
					continue
				}
				found = true
				if m := englishSentenceRe.FindString(ln); m != "" {
					t.Errorf("the Japanese error line carries untranslated English text %q: %q", m, clip(ln))
				}
			}
			if !found {
				t.Errorf("no Japanese error line: %s", clip(r.err))
			}
		})
	}
}
