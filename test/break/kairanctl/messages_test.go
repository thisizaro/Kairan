package kairanctlbreak

// Break pass for the message rules of M-D65 (Q-D32 .. Q-D35), PRD J7 and invariant I4, applied to kairanctl.
// Sources: the go doc of the kairanctl command ("Errors are printed in English and Japanese (PRD J7)",
// "Exit codes: 0 success, 1 the command was refused or failed, 2 bad usage"), PRD J7, M-D65.
//
// Contract checked, for every failing run below:
//   - standard error starts with exactly one English line "error: ..." immediately followed by exactly one
//     Japanese line "エラー: ..."; nothing else may precede or replace it (so the flag package's own English
//     only output "flag provided but not defined: ..." or "invalid value ..." is a failure); a usage block may
//     follow after a blank line;
//   - the English line holds no Japanese script, the Japanese line does;
//   - Q-D32: no path, URL, token or value the user typed or configured is echoed. Every such string below
//     carries a CANARY marker, so a leak is a hit. Values from a server's answer (status text, body) are never echoed;
//   - Q-D33: a typed flag name may be echoed only escaped (control bytes as \xNN, no raw newline or ESC) and
//     truncated to 128 bytes. The marker CANARYFLAG is used for names and is the only marker allowed in output;
//   - Q-D34: OS and library error text appears only on the English line: the Japanese line has no raw English
//     library error ("no such file or directory", "connection refused", "invalid value ... parse error");
//   - nothing in the output is a raw control character.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"unicode/utf8"
)

var ctlValueMarkers = []string{"CANARYVAL", "CANARYPATH", "CANARYDIR", "CANARYTLS", "CANARYTOKEN", "CANARYBODY", "CANARYURL", "CANARYHOST", "CANARYKEY", "CANARYPOS", "CANARYIN", "CANARYCMD", "CANARYSUB"}

var ctlEnglishRunRe = regexp.MustCompile(`\b[a-z]{2,}(?: [a-z]{2,}){2,}\b`)

var ctlLibPhrases = func() []string {
	ph := []string{"i/o timeout", "no such host", "unexpected eof", "context deadline exceeded", "context canceled",
		"file already exists", "file does not exist", "invalid argument", "tls: ", "x509: ", "dial tcp", "listen tcp",
		"json: ", "invalid character", "unexpected end", "cannot unmarshal", "not a directory", "is a directory",
		"parse error", "invalid value", "flag provided", "connection reset", "server closed", "malformed http"}
	for i := 1; i < 134; i++ {
		e := strings.ToLower(syscall.Errno(i).Error())
		if len(e) >= 8 && !strings.HasPrefix(e, "errno ") && !strings.HasPrefix(e, "unknown") {
			ph = append(ph, e)
		}
	}
	return ph
}()

func ctlRawEnglish(ja string) bool {
	low := strings.ToLower(ja)
	for _, p := range ctlLibPhrases {
		if strings.Contains(low, p) {
			return true
		}
	}
	return ctlEnglishRunRe.MatchString(ja)
}

func ctlHasJP(s string) bool {
	for _, r := range s {
		if (r >= 0x3040 && r <= 0x30ff) || (r >= 0x4e00 && r <= 0x9fff) {
			return true
		}
	}
	return false
}

func ctlClip(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

// checkCtl applies the contract to the standard error of a failing run.
func checkCtl(t testing.TB, what string, r result, flagName bool, extraForbid ...string) {
	t.Helper()
	out := r.stderr
	if os.Getenv("MSG_DUMP") != "" {
		t.Logf("%s: exit %d stderr:\n%s", what, r.code, out)
	}
	if r.code != 1 && r.code != 2 {
		t.Errorf("%s: exit %d, want 1 (refused or failed) or 2 (bad usage): %s", what, r.code, ctlClip(out))
	}
	if r.stdout != "" && r.code != 0 {
		t.Errorf("%s: standard output is not empty on a failure: %s", what, ctlClip(r.stdout))
	}
	low := strings.ToLower(out)
	for _, f := range append(append([]string{}, ctlValueMarkers...), extraForbid...) {
		if f != "" && strings.Contains(low, strings.ToLower(f)) {
			t.Errorf("%s: output echoes %q (Q-D32): %s", what, f, ctlClip(out))
		}
	}
	if !flagName && strings.Contains(out, "CANARY") {
		t.Errorf("%s: output carries a CANARY marker: %s", what, ctlClip(out))
	}
	if !utf8.ValidString(out) {
		t.Errorf("%s: output is not valid UTF-8: %q", what, ctlClip(out))
	}
	for _, c := range out {
		if (c < 0x20 && c != '\n' && c != '\t') || c == 0x7f || (c >= 0x80 && c < 0xa0) {
			t.Errorf("%s: raw control character %U in the output (Q-D33: escape it): %q", what, c, ctlClip(out))
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "error: ") || !strings.HasPrefix(lines[1], "エラー: ") {
		t.Errorf("%s: standard error does not start with an English line \"error: ...\" and a Japanese line \"エラー: ...\" (PRD J7): %s", what, ctlClip(out))
		return
	}
	if ctlHasJP(lines[0]) {
		t.Errorf("%s: the English line holds Japanese script: %q", what, ctlClip(lines[0]))
	}
	if !ctlHasJP(lines[1]) {
		t.Errorf("%s: the Japanese line holds no Japanese script: %q", what, ctlClip(lines[1]))
	}
	if ctlRawEnglish(strings.TrimPrefix(lines[1], "エラー: ")) {
		t.Errorf("%s: the Japanese line carries raw English library text (Q-D34): %q", what, ctlClip(lines[1]))
	}
	rest := lines[2:]
	for len(rest) > 0 && strings.TrimSpace(rest[0]) == "" {
		rest = rest[1:]
	}
	if len(rest) > 0 && !strings.HasPrefix(rest[0], "kairanctl:") {
		t.Errorf("%s: extra text after the error pair that is not the usage (a second message, or raw library output): %s", what, ctlClip(strings.Join(rest, "\n")))
	}
	for _, ln := range lines {
		if ln != lines[0] && strings.HasPrefix(ln, "error: ") {
			t.Errorf("%s: a second or forged English error line: %q", what, ctlClip(ln))
		}
		if ln != lines[1] && strings.HasPrefix(ln, "エラー: ") {
			t.Errorf("%s: a second Japanese error line: %q", what, ctlClip(ln))
		}
	}
	if flagName {
		if len(lines[0]) > 512 || len(lines[1]) > 640 {
			t.Errorf("%s: error lines are %d and %d bytes: the echoed flag name is not truncated to 128 bytes", what, len(lines[0]), len(lines[1]))
		}
	} else if len(out) > 8192 {
		t.Errorf("%s: %d bytes of output: typed text is echoed unbounded", what, len(out))
	}
}

func hasEscapedControl(out string) bool {
	return strings.Contains(out, `\x`) || strings.Contains(out, `\n`) || strings.Contains(out, `\r`)
}

// ---- usage and flag errors ----

func TestMsgUsageAndFlagErrors(t *testing.T) {
	bin := buildCtl(t)
	subs := [][]string{{"keygen"}, {"policy", "new"}, {"sign"}, {"approve"}, {"publish"}, {"rollout", "start"}, {"rollout", "status"},
		{"rollout", "rollback"}, {"fleet"}, {"evidence", "export"}, {"verify-applylog"}}
	type tc struct {
		name     string
		args     []string
		flagName bool
	}
	cases := []tc{
		{"no arguments", nil, false},
		{"unknown command", []string{"bogus"}, false},
		{"command is a canary", []string{"CANARYCMD"}, false},
		{"command is a flag", []string{"-CANARYFLAG"}, true},
		{"command with an escape", []string{"\x1b[2JCANARYCMD"}, false},
		{"command with a newline", []string{"a\nerror: forged"}, false},
		{"long command", []string{strings.Repeat("c", 50000)}, false},
		{"policy without a subcommand", []string{"policy"}, false},
		{"policy unknown subcommand", []string{"policy", "CANARYSUB"}, false},
		{"rollout unknown subcommand", []string{"rollout", "CANARYSUB"}, false},
		{"evidence unknown subcommand", []string{"evidence", "CANARYSUB"}, false},
	}
	for _, s := range subs {
		n := strings.Join(s, " ")
		pre := func(extra ...string) []string { return append(append([]string{}, s...), extra...) }
		cases = append(cases,
			tc{n + ": unknown flag", pre("-CANARYFLAG"), true},
			tc{n + ": double dash flag", pre("--CANARYFLAG"), true},
			tc{n + ": flag with a value", pre("-bogus=CANARYVAL"), true},
			tc{n + ": flag name with a newline", pre("-a\nerror: forged"), true},
			tc{n + ": flag name with an escape", pre("-\x1b[2JCANARYFLAG"), true},
			tc{n + ": flag name with a bell", pre("-a\x07CANARYFLAG"), true},
			tc{n + ": long flag name", pre("-" + strings.Repeat("x", 50000)), true},
			tc{n + ": positional canary", pre("CANARYPOS"), false},
		)
	}
	cases = append(cases,
		tc{"keygen -name without value", []string{"keygen", "-name"}, false},
		tc{"policy new bad -version", []string{"policy", "new", "-tenant", "bank-a", "-version", "CANARYVAL"}, false},
		tc{"policy new negative -version", []string{"policy", "new", "-tenant", "bank-a", "-version", "-5"}, false},
		tc{"policy new bad -validity", []string{"policy", "new", "-tenant", "bank-a", "-validity", "CANARYVAL"}, false},
		tc{"policy new bad tenant", []string{"policy", "new", "-tenant", "CANARYVAL Bank"}, false},
		tc{"policy new tenant with an escape", []string{"policy", "new", "-tenant", "a\x1b[2JCANARYVAL"}, false},
		tc{"rollout start bad -canary-dwell", []string{"rollout", "start", "-url", "https://127.0.0.1:1", "-tenant", "bank-a", "-version", "1", "-canary-dwell", "CANARYVAL"}, false},
		tc{"rollout start bad -version", []string{"rollout", "start", "-url", "https://127.0.0.1:1", "-tenant", "bank-a", "-version", "CANARYVAL"}, false},
		tc{"rollout rollback bad -from", []string{"rollout", "rollback", "-from", "CANARYVAL", "-version", "3", "-out", filepath.Join(t.TempDir(), "p.json")}, false},
		tc{"evidence export applylog without =", []string{"evidence", "export", "-url", "https://127.0.0.1:1", "-tenant", "bank-a", "-applylog", "CANARYVAL"}, false},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, bin, nil, "", c.args...)
			checkCtl(t, c.name, r, c.flagName)
			if c.flagName {
				for _, a := range c.args {
					if strings.ContainsAny(a, "\x1b\n\r\x07") && !hasEscapedControl(r.stderr) {
						t.Errorf("%s: a control byte in the typed flag name is not shown escaped (\\xNN): %s", c.name, ctlClip(r.stderr))
					}
				}
			}
		})
	}
}

func TestMsgHelp(t *testing.T) {
	bin := buildCtl(t)
	for _, args := range [][]string{{"-h"}, {"--help"}, {"help"}, {"-h", "-CANARYFLAG"}} {
		r := run(t, bin, nil, "", args...)
		if r.code != 0 && r.code != 2 {
			t.Errorf("%v: exit %d", args, r.code)
		}
		for _, m := range ctlValueMarkers {
			if strings.Contains(r.stdout+r.stderr, m) {
				t.Errorf("%v: help echoes %q", args, m)
			}
		}
	}
}

// ---- file, key and input errors ----

func TestMsgFileErrors(t *testing.T) {
	bin := buildCtl(t)
	work := t.TempDir()
	mkfile := func(name string, mode os.FileMode, body string) string {
		p := filepath.Join(work, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(p, mode)
		return p
	}
	missingDir := filepath.Join(work, "CANARYPATH-dir", "x")
	adir := filepath.Join(work, "CANARYPATH-adir")
	_ = os.MkdirAll(adir, 0o700)
	roDir := filepath.Join(work, "CANARYPATH-ro")
	_ = os.MkdirAll(roDir, 0o500)
	garbageKey := mkfile("CANARYKEY-garbage.key", 0o600, "CANARYKEY not hex at all\n")
	shortKey := mkfile("CANARYKEY-short.key", 0o600, strings.Repeat("ab", 10)+"\n")
	openKey := mkfile("CANARYKEY-open.key", 0o644, strings.Repeat("ab", 32)+"\n")
	badJSON := mkfile("CANARYIN-bad.json", 0o600, `{"tenant": CANARYVAL`)
	unknownField := mkfile("CANARYIN-unknown.json", 0o600, `{"bogus":"CANARYVAL"}`)
	big := mkfile("CANARYIN-big.json", 0o600, `{"x":"CANARYVAL`+strings.Repeat("a", 2<<20)+`"}`)
	garbageEnv := mkfile("CANARYIN-env.json", 0o600, `{"payloadType":"CANARYVAL","payload":"CANARYVAL","signatures":[]}`)
	notEnv := mkfile("CANARYIN-notenv.json", 0o600, "CANARYVAL not json")
	emptyF := mkfile("CANARYIN-empty.json", 0o600, "")
	badLog := mkfile("CANARYIN-applylog.log", 0o600, "CANARYVAL not an apply log\n{\"seq\":1,\"x\":\"CANARYVAL\"}\n")
	existing := mkfile("CANARYPATH-exists.json", 0o600, "{}")
	fifo := filepath.Join(work, "CANARYIN-fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// a real key pair for the "valid key, bad input" cases
	kd := filepath.Join(work, "keys")
	_ = os.MkdirAll(kd, 0o700)
	if r := run(t, bin, nil, "", "keygen", "-name", "k1", "-dir", kd); r.code != 0 {
		t.Fatalf("keygen: exit %d: %s", r.code, r.stderr)
	}
	k1 := filepath.Join(kd, "k1.key")
	out := filepath.Join(work, "out.json")

	cases := []struct {
		name string
		args []string
	}{
		{"keygen -dir missing", []string{"keygen", "-name", "x", "-dir", missingDir}},
		{"keygen -dir is a file", []string{"keygen", "-name", "x", "-dir", existing}},
		{"keygen -dir read-only", []string{"keygen", "-name", "x", "-dir", roDir}},
		{"keygen existing key", []string{"keygen", "-name", "k1", "-dir", kd}},
		{"keygen name with a path", []string{"keygen", "-name", "../CANARYPATH", "-dir", kd}},
		{"keygen name with an escape", []string{"keygen", "-name", "a\x1b[2JCANARYVAL", "-dir", kd}},
		{"keygen name with a newline", []string{"keygen", "-name", "a\nerror: forged CANARYVAL", "-dir", kd}},
		{"keygen name too long", []string{"keygen", "-name", strings.Repeat("n", 5000) + "CANARYVAL", "-dir", kd}},
		{"sign key missing", []string{"sign", "-key", filepath.Join(work, "CANARYPATH-nokey.key"), "-in", badJSON, "-out", out}},
		{"sign key is a directory", []string{"sign", "-key", adir, "-in", badJSON, "-out", out}},
		{"sign key garbage", []string{"sign", "-key", garbageKey, "-in", badJSON, "-out", out}},
		{"sign key short", []string{"sign", "-key", shortKey, "-in", badJSON, "-out", out}},
		{"sign key readable by others", []string{"sign", "-key", openKey, "-in", badJSON, "-out", out}},
		{"sign input missing", []string{"sign", "-key", k1, "-in", filepath.Join(work, "CANARYIN-nope.json"), "-out", out}},
		{"sign input is a directory", []string{"sign", "-key", k1, "-in", adir, "-out", out}},
		{"sign input empty", []string{"sign", "-key", k1, "-in", emptyF, "-out", out}},
		{"sign input not JSON", []string{"sign", "-key", k1, "-in", badJSON, "-out", out}},
		{"sign input unknown field", []string{"sign", "-key", k1, "-in", unknownField, "-out", out}},
		{"sign input too large", []string{"sign", "-key", k1, "-in", big, "-out", out}},
		{"sign output directory missing", []string{"sign", "-key", k1, "-in", unknownField, "-out", filepath.Join(missingDir, "o.json")}},
		{"sign output exists", []string{"sign", "-key", k1, "-in", unknownField, "-out", existing}},
		{"sign output in a read-only dir", []string{"sign", "-key", k1, "-in", unknownField, "-out", filepath.Join(roDir, "o.json")}},
		{"approve envelope not JSON", []string{"approve", "-key", k1, "-in", notEnv, "-out", out, "-yes"}},
		{"approve envelope garbage", []string{"approve", "-key", k1, "-in", garbageEnv, "-out", out, "-yes"}},
		{"approve envelope missing", []string{"approve", "-key", k1, "-in", filepath.Join(work, "CANARYIN-nope.json"), "-out", out, "-yes"}},
		{"approve bad -trusted", []string{"approve", "-key", k1, "-in", garbageEnv, "-out", out, "-yes", "-trusted", "CANARYKEY,CANARYVAL"}},
		{"approve key missing", []string{"approve", "-key", filepath.Join(work, "CANARYPATH-nokey.key"), "-in", garbageEnv, "-out", out, "-yes"}},
		{"publish input missing", []string{"publish", "-url", "https://127.0.0.1:1", "-in", filepath.Join(work, "CANARYIN-nope.json")}},
		{"publish input not JSON", []string{"publish", "-url", "https://127.0.0.1:1", "-in", notEnv}},
		{"publish input FIFO", []string{"publish", "-url", "https://127.0.0.1:1", "-in", fifo}},
		{"verify-applylog missing file", []string{"verify-applylog", "-in", filepath.Join(work, "CANARYIN-nope.log")}},
		{"verify-applylog directory", []string{"verify-applylog", "-in", adir}},
		{"verify-applylog garbage", []string{"verify-applylog", "-in", badLog}},
		{"verify-applylog too large", []string{"verify-applylog", "-in", big}},
		{"evidence export applylog missing", []string{"evidence", "export", "-url", "https://127.0.0.1:1", "-tenant", "bank-a", "-applylog", "p1=" + filepath.Join(work, "CANARYIN-nope.log")}},
		{"evidence export applylog garbage", []string{"evidence", "export", "-url", "https://127.0.0.1:1", "-tenant", "bank-a", "-applylog", "p1=" + badLog}},
		{"policy new output exists", []string{"policy", "new", "-tenant", "bank-a", "-out", existing}},
		{"policy new output dir missing", []string{"policy", "new", "-tenant", "bank-a", "-out", filepath.Join(missingDir, "p.json")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, bin, []string{"KCTL_ADMIN_TOKEN=CANARYTOKEN-0123456789"}, "", c.args...)
			checkCtl(t, c.name, r, false, work)
		})
	}
}

// ---- connection errors: no URL, no token, no raw network error text ----

func TestMsgConnectionErrors(t *testing.T) {
	bin := buildCtl(t)
	work := t.TempDir()
	tokOpen := filepath.Join(work, "CANARYTOKEN-open")
	_ = os.WriteFile(tokOpen, []byte("CANARYTOKEN-0123456789\n"), 0o600)
	_ = os.Chmod(tokOpen, 0o644)
	tokEmpty := filepath.Join(work, "CANARYTOKEN-empty")
	_ = os.WriteFile(tokEmpty, nil, 0o600)
	caGarbage := filepath.Join(work, "CANARYTLS-ca.pem")
	_ = os.WriteFile(caGarbage, []byte("-----BEGIN CERTIFICATE-----\nCANARYTLS\n-----END CERTIFICATE-----\n"), 0o600)
	refused := func() string {
		l, _ := net.Listen("tcp", "127.0.0.1:0")
		a := l.Addr().String()
		l.Close()
		return a
	}()
	tenant := []string{"-tenant", "bank-a"}
	tokEnv := []string{"KCTL_ADMIN_TOKEN=CANARYTOKEN-0123456789"}
	cases := []struct {
		name string
		env  []string
		args []string
	}{
		{"no url", tokEnv, append([]string{"fleet"}, tenant...)},
		{"no token", nil, append([]string{"fleet", "-url", "https://127.0.0.1:1"}, tenant...)},
		{"url over http without -allow-plaintext", tokEnv, append([]string{"fleet", "-url", "http://" + refused + "/CANARYURL"}, tenant...)},
		{"url with userinfo", tokEnv, append([]string{"fleet", "-url", "https://user:CANARYVAL@127.0.0.1:1"}, tenant...)},
		{"url with a path", tokEnv, append([]string{"fleet", "-url", "https://127.0.0.1:1/CANARYURL"}, tenant...)},
		{"url garbage", tokEnv, append([]string{"fleet", "-url", "CANARYURL ://"}, tenant...)},
		{"url with an escape", tokEnv, append([]string{"fleet", "-url", "https://127.0.0.1:1/\x1b[2JCANARYURL"}, tenant...)},
		{"url from the environment", append([]string{"KCTL_CP_URL=http://CANARYHOST.invalid:1/CANARYURL"}, tokEnv...), append([]string{"fleet", "-allow-plaintext"}, tenant...)},
		{"connection refused", tokEnv, append([]string{"fleet", "-allow-plaintext", "-url", "http://" + refused}, tenant...)},
		{"connection refused (publish)", tokEnv, []string{"publish", "-allow-plaintext", "-url", "http://" + refused, "-in", tokOpen}},
		{"host does not resolve", tokEnv, append([]string{"fleet", "-allow-plaintext", "-url", "http://canaryhost.invalid:1"}, tenant...)},
		{"https to a plaintext port", tokEnv, append([]string{"fleet", "-url", "https://" + refused}, tenant...)},
		{"token file missing", nil, append([]string{"fleet", "-url", "https://127.0.0.1:1", "-token-file", filepath.Join(work, "CANARYPATH-nope")}, tenant...)},
		{"token file via env missing", []string{"KCTL_ADMIN_TOKEN_FILE=" + filepath.Join(work, "CANARYPATH-nope")}, append([]string{"fleet", "-url", "https://127.0.0.1:1"}, tenant...)},
		{"token file readable by others", nil, append([]string{"fleet", "-url", "https://127.0.0.1:1", "-token-file", tokOpen}, tenant...)},
		{"token file empty", nil, append([]string{"fleet", "-url", "https://127.0.0.1:1", "-token-file", tokEmpty}, tenant...)},
		{"token in the environment is blank", []string{"KCTL_ADMIN_TOKEN= "}, append([]string{"fleet", "-url", "https://127.0.0.1:1"}, tenant...)},
		{"ca file missing", tokEnv, append([]string{"fleet", "-url", "https://127.0.0.1:1", "-ca-file", filepath.Join(work, "CANARYTLS-nope.pem")}, tenant...)},
		{"ca file garbage", tokEnv, append([]string{"fleet", "-url", "https://127.0.0.1:1", "-ca-file", caGarbage}, tenant...)},
		{"tenant invalid", tokEnv, []string{"fleet", "-url", "https://127.0.0.1:1", "-tenant", "CANARYVAL Bank"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, bin, c.env, "", c.args...)
			checkCtl(t, c.name, r, false, work, refused, "127.0.0.1")
		})
	}
}

// ---- a server that answers badly: nothing it says is echoed ----

func TestMsgServerAnswers(t *testing.T) {
	bin := buildCtl(t)
	body := func(status int, ct, b string, hdr map[string]string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for k, v := range hdr {
				w.Header().Set(k, v)
			}
			if ct != "" {
				w.Header().Set("Content-Type", ct)
			}
			w.WriteHeader(status)
			_, _ = w.Write([]byte(b))
		}))
	}
	codeBody := func(c string) string { b, _ := json.Marshal(map[string]string{"code": c}); return string(b) }
	type srv struct {
		name string
		s    *httptest.Server
	}
	var servers []srv
	for _, st := range []int{400, 401, 403, 404, 405, 409, 413, 500, 502, 503} {
		servers = append(servers,
			srv{fmt.Sprintf("HTTP %d with a known code", st), body(st, "application/json", codeBody("bad_request"), nil)},
			srv{fmt.Sprintf("HTTP %d with a canary code", st), body(st, "application/json", `{"code":"CANARYBODY"}`, map[string]string{"X-Note": "CANARYBODY"})},
			srv{fmt.Sprintf("HTTP %d with a canary text body", st), body(st, "text/plain", "CANARYBODY internal path /srv/CANARYBODY/data", map[string]string{"Retry-After": "CANARYBODY"})},
		)
	}
	servers = append(servers,
		srv{"HTTP 200 not JSON", body(200, "application/json", "CANARYBODY not json", nil)},
		srv{"HTTP 200 JSON of the wrong shape", body(200, "application/json", `{"tenant":"CANARYBODY","proxies":"CANARYBODY"}`, nil)},
		srv{"HTTP 200 unknown field", body(200, "application/json", `{"tenant":"bank-a","proxies":[],"CANARYBODY":1}`, nil)},
		srv{"HTTP 200 huge body", body(200, "application/json", `{"tenant":"bank-a","x":"CANARYBODY`+strings.Repeat("a", 6<<20)+`"}`, nil)},
		srv{"HTTP 200 empty body", body(200, "application/json", "", nil)},
		srv{"HTTP 302 redirect", body(302, "", "", map[string]string{"Location": "http://CANARYHOST.invalid/CANARYBODY"})},
		srv{"HTTP 307 redirect", body(307, "", "", map[string]string{"Location": "http://127.0.0.1:1/CANARYBODY"})},
	)
	// a server that closes the connection without answering
	closer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h, ok := w.(http.Hijacker); ok {
			c, _, _ := h.Hijack()
			_ = c.Close()
		}
	}))
	servers = append(servers, srv{"connection closed without an answer", closer})
	// garbage that is not HTTP
	rawLn, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := rawLn.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("CANARYBODY this is not http\r\n\r\n"))
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { rawLn.Close() })
	for _, s := range servers {
		defer s.s.Close()
	}
	tokEnv := []string{"KCTL_ADMIN_TOKEN=CANARYTOKEN-0123456789"}
	work := t.TempDir()
	envFile := filepath.Join(work, "env.json")
	_ = os.WriteFile(envFile, []byte(`{"payloadType":"application/vnd.kairan.policy+json","payload":"e30=","signatures":[]}`), 0o600)
	cmds := func(url string) map[string][]string {
		return map[string][]string{
			"fleet":          {"fleet", "-allow-plaintext", "-url", url, "-tenant", "bank-a"},
			"publish":        {"publish", "-allow-plaintext", "-url", url, "-in", envFile},
			"rollout start":  {"rollout", "start", "-allow-plaintext", "-url", url, "-tenant", "bank-a", "-version", "1"},
			"rollout status": {"rollout", "status", "-allow-plaintext", "-url", url, "-tenant", "bank-a"},
			"evidence":       {"evidence", "export", "-allow-plaintext", "-url", url, "-tenant", "bank-a"},
		}
	}
	all := append([]srv{}, servers...)
	all = append(all, srv{"not HTTP at all", &httptest.Server{URL: "http://" + rawLn.Addr().String()}})
	for _, s := range all {
		for name, args := range cmds(s.s.URL) {
			t.Run(s.name+" / "+name, func(t *testing.T) {
				r := run(t, bin, tokEnv, "", args...)
				// a 2xx that happens to parse is not an error; only failing runs are judged
				if r.code == 0 {
					return
				}
				checkCtl(t, s.name+" / "+name, r, false, "127.0.0.1", s.s.URL)
			})
		}
	}
}
