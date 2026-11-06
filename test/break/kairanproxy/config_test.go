package kairanproxybreak

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func goodCfg(t testing.TB) pcfg {
	return baseCfg(t, filepath.Join(t.TempDir(), "data"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", "127.0.0.1:0")
}

// Config strictness (P-D7, ARCHITECTURE kairan-proxy): bad config is exit 2 before any listener, the message
// names the field and never a value, and no listener opens.
func TestConfigRejections(t *testing.T) {
	a, b, c := key(t, "admin-a").pub, key(t, "admin-b").pub, key(t, "admin-c").pub
	g := goodCfg(t)
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
		{"not json", raw("tenant: bank-a")},
		{"array", raw("[]")},
		{"null", raw("null")},
		{"truncated", raw(base[:len(base)-5])},
		{"trailing second document", raw(base + "{}")},
		{"trailing garbage", raw(base + " x")},
		{"BOM", append([]byte("\xef\xbb\xbf"), []byte(base)...)},
		{"NUL byte", raw(base + "\x00")},
		{"unknown field", mut("bogus", 1)},
		{"unknown field import", mut("import", "x")},
		{"duplicate top-level key", raw(strings.Replace(base, `"tenant":"bank-a"`, `"tenant":"bank-a","tenant":"bank-b"`, 1))},
		{"duplicate via escape", raw(strings.Replace(base, `"tenant":"bank-a"`, `"tenant":"bank-a","tenant":"bank-b"`, 1))},
		{"upper-case key", raw(strings.Replace(base, `"tenant"`, `"Tenant"`, 1))},
		{"all caps key", raw(strings.Replace(base, `"token"`, `"TOKEN"`, 1))},
		{"nesting deeper than 8", raw(strings.Replace(base, `{`, `{"x":`+strings.Repeat("[", 9)+strings.Repeat("]", 9)+`,`, 1))},
		{"over 64 KiB", raw(strings.Replace(base, `{`, `{"x":"`+strings.Repeat("a", 70<<10)+`",`, 1))},
		// required fields
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
		// values
		{"tenant upper case", mut("tenant", "Bank-A")},
		{"tenant empty", mut("tenant", "")},
		{"tenant 64 chars", mut("tenant", strings.Repeat("a", 64))},
		{"tenant number", mut("tenant", 5)},
		{"proxy_id invalid", mut("proxy_id", "p 1")},
		{"proxy_id empty", mut("proxy_id", "")},
		{"token empty", mut("token", "")},
		{"token number", mut("token", 5)},
		{"cp_url http without allow_plaintext", g.with("allow_plaintext", nil).with("cp_url", "http://cp.example.test").bytes()},
		{"cp_url allow_plaintext false", g.with("allow_plaintext", false).with("cp_url", "http://cp.example.test").bytes()},
		{"cp_url ftp", mut("cp_url", "ftp://cp.example.test")},
		{"cp_url no scheme", mut("cp_url", "cp.example.test")},
		{"cp_url file", mut("cp_url", "file:///etc/passwd")},
		{"cp_url empty", mut("cp_url", "")},
		{"cp_url number", mut("cp_url", 5)},
		{"allow_plaintext string", mut("allow_plaintext", "true")},
		{"safe_mode unknown", mut("safe_mode", "allow_all")},
		{"safe_mode upper case", mut("safe_mode", "READ_ONLY")},
		{"safe_mode dash", mut("safe_mode", "deny-all")},
		{"safe_mode empty", mut("safe_mode", "")},
		{"safe_mode number", mut("safe_mode", 1)},
		{"skew 5m1s", mut("skew", "5m1s")},
		{"skew 1h", mut("skew", "1h")},
		{"skew negative", mut("skew", "-1s")},
		{"skew garbage", mut("skew", "soon")},
		{"skew number", mut("skew", 120)},
		{"skew huge", mut("skew", "99999999h")},
		// trust root
		{"threshold 1", mut("threshold", 1)},
		{"threshold 0", mut("threshold", 0)},
		{"threshold negative", mut("threshold", -2)},
		{"threshold above keys", mut("threshold", 4)},
		{"threshold float", mut("threshold", 2.5)},
		{"threshold string", mut("threshold", "2")},
		{"threshold huge", raw(strings.Replace(base, `"threshold":2`, `"threshold":18446744073709551616`, 1))},
		{"one trusted key", g.with("trusted_keys", []string{a}).bytes()},
		{"no trusted keys", g.with("trusted_keys", []string{}).bytes()},
		{"duplicate trusted key", g.with("trusted_keys", []string{a, a, b}).bytes()},
		{"17 trusted keys", g.with("trusted_keys", keys(17)).bytes()},
		{"trusted key not hex", g.with("trusted_keys", []string{a, strings.Repeat("g", 64)}).bytes()},
		{"trusted key short", g.with("trusted_keys", []string{a, b[:62]}).bytes()},
		{"trusted key long", g.with("trusted_keys", []string{a, b + "00"}).bytes()},
		{"trusted key number", g.with("trusted_keys", []any{a, 5}).bytes()},
		{"trusted key null", g.with("trusted_keys", []any{a, nil}).bytes()},
		{"trusted_keys object", g.with("trusted_keys", map[string]any{}).bytes()},
		// listeners and routing
		{"listen garbage", mut("listen", "no")},
		{"listen no port", mut("listen", "127.0.0.1")},
		{"listen port too big", mut("listen", "127.0.0.1:99999")},
		{"listen number", mut("listen", 80)},
		{"upstream ftp", mut("upstream", "ftp://x/y")},
		{"upstream no scheme", mut("upstream", "x/y")},
		{"upstream empty", mut("upstream", "")},
		{"api_keys empty", g.with("api_keys", map[string]string{}).bytes()},
		{"api_keys empty key", g.with("api_keys", map[string]string{"": "sales"}).bytes()},
		{"api_keys empty role", g.with("api_keys", map[string]string{keySales: ""}).bytes()},
		{"api_keys role invalid", g.with("api_keys", map[string]string{keySales: "Sales Role"}).bytes()},
		{"api_keys role number", g.with("api_keys", map[string]any{keySales: 5}).bytes()},
		{"api_keys array", g.with("api_keys", []string{"x"}).bytes()},
		{"api_keys duplicate key", raw(strings.Replace(base, `"api_keys":{`, `"api_keys":{"`+keySales+`":"intern",`, 1))},
		{"data_dir empty", mut("data_dir", "")},
		{"data_dir number", mut("data_dir", 5)},
		{"ca_file missing", mut("ca_file", filepath.Join(t.TempDir(), "nope.pem"))},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			if _, err := os.Stat(filepath.Dir(string(g["data_dir"].(string)))); err != nil {
				t.Fatal(err)
			}
			code, out := runOnce(t, cs.raw, nil)
			if code != 2 {
				t.Fatalf("exit %d, want 2 (bad config): %s", code, clip(out))
			}
			for _, secret := range []string{token, keySales, keyIntrn, canary} {
				if strings.Contains(out, secret) {
					t.Errorf("a configured secret appears in the error output: %q", clip(out))
				}
			}
			if contains(out, "panic:", "goroutine ") {
				t.Errorf("crash output: %s", clip(out))
			}
		})
	}
}

// A rejected config must not listen, create the data directory contents or reach the control plane.
func TestRejectedConfigHasNoSideEffects(t *testing.T) {
	cp := newCP(t)
	dir := filepath.Join(t.TempDir(), "data")
	c := baseCfg(t, dir, cp.url(), "http://127.0.0.1:9/mcp", freePort(t)).with("threshold", 1)
	code, _ := runOnce(t, c.bytes(), nil)
	if code != 2 {
		t.Fatalf("exit %d", code)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(cp.all()); n != 0 {
		t.Errorf("a proxy with a rejected config contacted the control plane %d times", n)
	}
	if ents, err := os.ReadDir(dir); err == nil && len(ents) > 0 {
		t.Errorf("rejected config left files in data_dir: %v", ents)
	}
}

// Usage errors are exit 2.
func TestUsageErrors(t *testing.T) {
	b := bin(t)
	good := writeCfg(t, goodCfg(t).bytes())
	_ = good
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"unknown flag", []string{"-bogus"}},
		{"-config without value", []string{"-config"}},
		{"-config empty", []string{"-config", ""}},
		{"-config missing file", []string{"-config", filepath.Join(t.TempDir(), "nope.json")}},
		{"-config directory", []string{"-config", t.TempDir()}},
		{"token as a flag", []string{"-config", good, "-token", token}},
		{"positional argument", []string{"-config", good, "extra"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := startCmd(t, b, c.args)
			code, ok := p.waitExit(10 * time.Second)
			if !ok {
				t.Fatalf("did not exit: %s", p.out.String())
			}
			if code != 2 {
				t.Fatalf("exit %d, want 2: %s", code, clip(p.out.String()))
			}
			if strings.Contains(p.out.String(), token) {
				t.Errorf("token echoed")
			}
		})
	}
	t.Run("config is a FIFO (opened non-blocking)", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(f, 0o600); err != nil {
			t.Fatal(err)
		}
		p := startCmd(t, b, []string{"-config", f})
		code, ok := p.waitExit(10 * time.Second)
		if !ok {
			t.Fatalf("hung on a FIFO config")
		}
		if code != 2 {
			t.Errorf("exit %d, want 2: %s", code, clip(p.out.String()))
		}
	})
	t.Run("config is /dev/zero", func(t *testing.T) {
		p := startCmd(t, b, []string{"-config", "/dev/zero"})
		code, ok := p.waitExit(10 * time.Second)
		if !ok || code != 2 {
			t.Errorf("exited=%v code=%d: %s", ok, code, clip(p.out.String()))
		}
	})
	t.Run("-help exits and names -config only", func(t *testing.T) {
		p := startCmd(t, b, []string{"-h"})
		if _, ok := p.waitExit(10 * time.Second); !ok {
			t.Fatal("did not exit")
		}
		if !strings.Contains(p.out.String(), "-config") {
			t.Errorf("usage: %s", clip(p.out.String()))
		}
	})
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func startCmd(t testing.TB, b string, args []string) *proc {
	t.Helper()
	return startRaw(t, b, args)
}

// Boundary values that must be accepted: a config that is merely strict must still start.
func TestBoundaryConfigsAreAccepted(t *testing.T) {
	cases := []struct {
		name string
		mod  func(c pcfg) pcfg
	}{
		{"skew 5m exactly", func(c pcfg) pcfg { return c.with("skew", "5m") }},
		{"skew 1s", func(c pcfg) pcfg { return c.with("skew", "1s") }},
		{"safe_mode deny_all", func(c pcfg) pcfg { return c.with("safe_mode", "deny_all") }},
		{"safe_mode read_only", func(c pcfg) pcfg { return c.with("safe_mode", "read_only") }},
		{"threshold equals key count", func(c pcfg) pcfg { return c.with("threshold", 3) }},
		{"two keys, threshold 2", func(c pcfg) pcfg {
			return c.with("trusted_keys", []string{key(t, "admin-a").pub, key(t, "admin-b").pub})
		}},
	}
	for _, cs := range cases {
		t.Run(cs.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "data")
			c := cs.mod(baseCfg(t, dir, "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t)))
			p := startServing(t, c, nil)
			if p.exited() {
				t.Fatalf("exited: %s", p.out.String())
			}
		})
	}
}
