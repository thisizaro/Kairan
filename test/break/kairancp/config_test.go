package kairancpbreak

import (
	"path/filepath"
	"strings"
	"testing"
)

// Baseline: the valid config passes -check with exit 0, and without the token in the output.
func TestCheckAcceptsValidConfig(t *testing.T) {
	r := check(t, baseCfg(t, t.TempDir()).bytes(t))
	if r.code != 0 {
		t.Fatalf("valid config rejected: %d %s", r.code, r.all())
	}
	noPanic(t, r)
	if strings.Contains(r.all(), adminTok) {
		t.Errorf("admin token printed by -check")
	}
}

func rejected(t *testing.T, name string, raw []byte) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		r := check(t, raw)
		noPanic(t, r)
		if r.code != 2 {
			t.Fatalf("exit %d, want 2 (config or usage error; C-D10): %s", r.code, clip(r.all()))
		}
		// C-D10: every message is English and Japanese
		if !hasCJK(r.stderr) || !strings.Contains(strings.ToLower(r.stderr), "error") {
			t.Errorf("message is not English and Japanese: %q", clip(r.stderr))
		}
		if strings.Contains(r.all(), adminTok) || strings.Contains(r.all(), canary) {
			t.Errorf("secret or canary echoed: %q", clip(r.all()))
		}
	})
}

// C-D10 config strictness, each a config error with exit 2.
func TestConfigStrictness(t *testing.T) {
	d := t.TempDir()
	b := baseCfg(t, d)
	a := pub(t, "admin-a")
	tenants := func(v any) []byte { return b.with(t, "tenants", v).bytes(t) }
	tenantA := func(m map[string]any) []byte {
		return tenants(map[string]any{"bank-a": m})
	}
	keys := func(n int) []string {
		var ks []string
		ks = append(ks, pub(t, "admin-a"), pub(t, "admin-b"), pub(t, "admin-c"), pub(t, "outsider"))
		for len(ks) < n {
			ks = append(ks, strings.Repeat("0", 62)+string("0123456789abcdef"[len(ks)/16])+string("0123456789abcdef"[len(ks)%16]))
		}
		return ks[:n]
	}
	enr := func(m map[string]any) []byte { return b.with(t, "enrollments", []any{m}).bytes(t) }
	okEnr := func(over map[string]any) map[string]any {
		m := map[string]any{"proxy_id": "p1", "tenant": "bank-a", "group": "main", "token_sha256": sha(tokOf("p1"))}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	ok2 := func(over map[string]any) map[string]any {
		m := map[string]any{"threshold": 2, "admin_keys": []string{pub(t, "admin-a"), pub(t, "admin-b")}}
		for k, v := range over {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	raw := func(s string) []byte { return []byte(s) }
	prefix := `{"listen":"127.0.0.1:0","data_dir":"` + d + `","allow_plaintext":true,"tenants":{"bank-a":{"threshold":2,"admin_keys":["` + a + `","` + pub(t, "admin-b") + `"]}}`

	cases := []struct {
		name string
		raw  []byte
	}{
		// syntax
		{"empty file", raw("")},
		{"whitespace file", raw("  \n")},
		{"not json", raw("listen: x")},
		{"array", raw("[]")},
		{"null", raw("null")},
		{"truncated", raw(prefix)},
		{"trailing second document", raw(prefix + `}{}`)},
		{"trailing garbage", raw(prefix + `} x`)},
		{"UTF-8 BOM", append([]byte("\xef\xbb\xbf"), []byte(prefix+"}")...)},
		{"NUL byte", raw(prefix + "}\x00")},
		{"comment", raw("// hi\n" + prefix + "}")},
		{"trailing comma", raw(prefix + ",}")},
		{"single quotes", raw(strings.ReplaceAll(prefix+"}", `"`, `'`))},
		// duplicates and case (C-D10: repeated fields, upper-case field names)
		{"duplicate top-level key", raw(prefix + `,"listen":"127.0.0.1:1"}`)},
		{"duplicate tenant", raw(strings.Replace(prefix+"}", `"tenants":{`, `"tenants":{"bank-a":{"threshold":2,"admin_keys":["`+a+`","`+pub(t, "admin-b")+`"]},`, 1))},
		{"duplicate nested key", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"threshold":2`, 1))},
		{"upper-case top-level key", raw(strings.Replace(prefix+"}", `"listen"`, `"Listen"`, 1))},
		{"all-caps key", raw(strings.Replace(prefix+"}", `"data_dir"`, `"DATA_DIR"`, 1))},
		{"upper-case nested key", raw(strings.Replace(prefix+"}", `"threshold"`, `"Threshold"`, 1))},
		{"duplicate via escape", raw(prefix + `,"listen":"127.0.0.1:1"}`)},
		{"unknown top-level field", raw(prefix + `,"bogus":1}`)},
		{"unknown nested field", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"bogus":1`, 1))},
		// types
		{"listen number", b.with(t, "listen", 8080).bytes(t)},
		{"listen null", b.with(t, "listen", nil).bytes(t)},
		{"listen empty", b.with(t, "listen", "").bytes(t)},
		{"listen no port", b.with(t, "listen", "127.0.0.1").bytes(t)},
		{"listen port 99999", b.with(t, "listen", "127.0.0.1:99999").bytes(t)},
		{"listen garbage", b.with(t, "listen", "not an address").bytes(t)},
		{"listen with newline", b.with(t, "listen", "127.0.0.1:0\n").bytes(t)},
		{"data_dir null", b.with(t, "data_dir", nil).bytes(t)},
		{"data_dir empty", b.with(t, "data_dir", "").bytes(t)},
		{"data_dir number", b.with(t, "data_dir", 5).bytes(t)},
		{"allow_plaintext string", b.with(t, "allow_plaintext", "true").bytes(t)},
		{"allow_plaintext number", b.with(t, "allow_plaintext", 1).bytes(t)},
		{"metrics_listen garbage", b.with(t, "metrics_listen", "no").bytes(t)},
		{"metrics_listen number", b.with(t, "metrics_listen", 9).bytes(t)},
		{"tenants missing", b.with(t, "tenants", nil).bytes(t)},
		{"tenants empty object", tenants(map[string]any{})},
		{"tenants array", tenants([]any{})},
		{"tenants null", tenants(nil)},
		{"tenant id upper case", tenants(map[string]any{"Bank-A": ok2(nil)})},
		{"tenant id invalid chars", tenants(map[string]any{"bank a": ok2(nil)})},
		{"tenant id 64 chars", tenants(map[string]any{strings.Repeat("a", 64): ok2(nil)})},
		{"tenant id empty", tenants(map[string]any{"": ok2(nil)})},
		{"tenant body not object", tenants(map[string]any{"bank-a": 5})},
		// trust floor: threshold >= 2 and <= number of admin_keys, at most 16 keys
		{"threshold 0", tenantA(ok2(map[string]any{"threshold": 0}))},
		{"threshold 1 (below the floor)", tenantA(ok2(map[string]any{"threshold": 1}))},
		{"threshold negative", tenantA(ok2(map[string]any{"threshold": -2}))},
		{"threshold above key count", tenantA(ok2(map[string]any{"threshold": 3}))},
		{"threshold float", tenantA(ok2(map[string]any{"threshold": 2.5}))},
		{"threshold string", tenantA(ok2(map[string]any{"threshold": "2"}))},
		{"threshold missing", tenantA(ok2(map[string]any{"threshold": nil}))},
		{"threshold huge", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":18446744073709551616`, 1))},
		{"no admin keys", tenantA(ok2(map[string]any{"admin_keys": []string{}}))},
		{"one admin key, threshold 2", tenantA(ok2(map[string]any{"admin_keys": []string{a}}))},
		{"one admin key, threshold 1", tenantA(ok2(map[string]any{"admin_keys": []string{a}, "threshold": 1}))},
		{"17 admin keys (max 16)", tenantA(ok2(map[string]any{"admin_keys": keys(17), "threshold": 2}))},
		{"duplicate admin key", tenantA(ok2(map[string]any{"admin_keys": []string{a, a}}))},
		{"admin key not hex", tenantA(ok2(map[string]any{"admin_keys": []string{a, strings.Repeat("g", 64)}}))},
		{"admin key short", tenantA(ok2(map[string]any{"admin_keys": []string{a, a[:62]}}))},
		{"admin key long", tenantA(ok2(map[string]any{"admin_keys": []string{a, a + "00"}}))},
		{"admin key upper-case", tenantA(ok2(map[string]any{"admin_keys": []string{a, strings.ToUpper(pub(t, "admin-b"))}}))},
		{"admin key number", tenantA(ok2(map[string]any{"admin_keys": []any{a, 5}}))},
		{"admin key null", tenantA(ok2(map[string]any{"admin_keys": []any{a, nil}}))},
		{"admin key all zero", tenantA(ok2(map[string]any{"admin_keys": []string{a, strings.Repeat("0", 64)}}))},
		{"admin_keys object", tenantA(ok2(map[string]any{"admin_keys": map[string]any{}}))},
		// private key material (C-D10)
		{"seed field", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"seed":"`+seed(t, "admin-a")+`"`, 1))},
		{"private_key field", raw(strings.Replace(prefix+"}", `"threshold":2`, `"threshold":2,"private_key":"x"`, 1))},
		{"secret field top level", raw(prefix + `,"secret":"x"}`)},
		{"private field", raw(prefix + `,"private":"x"}`)},
		{"seed listed as admin key next to its public key", tenantA(ok2(map[string]any{"admin_keys": []string{a, pub(t, "admin-b"), seed(t, "admin-a")}, "threshold": 2}))},
		{"seed only as admin key", tenantA(ok2(map[string]any{"admin_keys": []string{seed(t, "admin-a"), pub(t, "admin-b")}}))},
		{"PEM private key in a value", b.with(t, "data_dir", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----").bytes(t)},
		{"128-hex key in a value", b.with(t, "listen", seed(t, "admin-a")+seed(t, "admin-b")).bytes(t)},
		// enrollments
		{"enrollments object", b.with(t, "enrollments", map[string]any{}).bytes(t)},
		{"enrollment plaintext token field", enr(okEnr(map[string]any{"token": tokOf("p1")}))},
		{"enrollment token_sha256 missing", enr(okEnr(map[string]any{"token_sha256": nil}))},
		{"enrollment token_sha256 short", enr(okEnr(map[string]any{"token_sha256": sha("x")[:63]}))},
		{"enrollment token_sha256 long", enr(okEnr(map[string]any{"token_sha256": sha("x") + "0"}))},
		{"enrollment token_sha256 non-hex", enr(okEnr(map[string]any{"token_sha256": strings.Repeat("z", 64)}))},
		{"enrollment token_sha256 upper-case", enr(okEnr(map[string]any{"token_sha256": strings.ToUpper(sha(tokOf("p1")) + "G")}))},
		{"enrollment token_sha256 is the plaintext", enr(okEnr(map[string]any{"token_sha256": tokOf("p1")}))},
		{"enrollment proxy_id missing", enr(okEnr(map[string]any{"proxy_id": nil}))},
		{"enrollment proxy_id invalid", enr(okEnr(map[string]any{"proxy_id": "P 1"}))},
		{"enrollment proxy_id empty", enr(okEnr(map[string]any{"proxy_id": ""}))},
		{"enrollment tenant unknown", enr(okEnr(map[string]any{"tenant": "nobody"}))},
		{"enrollment tenant missing", enr(okEnr(map[string]any{"tenant": nil}))},
		{"enrollment group invalid", enr(okEnr(map[string]any{"group": "Main!"}))},
		{"enrollment group missing", enr(okEnr(map[string]any{"group": nil}))},
		{"duplicate proxy id", b.with(t, "enrollments", []any{okEnr(nil), okEnr(map[string]any{"token_sha256": sha("other-token-0123456789")})}).bytes(t)},
		{"same proxy id under another tenant", b.with(t, "enrollments", []any{okEnr(nil), okEnr(map[string]any{"tenant": "bank-b", "token_sha256": sha("other-token-0123456789")})}).bytes(t)},
		{"two proxies share one token", b.with(t, "enrollments", []any{okEnr(nil), okEnr(map[string]any{"proxy_id": "p9"})}).bytes(t)},
		// TLS: either a certificate or allow_plaintext
		{"neither TLS nor allow_plaintext", b.with(t, "allow_plaintext", nil).bytes(t)},
		{"allow_plaintext false and no TLS", b.with(t, "allow_plaintext", false).bytes(t)},
		{"tls cert without key", b.with(t, "allow_plaintext", nil).with(t, "tls_cert_file", filepath.Join(d, "c.pem")).bytes(t)},
		{"tls key without cert", b.with(t, "allow_plaintext", nil).with(t, "tls_key_file", filepath.Join(d, "k.pem")).bytes(t)},
		{"tls files missing", b.with(t, "allow_plaintext", nil).with(t, "tls_cert_file", filepath.Join(d, "nope.pem")).with(t, "tls_key_file", filepath.Join(d, "nope.key")).bytes(t)},
	}
	for _, c := range cases {
		rejected(t, c.name, c.raw)
	}
}

// C-D10: nesting deeper than 8 is refused, and a huge file does not exhaust memory or hang.
func TestConfigNestingAndSize(t *testing.T) {
	d := t.TempDir()
	deep := `{"listen":"127.0.0.1:0","data_dir":"` + d + `","allow_plaintext":true,"x":` + strings.Repeat("[", 9) + strings.Repeat("]", 9) + `}`
	rejected(t, "nesting 9 in an unknown field", []byte(deep))
	rejected(t, "nesting 100000", []byte(strings.Repeat("[", 100000)))
	rejected(t, "objects 100000", []byte(strings.Repeat(`{"a":`, 100000)))
	rejected(t, "50 MiB of spaces", []byte(strings.Repeat(" ", 50<<20)+`{}`))
	rejected(t, "huge string value", []byte(`{"listen":"`+strings.Repeat("a", 20<<20)+`"}`))
	rejected(t, "100000 tenants", func() []byte {
		var sb strings.Builder
		sb.WriteString(`{"listen":"127.0.0.1:0","data_dir":"` + d + `","allow_plaintext":true,"tenants":{`)
		for i := 0; i < 100000; i++ {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(`"t` + strings.Repeat("a", 5) + string(rune('a'+i%26)) + `":{}`)
		}
		sb.WriteString("}}")
		return []byte(sb.String())
	}())
}

// Usage errors are exit 2 and never start the server (C-D10: exit 2 for config or usage).
func TestUsageErrors(t *testing.T) {
	f := writeFiles(t, baseCfg(t, t.TempDir()).bytes(t), adminTok)
	cases := []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"no config flag", []string{"-check", "-admin-token-file", f.tokPath}},
		{"config empty value", []string{"-config", "", "-check", "-admin-token-file", f.tokPath}},
		{"config missing file", []string{"-config", filepath.Join(f.dir, "nope.json"), "-check", "-admin-token-file", f.tokPath}},
		{"config is a directory", []string{"-config", f.dir, "-check", "-admin-token-file", f.tokPath}},
		{"unknown flag", []string{"-config", f.cfgPath, "-bogus"}},
		{"admin token as a flag value", []string{"-config", f.cfgPath, "-check", "-admin-token", adminTok}},
		{"admin token as a flag value with =", []string{"-config", f.cfgPath, "-check", "-admin-token=" + adminTok}},
		{"old -data flag", []string{"-config", f.cfgPath, "-check", "-admin-token-file", f.tokPath, "-data", f.dir}},
		{"old -addr flag", []string{"-config", f.cfgPath, "-check", "-admin-token-file", f.tokPath, "-addr", ":8080"}},
		{"positional argument", []string{"-config", f.cfgPath, "-check", "-admin-token-file", f.tokPath, "extra"}},
		{"-check with a value", []string{"-config", f.cfgPath, "-check=maybe", "-admin-token-file", f.tokPath}},
		{"token file flag without value", []string{"-config", f.cfgPath, "-check", "-admin-token-file"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, nil, c.args...)
			noPanic(t, r)
			if r.code != 2 {
				t.Fatalf("exit %d, want 2: %s", r.code, clip(r.all()))
			}
			if strings.Contains(r.all(), adminTok) {
				t.Errorf("admin token echoed back: %q", clip(r.all()))
			}
		})
	}
}

// -h / -help print usage and exit 0 or 2, never start, never hang.
func TestHelpDoesNotStart(t *testing.T) {
	r := run(t, nil, "-h")
	noPanic(t, r)
	if r.code != 0 && r.code != 2 {
		t.Errorf("-h exit %d", r.code)
	}
	if !strings.Contains(r.all(), "-config") || !strings.Contains(r.all(), "-admin-token-file") {
		t.Errorf("usage does not name the flags: %q", clip(r.all()))
	}
	if strings.Contains(r.all(), "-admin-token ") {
		t.Errorf("usage advertises a token-valued flag")
	}
}
