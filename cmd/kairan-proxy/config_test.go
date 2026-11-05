package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

func testPub(name string) string {
	s := sha256.Sum256([]byte("kairan proxy cmd test " + name))
	return hex.EncodeToString(ed25519.NewKeyFromSeed(s[:]).Public().(ed25519.PublicKey))
}

// goodConfig is a minimal valid config; tests change one thing at a time.
func goodConfig(mods map[string]string) string {
	f := map[string]string{
		"tenant":          `"bank-a"`,
		"proxy_id":        `"proxy-1"`,
		"cp_url":          `"https://cp.example.com"`,
		"token":           `"enroll-token"`,
		"trusted_keys":    fmt.Sprintf(`[%q,%q,%q]`, testPub("a"), testPub("b"), testPub("c")),
		"threshold":       `2`,
		"listen":          `"127.0.0.1:8081"`,
		"upstream":        `"http://127.0.0.1:9090/mcp"`,
		"api_keys":        `{"key-sales":"sales","key-eng":"engineer"}`,
		"data_dir":        `"/var/lib/kairan"`,
		"skew":            `"2m"`,
		"safe_mode":       `"read_only"`,
		"ca_file":         `"/etc/kairan/ca.pem"`,
		"allow_plaintext": `false`,
	}
	for k, v := range mods {
		if v == "-" {
			delete(f, k)
		} else {
			f[k] = v
		}
	}
	var parts []string
	for k, v := range f {
		parts = append(parts, fmt.Sprintf("%q:%s", k, v))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func TestParseConfigValid(t *testing.T) {
	c, err := ParseConfig([]byte(goodConfig(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if c.Tenant != "bank-a" || c.ProxyID != "proxy-1" || c.Token != "enroll-token" || c.Root.Threshold != 2 ||
		c.Skew != 2*time.Minute || c.SafeMode != "read_only" || c.Listen != "127.0.0.1:8081" ||
		c.DataDir != "/var/lib/kairan" || c.CAFile != "/etc/kairan/ca.pem" || c.AllowPlaintext {
		t.Fatalf("config = %+v", c)
	}
	if c.CP.String() != "https://cp.example.com" || c.Upstream.String() != "http://127.0.0.1:9090/mcp" {
		t.Fatalf("urls %v %v", c.CP, c.Upstream)
	}
	if len(c.Root.Keys) != 3 || c.Root.Threshold != 2 || c.Root.Tenant != "bank-a" {
		t.Fatalf("root = %+v", c.Root)
	}
	if c.APIKeys["key-sales"] != "sales" || len(c.APIKeys) != 2 {
		t.Fatalf("api keys = %v", c.APIKeys)
	}
	for id, pub := range c.Root.Keys {
		if trust.KeyID(pub) != id {
			t.Fatal("key stored under the wrong id")
		}
	}
}

func TestParseConfigDefaults(t *testing.T) {
	c, err := ParseConfig([]byte(goodConfig(map[string]string{"skew": "-", "safe_mode": "-", "ca_file": "-", "allow_plaintext": "-"})))
	if err != nil {
		t.Fatal(err)
	}
	if c.Skew != DefaultSkew || DefaultSkew > trust.MaxSkew {
		t.Fatalf("skew = %v", c.Skew)
	}
	if c.SafeMode != "read_only" || c.CAFile != "" || c.AllowPlaintext {
		t.Fatalf("config = %+v", c)
	}
}

func TestParseConfigSafeModeAndSkew(t *testing.T) {
	c, err := ParseConfig([]byte(goodConfig(map[string]string{"safe_mode": `"deny_all"`, "skew": `"5m"`, "allow_plaintext": "true", "cp_url": `"http://cp:8080"`})))
	if err != nil {
		t.Fatal(err)
	}
	if c.SafeMode != "deny_all" || c.Skew != 5*time.Minute || !c.AllowPlaintext {
		t.Fatalf("config = %+v", c)
	}
	if c, err = ParseConfig([]byte(goodConfig(map[string]string{"skew": `"0s"`}))); err != nil || c.Skew != 0 {
		t.Fatalf("zero skew: %v %v", c, err)
	}
}

func TestParseConfigRejects(t *testing.T) {
	pubA, pubB := testPub("a"), testPub("b")
	keys := func(ks ...string) string {
		q := make([]string, len(ks))
		for i, k := range ks {
			q[i] = fmt.Sprintf("%q", k)
		}
		return "[" + strings.Join(q, ",") + "]"
	}
	tests := []struct {
		name string
		raw  string
		want string // substring of the error
	}{
		{"empty", ``, "config"},
		{"not json", `{`, "config"},
		{"array", `[]`, "config"},
		{"trailing data", goodConfig(nil) + ` {}`, "config"},
		{"unknown field", strings.Replace(goodConfig(nil), "{", `{"extra":1,`, 1), "extra"},
		{"case variant field", strings.Replace(goodConfig(map[string]string{"tenant": "-"}), "{", `{"Tenant":"bank-a",`, 1), "Tenant"},
		{"duplicate field", strings.Replace(goodConfig(nil), "{", `{"tenant":"other",`, 1), "duplicate"},
		{"duplicate api key", goodConfig(map[string]string{"api_keys": `{"k":"sales","k":"engineer"}`}), "duplicate"},
		{"missing tenant", goodConfig(map[string]string{"tenant": "-"}), "tenant"},
		{"bad tenant", goodConfig(map[string]string{"tenant": `"Bank A"`}), "tenant"},
		{"tenant wrong type", goodConfig(map[string]string{"tenant": `7`}), "config"},
		{"missing proxy id", goodConfig(map[string]string{"proxy_id": "-"}), "proxy_id"},
		{"bad proxy id", goodConfig(map[string]string{"proxy_id": `"-x"`}), "proxy_id"},
		{"missing cp_url", goodConfig(map[string]string{"cp_url": "-"}), "cp_url"},
		{"cp_url relative", goodConfig(map[string]string{"cp_url": `"cp.example.com"`}), "cp_url"},
		{"cp_url with userinfo", goodConfig(map[string]string{"cp_url": `"https://u:p@cp.example.com"`}), "cp_url"},
		{"cp_url http without allow_plaintext", goodConfig(map[string]string{"cp_url": `"http://cp.example.com"`}), "plaintext"},
		{"cp_url ftp", goodConfig(map[string]string{"cp_url": `"ftp://cp.example.com"`, "allow_plaintext": "true"}), "cp_url"},
		{"missing token", goodConfig(map[string]string{"token": "-"}), "token"},
		{"empty token", goodConfig(map[string]string{"token": `""`}), "token"},
		{"missing trusted_keys", goodConfig(map[string]string{"trusted_keys": "-"}), "trusted_keys"},
		{"empty trusted_keys", goodConfig(map[string]string{"trusted_keys": "[]"}), "trusted_keys"},
		{"key not hex", goodConfig(map[string]string{"trusted_keys": keys(pubA, strings.Repeat("z", 64))}), "trusted_keys"},
		{"key too short", goodConfig(map[string]string{"trusted_keys": keys(pubA, pubB[:62])}), "trusted_keys"},
		{"key too long", goodConfig(map[string]string{"trusted_keys": keys(pubA, pubB+"00")}), "trusted_keys"},
		{"duplicate trusted key", goodConfig(map[string]string{"trusted_keys": keys(pubA, pubA, pubB)}), "trusted_keys"},
		{"duplicate trusted key different case", goodConfig(map[string]string{"trusted_keys": keys(pubA, strings.ToUpper(pubA), pubB)}), "trusted_keys"},
		{"too many keys", goodConfig(map[string]string{"trusted_keys": keys(manyKeys(maxTrustedKeys + 1)...)}), "trusted_keys"},
		{"missing threshold", goodConfig(map[string]string{"threshold": "-"}), "threshold"},
		{"threshold zero", goodConfig(map[string]string{"threshold": "0"}), "threshold"},
		{"threshold one", goodConfig(map[string]string{"threshold": "1"}), "threshold"},
		{"threshold negative", goodConfig(map[string]string{"threshold": "-2"}), "threshold"},
		{"threshold above keys", goodConfig(map[string]string{"threshold": "4"}), "threshold"},
		{"threshold fractional", goodConfig(map[string]string{"threshold": "2.5"}), "config"},
		{"threshold string", goodConfig(map[string]string{"threshold": `"2"`}), "config"},
		{"one key, threshold two", goodConfig(map[string]string{"trusted_keys": keys(pubA)}), "threshold"},
		{"skew over 5m", goodConfig(map[string]string{"skew": `"5m1s"`}), "skew"},
		{"skew negative", goodConfig(map[string]string{"skew": `"-1s"`}), "skew"},
		{"skew not a duration", goodConfig(map[string]string{"skew": `"soon"`}), "skew"},
		{"skew a number", goodConfig(map[string]string{"skew": `120`}), "config"},
		{"safe_mode unknown", goodConfig(map[string]string{"safe_mode": `"allow_all"`}), "safe_mode"},
		{"safe_mode wrong case", goodConfig(map[string]string{"safe_mode": `"READ_ONLY"`}), "safe_mode"},
		{"safe_mode empty string", goodConfig(map[string]string{"safe_mode": `""`}), "safe_mode"},
		{"missing listen", goodConfig(map[string]string{"listen": "-"}), "listen"},
		{"listen without port", goodConfig(map[string]string{"listen": `"127.0.0.1"`}), "listen"},
		{"listen bad port", goodConfig(map[string]string{"listen": `"127.0.0.1:99999"`}), "listen"},
		{"missing upstream", goodConfig(map[string]string{"upstream": "-"}), "upstream"},
		{"upstream not http", goodConfig(map[string]string{"upstream": `"file:///etc/passwd"`}), "upstream"},
		{"upstream no host", goodConfig(map[string]string{"upstream": `"http:///x"`}), "upstream"},
		{"upstream userinfo", goodConfig(map[string]string{"upstream": `"http://u:p@h/x"`}), "upstream"},
		{"missing api_keys", goodConfig(map[string]string{"api_keys": "-"}), "api_keys"},
		{"empty api_keys", goodConfig(map[string]string{"api_keys": "{}"}), "api_keys"},
		{"empty api key", goodConfig(map[string]string{"api_keys": `{"":"sales"}`}), "api_keys"},
		{"empty role", goodConfig(map[string]string{"api_keys": `{"k":""}`}), "api_keys"},
		{"api key with space", goodConfig(map[string]string{"api_keys": `{"a b":"sales"}`}), "api_keys"},
		{"api key with newline", goodConfig(map[string]string{"api_keys": `{"a\nb":"sales"}`}), "api_keys"},
		{"role not string", goodConfig(map[string]string{"api_keys": `{"k":1}`}), "config"},
		{"missing data_dir", goodConfig(map[string]string{"data_dir": "-"}), "data_dir"},
		{"empty data_dir", goodConfig(map[string]string{"data_dir": `""`}), "data_dir"},
		{"too deeply nested", `{"api_keys":` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`, "config"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseConfig([]byte(tc.raw))
			if err == nil {
				t.Fatalf("accepted: %+v", c)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
			// Errors name the field, never the secret value.
			for _, secret := range []string{"enroll-token", "key-sales", pubA} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error echoes a secret: %v", err)
				}
			}
		})
	}
}

func manyKeys(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = testPub(fmt.Sprint("many", i))
	}
	return out
}

func TestParseConfigSizeCap(t *testing.T) {
	big := goodConfig(map[string]string{"token": `"` + strings.Repeat("x", maxConfigBytes) + `"`})
	if _, err := ParseConfig([]byte(big)); err == nil {
		t.Fatal("oversize config accepted")
	}
}

func TestLoadConfigFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "proxy.json")
	if err := os.WriteFile(p, []byte(goodConfig(nil)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(p); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(filepath.Join(dir, "none.json")); err == nil {
		t.Fatal("missing file accepted")
	}
	if _, err := LoadConfig(dir); err == nil {
		t.Fatal("directory accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := mkfifo(fifo); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := LoadConfig(fifo); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fifo accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("LoadConfig hung on a FIFO")
	}
}

// The hard-coded TEST-ONLY key list (M-D39) must be the fixture keys.
func TestTestOnlyKeyListMatchesFixtures(t *testing.T) {
	matches, err := filepath.Glob("../../test/fixtures/TEST-ONLY-*.pub")
	if err != nil || len(matches) < 4 {
		t.Fatalf("fixtures: %v %v", matches, err)
	}
	want := map[wire.Hash]bool{}
	for _, m := range matches {
		b, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("%s: not a hex public key", m)
		}
		want[trust.KeyID(raw)] = true
	}
	if len(testOnlyKeyIDs) != len(want) {
		t.Fatalf("list has %d ids, fixtures have %d", len(testOnlyKeyIDs), len(want))
	}
	for id := range want {
		if !testOnlyKeyIDs[id] {
			t.Fatalf("fixture key %s missing from the TEST-ONLY list", id)
		}
	}
}

func TestConfigCountsTestOnlyKeys(t *testing.T) {
	b, _ := os.ReadFile("../../test/fixtures/TEST-ONLY-admin-a.pub")
	b2, _ := os.ReadFile("../../test/fixtures/TEST-ONLY-admin-b.pub")
	pubA, pubB := strings.TrimSpace(string(b)), strings.TrimSpace(string(b2))
	c, err := ParseConfig([]byte(goodConfig(map[string]string{"trusted_keys": fmt.Sprintf(`[%q,%q,%q]`, pubA, pubB, testPub("c"))})))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.TestOnlyKeys(); got != 2 {
		t.Fatalf("TestOnlyKeys = %d, want 2", got)
	}
	c, _ = ParseConfig([]byte(goodConfig(nil)))
	if c.TestOnlyKeys() != 0 {
		t.Fatal("fresh keys flagged as TEST-ONLY")
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(goodConfig(nil)))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"tenant":"a","tenant":"b"}`))
	f.Add([]byte(`{"threshold":1e999}`))
	f.Add([]byte(strings.Repeat("[", 300)))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := ParseConfig(data)
		if err != nil {
			return
		}
		// Whatever parses must satisfy every floor.
		switch {
		case c.Root.Threshold < 2 || c.Root.Threshold > len(c.Root.Keys):
			t.Fatalf("threshold %d with %d keys", c.Root.Threshold, len(c.Root.Keys))
		case c.Skew < 0 || c.Skew > trust.MaxSkew:
			t.Fatalf("skew %v", c.Skew)
		case c.SafeMode != "read_only" && c.SafeMode != "deny_all":
			t.Fatalf("safe mode %q", c.SafeMode)
		case !c.Tenant.Valid() || !c.ProxyID.Valid() || c.Token == "":
			t.Fatal("identity")
		case c.CP.Scheme != "https" && !c.AllowPlaintext:
			t.Fatal("plaintext control plane without allow_plaintext")
		case len(c.APIKeys) == 0 || c.Root.Tenant != c.Tenant:
			t.Fatal("keys or root")
		}
	})
}

func mkfifo(path string) error { return syscall.Mkfifo(path, 0o600) }
