package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// pubHex returns the public key made from a one-byte repeated seed.
func pubHex(n byte) string {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = n
	}
	return hex.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

func seedHex(n byte) string { return strings.Repeat(hex.EncodeToString([]byte{n}), ed25519.SeedSize) }

func digestOf(tok string) string {
	d := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(d[:])
}

// baseConfig is a valid plaintext config as a generic map, so a test can
// change one thing.
func baseConfig() map[string]any {
	return map[string]any{
		"listen":          "127.0.0.1:8080",
		"metrics_listen":  "127.0.0.1:9090",
		"data_dir":        "/var/lib/kairan",
		"log_level":       "info",
		"allow_plaintext": true,
		"tenants": map[string]any{
			"bank-a": map[string]any{"threshold": 2, "admin_keys": []any{pubHex(1), pubHex(2), pubHex(3)}},
			"bank-b": map[string]any{"threshold": 2, "admin_keys": []any{pubHex(4), pubHex(5)}},
		},
		"enrollments": []any{
			map[string]any{"proxy_id": "px-1", "tenant": "bank-a", "group": "canary", "token_sha256": digestOf("tok-1")},
			map[string]any{"proxy_id": "px-2", "tenant": "bank-a", "group": "main", "token_sha256": digestOf("tok-2")},
		},
	}
}

func marshal(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func tenantOf(m map[string]any, name string) map[string]any {
	return m["tenants"].(map[string]any)[name].(map[string]any)
}

func enrollOf(m map[string]any, i int) map[string]any {
	return m["enrollments"].([]any)[i].(map[string]any)
}

func TestValidConfig(t *testing.T) {
	cfg, cerr := parseConfig(marshal(t, baseConfig()))
	if cerr != nil {
		t.Fatalf("valid config refused: %v", cerr)
	}
	if cfg.Listen != "127.0.0.1:8080" || cfg.MetricsListen != "127.0.0.1:9090" || cfg.DataDir != "/var/lib/kairan" {
		t.Errorf("addresses/data_dir: %+v", cfg)
	}
	if len(cfg.AdminKeys) != 2 || cfg.AdminKeys["bank-a"].Threshold != 2 || len(cfg.AdminKeys["bank-a"].Keys) != 3 {
		t.Errorf("admin keys: %+v", cfg.AdminKeys)
	}
	if len(cfg.Proxies) != 2 || cfg.Proxies["px-1"].Group != "canary" || cfg.Proxies["px-1"].Tenant != "bank-a" {
		t.Errorf("proxies: %+v", cfg.Proxies)
	}
	wantD := sha256.Sum256([]byte("tok-2"))
	if cfg.Proxies["px-2"].TokenDigest != wantD || cfg.Proxies["px-2"].Token != "" {
		t.Errorf("enrollment must carry the digest only")
	}
	if cfg.Dwell != 60*time.Second || cfg.Thresholds.Stale != 30*time.Second || cfg.Thresholds.Lost != 2*time.Minute || cfg.MaxPolls != 5000 {
		t.Errorf("defaults: dwell %v th %+v maxpolls %d", cfg.Dwell, cfg.Thresholds, cfg.MaxPolls)
	}
}

func TestOptionalSettings(t *testing.T) {
	m := baseConfig()
	m["canary_dwell_seconds"], m["stale_seconds"], m["lost_seconds"], m["max_polls"], m["log_level"] = 5, 10, 20, 7, "debug"
	delete(m, "metrics_listen")
	cfg, cerr := parseConfig(marshal(t, m))
	if cerr != nil {
		t.Fatal(cerr)
	}
	if cfg.Dwell != 5*time.Second || cfg.Thresholds.Stale != 10*time.Second || cfg.Thresholds.Lost != 20*time.Second || cfg.MaxPolls != 7 || cfg.MetricsListen != "" {
		t.Errorf("%+v", cfg)
	}
}

// A tenant may have a name that looks like a secret-ish word.
func TestTenantNamesAreNotFieldNames(t *testing.T) {
	m := baseConfig()
	m["tenants"].(map[string]any)["secretary"] = map[string]any{"threshold": 2, "admin_keys": []any{pubHex(6), pubHex(7)}}
	if _, cerr := parseConfig(marshal(t, m)); cerr != nil {
		t.Fatalf("tenant named secretary refused: %v", cerr)
	}
}

func TestConfigRules(t *testing.T) {
	set := func(k string, v any) func(map[string]any) { return func(m map[string]any) { m[k] = v } }
	tests := []struct {
		name string
		mut  func(map[string]any)
		raw  string // used instead of the base config when set
		want string // substring of the English message
	}{
		// file shape
		{name: "unknown top-level field", mut: set("lisen", "x"), want: "unknown field: lisen"},
		{name: "unknown tenant field", mut: func(m map[string]any) { tenantOf(m, "bank-a")["extra"] = 1 }, want: "unknown field: extra"},
		{name: "unknown enrollment field", mut: func(m map[string]any) { enrollOf(m, 0)["token"] = "plain" }, want: "unknown field: token"},
		{name: "upper-case field name", mut: set("Listen", "127.0.0.1:1"), want: "lower case"},
		{name: "duplicate field", raw: `{"listen":"a:1","listen":"b:2"}`, want: "repeats a field: listen"},
		{name: "duplicate tenant", raw: `{"tenants":{"a":{},"a":{}}}`, want: "repeats a field: a"},
		{name: "trailing data", raw: string(marshal(t, baseConfig())) + ` {}`, want: "after the JSON object"},
		{name: "trailing garbage", raw: string(marshal(t, baseConfig())) + `x`, want: "after the JSON object"},
		{name: "empty file", raw: ``, want: "not valid JSON"},
		{name: "not json", raw: `listen: 8080`, want: "not valid JSON"},
		{name: "array root", raw: `[]`, want: "must be a JSON object"},
		{name: "wrong type", mut: set("listen", 8080), want: "listen has the wrong type"},
		{name: "wrong type nested", mut: func(m map[string]any) { tenantOf(m, "bank-a")["threshold"] = "two" }, want: "wrong type"},
		{name: "too deep", raw: strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40), want: "nested too deeply"},
		// listeners and paths
		{name: "listen missing", mut: func(m map[string]any) { delete(m, "listen") }, want: "listen is required"},
		{name: "listen without port", mut: set("listen", "localhost"), want: "listen must look like host:port"},
		{name: "listen port too big", mut: set("listen", "127.0.0.1:70000"), want: "listen must look like host:port"},
		{name: "metrics_listen bad", mut: set("metrics_listen", "nope"), want: "metrics_listen must look like host:port"},
		{name: "metrics_listen same as listen", mut: set("metrics_listen", "127.0.0.1:8080"), want: "must differ from listen"},
		{name: "data_dir missing", mut: func(m map[string]any) { delete(m, "data_dir") }, want: "data_dir is required"},
		{name: "data_dir blank", mut: set("data_dir", "  "), want: "data_dir is required"},
		{name: "log_level unknown", mut: set("log_level", "loud"), want: "log_level must be"},
		// TLS
		{name: "no tls and no plaintext", mut: set("allow_plaintext", false), want: "no TLS"},
		{name: "cert without key", mut: func(m map[string]any) { m["allow_plaintext"] = false; m["tls_cert_file"] = "c.pem" }, want: "go together"},
		{name: "key without cert", mut: func(m map[string]any) { m["allow_plaintext"] = false; m["tls_key_file"] = "k.pem" }, want: "go together"},
		{name: "plaintext with cert", mut: func(m map[string]any) { m["tls_cert_file"] = "c.pem"; m["tls_key_file"] = "k.pem" }, want: "cannot be combined"},
		{name: "unreadable cert", mut: func(m map[string]any) {
			m["allow_plaintext"] = false
			m["tls_cert_file"] = "/nonexistent/c.pem"
			m["tls_key_file"] = "/nonexistent/k.pem"
		}, want: "cannot load the TLS certificate"},
		// numbers
		{name: "dwell zero", mut: set("canary_dwell_seconds", 0), want: "canary_dwell_seconds must be"},
		{name: "dwell too long", mut: set("canary_dwell_seconds", 700000), want: "canary_dwell_seconds must be"},
		{name: "stale zero", mut: set("stale_seconds", 0), want: "stale_seconds must be"},
		{name: "lost below stale", mut: func(m map[string]any) { m["stale_seconds"] = 100; m["lost_seconds"] = 50 }, want: "lost_seconds must not be less"},
		{name: "stale above default lost", mut: set("stale_seconds", 600), want: "lost_seconds must not be less"},
		{name: "max_polls zero", mut: set("max_polls", 0), want: "max_polls must be"},
		{name: "max_polls huge", mut: set("max_polls", 10000000), want: "max_polls must be"},
		// tenants and trust floors
		{name: "no tenants", mut: func(m map[string]any) { delete(m, "tenants"); delete(m, "enrollments") }, want: "tenants is required"},
		{name: "empty tenants", mut: func(m map[string]any) { m["tenants"] = map[string]any{}; delete(m, "enrollments") }, want: "tenants is required"},
		{name: "bad tenant name", mut: func(m map[string]any) {
			m["tenants"].(map[string]any)["Bad_Name"] = map[string]any{"threshold": 2, "admin_keys": []any{pubHex(6), pubHex(7)}}
		}, want: "not a valid ID"},
		{name: "threshold 1", mut: func(m map[string]any) { tenantOf(m, "bank-a")["threshold"] = 1 }, want: "threshold must be at least 2"},
		{name: "threshold 0", mut: func(m map[string]any) { tenantOf(m, "bank-a")["threshold"] = 0 }, want: "threshold must be at least 2"},
		{name: "threshold missing", mut: func(m map[string]any) { delete(tenantOf(m, "bank-a"), "threshold") }, want: "threshold must be at least 2"},
		{name: "threshold negative", mut: func(m map[string]any) { tenantOf(m, "bank-a")["threshold"] = -2 }, want: "threshold must be at least 2"},
		{name: "threshold above key count", mut: func(m map[string]any) { tenantOf(m, "bank-a")["threshold"] = 4 }, want: "threshold must be at least 2"},
		{name: "one key only", mut: func(m map[string]any) { tenantOf(m, "bank-a")["admin_keys"] = []any{pubHex(1)} }, want: "threshold must be at least 2"},
		{name: "no keys", mut: func(m map[string]any) { delete(tenantOf(m, "bank-a"), "admin_keys") }, want: "threshold must be at least 2"},
		{name: "key upper-case hex", mut: func(m map[string]any) {
			tenantOf(m, "bank-a")["admin_keys"] = []any{strings.ToUpper(pubHex(1)), pubHex(2)}
		}, want: "64 lower-case hex"},
		{name: "key too short", mut: func(m map[string]any) { tenantOf(m, "bank-a")["admin_keys"] = []any{pubHex(1)[:62], pubHex(2)} }, want: "64 lower-case hex"},
		{name: "key not hex", mut: func(m map[string]any) {
			tenantOf(m, "bank-a")["admin_keys"] = []any{strings.Repeat("zz", 32), pubHex(2)}
		}, want: "64 lower-case hex"},
		{name: "key is a file name", mut: func(m map[string]any) { tenantOf(m, "bank-a")["admin_keys"] = []any{"admin-a.pub", pubHex(2)} }, want: "64 lower-case hex"},
		{name: "same key twice", mut: func(m map[string]any) { tenantOf(m, "bank-a")["admin_keys"] = []any{pubHex(1), pubHex(1), pubHex(2)} }, want: "listed twice"},
		{name: "too many keys", mut: func(m map[string]any) {
			var ks []any
			for i := 0; i < 17; i++ {
				ks = append(ks, pubHex(byte(100+i)))
			}
			tenantOf(m, "bank-a")["admin_keys"] = ks
		}, want: "too many admin_keys"},
		// private key material (M-D37)
		{name: "seed field", mut: func(m map[string]any) { tenantOf(m, "bank-a")["seed"] = seedHex(1) }, want: "private key material"},
		{name: "private_key field", mut: set("private_key", "x"), want: "private key material"},
		{name: "secret field name", mut: set("Secret", "x"), want: "lower case"}, // case first
		{name: "signing secret field", mut: set("signing_secret", "x"), want: "private key material"},
		{name: "pem block as value", mut: set("data_dir", "-----BEGIN PRIVATE KEY-----\nMC4CAQAw\n-----END PRIVATE KEY-----"), want: "private key material"},
		{name: "openssh key as value", mut: set("log_level", "-----BEGIN OPENSSH PRIVATE KEY-----"), want: "private key material"},
		{name: "128 hex private key in admin_keys", mut: func(m map[string]any) {
			tenantOf(m, "bank-a")["admin_keys"] = []any{seedHex(1) + pubHex(1), pubHex(2)}
		}, want: "private key material"},
		{name: "seed next to its public key", mut: func(m map[string]any) {
			tenantOf(m, "bank-a")["admin_keys"] = []any{seedHex(1), pubHex(1), pubHex(2)}
		}, want: "private key material"},
		// enrollments
		{name: "proxy_id empty", mut: func(m map[string]any) { enrollOf(m, 0)["proxy_id"] = "" }, want: "enrollments[0]: proxy_id"},
		{name: "proxy_id invalid", mut: func(m map[string]any) { enrollOf(m, 1)["proxy_id"] = "Px_2" }, want: "enrollments[1]: proxy_id"},
		{name: "tenant empty", mut: func(m map[string]any) { enrollOf(m, 0)["tenant"] = "" }, want: "enrollments[0]: tenant is missing"},
		{name: "tenant not configured", mut: func(m map[string]any) { enrollOf(m, 0)["tenant"] = "bank-z" }, want: "not listed in tenants"},
		{name: "group empty", mut: func(m map[string]any) { enrollOf(m, 0)["group"] = "" }, want: "group is missing"},
		{name: "group invalid", mut: func(m map[string]any) { enrollOf(m, 0)["group"] = "Main Group" }, want: "group is missing or not a valid ID"},
		{name: "duplicate proxy id", mut: func(m map[string]any) { enrollOf(m, 1)["proxy_id"] = "px-1" }, want: "already enrolled"},
		{name: "token digest missing", mut: func(m map[string]any) { delete(enrollOf(m, 0), "token_sha256") }, want: "token_sha256 must be"},
		{name: "token digest empty string", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = "" }, want: "token_sha256 must be"},
		{name: "token digest upper-case", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = strings.ToUpper(digestOf("x")) }, want: "token_sha256 must be"},
		{name: "token digest short", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = digestOf("x")[:60] }, want: "token_sha256 must be"},
		{name: "token digest is the token", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = "tok-1" }, want: "token_sha256 must be"},
		{name: "token digest of empty token", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = digestOf("") }, want: "empty token"},
		{name: "token digest all zero", mut: func(m map[string]any) { enrollOf(m, 0)["token_sha256"] = strings.Repeat("0", 64) }, want: "enrollments[0]"},
		{name: "duplicate token digest", mut: func(m map[string]any) { enrollOf(m, 1)["token_sha256"] = enrollOf(m, 0)["token_sha256"] }, want: "same as enrollments[0]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if tc.raw != "" || tc.mut == nil {
				data = []byte(tc.raw)
			} else {
				m := baseConfig()
				tc.mut(m)
				data = marshal(t, m)
			}
			cfg, cerr := parseConfig(data)
			if cerr == nil {
				t.Fatalf("accepted: %+v", cfg)
			}
			if !strings.Contains(cerr.en, tc.want) {
				t.Errorf("en = %q, want it to contain %q", cerr.en, tc.want)
			}
			if cerr.ja == "" || cerr.ja == cerr.en {
				t.Errorf("ja message missing: %q", cerr.ja)
			}
			if !hasJapanese(cerr.ja) {
				t.Errorf("ja message has no Japanese: %q", cerr.ja)
			}
		})
	}
}

func hasJapanese(s string) bool {
	for _, r := range s {
		if r >= 0x3040 && r <= 0x9fff {
			return true
		}
	}
	return false
}

// A message never repeats a config value: not a token digest, not a key.
func TestMessagesDoNotEchoValues(t *testing.T) {
	m := baseConfig()
	enrollOf(m, 1)["token_sha256"] = enrollOf(m, 0)["token_sha256"]
	tenantOf(m, "bank-a")["admin_keys"] = []any{pubHex(1), pubHex(1)}
	_, cerr := parseConfig(marshal(t, m))
	if cerr == nil {
		t.Fatal("accepted")
	}
	for _, s := range []string{cerr.en, cerr.ja} {
		if strings.Contains(s, pubHex(1)) || strings.Contains(s, digestOf("tok-1")) {
			t.Errorf("message echoes a value: %q", s)
		}
	}
	seed := baseConfig()
	tenantOf(seed, "bank-a")["seed"] = seedHex(9)
	_, cerr = parseConfig(marshal(t, seed))
	if cerr == nil || strings.Contains(cerr.en, seedHex(9)) || strings.Contains(cerr.ja, seedHex(9)) {
		t.Errorf("seed echoed or accepted: %v", cerr)
	}
}

func TestEveryMessageHasTwoLanguages(t *testing.T) {
	_, cerr := loadConfig(filepath.Join(t.TempDir(), "missing.json"))
	if cerr == nil || !strings.HasPrefix(cerr.en, "config file:") || !strings.HasPrefix(cerr.ja, "設定ファイル") {
		t.Fatalf("%v", cerr)
	}
}

func TestLoadConfigFileKinds(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "cp.json")
	if err := os.WriteFile(good, marshal(t, baseConfig()), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, cerr := loadConfig(good); cerr != nil {
		t.Fatalf("good: %v", cerr)
	}
	if _, cerr := loadConfig(dir); cerr == nil {
		t.Error("a directory was accepted")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(`{"data_dir":"`+strings.Repeat("a", maxConfigBytes)+`"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, cerr := loadConfig(big); cerr == nil || !strings.Contains(cerr.en, "too large") {
		t.Errorf("big file: %v", cerr)
	}
}

// The trust floor in the config must be the one trust.Verify enforces.
func TestAdminKeysMapToTrustRoot(t *testing.T) {
	cfg, cerr := parseConfig(marshal(t, baseConfig()))
	if cerr != nil {
		t.Fatal(cerr)
	}
	root := cfg.AdminKeys[wire.ID("bank-a")]
	if root.Tenant != "bank-a" {
		t.Fatalf("tenant %q", root.Tenant)
	}
	for id, k := range root.Keys {
		if len(k) != ed25519.PublicKeySize || id == "" {
			t.Errorf("bad key entry %q", id)
		}
	}
}

// FuzzParseConfig: any input either parses into a config that keeps the trust
// floor, or fails with a short two-language message; never a panic.
func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"listen":"a:1","listen":"b:2"}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(strings.Repeat(`{"a":`, 40)))
	b, _ := json.Marshal(baseConfig())
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, cerr := parseConfig(data)
		if cerr != nil {
			if cfg != nil || cerr.en == "" || cerr.ja == "" || len(cerr.en) >= 400 || len(cerr.ja) >= 600 {
				t.Fatalf("bad refusal: %v %v", cfg, cerr)
			}
			return
		}
		for id, r := range cfg.AdminKeys {
			if r.Threshold < 2 || len(r.Keys) < r.Threshold || r.Tenant != id {
				t.Fatalf("trust floor broken for %s: %+v", id, r)
			}
		}
		for id, e := range cfg.Proxies {
			if !id.Valid() || e.Token != "" || e.TokenDigest == ([sha256.Size]byte{}) {
				t.Fatalf("bad enrollment %s: %+v", id, e)
			}
			if _, ok := cfg.AdminKeys[e.Tenant]; !ok {
				t.Fatalf("enrollment for an unlisted tenant: %s", id)
			}
		}
	})
}
