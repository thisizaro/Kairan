package kairancpbreak

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The config shape below was learned from the program's own diagnostics (-check) and ARCHITECTURE/C-D9/C-D10;
// it is not written down in the docs (see the change-request filed with this pass).
const (
	adminTok = "ADMIN-TOKEN-0123456789abcdef"
	canary   = "CANARY-9f3b27-SECRET"
)

func fixture(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

func pub(t testing.TB, who string) string  { return fixture(t, "TEST-ONLY-"+who+".pub") }
func seed(t testing.TB, who string) string { return fixture(t, "TEST-ONLY-"+who+".seed") }

func privKey(t testing.TB, who string) ed25519.PrivateKey {
	t.Helper()
	b, err := hex.DecodeString(seed(t, who))
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(b)
}

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func tokOf(id string) string { return "tok-" + id + "-0123456789abcdef" }

type cfg map[string]any

// baseCfg is a valid plaintext config for tenants bank-a (admin a,b,c; threshold 2) and bank-b (a,b; 2).
func baseCfg(t testing.TB, dataDir string) cfg {
	return cfg{
		"listen":          "127.0.0.1:0",
		"data_dir":        dataDir,
		"allow_plaintext": true,
		"tenants": map[string]any{
			"bank-a": map[string]any{"threshold": 2, "admin_keys": []string{pub(t, "admin-a"), pub(t, "admin-b"), pub(t, "admin-c")}},
			"bank-b": map[string]any{"threshold": 2, "admin_keys": []string{pub(t, "admin-a"), pub(t, "admin-b")}},
		},
		"enrollments": []any{
			map[string]any{"proxy_id": "p1", "tenant": "bank-a", "group": "main", "token_sha256": sha(tokOf("p1"))},
			map[string]any{"proxy_id": "p2", "tenant": "bank-a", "group": "main", "token_sha256": sha(tokOf("p2"))},
			map[string]any{"proxy_id": "c1", "tenant": "bank-a", "group": "canary", "token_sha256": sha(tokOf("c1"))},
			map[string]any{"proxy_id": "q1", "tenant": "bank-b", "group": "main", "token_sha256": sha(tokOf("q1"))},
		},
	}
}

func (c cfg) clone(t testing.TB) cfg {
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var out cfg
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// with returns a deep copy with the top-level key set (nil deletes it).
func (c cfg) with(t testing.TB, k string, v any) cfg {
	out := c.clone(t)
	if v == nil {
		delete(out, k)
	} else {
		out[k] = v
	}
	return out
}

func (c cfg) bytes(t testing.TB) []byte {
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// files writes cfg bytes and the admin token file (0600) into one temp dir.
type files struct {
	dir, cfgPath, tokPath string
}

func writeFiles(t testing.TB, cfgBytes []byte, token string) files {
	t.Helper()
	d := t.TempDir()
	f := files{dir: d, cfgPath: filepath.Join(d, "cp.json"), tokPath: filepath.Join(d, "admin.token")}
	if err := os.WriteFile(f.cfgPath, cfgBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.tokPath, []byte(token), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

// check runs -check on cfgBytes with the admin token in a 0600 file.
func check(t testing.TB, cfgBytes []byte) result {
	t.Helper()
	f := writeFiles(t, cfgBytes, adminTok+"\n")
	return run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath, "-check")
}

func freePort(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

// noPanic fails when the output looks like a Go crash.
func noPanic(t testing.TB, r result) {
	t.Helper()
	if contains(r.all(), "panic:", "goroutine ", "runtime error", "fatal error:") {
		t.Errorf("crash output: %s", clip(r.all()))
	}
}

func clip(s string) string {
	if len(s) > 400 {
		return s[:400] + "..."
	}
	return s
}

func hasCJK(s string) bool {
	for _, r := range s {
		if r >= 0x3040 && r <= 0x9fff {
			return true
		}
	}
	return false
}
