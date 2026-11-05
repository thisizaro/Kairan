// Package declogbreak holds black-box attack tests for the proxy decision log (task P-06) and its
// I5 stamping through enforce. Sources: the go doc of declog and enforce, ARCHITECTURE proxy/enforce
// (M-D33), invariants I4 and I5, THREATS #7. Only exported API is used.
package declogbreak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

const canary = "CANARY-9f3b27-SECRET"

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func hashN(n int) wire.Hash { return wire.Hash(fmt.Sprintf("%064x", n)) }

func rec(n int) enforce.Record {
	return enforce.Record{
		Time: t0.Add(time.Duration(n) * time.Second), Role: "sales", Tool: "crm.read_contact",
		Allowed: true, Class: policy.ClassR, Version: uint64(n + 1), Hash: hashN(n + 1), State: wire.StateEnforcing,
	}
}

type metrics struct {
	mu sync.Mutex
	m  map[string]int
}

func (m *metrics) Inc(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]int{}
	}
	m.m[name]++
}

func (m *metrics) get(n string) int { m.mu.Lock(); defer m.mu.Unlock(); return m.m[n] }

// goodLine returns one line as the package writes it, via an in-memory log.
func goodLine(t testing.TB) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := declog.New(&b, nil).Record(rec(1)); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimRight(b.Bytes(), "\n")
}

// mutate decodes a good line to a generic map, lets f edit it and re-encodes it compactly.
func mutate(t testing.TB, f func(map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(goodLine(t), &m); err != nil {
		t.Fatalf("log line is not a JSON object: %v", err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func readLines(t testing.TB, path string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) == 0 {
		return nil
	}
	s := string(b)
	if !strings.HasSuffix(s, "\n") {
		t.Fatalf("%s does not end with a newline: torn line %q", path, tail(s))
	}
	return strings.Split(strings.TrimSuffix(s, "\n"), "\n")
}

func tail(s string) string {
	if len(s) > 80 {
		return "..." + s[len(s)-80:]
	}
	return s
}

func openLog(t testing.TB, o declog.Options) (*declog.Log, string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "decisions.log")
	l, err := declog.Open(p, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, p
}
