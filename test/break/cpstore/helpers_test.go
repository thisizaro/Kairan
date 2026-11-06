// Package cpstorebreak holds black-box attack tests for the control-plane
// store (task C-03). Sources: ARCHITECTURE cp/store LLD, invariants I3/I4,
// decisions M-D35 and M-D41 (EnvelopeMeta, timeline log anchor), the go doc of
// the store package and wire. Files are inspected only as opaque JSON that the
// store itself wrote into a temp directory.
package cpstorebreak

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func hx(s string) wire.Hash {
	sum := sha256.Sum256([]byte(s))
	return wire.Hash(hex.EncodeToString(sum[:]))
}

func payloadHash(p []byte) wire.Hash {
	sum := sha256.Sum256(p)
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// envFor builds an envelope with a valid shape and its matching meta.
func envFor(tenant wire.ID, version uint64, payload string) (wire.Envelope, store.EnvelopeMeta) {
	sig := func(b byte) wire.Signature {
		s := make([]byte, wire.SignatureSize)
		for i := range s {
			s[i] = b
		}
		return wire.Signature{KeyID: hx(fmt.Sprintf("key-%d", b)), Sig: s}
	}
	p := []byte(payload)
	return wire.Envelope{
		PayloadType: wire.PayloadTypePolicy,
		Payload:     p,
		Signatures:  []wire.Signature{sig(1), sig(2)},
	}, store.EnvelopeMeta{
		Tenant: tenant, Version: version, Hash: payloadHash(p),
	}
}

func mustPut(t *testing.T, s store.Store, tenant wire.ID, version uint64, payload string) wire.Envelope {
	t.Helper()
	e, m := envFor(tenant, version, payload)
	if err := s.PutEnvelope(e, m); err != nil {
		t.Fatalf("PutEnvelope(%s v%d): %v", tenant, version, err)
	}
	return e
}

func open(t *testing.T, dir string) store.Store {
	t.Helper()
	s, err := store.OpenFiles(dir)
	if err != nil {
		t.Fatalf("OpenFiles(%s): %v", dir, err)
	}
	return s
}

// sandbox returns <root>/state (the store dir) so tests can see escapes into <root>.
func sandbox(t *testing.T) (root, dir string) {
	t.Helper()
	root = t.TempDir()
	dir = filepath.Join(root, "state")
	return
}

// repOpt tweaks a StatusReport.
type repOpt func(*wire.StatusReport)

func withVersion(v uint64) repOpt {
	return func(r *wire.StatusReport) {
		r.AppliedVersion = v
		if v == 0 {
			r.PolicyHash = ""
			return
		}
		r.PolicyHash = hx(fmt.Sprintf("policy-%d", v))
	}
}
func withHash(h wire.Hash) repOpt { return func(r *wire.StatusReport) { r.PolicyHash = h } }
func withState(s wire.ProxyState) repOpt {
	return func(r *wire.StatusReport) { r.State = s }
}
func withAnchor(seq uint64) repOpt {
	return func(r *wire.StatusReport) {
		r.LogSeq = seq
		if seq == 0 {
			r.LogHead = ""
			return
		}
		r.LogHead = hx(fmt.Sprintf("head-%d", seq))
	}
}
func withErr(c wire.ErrorCode, v uint64) repOpt {
	return func(r *wire.StatusReport) { r.LastError = &wire.ApplyError{Code: c, Version: v} }
}
func withSeq(seq, uptime uint64) repOpt {
	return func(r *wire.StatusReport) { r.Seq, r.UptimeSeconds = seq, uptime }
}
func withCounters(a, d, rj uint64) repOpt {
	return func(r *wire.StatusReport) {
		r.Counters = wire.Counters{CallsAllowed: a, CallsDenied: d, EnvelopesRejected: rj}
	}
}

// rep builds a valid report: enforcing at version 1 unless changed.
func rep(tenant, proxy wire.ID, opts ...repOpt) wire.StatusReport {
	r := wire.StatusReport{Tenant: tenant, ProxyID: proxy, Seq: 1, State: wire.StateEnforcing}
	withVersion(1)(&r)
	for _, o := range opts {
		o(&r)
	}
	return r
}

func last(group wire.ID, r wire.StatusReport, at time.Time) fleet.Last {
	return fleet.Last{Group: group, Report: r, SeenAt: at}
}

// files lists regular files below root (relative, sorted).
func files(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			rel, _ := filepath.Rel(root, p)
			out = append(out, rel)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree: %v", err)
	}
}

// findFile returns the single file under dir whose slash path contains all parts.
func findFile(t *testing.T, dir string, parts ...string) string {
	t.Helper()
	var hits []string
	for _, f := range files(t, dir) {
		ok := true
		for _, p := range parts {
			if !strings.Contains(filepath.ToSlash(f), p) {
				ok = false
			}
		}
		if ok && !strings.Contains(f, ".tmp") {
			hits = append(hits, f)
		}
	}
	if len(hits) != 1 {
		t.Fatalf("want exactly one file containing %v under %s, got %v (all: %v)", parts, dir, hits, files(t, dir))
	}
	return filepath.Join(dir, hits[0])
}

// editJSON reads path as generic JSON, applies f, and writes it back.
func editJSON(t *testing.T, path string, f func(m map[string]any)) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("store wrote a file that is not a JSON object: %v", err)
	}
	f(m)
	nb, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nb, 0o600); err != nil {
		t.Fatal(err)
	}
}

// walkStrings calls f for each string value (and may replace it) in a generic JSON tree.
func walkStrings(v any, f func(key string, s string) (string, bool)) bool {
	changed := false
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok {
				if ns, ch := f(k, s); ch {
					x[k] = ns
					changed = true
				}
			} else if walkStrings(e, f) {
				changed = true
			}
		}
	case []any:
		for i, e := range x {
			if s, ok := e.(string); ok {
				if ns, ch := f("", s); ch {
					x[i] = ns
					changed = true
				}
			} else if walkStrings(e, f) {
				changed = true
			}
		}
	}
	return changed
}

func os_Stat(p string) (os.FileInfo, error) { return os.Stat(p) }

func inodeOf(i os.FileInfo) uint64 {
	if st, ok := i.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}
