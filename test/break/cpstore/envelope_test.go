package cpstorebreak

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

// LLD: PutEnvelope "conflict if the version exists"; doc: ErrConflict, wire.ErrInvalid.
func TestPutEnvelopeRoundTripAndReopen(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	e1 := mustPut(t, s, "bank-a", 1, `{"v":1}`)
	e2 := mustPut(t, s, "bank-a", math.MaxUint64, "\xff\xfe not utf8 \x00 payload")
	e3 := mustPut(t, s, "city-b", 1, strings.Repeat("x", 150<<10))
	for _, c := range []struct {
		tenant wire.ID
		v      uint64
		want   wire.Envelope
	}{{"bank-a", 1, e1}, {"bank-a", math.MaxUint64, e2}, {"city-b", 1, e3}} {
		for round, st := range []store.Store{s, open(t, dir)} {
			got, err := st.Envelope(c.tenant, c.v)
			if err != nil {
				t.Fatalf("round %d Envelope(%s,%d): %v", round, c.tenant, c.v, err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("round %d Envelope(%s,%d) differs from what was stored", round, c.tenant, c.v)
			}
		}
	}
	// tenants are isolated
	if _, err := s.Envelope("city-b", 2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing version: %v, want ErrNotFound", err)
	}
	if _, err := s.Envelope("other", 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing tenant: %v, want ErrNotFound", err)
	}
	if _, err := s.Envelope("bank-a", 0); err == nil {
		t.Fatal("Envelope(version 0) returned nil error")
	}
}

func TestPutEnvelopeConflictNeverOverwrites(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	first := mustPut(t, s, "bank-a", 5, "first")
	for _, payload := range []string{"first", "second"} {
		e, m := envFor("bank-a", 5, payload)
		if err := s.PutEnvelope(e, m); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("second put of v5 (%q): %v, want ErrConflict", payload, err)
		}
	}
	// the conflict also holds across restart
	s2 := open(t, dir)
	e, m := envFor("bank-a", 5, "third")
	if err := s2.PutEnvelope(e, m); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("after reopen: %v, want ErrConflict", err)
	}
	for _, st := range []store.Store{s, s2} {
		got, err := st.Envelope("bank-a", 5)
		if err != nil || !bytes.Equal(got.Payload, first.Payload) {
			t.Fatalf("stored v5 changed by a conflicting put: %q err=%v", got.Payload, err)
		}
	}
	// the same version in another tenant is not a conflict
	mustPut(t, s, "city-b", 5, "other tenant")
}

func TestPutEnvelopeConcurrentSameVersionExactlyOneWins(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	const n = 48
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e, m := envFor("bank-a", 9, fmt.Sprintf("writer-%d", i))
			<-start
			errs[i] = s.PutEnvelope(e, m)
		}(i)
	}
	close(start)
	wg.Wait()
	winner := -1
	for i, err := range errs {
		switch {
		case err == nil:
			if winner != -1 {
				t.Fatalf("two writers won (%d and %d)", winner, i)
			}
			winner = i
		case !errors.Is(err, store.ErrConflict):
			t.Fatalf("writer %d: %v, want nil or ErrConflict", i, err)
		}
	}
	if winner < 0 {
		t.Fatal("no writer won")
	}
	want := fmt.Sprintf("writer-%d", winner)
	for _, st := range []store.Store{s, open(t, dir)} {
		got, err := st.Envelope("bank-a", 9)
		if err != nil || string(got.Payload) != want {
			t.Fatalf("stored payload %q err=%v, want winner's %q", got.Payload, err, want)
		}
	}
}

func TestPutEnvelopeConcurrentDistinctVersionsAllSurvive(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	var wg sync.WaitGroup
	const n = 64
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(v uint64) {
			defer wg.Done()
			tenant := wire.ID("bank-a")
			if v%2 == 0 {
				tenant = "city-b"
			}
			e, m := envFor(tenant, v, fmt.Sprintf("p%d", v))
			if err := s.PutEnvelope(e, m); err != nil {
				t.Errorf("put v%d: %v", v, err)
			}
			// concurrent readers on the same store
			_, _ = s.Envelope(tenant, v)
			_, _ = s.Timeline(tenant)
		}(uint64(i))
	}
	wg.Wait()
	s2 := open(t, dir)
	for v := uint64(1); v <= n; v++ {
		tenant := wire.ID("bank-a")
		if v%2 == 0 {
			tenant = "city-b"
		}
		got, err := s2.Envelope(tenant, v)
		if err != nil || string(got.Payload) != fmt.Sprintf("p%d", v) {
			t.Fatalf("v%d after reopen: %q err=%v", v, got.Payload, err)
		}
	}
}

// Doc: PutEnvelope returns wire.ErrInvalid if the shape, tenant, version or hash is wrong,
// and nothing is stored. LLD: "Never stores payload beyond the signed envelope".
func TestPutEnvelopeRejectsBadInput(t *testing.T) {
	good, goodMeta := envFor("bank-a", 3, `{"ok":1}`)
	mut := func(f func(e *wire.Envelope, m *store.EnvelopeMeta)) (wire.Envelope, store.EnvelopeMeta) {
		e := wire.Envelope{PayloadType: good.PayloadType, Payload: append([]byte(nil), good.Payload...)}
		for _, s := range good.Signatures {
			e.Signatures = append(e.Signatures, wire.Signature{KeyID: s.KeyID, Sig: append([]byte(nil), s.Sig...)})
		}
		m := goodMeta
		f(&e, &m)
		return e, m
	}
	manySigs := func(n int) []wire.Signature {
		var out []wire.Signature
		for i := 0; i < n; i++ {
			out = append(out, wire.Signature{KeyID: hx(fmt.Sprint("k", i)), Sig: make([]byte, wire.SignatureSize)})
		}
		return out
	}
	cases := []struct {
		name string
		f    func(e *wire.Envelope, m *store.EnvelopeMeta)
	}{
		{"payload-type", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.PayloadType = "text/plain" }},
		{"empty-payload", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Payload = nil; m.Hash = payloadHash(nil) }},
		{"zero-signatures", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Signatures = nil }},
		{"nine-signatures", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Signatures = manySigs(9) }},
		{"short-sig", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Signatures[0].Sig = e.Signatures[0].Sig[:63] }},
		{"long-sig", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Signatures[0].Sig = append(e.Signatures[0].Sig, 0) }},
		{"bad-keyid", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Signatures[0].KeyID = "ABC" }},
		{"uppercase-keyid", func(e *wire.Envelope, m *store.EnvelopeMeta) {
			e.Signatures[0].KeyID = wire.Hash(strings.ToUpper(string(e.Signatures[0].KeyID)))
		}},
		{"tenant-empty", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "" }},
		{"tenant-upper", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "Bank-A" }},
		{"tenant-dotdot", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = ".." }},
		{"tenant-traversal", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "../../evil" }},
		{"tenant-slash", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "a/b" }},
		{"tenant-backslash", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = `a\b` }},
		{"tenant-nul", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "a\x00b" }},
		{"tenant-dash-first", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "-a" }},
		{"tenant-64-chars", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = wire.ID(strings.Repeat("a", 64)) }},
		{"tenant-newline", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Tenant = "a\nb" }},
		{"version-zero", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Version = 0 }},
		{"hash-empty", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Hash = "" }},
		{"hash-other-payload", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Hash = payloadHash([]byte("different")) }},
		{"hash-payload-plus-newline", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Hash = payloadHash(append(e.Payload, '\n')) }},
		{"hash-uppercase", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Hash = wire.Hash(strings.ToUpper(string(m.Hash))) }},
		{"hash-truncated", func(e *wire.Envelope, m *store.EnvelopeMeta) { m.Hash = m.Hash[:63] }},
		{"hash-of-payload-mutated-after", func(e *wire.Envelope, m *store.EnvelopeMeta) { e.Payload[0] ^= 1 }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, dir := sandbox(t)
			s := open(t, dir)
			before := files(t, root)
			e, m := mut(c.f)
			err := s.PutEnvelope(e, m)
			if !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("err = %v, want wire.ErrInvalid", err)
			}
			if after := files(t, root); !reflect.DeepEqual(before, after) {
				t.Fatalf("rejected put left files behind: %v -> %v", before, after)
			}
			if _, err := s.Envelope("bank-a", 3); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("rejected envelope is retrievable: %v", err)
			}
			// and the version is still free
			if err := s.PutEnvelope(good, goodMeta); err != nil {
				t.Fatalf("version burned by a rejected put: %v", err)
			}
		})
	}
}

// Path traversal through the tenant must never read or write outside the state dir.
func TestTenantTraversalNeverTouchesOutside(t *testing.T) {
	root, dir := sandbox(t)
	// a victim store beside the state dir holds a perfectly valid envelope
	victimDir := filepath.Join(root, "victim")
	vs := open(t, victimDir)
	mustPut(t, vs, "t1", 1, "victim secret")

	s := open(t, dir)
	hostile := []wire.ID{
		"../../victim/envelopes/t1", "..", "../victim", "/etc", "t1/..", "a/../../victim/envelopes/t1",
		"%2e%2e", "..%2f", "./t1", "t1\x00", "", "C:", `..\..\victim`,
	}
	snapshot := files(t, root)
	for _, h := range hostile {
		name := fmt.Sprintf("%q", string(h))
		if e, err := s.Envelope(h, 1); err == nil {
			t.Fatalf("Envelope(%s) returned data outside the state dir: %q", name, e.Payload)
		}
		if _, ok, err := s.Rollout(h); ok && err == nil {
			t.Fatalf("Rollout(%s) found something", name)
		}
		if f, err := s.Fleet(h); err == nil && len(f) != 0 {
			t.Fatalf("Fleet(%s) returned %d rows", name, len(f))
		}
		if tl, err := s.Timeline(h); err == nil && len(tl) != 0 {
			t.Fatalf("Timeline(%s) returned %d entries", name, len(tl))
		}
		e, m := envFor(h, 1, "evil")
		if err := s.PutEnvelope(e, m); err == nil {
			t.Fatalf("PutEnvelope(tenant %s) succeeded", name)
		}
		rr := rolloutFor(h, 2, 1)
		if err := s.PutRollout(rr); err == nil {
			t.Fatalf("PutRollout(tenant %s) succeeded", name)
		}
		if err := s.RecordStatus(last("main", rep(h, "p1"), t0)); err == nil {
			t.Fatalf("RecordStatus(tenant %s) succeeded", name)
		}
		if err := s.RecordStatus(last("main", rep("bank-a", h), t0)); err == nil {
			t.Fatalf("RecordStatus(proxy %s) succeeded", name)
		}
		if err := s.RecordStatus(last(h, rep("bank-a", "p1"), t0)); err == nil {
			t.Fatalf("RecordStatus(group %s) succeeded", name)
		}
	}
	// nothing new anywhere under the sandbox except the (possibly created) state dir tree
	for _, f := range files(t, root) {
		if strings.HasPrefix(f, "state"+string(filepath.Separator)) {
			continue
		}
		found := false
		for _, o := range snapshot {
			if o == f {
				found = true
			}
		}
		if !found {
			t.Fatalf("new file outside the state dir: %s", f)
		}
	}
	// the state dir has no data files at all
	for _, f := range files(t, dir) {
		t.Errorf("hostile input left a file in the state dir: %s", f)
	}
	if ents, _ := os.ReadDir(filepath.Dir(dir)); len(ents) != 2 {
		t.Fatalf("sandbox root entries changed: %v", ents)
	}
}

// Copy isolation: "Values going in and out are copies."
func TestEnvelopeCopyIsolation(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	e, m := envFor("bank-a", 1, `{"orig":true}`)
	if err := s.PutEnvelope(e, m); err != nil {
		t.Fatal(err)
	}
	orig := append([]byte(nil), e.Payload...)
	origSig := append([]byte(nil), e.Signatures[0].Sig...)
	// mutate the caller's copy after Put
	e.Payload[0] = 'X'
	e.Signatures[0].Sig[0] ^= 0xff
	e.Signatures[0].KeyID = "mutated"
	got, err := s.Envelope("bank-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, orig) || !bytes.Equal(got.Signatures[0].Sig, origSig) || got.Signatures[0].KeyID == "mutated" {
		t.Fatal("store aliases the caller's envelope given to PutEnvelope")
	}
	// mutate what was returned
	got.Payload[0] = 'Y'
	got.Signatures[1].Sig[5] ^= 0xff
	got.Signatures = got.Signatures[:1]
	again, _ := s.Envelope("bank-a", 1)
	if !bytes.Equal(again.Payload, orig) || len(again.Signatures) != 2 {
		t.Fatal("store aliases the envelope it returned")
	}
	for i, sg := range again.Signatures {
		want := byte(i + 1)
		if i == 0 {
			continue // checked above against origSig
		}
		if sg.Sig[5] != want {
			t.Fatal("returned signature bytes alias the stored ones")
		}
	}
	if payloadHash(again.Payload) != m.Hash {
		t.Fatal("stored payload no longer matches its hash")
	}
}

// Failed writes must not leave the store claiming success (I3: fail closed on disk errors).
func TestWriteFailureLeavesNoPhantomState(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	mustPut(t, s, "bank-a", 1, "seed") // creates envelopes/bank-a
	envDir := filepath.Join(dir, "envelopes", "bank-a")
	if err := os.Chmod(envDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(envDir, 0o700)
	e, m := envFor("bank-a", 2, "phantom")
	err := s.PutEnvelope(e, m)
	if err == nil {
		t.Fatal("PutEnvelope on a read-only directory returned nil")
	}
	if _, gerr := s.Envelope("bank-a", 2); !errors.Is(gerr, store.ErrNotFound) {
		t.Fatalf("failed put is visible in memory: %v", gerr)
	}
	if err := os.Chmod(envDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEnvelope(e, m); err != nil {
		t.Fatalf("retry after the disk recovered: %v (version burned by the failed put?)", err)
	}
	for _, f := range files(t, dir) {
		if strings.Contains(f, ".tmp") {
			t.Fatalf("temp file left behind: %s", f)
		}
	}
}

func TestFileModesNotWritableByOthers(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	mustPut(t, s, "bank-a", 1, "p")
	if err := s.PutRollout(rolloutFor("bank-a", 1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStatus(last("main", rep("bank-a", "p1"), t0)); err != nil {
		t.Fatal(err)
	}
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		info, _ := d.Info()
		mode := info.Mode().Perm()
		if mode&0o022 != 0 {
			t.Errorf("%s has mode %o: writable by group/others", p, mode)
		}
		if !d.IsDir() && mode&0o111 != 0 {
			t.Errorf("%s has mode %o: data file is executable", p, mode)
		}
		return nil
	})
}
