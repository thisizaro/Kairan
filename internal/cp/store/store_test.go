package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func hashOf(b []byte) wire.Hash {
	h := sha256.Sum256(b)
	return wire.Hash(hex.EncodeToString(h[:]))
}

func hh(c byte) wire.Hash { return wire.Hash(strings.Repeat(string(c), 64)) }

func mkEnv(payload string) (wire.Envelope, EnvelopeMeta) {
	env := wire.Envelope{
		PayloadType: wire.PayloadTypePolicy,
		Payload:     []byte(payload),
		Signatures: []wire.Signature{
			{KeyID: hh('a'), Sig: bytes.Repeat([]byte{1}, wire.SignatureSize)},
			{KeyID: hh('b'), Sig: bytes.Repeat([]byte{2}, wire.SignatureSize)},
		},
	}
	return env, EnvelopeMeta{Tenant: "acme", Version: 8, Hash: hashOf(env.Payload)}
}

func open(t *testing.T) (Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenFiles(dir)
	if err != nil {
		t.Fatalf("OpenFiles: %v", err)
	}
	return s, dir
}

func reopen(t *testing.T, dir string) Store {
	t.Helper()
	s, err := OpenFiles(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	return s
}

func report(proxy wire.ID, seq, applied uint64) wire.StatusReport {
	r := wire.StatusReport{
		Tenant: "acme", ProxyID: proxy, Seq: seq, State: wire.StateEnforcing,
		AppliedVersion: applied, PolicyHash: hh('c'), UptimeSeconds: seq * 10,
		Counters: wire.Counters{CallsAllowed: seq},
	}
	if applied == 0 {
		r.State, r.PolicyHash = wire.StateDenyAll, ""
	}
	return r
}

func TestEnvelopeRoundTripAndReopen(t *testing.T) {
	s, dir := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	if err := s.PutEnvelope(env, meta); err != nil {
		t.Fatal(err)
	}
	got, err := s.Envelope("acme", 8)
	if err != nil || !reflect.DeepEqual(got, env) {
		t.Fatalf("got %+v, %v", got, err)
	}
	s2 := reopen(t, dir)
	got, err = s2.Envelope("acme", 8)
	if err != nil || !reflect.DeepEqual(got, env) {
		t.Fatalf("after reopen: %+v, %v", got, err)
	}
}

func TestEnvelopeIsCopied(t *testing.T) {
	s, _ := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	if err := s.PutEnvelope(env, meta); err != nil {
		t.Fatal(err)
	}
	env.Payload[0] = 'X' // caller mutates its own copy
	env.Signatures[0].Sig[0] = 99
	got, _ := s.Envelope("acme", 8)
	got.Payload[1] = 'Y' // caller mutates a returned copy
	again, _ := s.Envelope("acme", 8)
	if string(again.Payload) != `{"policy":"x"}` || again.Signatures[0].Sig[0] != 1 {
		t.Fatalf("store state changed through a caller copy: %q", again.Payload)
	}
}

func TestPutEnvelopeErrors(t *testing.T) {
	s, _ := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	if err := s.PutEnvelope(env, meta); err != nil {
		t.Fatal(err)
	}
	other, _ := mkEnv(`{"policy":"other"}`)
	badShape := env
	badShape.Signatures = nil
	badHash := meta
	badHash.Hash = hh('f')
	zeroVer := meta
	zeroVer.Version = 0
	badTenant := meta
	badTenant.Tenant = "Acme!"
	tests := []struct {
		name string
		env  wire.Envelope
		meta EnvelopeMeta
		want error
	}{
		{"same version again", env, meta, ErrConflict},
		{"same version, different content", other, EnvelopeMeta{"acme", 8, hashOf(other.Payload)}, ErrConflict},
		{"bad shape", badShape, meta, wire.ErrInvalid},
		{"hash does not match payload", env, badHash, wire.ErrInvalid},
		{"version zero", env, zeroVer, wire.ErrInvalid},
		{"bad tenant", env, badTenant, wire.ErrInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.PutEnvelope(tc.env, tc.meta); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// the original is untouched by the failed puts
	got, err := s.Envelope("acme", 8)
	if err != nil || !bytes.Equal(got.Payload, env.Payload) {
		t.Fatalf("original changed: %v", err)
	}
}

func TestEnvelopeNotFoundAndTenantIsolation(t *testing.T) {
	s, _ := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	if err := s.PutEnvelope(env, meta); err != nil {
		t.Fatal(err)
	}
	meta2 := meta
	meta2.Tenant = "globex"
	if err := s.PutEnvelope(env, meta2); err != nil {
		t.Fatalf("same version for another tenant must be allowed: %v", err)
	}
	for _, c := range []struct {
		tenant wire.ID
		ver    uint64
	}{{"acme", 9}, {"nobody", 8}, {"../etc", 8}} {
		if _, err := s.Envelope(c.tenant, c.ver); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Envelope(%q,%d) err = %v, want ErrNotFound", c.tenant, c.ver, err)
		}
	}
}

func TestRolloutRoundTrip(t *testing.T) {
	s, dir := open(t)
	if _, ok, err := s.Rollout("acme"); ok || err != nil {
		t.Fatalf("empty: ok=%v err=%v", ok, err)
	}
	r1 := rollout.Rollout{Tenant: "acme", Version: 8, Previous: 7, Phase: wire.PhaseCanary,
		Dwell: 1500 * time.Millisecond, CanaryOK: t0.Add(123456789 * time.Nanosecond)}
	r2 := rollout.Rollout{Tenant: "acme", Version: 9, Previous: 8, Phase: wire.PhaseHalted,
		Reason: wire.ErrCanaryLost, Dwell: time.Minute}
	for _, r := range []rollout.Rollout{r1, r2} { // second replaces first
		if err := s.PutRollout(r); err != nil {
			t.Fatal(err)
		}
	}
	check := func(s Store, want rollout.Rollout) {
		t.Helper()
		got, ok, err := s.Rollout("acme")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		if !got.CanaryOK.Equal(want.CanaryOK) {
			t.Fatalf("CanaryOK %v != %v", got.CanaryOK, want.CanaryOK)
		}
		got.CanaryOK, want.CanaryOK = time.Time{}, time.Time{}
		if got != want {
			t.Fatalf("got %+v want %+v", got, want)
		}
	}
	check(s, r2)
	check(reopen(t, dir), r2)
	if err := s.PutRollout(r1); err != nil {
		t.Fatal(err)
	}
	check(reopen(t, dir), r1)
}

func TestPutRolloutInvalid(t *testing.T) {
	s, _ := open(t)
	for name, r := range map[string]rollout.Rollout{
		"bad tenant": {Tenant: "A/B", Version: 1, Phase: wire.PhaseCanary},
		"bad phase":  {Tenant: "acme", Version: 1, Phase: "weird"},
		"neg dwell":  {Tenant: "acme", Version: 1, Phase: wire.PhaseCanary, Dwell: -1},
	} {
		if err := s.PutRollout(r); !errors.Is(err, wire.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestRecordStatusAndFleet(t *testing.T) {
	s, dir := open(t)
	if l, err := s.Fleet("acme"); err != nil || len(l) != 0 {
		t.Fatalf("empty fleet: %v %v", l, err)
	}
	a := fleet.Last{Group: "canary", Report: report("p-b", 1, 8), SeenAt: t0}
	b := fleet.Last{Group: "prod", Report: report("p-a", 1, 7), SeenAt: t0.Add(time.Second)}
	b.Report.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 8}
	for _, l := range []fleet.Last{a, b} {
		if err := s.RecordStatus(l); err != nil {
			t.Fatal(err)
		}
	}
	other := fleet.Last{Group: "prod", Report: report("p-c", 1, 7), SeenAt: t0}
	other.Report.Tenant = "globex"
	if err := s.RecordStatus(other); err != nil {
		t.Fatal(err)
	}
	check := func(s Store) {
		t.Helper()
		got, err := s.Fleet("acme")
		if err != nil || len(got) != 2 {
			t.Fatalf("fleet: %v %v", got, err)
		}
		if got[0].Report.ProxyID != "p-a" || got[1].Report.ProxyID != "p-b" {
			t.Fatalf("not sorted by proxy ID: %v", got)
		}
		for i, want := range []fleet.Last{b, a} {
			if got[i].Group != want.Group || !got[i].SeenAt.Equal(want.SeenAt) ||
				!reflect.DeepEqual(got[i].Report, want.Report) {
				t.Fatalf("row %d: %+v want %+v", i, got[i], want)
			}
		}
	}
	check(s)
	check(reopen(t, dir))
}

func TestRecordStatusLatestWinsAndIsCopied(t *testing.T) {
	s, _ := open(t)
	l := fleet.Last{Group: "canary", Report: report("p1", 1, 7), SeenAt: t0}
	l.Report.LastError = &wire.ApplyError{Code: wire.ErrExpired}
	if err := s.RecordStatus(l); err != nil {
		t.Fatal(err)
	}
	l.Report.LastError.Code = wire.ErrTampered // mutate caller's pointer
	got, _ := s.Fleet("acme")
	if got[0].Report.LastError.Code != wire.ErrExpired {
		t.Fatal("store shares the caller's LastError pointer")
	}
	got[0].Report.LastError.Code = wire.ErrNotNewer // mutate returned pointer
	again, _ := s.Fleet("acme")
	if again[0].Report.LastError.Code != wire.ErrExpired {
		t.Fatal("store shares the returned LastError pointer")
	}
	l2 := fleet.Last{Group: "canary", Report: report("p1", 2, 8), SeenAt: t0.Add(time.Second)}
	if err := s.RecordStatus(l2); err != nil {
		t.Fatal(err)
	}
	again, _ = s.Fleet("acme")
	if len(again) != 1 || again[0].Report.AppliedVersion != 8 || again[0].Report.LastError != nil {
		t.Fatalf("latest report did not replace the old one: %+v", again)
	}
}

func TestRecordStatusInvalid(t *testing.T) {
	s, _ := open(t)
	good := fleet.Last{Group: "canary", Report: report("p1", 1, 7), SeenAt: t0}
	badReport := good
	badReport.Report.State = "weird"
	noGroup := good
	noGroup.Group = ""
	noSeen := good
	noSeen.SeenAt = time.Time{}
	for name, l := range map[string]fleet.Last{"bad report": badReport, "no group": noGroup, "never seen": noSeen} {
		if err := s.RecordStatus(l); !errors.Is(err, wire.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if l, _ := s.Fleet("acme"); len(l) != 0 {
		t.Fatalf("invalid reports were stored: %v", l)
	}
}

func TestTimeline(t *testing.T) {
	s, dir := open(t)
	rec := func(proxy wire.ID, seq, applied uint64, at time.Duration, logSeq uint64) {
		t.Helper()
		r := report(proxy, seq, applied)
		if applied > 0 {
			r.PolicyHash = hh(byte('0' + applied))
		}
		if logSeq > 0 {
			r.LogSeq, r.LogHead = logSeq, hh(byte('a'+logSeq))
		}
		if err := s.RecordStatus(fleet.Last{Group: "prod", Report: r, SeenAt: t0.Add(at)}); err != nil {
			t.Fatal(err)
		}
	}
	rec("p1", 1, 0, 0, 0)              // deny-all, no policy
	rec("p1", 2, 7, 10*time.Second, 1) // applied 7
	rec("p1", 3, 7, 20*time.Second, 1) // heartbeat
	rec("p1", 4, 7, 25*time.Second, 1) // heartbeat
	rec("p1", 5, 8, 30*time.Second, 2) // applied 8
	rec("p2", 1, 8, 5*time.Second, 1)  // other proxy
	rec("p1", 1, 8, 40*time.Second, 2) // process restart: Seq resets, same version
	rec("p1", 2, 0, 50*time.Second, 2) // dropped to deny-all (tampered?) then...
	rec("p1", 3, 8, 60*time.Second, 3) // ...back to 8: a new entry, not a merge
	ms := func(d time.Duration) int64 { return t0.Add(d).UnixMilli() }
	want := []wire.TimelineEntry{
		{ProxyID: "p1", Version: 0, FirstSeenUnixMs: ms(0), LastSeenUnixMs: ms(0)},
		{ProxyID: "p1", Version: 7, PolicyHash: hh('7'), FirstSeenUnixMs: ms(10 * time.Second), LastSeenUnixMs: ms(25 * time.Second)},
		{ProxyID: "p1", Version: 8, PolicyHash: hh('8'), FirstSeenUnixMs: ms(30 * time.Second), LastSeenUnixMs: ms(40 * time.Second)},
		{ProxyID: "p1", Version: 0, FirstSeenUnixMs: ms(50 * time.Second), LastSeenUnixMs: ms(50 * time.Second)},
		{ProxyID: "p1", Version: 8, PolicyHash: hh('8'), FirstSeenUnixMs: ms(60 * time.Second), LastSeenUnixMs: ms(60 * time.Second)},
		{ProxyID: "p2", Version: 8, PolicyHash: hh('8'), FirstSeenUnixMs: ms(5 * time.Second), LastSeenUnixMs: ms(5 * time.Second)},
	}
	for name, st := range map[string]Store{"live": s, "reopened": reopen(t, dir)} {
		got, err := st.Timeline("acme")
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("%s timeline:\n got %+v\nwant %+v\nerr %v", name, got, want, err)
		}
	}
	if got, _ := s.Timeline("nobody"); len(got) != 0 {
		t.Fatalf("other tenant sees entries: %v", got)
	}
}

// M-D35: the timeline keeps each entry's apply-log anchor.
func TestTimelineKeepsLogAnchor(t *testing.T) {
	s, dir := open(t)
	for i, seq := range []uint64{1, 2, 3} {
		r := report("p1", seq, 7)
		r.LogSeq, r.LogHead = seq, hh(byte('a'+seq))
		if err := s.RecordStatus(fleet.Last{Group: "g", Report: r, SeenAt: t0.Add(time.Duration(i) * time.Second)}); err != nil {
			t.Fatal(err)
		}
	}
	r := report("p1", 4, 8)
	r.LogSeq, r.LogHead = 1, hh('f') // a regression must be recorded, not hidden
	if err := s.RecordStatus(fleet.Last{Group: "g", Report: r, SeenAt: t0.Add(5 * time.Second)}); err != nil {
		t.Fatal(err)
	}
	for _, st := range []Store{s, reopen(t, dir)} {
		got := st.(*files).anchors("acme")
		want := []anchor{{"p1", 7, 3, hh('d')}, {"p1", 8, 1, hh('f')}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("anchors = %+v want %+v", got, want)
		}
		last, _ := st.Fleet("acme")
		if last[0].Report.LogSeq != 1 || last[0].Report.LogHead != hh('f') {
			t.Fatalf("fleet lost the anchor: %+v", last[0].Report)
		}
	}
}

// Heartbeats that change nothing but Seq and SeenAt are flushed at most every
// heartbeatFlush; anything else is flushed at once.
func TestHeartbeatCoalescing(t *testing.T) {
	s, dir := open(t)
	rec := func(seq uint64, applied uint64, at time.Duration) {
		t.Helper()
		if err := s.RecordStatus(fleet.Last{Group: "g", Report: report("p1", seq, applied), SeenAt: t0.Add(at)}); err != nil {
			t.Fatal(err)
		}
	}
	diskSeq := func() uint64 {
		l, err := reopen(t, dir).Fleet("acme")
		if err != nil || len(l) != 1 {
			t.Fatalf("%v %v", l, err)
		}
		return l[0].Report.Seq
	}
	rec(1, 7, 0)
	if diskSeq() != 1 {
		t.Fatal("first report must be written at once")
	}
	rec(2, 7, 10*time.Second)
	if diskSeq() != 1 {
		t.Fatal("heartbeat inside the flush window should not touch the disk")
	}
	live, _ := s.Fleet("acme")
	if live[0].Report.Seq != 2 {
		t.Fatal("memory must have the latest heartbeat")
	}
	rec(3, 7, heartbeatFlush)
	if diskSeq() != 3 {
		t.Fatal("heartbeat after the flush window must be written")
	}
	rec(4, 8, heartbeatFlush+time.Second)
	if diskSeq() != 4 {
		t.Fatal("a version change must be written at once")
	}
	rec(5, 8, 0) // clock stepped back: write rather than trust the window
	if diskSeq() != 5 {
		t.Fatal("a SeenAt before the last flush must be written")
	}
}

func TestLeftoverTempFilesAreIgnored(t *testing.T) {
	s, dir := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	if err := s.PutEnvelope(env, meta); err != nil {
		t.Fatal(err)
	}
	if err := s.PutRollout(rollout.Rollout{Tenant: "acme", Version: 8, Phase: wire.PhaseCanary}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStatus(fleet.Last{Group: "g", Report: report("p1", 1, 7), SeenAt: t0}); err != nil {
		t.Fatal(err)
	}
	// a crash mid-write leaves a half-written temp next to each kind of file
	for _, sub := range []string{"envelopes/acme", "rollouts", "fleet/acme"} {
		junk := filepath.Join(dir, sub, ".tmp-123456")
		if err := os.WriteFile(junk, []byte(`{"truncated":`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s2 := reopen(t, dir)
	if _, err := s2.Envelope("acme", 8); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s2.Rollout("acme"); !ok || err != nil {
		t.Fatalf("rollout: %v %v", ok, err)
	}
	if l, err := s2.Fleet("acme"); err != nil || len(l) != 1 {
		t.Fatalf("fleet: %v %v", l, err)
	}
	if err := s2.PutEnvelope(mustEnv(`{"policy":"y"}`, 9)); err != nil {
		t.Fatal(err)
	}
}

func mustEnv(payload string, v uint64) (wire.Envelope, EnvelopeMeta) {
	env, m := mkEnv(payload)
	m.Version = v
	return env, m
}

func TestCorruptFilesFailOpenWithClearError(t *testing.T) {
	setup := func(t *testing.T) string {
		s, dir := open(t)
		env, meta := mkEnv(`{"policy":"x"}`)
		if err := s.PutEnvelope(env, meta); err != nil {
			t.Fatal(err)
		}
		if err := s.PutRollout(rollout.Rollout{Tenant: "acme", Version: 8, Phase: wire.PhaseCanary}); err != nil {
			t.Fatal(err)
		}
		if err := s.RecordStatus(fleet.Last{Group: "g", Report: report("p1", 1, 7), SeenAt: t0}); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	env := "envelopes/acme/00000000000000000008.json"
	roll := "rollouts/acme.json"
	flt := "fleet/acme/p1.json"
	read := func(t *testing.T, p string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	tests := []struct {
		name   string
		file   string
		mutate func(old string) string
	}{
		{"envelope truncated", env, func(s string) string { return s[:len(s)/2] }},
		{"envelope empty", env, func(string) string { return "" }},
		{"envelope unknown field", env, func(s string) string { return strings.Replace(s, `{`, `{"extra":1,`, 1) }},
		{"envelope trailing data", env, func(s string) string { return s + `{}` }},
		{"envelope payload changed under its hash", env, func(s string) string {
			return strings.Replace(s, "eyJwb2xpY3kiOiJ4In0=", "eyJwb2xpY3kiOiJ5In0=", 1)
		}},
		{"rollout truncated", roll, func(s string) string { return s[:len(s)/2] }},
		{"rollout unknown field", roll, func(s string) string { return strings.Replace(s, `{`, `{"extra":1,`, 1) }},
		{"rollout wrong tenant for its name", roll, func(s string) string { return strings.Replace(s, `"acme"`, `"globex"`, 1) }},
		{"rollout bad phase", roll, func(s string) string { return strings.Replace(s, `"canary"`, `"weird"`, 1) }},
		{"fleet truncated", flt, func(s string) string { return s[:len(s)/2] }},
		{"fleet unknown field", flt, func(s string) string { return strings.Replace(s, `{`, `{"extra":1,`, 1) }},
		{"fleet wrong proxy for its name", flt, func(s string) string { return strings.Replace(s, `"p1"`, `"p2"`, 1) }},
		{"fleet bad state", flt, func(s string) string { return strings.Replace(s, `"enforcing"`, `"weird"`, 1) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := setup(t)
			p := filepath.Join(dir, tc.file)
			old := read(t, p)
			changed := tc.mutate(old)
			if changed == old {
				t.Fatal("mutation did not change the file; fix the test")
			}
			if err := os.WriteFile(p, []byte(changed), 0o600); err != nil {
				t.Fatal(err)
			}
			s, err := OpenFiles(dir)
			if err == nil {
				t.Fatalf("OpenFiles accepted a corrupt file (store %v)", s)
			}
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("err = %v, want ErrCorrupt", err)
			}
			if !strings.Contains(err.Error(), filepath.Base(tc.file)) {
				t.Fatalf("error should name the file: %v", err)
			}
		})
	}
}

func TestUnexpectedFileNameIsCorrupt(t *testing.T) {
	_, dir := open(t)
	if err := os.MkdirAll(filepath.Join(dir, "envelopes", "acme"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "envelopes", "acme", "notes.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFiles(dir); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func TestOpenFilesCreatesPrivateDir(t *testing.T) {
	_, dir := open(t)
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFiles(f); err == nil {
		t.Fatal("opening a file as a directory must fail")
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.json")
	if err := writeFileAtomic(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(p, []byte("two")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "two" {
		t.Fatalf("content %q", b)
	}
	// rename into a directory fails: error returned, no temp left, old data kept
	target := filepath.Join(dir, "d")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomic(target, []byte("x")); err == nil {
		t.Fatal("expected an error")
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			t.Fatalf("temp file left behind: %s", e.Name())
		}
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestFailedWriteLeavesMemoryUnchanged(t *testing.T) {
	s, dir := open(t)
	env, meta := mkEnv(`{"policy":"x"}`)
	// block the tenant's envelope directory with a plain file
	if err := os.MkdirAll(filepath.Join(dir, "envelopes"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "envelopes", "acme"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEnvelope(env, meta); err == nil {
		t.Fatal("expected a write error")
	}
	if _, err := s.Envelope("acme", 8); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed put became visible: %v", err)
	}
}

func TestConcurrentUse(t *testing.T) {
	s, dir := open(t)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 25; i++ {
				v := uint64(g*100 + i + 1)
				env, m := mustEnv(fmt.Sprintf(`{"v":%d}`, v), v)
				if err := s.PutEnvelope(env, m); err != nil {
					t.Error(err)
				}
				_, _ = s.Envelope("acme", v)
				proxy := wire.ID(fmt.Sprintf("p-%d", g))
				if err := s.RecordStatus(fleet.Last{Group: "g", Report: report(proxy, uint64(i+1), uint64(i%3+1)), SeenAt: t0.Add(time.Duration(i) * time.Second)}); err != nil {
					t.Error(err)
				}
				_, _ = s.Fleet("acme")
				_, _ = s.Timeline("acme")
				_ = s.PutRollout(rollout.Rollout{Tenant: "acme", Version: v, Phase: wire.PhaseCanary})
				_, _, _ = s.Rollout("acme")
			}
		}(g)
	}
	wg.Wait()
	// racing puts of one version: exactly one wins
	var wins, conflicts int
	var mu sync.Mutex
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env, m := mustEnv(`{"same":1}`, 9999)
			err := s.PutEnvelope(env, m)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				wins++
			case errors.Is(err, ErrConflict):
				conflicts++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if wins != 1 || conflicts != 7 {
		t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
	}
	s2 := reopen(t, dir)
	if l, _ := s2.Fleet("acme"); len(l) != 8 {
		t.Fatalf("fleet after reopen: %d", len(l))
	}
}

func FuzzOpenCorruptFiles(f *testing.F) {
	f.Add([]byte(`{"tenant":"acme"}`))
	f.Add([]byte(``))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte("\x00\xff"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := filepath.Join(t.TempDir(), "state")
		for _, p := range []string{"envelopes/acme/00000000000000000008.json", "rollouts/acme.json", "fleet/acme/p1.json"} {
			full := filepath.Join(dir, p)
			if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(full, data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		// must never panic; garbage must be an error
		if _, err := OpenFiles(dir); err == nil {
			t.Fatal("garbage accepted")
		}
	})
}
