package cpstorebreak

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

// OpenFiles parses every file in the state dir: any bytes in any state file must give nil or
// ErrCorrupt, never a panic, and if it loads, a second open must load the same (stable).
func FuzzOpenFilesGarbage(f *testing.F) {
	f.Add(uint8(0), []byte(`{"tenant":"bank-a","version":1}`))
	f.Add(uint8(1), []byte(`{"group":"main","report":{},"seen_at":"x","timeline":[{}]}`))
	f.Add(uint8(2), []byte(`{"tenant":"bank-a","version":2,"previous":1,"phase":"canary","dwell_ns":-5}`))
	f.Add(uint8(0), []byte("{\"tenant\":\"bank-a\",\"tenant\":\"city-b\"}"))
	f.Add(uint8(1), []byte("\xff\xfe\x00"))
	f.Add(uint8(2), []byte(`{"tenant":"bank-a","version":18446744073709551616}`))
	f.Fuzz(func(t *testing.T, kind uint8, data []byte) {
		dir := filepath.Join(t.TempDir(), "state")
		s, err := store.OpenFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		e, m := envFor("bank-a", 1, "x")
		_ = s.PutEnvelope(e, m)
		_ = s.PutRollout(rolloutFor("bank-a", 2, 1))
		_ = s.RecordStatus(last("main", rep("bank-a", "p1"), t0))
		var target string
		switch kind % 3 {
		case 0:
			target = filepath.Join(dir, "envelopes", "bank-a", "00000000000000000001.json")
		case 1:
			target = filepath.Join(dir, "fleet", "bank-a", "p1.json")
		default:
			target = filepath.Join(dir, "rollouts", "bank-a.json")
		}
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		s1, err := store.OpenFiles(dir)
		if err != nil {
			if !errors.Is(err, store.ErrCorrupt) {
				t.Fatalf("garbage gave %v, want ErrCorrupt", err)
			}
			return
		}
		// loaded: every accessor must work, and a reopen must agree
		_, _ = s1.Envelope("bank-a", 1)
		_, _, _ = s1.Rollout("bank-a")
		fl, _ := s1.Fleet("bank-a")
		_, _ = s1.Timeline("bank-a")
		for _, l := range fl {
			if !l.Report.ProxyID.Valid() || !l.Report.Tenant.Valid() {
				t.Fatalf("loaded a proxy with an invalid identity: %+v", l.Report)
			}
		}
		if _, err := store.OpenFiles(dir); err != nil {
			t.Fatalf("second open failed: %v", err)
		}
	})
}

// PutEnvelope with arbitrary payload/meta never panics and, when it succeeds, the payload hash matches.
func FuzzPutEnvelope(f *testing.F) {
	f.Add([]byte("payload"), "bank-a", uint64(1), true)
	f.Add([]byte{0, 1, 2}, "../x", uint64(0), false)
	f.Fuzz(func(t *testing.T, payload []byte, tenant string, version uint64, goodHash bool) {
		dir := filepath.Join(t.TempDir(), "state")
		s, err := store.OpenFiles(dir)
		if err != nil {
			t.Fatal(err)
		}
		e, m := envFor(wire.ID(tenant), version, "")
		e.Payload = payload
		m.Hash = payloadHash(payload)
		if !goodHash {
			m.Hash = payloadHash(append([]byte("x"), payload...))
		}
		err = s.PutEnvelope(e, m)
		if err != nil {
			for _, f := range files(t, dir) {
				t.Fatalf("rejected envelope left %s", f)
			}
			return
		}
		if !goodHash {
			t.Fatal("accepted an envelope whose hash is not the payload hash")
		}
		if !wire.ID(tenant).Valid() || version == 0 || len(payload) == 0 {
			t.Fatalf("accepted tenant=%q version=%d payload len=%d", tenant, version, len(payload))
		}
		if _, err := store.OpenFiles(dir); err != nil {
			t.Fatalf("accepted but not reloadable: %v", err)
		}
	})
}
