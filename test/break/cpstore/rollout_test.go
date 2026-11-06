package cpstorebreak

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

func rolloutFor(tenant wire.ID, version, previous uint64) rollout.Rollout {
	return rollout.Rollout{
		Tenant: tenant, Version: version, Previous: previous,
		Phase: wire.PhaseCanary, Dwell: 5 * time.Minute,
	}
}

func sameRollout(a, b rollout.Rollout) bool {
	return a.Tenant == b.Tenant && a.Version == b.Version && a.Previous == b.Previous && a.Phase == b.Phase &&
		a.Reason == b.Reason && a.Dwell == b.Dwell && a.CanaryOK.Equal(b.CanaryOK) && a.Promoted == b.Promoted
}

func TestRolloutNotFoundIsNotAnError(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	r, ok, err := s.Rollout("bank-a")
	if ok || err != nil {
		t.Fatalf("Rollout of an unknown tenant = %+v, %v, %v; want zero, false, nil", r, ok, err)
	}
}

// M-D44 / C-D6: a halted-after-promoting rollout must survive the store unchanged, so that
// DesiredFor (which the fleet page and the poll path use) gives the same answer afterwards.
func TestRolloutRoundTripEveryPhaseAndDesiredForConsistency(t *testing.T) {
	ns := time.Date(2026, 11, 5, 12, 0, 0, 123456789, time.FixedZone("JST", 9*3600))
	cases := []rollout.Rollout{
		rolloutFor("bank-a", 8, 7),
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhasePromoting, Dwell: time.Minute, CanaryOK: ns},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseComplete, Dwell: time.Minute, CanaryOK: ns},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseHalted, Reason: wire.ErrCanaryLost, Dwell: time.Minute},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseHalted, Reason: wire.ErrThreshold, Dwell: time.Minute, CanaryOK: ns, Promoted: true},
		{Tenant: "bank-a", Version: math.MaxUint64, Previous: math.MaxUint64 - 1, Phase: wire.PhasePromoting, Dwell: rollout.MaxDwell, Promoted: false},
		{Tenant: "bank-a", Version: 2, Previous: 1, Phase: wire.PhaseHalted, Reason: wire.ErrBadRequest, Dwell: 0},
	}
	for i, want := range cases {
		t.Run(fmt.Sprint(i, "-", want.Phase, "-promoted=", want.Promoted), func(t *testing.T) {
			_, dir := sandbox(t)
			s := open(t, dir)
			if err := s.PutRollout(want); err != nil {
				t.Fatalf("PutRollout: %v", err)
			}
			for round, st := range []store.Store{s, open(t, dir)} {
				got, ok, err := st.Rollout("bank-a")
				if err != nil || !ok {
					t.Fatalf("round %d: %v ok=%v", round, err, ok)
				}
				if !sameRollout(got, want) {
					t.Fatalf("round %d: got %+v, want %+v", round, got, want)
				}
				for _, g := range []wire.ID{"main", rollout.CanaryGroup, "edge"} {
					if a, b := rollout.DesiredFor(got, g), rollout.DesiredFor(want, g); a != b {
						t.Fatalf("round %d group %q: DesiredFor after store %d != before %d", round, g, a, b)
					}
				}
			}
		})
	}
}

// C-D6: "Old files without the field decode as false" and the flag really is stored.
func TestRolloutPromotedFlagIsPersistedAndAbsentMeansFalse(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	r := rollout.Rollout{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseHalted, Reason: wire.ErrThreshold, Dwell: time.Minute, Promoted: true}
	if err := s.PutRollout(r); err != nil {
		t.Fatal(err)
	}
	path := findFile(t, dir, "rollouts", "bank-a")
	var had bool
	editJSON(t, path, func(m map[string]any) {
		_, had = m["promoted"]
		delete(m, "promoted")
	})
	if !had {
		t.Fatal("Promoted=true is not in the rollout file: a restart would turn a halted-after-promoting rollout into one that lowers desired versions (M-D44)")
	}
	got, _, err := open(t, dir).Rollout("bank-a")
	if err != nil {
		t.Fatalf("file without the promoted key must load: %v", err)
	}
	if got.Promoted {
		t.Fatal("absent promoted key decoded as true")
	}
	// Writing Promoted=false must not write promoted:true.
	r.Promoted = false
	if err := s.PutRollout(r); err != nil {
		t.Fatal(err)
	}
	editJSON(t, path, func(m map[string]any) {
		if v, ok := m["promoted"]; ok && v != false {
			t.Errorf("Promoted=false stored as %v", v)
		}
	})
}

func TestPutRolloutReplacesAndIsolatesTenants(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	a1 := rolloutFor("bank-a", 8, 7)
	b1 := rolloutFor("city-b", 3, 2)
	a2 := a1
	a2.Phase = wire.PhaseComplete
	for _, r := range []rollout.Rollout{a1, b1, a2} {
		if err := s.PutRollout(r); err != nil {
			t.Fatal(err)
		}
	}
	for _, st := range []store.Store{s, open(t, dir)} {
		ga, _, _ := st.Rollout("bank-a")
		gb, _, _ := st.Rollout("city-b")
		if !sameRollout(ga, a2) || !sameRollout(gb, b1) {
			t.Fatalf("got %+v / %+v", ga, gb)
		}
	}
}

func TestPutRolloutConcurrentLastWriteIsOneOfThem(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	var wg sync.WaitGroup
	for i := 1; i <= 40; i++ {
		wg.Add(1)
		go func(v uint64) {
			defer wg.Done()
			if err := s.PutRollout(rolloutFor("bank-a", v+1, v)); err != nil {
				t.Errorf("put: %v", err)
			}
			_, _, _ = s.Rollout("bank-a")
		}(uint64(i))
	}
	wg.Wait()
	mem, _, _ := s.Rollout("bank-a")
	disk, _, err := open(t, dir).Rollout("bank-a")
	if err != nil {
		t.Fatal(err)
	}
	if !sameRollout(mem, disk) {
		t.Fatalf("memory %+v and disk %+v disagree after concurrent writes", mem, disk)
	}
	if mem.Version != mem.Previous+1 {
		t.Fatalf("torn rollout: %+v", mem)
	}
}

func TestPutRolloutRejectsBadTenant(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	for _, tenant := range []wire.ID{"", "Bank", "a/b", "..", "a b"} {
		if err := s.PutRollout(rolloutFor(tenant, 2, 1)); err == nil {
			t.Fatalf("tenant %q accepted", tenant)
		}
	}
	if len(files(t, dir)) != 0 {
		t.Fatalf("files written for rejected rollouts: %v", files(t, dir))
	}
}

// Whatever the store accepts it must be able to load again (a CP that cannot restart is an outage).
func TestRolloutAcceptedImpliesReloadable(t *testing.T) {
	weird := []rollout.Rollout{
		{Tenant: "bank-a"},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: "bogus"},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseHalted, Reason: "not a code"},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: -time.Hour},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: math.MaxInt64},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, CanaryOK: time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)},
		{Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, CanaryOK: time.Time{}.Add(-time.Hour)},
		{Tenant: "bank-a", Version: 7, Previous: 8, Phase: wire.PhaseCanary},
	}
	for i, r := range weird {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			_, dir := sandbox(t)
			s := open(t, dir)
			if err := s.PutRollout(r); err != nil {
				return // rejecting is fine
			}
			s2, err := store.OpenFiles(dir)
			if err != nil {
				t.Fatalf("store accepted %+v but then refuses to start: %v", r, err)
			}
			got, ok, err := s2.Rollout("bank-a")
			if err != nil || !ok || !sameRollout(got, r) {
				t.Fatalf("accepted %+v, reloaded %+v ok=%v err=%v", r, got, ok, err)
			}
		})
	}
}

func TestRolloutFileTamperingFailsOpen(t *testing.T) {
	setup := func(t *testing.T) (string, string) {
		_, dir := sandbox(t)
		s := open(t, dir)
		if err := s.PutRollout(rolloutFor("bank-a", 8, 7)); err != nil {
			t.Fatal(err)
		}
		return dir, findFile(t, dir, "rollouts", "bank-a")
	}
	t.Run("renamed-to-other-tenant", func(t *testing.T) {
		dir, path := setup(t)
		if err := os.Rename(path, filepath.Join(filepath.Dir(path), "city-b.json")); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("unknown-field", func(t *testing.T) {
		dir, path := setup(t)
		editJSON(t, path, func(m map[string]any) { m["extra"] = 1 })
		expectCorrupt(t, dir)
	})
	t.Run("tenant-changed-inside", func(t *testing.T) {
		dir, path := setup(t)
		editJSON(t, path, func(m map[string]any) {
			for k := range m {
				if v, ok := m[k].(string); ok && v == "bank-a" {
					m[k] = "city-b"
				}
			}
		})
		expectCorrupt(t, dir)
	})
	t.Run("tenant-traversal-inside", func(t *testing.T) {
		dir, path := setup(t)
		editJSON(t, path, func(m map[string]any) {
			for k := range m {
				if v, ok := m[k].(string); ok && v == "bank-a" {
					m[k] = "../x"
				}
			}
		})
		expectCorrupt(t, dir)
	})
}

func expectCorrupt(t *testing.T, dir string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := store.OpenFiles(dir); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, store.ErrCorrupt) {
			t.Fatalf("OpenFiles = %v, want ErrCorrupt", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("OpenFiles hung on a damaged state dir")
	}
}

var _ = reflect.DeepEqual
