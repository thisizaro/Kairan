// Package fleetbreak holds black-box attack tests for the control-plane fleet
// package (task C-01). Sources: PRD G2/Q1-Q3, ARCHITECTURE section 5 (health
// 30s/2m, drift) and the fleet LLD, wire (timing constants, ProxyView), and the
// go doc of the fleet package.
package fleetbreak

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func TestDefaultsMatchArchitecture(t *testing.T) {
	// ARCH section 5: stale after 30s, lost after 2m.
	th := fleet.DefaultThresholds()
	if th.Stale != 30*time.Second || th.Lost != 2*time.Minute {
		t.Fatalf("DefaultThresholds = %+v, want {30s 2m}", th)
	}
	if fleet.DefaultStale != 30*time.Second || fleet.DefaultLost != 2*time.Minute {
		t.Fatalf("Default constants wrong: %v %v", fleet.DefaultStale, fleet.DefaultLost)
	}
	// PRD M2: stale <= 41s, lost <= 131s after a kill. The status interval is 10s,
	// so a proxy killed right after a report is stale at 30s of silence.
	if wire.StatusInterval != 10*time.Second {
		t.Fatalf("wire.StatusInterval changed: %v", wire.StatusInterval)
	}
}

func TestHealthBoundaries(t *testing.T) {
	th := fleet.DefaultThresholds()
	seen := t0
	cases := []struct {
		name  string
		delta time.Duration // now - seenAt
		want  wire.Health
	}{
		{"just-seen", 0, wire.HealthHealthy},
		{"1ns", 1, wire.HealthHealthy},
		{"29.999999999s", 30*time.Second - 1, wire.HealthHealthy},
		{"exactly-30s (inclusive stale)", 30 * time.Second, wire.HealthStale},
		{"30s+1ns", 30*time.Second + 1, wire.HealthStale},
		{"1m", time.Minute, wire.HealthStale},
		{"1m59.999999999s", 2*time.Minute - 1, wire.HealthStale},
		{"exactly-2m (inclusive lost)", 2 * time.Minute, wire.HealthLost},
		{"2m+1ns", 2*time.Minute + 1, wire.HealthLost},
		{"1h", time.Hour, wire.HealthLost},
		{"100y", 100 * 365 * 24 * time.Hour, wire.HealthLost},
		{"future-1ns (now before seen)", -1, wire.HealthHealthy},
		{"future-1h (clock stepped back)", -time.Hour, wire.HealthHealthy},
		{"future-10y", -10 * 365 * 24 * time.Hour, wire.HealthHealthy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := fleet.Health(seen, seen.Add(c.delta), th)
			if got != c.want {
				t.Fatalf("Health(delta=%v) = %q, want %q", c.delta, got, c.want)
			}
		})
	}
}

func TestHealthNeverSeenAndExtremes(t *testing.T) {
	th := fleet.DefaultThresholds()
	loc := time.FixedZone("JST", 9*3600)
	cases := []struct {
		name      string
		seen, now time.Time
		want      wire.Health
	}{
		{"zero-seen-is-lost", time.Time{}, t0, wire.HealthLost},
		{"zero-seen-zero-now", time.Time{}, time.Time{}, wire.HealthLost},
		{"zero-seen-other-zone", time.Time{}.In(loc), t0, wire.HealthLost},
		{"unix-epoch-is-a-real-time-not-never", time.Unix(0, 0), time.Unix(0, 0), wire.HealthHealthy},
		{"extreme-silence-saturates-to-lost", time.Unix(0, 0), time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), wire.HealthLost},
		{"extreme-future-seen", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(1971, 1, 1, 0, 0, 0, 0, time.UTC), wire.HealthHealthy},
		{"zone-independent", t0.In(loc), t0.Add(45 * time.Second).In(time.UTC), wire.HealthStale},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			if got := fleet.Health(c.seen, c.now, th); got != c.want {
				t.Fatalf("Health = %q, want %q", got, c.want)
			}
		})
	}
}

func TestHealthMonotoneInSilenceAndConfigurable(t *testing.T) {
	rank := map[wire.Health]int{wire.HealthHealthy: 0, wire.HealthStale: 1, wire.HealthLost: 2}
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 2000; i++ {
		st := time.Duration(1 + r.Int63n(int64(time.Hour)))
		lo := st + time.Duration(r.Int63n(int64(time.Hour)))
		th := fleet.Thresholds{Stale: st, Lost: lo}
		prev := -1
		for d := time.Duration(0); d < 3*time.Hour; d += time.Duration(1 + r.Int63n(int64(5*time.Minute))) {
			h := fleet.Health(t0, t0.Add(d), th)
			rk, ok := rank[h]
			if !ok {
				t.Fatalf("Health returned unknown value %q", h)
			}
			if rk < prev {
				t.Fatalf("health improved with more silence: th=%+v d=%v got %q", th, d, h)
			}
			prev = rk
			// Both bounds inclusive, documented.
			if d >= lo && h != wire.HealthLost {
				t.Fatalf("silence %v >= Lost %v but %q (th=%+v)", d, lo, h, th)
			}
			if d < st && h != wire.HealthHealthy {
				t.Fatalf("silence %v < Stale %v but %q (th=%+v)", d, st, h, th)
			}
		}
	}
	// A 5s/10s custom config really differs from the defaults.
	short := fleet.Thresholds{Stale: 5 * time.Second, Lost: 10 * time.Second}
	if fleet.Health(t0, t0.Add(5*time.Second), short) != wire.HealthStale || fleet.Health(t0, t0.Add(10*time.Second), short) != wire.HealthLost {
		t.Fatal("custom thresholds not honored")
	}
}

// --- Classify -----------------------------------------------------------

func TestClassify(t *testing.T) {
	h1 := wire.Hash("11111111111111111111111111111111111111111111111111111111111111aa")
	h2 := wire.Hash("22222222222222222222222222222222222222222222222222222222222222bb")
	max := uint64(math.MaxUint64)
	cases := []struct {
		name    string
		want    fleet.Desired
		applied uint64
		ahash   wire.Hash
		kind    fleet.DriftKind
		behind  uint64
	}{
		{"equal", fleet.Desired{Version: 5, Hash: h1}, 5, h1, fleet.DriftNone, 0},
		{"equal-no-desired-hash", fleet.Desired{Version: 5}, 5, h2, fleet.DriftNone, 0},
		{"behind-by-3", fleet.Desired{Version: 8, Hash: h1}, 5, h2, fleet.DriftBehind, 3},
		{"behind-no-policy-yet", fleet.Desired{Version: 4}, 0, "", fleet.DriftBehind, 4},
		{"ahead", fleet.Desired{Version: 5}, 9, h1, fleet.DriftAhead, 0},
		{"ahead-of-nothing", fleet.Desired{Version: 0}, 3, h1, fleet.DriftAhead, 0},
		{"nothing-desired-nothing-applied", fleet.Desired{}, 0, "", fleet.DriftNone, 0},
		{"hash-mismatch-same-version", fleet.Desired{Version: 5, Hash: h1}, 5, h2, fleet.DriftHashMismatch, 0},
		{"behind-with-different-hash-is-just-behind", fleet.Desired{Version: 6, Hash: h1}, 5, h2, fleet.DriftBehind, 1},
		{"max-desired-zero-applied", fleet.Desired{Version: max}, 0, "", fleet.DriftBehind, max},
		{"zero-desired-max-applied", fleet.Desired{Version: 0}, max, h1, fleet.DriftAhead, 0},
		{"max-max", fleet.Desired{Version: max, Hash: h1}, max, h1, fleet.DriftNone, 0},
		{"max-vs-max-1", fleet.Desired{Version: max}, max - 1, "", fleet.DriftBehind, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k, n := fleet.Classify(c.want, c.applied, c.ahash)
			if k != c.kind || n != c.behind {
				t.Fatalf("Classify(%+v, %d, %q) = %q,%d want %q,%d", c.want, c.applied, c.ahash, k, n, c.kind, c.behind)
			}
		})
	}
}

// --- View ---------------------------------------------------------------

func rep(tenant, id string, applied uint64, st wire.ProxyState) wire.StatusReport {
	r := wire.StatusReport{Tenant: wire.ID(tenant), ProxyID: wire.ID(id), State: st, AppliedVersion: applied}
	if applied > 0 {
		r.PolicyHash = wire.Hash(fmt.Sprintf("%064x", applied))
	}
	return r
}

func last(tenant, group, id string, applied uint64, seen time.Time) fleet.Last {
	return fleet.Last{Group: wire.ID(group), Report: rep(tenant, id, applied, wire.StateEnforcing), SeenAt: seen}
}

func TestViewBasics(t *testing.T) {
	th := fleet.DefaultThresholds()
	l := []fleet.Last{
		last("bank-a", "canary", "p1", 3, t0),
		last("bank-a", "main", "p2", 1, t0.Add(-45*time.Second)),
		last("bank-a", "main", "p3", 3, t0.Add(-3*time.Minute)),
	}
	l[1].Report.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 3}
	l[1].Report.State = wire.StateTampered
	v := fleet.View("bank-a", map[wire.ID]uint64{"canary": 3, "main": 3}, l, t0, th)
	if v.Tenant != "bank-a" || len(v.Proxies) != 3 {
		t.Fatalf("bad view: %+v", v)
	}
	by := map[wire.ID]wire.ProxyView{}
	for _, p := range v.Proxies {
		by[p.ProxyID] = p
	}
	p1, p2, p3 := by["p1"], by["p2"], by["p3"]
	if p1.Health != wire.HealthHealthy || p1.Drift != 0 || p1.DesiredVersion != 3 || p1.AppliedVersion != 3 || p1.Group != "canary" {
		t.Fatalf("p1 wrong: %+v", p1)
	}
	if p2.Health != wire.HealthStale || p2.Drift != 2 || p2.DesiredVersion != 3 || p2.State != wire.StateTampered {
		t.Fatalf("p2 wrong: %+v", p2)
	}
	if p2.LastError == nil || p2.LastError.Code != wire.ErrThreshold || p2.LastError.Version != 3 {
		t.Fatalf("p2 last error not passed through: %+v", p2.LastError)
	}
	if p2.PolicyHash != rep("", "", 1, "").PolicyHash {
		t.Fatalf("p2 hash not passed through: %q", p2.PolicyHash)
	}
	if p3.Health != wire.HealthLost || p3.Drift != 0 {
		t.Fatalf("p3 wrong: %+v", p3)
	}
	if p1.LastSeenUnixMs != t0.UnixMilli() || p2.LastSeenUnixMs != t0.Add(-45*time.Second).UnixMilli() {
		t.Fatalf("LastSeenUnixMs wrong: %d %d", p1.LastSeenUnixMs, p2.LastSeenUnixMs)
	}
	// Order: drift desc (p2:2), then lost(p3) then healthy(p1).
	if v.Proxies[0].ProxyID != "p2" || v.Proxies[1].ProxyID != "p3" || v.Proxies[2].ProxyID != "p1" {
		t.Fatalf("order wrong: %v %v %v", v.Proxies[0].ProxyID, v.Proxies[1].ProxyID, v.Proxies[2].ProxyID)
	}
}

func TestViewNeverSeenReportsNoTimestamp(t *testing.T) {
	// fleet.Last: "SeenAt zero means never seen". A never-seen proxy must not
	// surface the year-1 Unix epoch value (-62135596800000) as a last-seen time.
	l := []fleet.Last{{Group: "main", Report: rep("bank-a", "ghost", 0, wire.StateBooting)}}
	v := fleet.View("bank-a", map[wire.ID]uint64{"main": 2}, l, t0, fleet.DefaultThresholds())
	if len(v.Proxies) != 1 {
		t.Fatalf("want 1 row, got %d", len(v.Proxies))
	}
	p := v.Proxies[0]
	if p.Health != wire.HealthLost {
		t.Fatalf("never seen proxy health = %q, want lost", p.Health)
	}
	if p.LastSeenUnixMs != 0 {
		t.Fatalf("never-seen proxy has LastSeenUnixMs=%d, want 0", p.LastSeenUnixMs)
	}
	if p.Drift != 2 {
		t.Fatalf("drift = %d, want 2", p.Drift)
	}
}

func TestViewCrossTenantReportsSkipped(t *testing.T) {
	th := fleet.DefaultThresholds()
	l := []fleet.Last{
		last("bank-a", "main", "p1", 3, t0),
		last("city-b", "main", "p2", 9, t0),                                                   // other tenant
		{Group: "main", Report: rep("", "p3", 3, wire.StateEnforcing), SeenAt: t0},            // empty tenant
		{Group: "main", Report: rep("BANK-A", "p4", 3, wire.StateEnforcing), SeenAt: t0},      // case variant
		{Group: "main", Report: rep("bank-a ", "p5", 3, wire.StateEnforcing), SeenAt: t0},     // padded
		{Group: "main", Report: rep("bank-a-evil", "p6", 3, wire.StateEnforcing), SeenAt: t0}, // prefix
		{Group: "main", Report: rep("bank-", "p7", 3, wire.StateEnforcing), SeenAt: t0},       // prefix
	}
	v := fleet.View("bank-a", map[wire.ID]uint64{"main": 3}, l, t0, th)
	if len(v.Proxies) != 1 || v.Proxies[0].ProxyID != "p1" {
		t.Fatalf("cross-tenant rows leaked into bank-a view: %+v", v.Proxies)
	}
	v2 := fleet.View("city-b", map[wire.ID]uint64{"main": 3}, l, t0, th)
	if len(v2.Proxies) != 1 || v2.Proxies[0].ProxyID != "p2" || v2.Tenant != "city-b" {
		t.Fatalf("city-b view wrong: %+v", v2)
	}
	// Same proxy ID in two tenants stays separate.
	l2 := []fleet.Last{last("bank-a", "main", "px", 1, t0), last("city-b", "main", "px", 2, t0)}
	va := fleet.View("bank-a", nil, l2, t0, th)
	if len(va.Proxies) != 1 || va.Proxies[0].AppliedVersion != 1 {
		t.Fatalf("tenant isolation by proxy id broke: %+v", va)
	}
	// Unknown tenant: empty, not everything.
	if vz := fleet.View("nobody", nil, l, t0, th); len(vz.Proxies) != 0 {
		t.Fatalf("unknown tenant sees rows: %+v", vz.Proxies)
	}
}

func TestViewDriftSemantics(t *testing.T) {
	th := fleet.DefaultThresholds()
	max := uint64(math.MaxUint64)
	l := []fleet.Last{
		last("bank-a", "g1", "behind", 1, t0),
		last("bank-a", "g1", "equal", 5, t0),
		last("bank-a", "g1", "ahead", 9, t0),
		last("bank-a", "g1", "none-applied", 0, t0),
		last("bank-a", "nogroup", "undesired", 4, t0),
		last("bank-a", "g2", "huge-behind", 0, t0),
		last("bank-a", "g2", "huge-ahead", max, t0),
	}
	desired := map[wire.ID]uint64{"g1": 5, "g2": max}
	v := fleet.View("bank-a", desired, l, t0, th)
	got := map[wire.ID]wire.ProxyView{}
	for _, p := range v.Proxies {
		got[p.ProxyID] = p
	}
	want := map[wire.ID][2]uint64{ // desired, drift
		"behind": {5, 4}, "equal": {5, 0}, "ahead": {5, 0}, "none-applied": {5, 5},
		"undesired": {0, 0}, "huge-behind": {max, max}, "huge-ahead": {max, 0},
	}
	for id, w := range want {
		p, ok := got[id]
		if !ok {
			t.Fatalf("%s missing", id)
		}
		if p.DesiredVersion != w[0] || p.Drift != w[1] {
			t.Fatalf("%s: desired=%d drift=%d, want %d %d", id, p.DesiredVersion, p.Drift, w[0], w[1])
		}
	}
	// Group comes from Last.Group, not the report: a report cannot pick its group.
	if got["undesired"].Group != "nogroup" {
		t.Fatalf("group not taken from Last.Group: %q", got["undesired"].Group)
	}
}

func TestViewSortOrderProperty(t *testing.T) {
	th := fleet.DefaultThresholds()
	r := rand.New(rand.NewSource(11))
	rank := map[wire.Health]int{wire.HealthLost: 0, wire.HealthStale: 1, wire.HealthHealthy: 2}
	for iter := 0; iter < 50; iter++ {
		var in []fleet.Last
		n := r.Intn(300)
		for i := 0; i < n; i++ {
			seen := t0.Add(-time.Duration(r.Int63n(int64(5 * time.Minute))))
			if r.Intn(10) == 0 {
				seen = time.Time{}
			}
			in = append(in, last("bank-a", []string{"canary", "main", "x"}[r.Intn(3)], fmt.Sprintf("p-%03d-%d", r.Intn(1000), i), uint64(r.Intn(6)), seen))
		}
		desired := map[wire.ID]uint64{"canary": uint64(r.Intn(8)), "main": uint64(r.Intn(8))}
		v := fleet.View("bank-a", desired, in, t0, th)
		if len(v.Proxies) != n {
			t.Fatalf("rows %d != %d", len(v.Proxies), n)
		}
		for i := 1; i < len(v.Proxies); i++ {
			a, b := v.Proxies[i-1], v.Proxies[i]
			switch {
			case a.Drift != b.Drift:
				if a.Drift < b.Drift {
					t.Fatalf("not sorted by drift desc at %d: %+v then %+v", i, a, b)
				}
			case a.Health != b.Health:
				if rank[a.Health] > rank[b.Health] {
					t.Fatalf("not sorted by health (lost, stale, healthy) at %d: %q then %q", i, a.Health, b.Health)
				}
			default:
				if a.ProxyID >= b.ProxyID {
					t.Fatalf("not sorted by proxy id at %d: %q then %q", i, a.ProxyID, b.ProxyID)
				}
			}
		}
		// Determinism under input permutation.
		sh := append([]fleet.Last(nil), in...)
		r.Shuffle(len(sh), func(i, j int) { sh[i], sh[j] = sh[j], sh[i] })
		v2 := fleet.View("bank-a", desired, sh, t0, th)
		if !reflect.DeepEqual(v, v2) {
			t.Fatal("View output depends on input order")
		}
	}
}

func TestViewDoesNotModifyInput(t *testing.T) {
	th := fleet.DefaultThresholds()
	in := []fleet.Last{
		last("bank-a", "main", "z", 1, t0),
		last("bank-a", "main", "a", 3, t0.Add(-time.Minute)),
		last("city-b", "main", "m", 3, t0),
	}
	in[0].Report.LastError = &wire.ApplyError{Code: wire.ErrExpired, Version: 2}
	desired := map[wire.ID]uint64{"main": 3}
	inCopy := make([]fleet.Last, len(in))
	copy(inCopy, in)
	errCopy := *in[0].Report.LastError
	desCopy := map[wire.ID]uint64{"main": 3}

	v := fleet.View("bank-a", desired, in, t0, th)
	if !reflect.DeepEqual(inCopy, in) {
		t.Fatal("View reordered or modified the proxies slice")
	}
	if *in[0].Report.LastError != errCopy {
		t.Fatal("View modified LastError")
	}
	if !reflect.DeepEqual(desired, desCopy) {
		t.Fatal("View modified the desired map")
	}
	// Mutating the returned view must not reach back into the caller's slice.
	for i := range v.Proxies {
		v.Proxies[i].ProxyID = "mutated"
		v.Proxies[i].Drift = 99
	}
	if !reflect.DeepEqual(inCopy, in) {
		t.Fatal("returned view shares storage with input")
	}
}

func TestViewNilAndEmpty(t *testing.T) {
	th := fleet.DefaultThresholds()
	for name, fn := range map[string]func() wire.FleetView{
		"all-nil":      func() wire.FleetView { return fleet.View("bank-a", nil, nil, time.Time{}, fleet.Thresholds{}) },
		"empty":        func() wire.FleetView { return fleet.View("bank-a", map[wire.ID]uint64{}, []fleet.Last{}, t0, th) },
		"empty-tenant": func() wire.FleetView { return fleet.View("", nil, []fleet.Last{last("", "g", "p", 1, t0)}, t0, th) },
		"zero-thresholds": func() wire.FleetView {
			return fleet.View("bank-a", nil, []fleet.Last{last("bank-a", "g", "p", 1, t0)}, t0, fleet.Thresholds{})
		},
		"negative-thresholds": func() wire.FleetView {
			return fleet.View("bank-a", nil, []fleet.Last{last("bank-a", "g", "p", 1, t0)}, t0, fleet.Thresholds{Stale: -1, Lost: -1})
		},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			v := fn()
			for _, p := range v.Proxies {
				switch p.Health {
				case wire.HealthHealthy, wire.HealthStale, wire.HealthLost:
				default:
					t.Fatalf("unknown health %q", p.Health)
				}
			}
		})
	}
}

// Fail-closed health: with a nonsense configuration a proxy must not be reported
// healthier than the documented rules allow for a proxy that was never seen.
func TestZeroSeenAlwaysLostWhatEverThresholds(t *testing.T) {
	for _, th := range []fleet.Thresholds{{}, {Stale: time.Hour, Lost: 2 * time.Hour}, {Stale: math.MaxInt64, Lost: math.MaxInt64}, fleet.DefaultThresholds()} {
		if h := fleet.Health(time.Time{}, t0, th); h != wire.HealthLost {
			t.Fatalf("never-seen proxy is %q under %+v, want lost", h, th)
		}
	}
}

func TestViewHugeFleet(t *testing.T) {
	th := fleet.DefaultThresholds()
	const n = 200_000
	in := make([]fleet.Last, n)
	for i := range in {
		in[i] = last("bank-a", "main", fmt.Sprintf("sim-%06d", (i*7919)%n), uint64(i%5), t0.Add(-time.Duration(i%200)*time.Second))
	}
	start := time.Now()
	v := fleet.View("bank-a", map[wire.ID]uint64{"main": 4}, in, t0, th)
	if len(v.Proxies) != n {
		t.Fatalf("got %d rows", len(v.Proxies))
	}
	if d := time.Since(start); d > 60*time.Second {
		t.Fatalf("View of %d proxies took %v", n, d)
	}
	if !sort.SliceIsSorted(v.Proxies, func(i, j int) bool { return v.Proxies[i].Drift > v.Proxies[j].Drift }) {
		t.Fatal("huge view not sorted by drift")
	}
}

func TestConcurrentViewAndHealth(t *testing.T) {
	th := fleet.DefaultThresholds()
	shared := []fleet.Last{last("bank-a", "main", "p1", 1, t0), last("bank-a", "main", "p2", 2, t0)}
	desired := map[wire.ID]uint64{"main": 3}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				v := fleet.View("bank-a", desired, shared, t0.Add(time.Duration(i)*time.Second), th)
				if len(v.Proxies) != 2 {
					t.Error("bad view under concurrency")
					return
				}
				_ = fleet.Health(t0, t0.Add(time.Duration(i)*time.Second), th)
			}
		}()
	}
	wg.Wait()
}
