package fleet

import (
	"reflect"
	"testing"
	"time"

	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func TestHealthBoundaries(t *testing.T) {
	th := DefaultThresholds()
	tests := []struct {
		name string
		age  time.Duration
		want wire.Health
	}{
		{"just seen", 0, wire.HealthHealthy},
		{"29.999s", 29*time.Second + 999*time.Millisecond, wire.HealthHealthy},
		{"exactly 30s", 30 * time.Second, wire.HealthStale},
		{"30.001s", 30*time.Second + time.Millisecond, wire.HealthStale},
		{"1m59.999s", 2*time.Minute - time.Millisecond, wire.HealthStale},
		{"exactly 2m", 2 * time.Minute, wire.HealthLost},
		{"2m0.001s", 2*time.Minute + time.Millisecond, wire.HealthLost},
		{"a day", 24 * time.Hour, wire.HealthLost},
		{"seen in the future", -time.Hour, wire.HealthHealthy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Health(t0.Add(-tc.age), t0, th); got != tc.want {
				t.Fatalf("age %v: got %q want %q", tc.age, got, tc.want)
			}
		})
	}
}

func TestHealthNeverSeenIsLost(t *testing.T) {
	if got := Health(time.Time{}, t0, DefaultThresholds()); got != wire.HealthLost {
		t.Fatalf("zero SeenAt: got %q", got)
	}
}

func TestHealthCustomThresholds(t *testing.T) {
	th := Thresholds{Stale: 5 * time.Second, Lost: 20 * time.Second}
	cases := []struct {
		age  time.Duration
		want wire.Health
	}{
		{4999 * time.Millisecond, wire.HealthHealthy},
		{5 * time.Second, wire.HealthStale},
		{19999 * time.Millisecond, wire.HealthStale},
		{20 * time.Second, wire.HealthLost},
	}
	for _, c := range cases {
		if got := Health(t0.Add(-c.age), t0, th); got != c.want {
			t.Errorf("age %v: got %q want %q", c.age, got, c.want)
		}
	}
}

func TestHealthBadThresholds(t *testing.T) {
	// Non-positive values fall back to defaults; Lost below Stale is raised to Stale
	// so a proxy is never lost before it is stale.
	tests := []struct {
		name string
		th   Thresholds
		age  time.Duration
		want wire.Health
	}{
		{"zero thresholds use defaults, healthy", Thresholds{}, 29 * time.Second, wire.HealthHealthy},
		{"zero thresholds use defaults, stale", Thresholds{}, 30 * time.Second, wire.HealthStale},
		{"negative stale uses default", Thresholds{Stale: -1, Lost: time.Minute}, 29 * time.Second, wire.HealthHealthy},
		{"lost below stale is raised to stale: lost at 10s", Thresholds{Stale: 10 * time.Second, Lost: 5 * time.Second}, 10 * time.Second, wire.HealthLost},
		{"lost below stale is raised to stale: healthy at 9s", Thresholds{Stale: 10 * time.Second, Lost: 5 * time.Second}, 9 * time.Second, wire.HealthHealthy},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Health(t0.Add(-tc.age), t0, tc.th); got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultThresholds(t *testing.T) {
	th := DefaultThresholds()
	if th.Stale != 30*time.Second || th.Lost != 2*time.Minute {
		t.Fatalf("defaults: %+v", th)
	}
}

func TestClassify(t *testing.T) {
	h1 := wire.Hash("1111111111111111111111111111111111111111111111111111111111111111")
	h2 := wire.Hash("2222222222222222222222222222222222222222222222222222222222222222")
	tests := []struct {
		name        string
		want        Desired
		applied     uint64
		appliedHash wire.Hash
		kind        DriftKind
		drift       uint64
	}{
		{"in sync", Desired{8, h1}, 8, h1, DriftNone, 0},
		{"in sync, hash unknown on CP side", Desired{8, ""}, 8, h1, DriftNone, 0},
		{"behind by one", Desired{8, h1}, 7, h2, DriftBehind, 1},
		{"behind by many", Desired{10, h1}, 3, h2, DriftBehind, 7},
		{"no policy yet", Desired{8, h1}, 0, "", DriftBehind, 8},
		{"nothing desired, nothing applied", Desired{0, ""}, 0, "", DriftNone, 0},
		{"ahead of desired", Desired{8, h1}, 9, h2, DriftAhead, 0},
		{"same version, different hash", Desired{8, h1}, 8, h2, DriftHashMismatch, 0},
		{"same version, proxy hash empty", Desired{8, h1}, 8, "", DriftHashMismatch, 0},
		{"hash differs but behind is just behind", Desired{8, h1}, 5, h2, DriftBehind, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kind, drift := Classify(tc.want, tc.applied, tc.appliedHash)
			if kind != tc.kind || drift != tc.drift {
				t.Fatalf("got (%q,%d) want (%q,%d)", kind, drift, tc.kind, tc.drift)
			}
		})
	}
}

func rep(id string, state wire.ProxyState, applied uint64) wire.StatusReport {
	r := wire.StatusReport{Tenant: "acme", ProxyID: wire.ID(id), State: state, AppliedVersion: applied}
	if applied > 0 {
		r.PolicyHash = wire.Hash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	return r
}

func last(id, group string, state wire.ProxyState, applied uint64, age time.Duration) Last {
	return Last{Group: wire.ID(group), Report: rep(id, state, applied), SeenAt: t0.Add(-age)}
}

func TestViewSurfacesFields(t *testing.T) {
	errd := last("p1", "main", wire.StateEnforcing, 7, time.Second)
	errd.Report.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 8}
	tam := last("p2", "main", wire.StateTampered, 0, time.Second)
	tam.Report.LastError = &wire.ApplyError{Code: wire.ErrTampered}
	safe := last("p3", "canary", wire.StateSafeMode, 8, time.Second)

	v := View("acme", map[wire.ID]uint64{"main": 8, "canary": 8}, []Last{errd, tam, safe}, t0, DefaultThresholds())
	if v.Tenant != "acme" || len(v.Proxies) != 3 {
		t.Fatalf("view: %+v", v)
	}
	by := map[wire.ID]wire.ProxyView{}
	for _, p := range v.Proxies {
		by[p.ProxyID] = p
	}
	p1 := by["p1"]
	if p1.Group != "main" || p1.Health != wire.HealthHealthy || p1.State != wire.StateEnforcing ||
		p1.DesiredVersion != 8 || p1.AppliedVersion != 7 || p1.Drift != 1 ||
		p1.PolicyHash != errd.Report.PolicyHash || p1.LastSeenUnixMs != errd.SeenAt.UnixMilli() ||
		p1.LastError == nil || p1.LastError.Code != wire.ErrThreshold || p1.LastError.Version != 8 {
		t.Fatalf("p1: %+v", p1)
	}
	p2 := by["p2"]
	if p2.State != wire.StateTampered || p2.Drift != 8 || p2.AppliedVersion != 0 || p2.LastError == nil || p2.LastError.Code != wire.ErrTampered {
		t.Fatalf("p2: %+v", p2)
	}
	p3 := by["p3"]
	if p3.State != wire.StateSafeMode || p3.Drift != 0 {
		t.Fatalf("p3: %+v", p3)
	}
}

func TestViewDoesNotAliasLastError(t *testing.T) {
	l := last("p1", "main", wire.StateEnforcing, 7, 0)
	l.Report.LastError = &wire.ApplyError{Code: wire.ErrExpired, Version: 8}
	v := View("acme", map[wire.ID]uint64{"main": 8}, []Last{l}, t0, DefaultThresholds())
	v.Proxies[0].LastError.Code = wire.ErrInternal
	if l.Report.LastError.Code != wire.ErrExpired {
		t.Fatal("View shares the LastError pointer with its input")
	}
}

func TestViewSortOrder(t *testing.T) {
	th := DefaultThresholds()
	desired := map[wire.ID]uint64{"main": 10}
	proxies := []Last{
		last("e-healthy-synced", "main", wire.StateEnforcing, 10, time.Second),
		last("b-healthy-synced", "main", wire.StateEnforcing, 10, time.Second),
		last("c-stale-synced", "main", wire.StateEnforcing, 10, time.Minute),
		last("d-lost-synced", "main", wire.StateEnforcing, 10, time.Hour),
		last("f-healthy-behind1", "main", wire.StateEnforcing, 9, time.Second),
		last("g-lost-behind5", "main", wire.StateEnforcing, 5, time.Hour),
		last("a-healthy-behind5", "main", wire.StateEnforcing, 5, time.Second),
		last("h-stale-behind5", "main", wire.StateEnforcing, 5, time.Minute),
	}
	got := View("acme", desired, proxies, t0, th)
	var ids []wire.ID
	for _, p := range got.Proxies {
		ids = append(ids, p.ProxyID)
	}
	want := []wire.ID{
		"g-lost-behind5", "h-stale-behind5", "a-healthy-behind5", // drift 5: lost, stale, healthy
		"f-healthy-behind1",                                                       // drift 1
		"d-lost-synced", "c-stale-synced", "b-healthy-synced", "e-healthy-synced", // drift 0
	}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("order:\n got %v\nwant %v", ids, want)
	}
}

func TestViewDeterministicRegardlessOfInputOrder(t *testing.T) {
	a := last("a", "main", wire.StateEnforcing, 3, time.Second)
	b := last("b", "main", wire.StateEnforcing, 3, time.Second)
	c := last("c", "main", wire.StateEnforcing, 3, time.Second)
	d := map[wire.ID]uint64{"main": 3}
	v1 := View("acme", d, []Last{a, b, c}, t0, DefaultThresholds())
	v2 := View("acme", d, []Last{c, a, b}, t0, DefaultThresholds())
	if !reflect.DeepEqual(v1, v2) {
		t.Fatalf("order depends on input:\n%+v\n%+v", v1, v2)
	}
}

func TestViewDoesNotMutateInput(t *testing.T) {
	in := []Last{
		last("b", "main", wire.StateEnforcing, 1, 0),
		last("a", "main", wire.StateEnforcing, 1, 0),
	}
	View("acme", map[wire.ID]uint64{"main": 1}, in, t0, DefaultThresholds())
	if in[0].Report.ProxyID != "b" {
		t.Fatal("input slice was reordered")
	}
}

func TestViewPerGroupDesired(t *testing.T) {
	desired := map[wire.ID]uint64{"canary": 8, "main": 7}
	v := View("acme", desired, []Last{
		last("c1", "canary", wire.StateEnforcing, 7, 0),
		last("m1", "main", wire.StateEnforcing, 7, 0),
		last("x1", "unlisted", wire.StateEnforcing, 7, 0),
	}, t0, DefaultThresholds())
	by := map[wire.ID]wire.ProxyView{}
	for _, p := range v.Proxies {
		by[p.ProxyID] = p
	}
	if by["c1"].DesiredVersion != 8 || by["c1"].Drift != 1 {
		t.Errorf("c1: %+v", by["c1"])
	}
	if by["m1"].DesiredVersion != 7 || by["m1"].Drift != 0 {
		t.Errorf("m1: %+v", by["m1"])
	}
	// A group with no desired entry has nothing desired: never counted as drift.
	if by["x1"].DesiredVersion != 0 || by["x1"].Drift != 0 {
		t.Errorf("x1: %+v", by["x1"])
	}
}

func TestViewAheadIsNotDrift(t *testing.T) {
	v := View("acme", map[wire.ID]uint64{"main": 5}, []Last{last("p", "main", wire.StateEnforcing, 9, 0)}, t0, DefaultThresholds())
	if v.Proxies[0].Drift != 0 {
		t.Fatalf("drift %d", v.Proxies[0].Drift)
	}
}

func TestViewHealthIsComputedFromNow(t *testing.T) {
	l := last("p", "main", wire.StateEnforcing, 1, 0)
	th := DefaultThresholds()
	if h := View("acme", nil, []Last{l}, t0.Add(29*time.Second+999*time.Millisecond), th).Proxies[0].Health; h != wire.HealthHealthy {
		t.Fatalf("29.999s: %q", h)
	}
	if h := View("acme", nil, []Last{l}, t0.Add(30*time.Second), th).Proxies[0].Health; h != wire.HealthStale {
		t.Fatalf("30s: %q", h)
	}
	if h := View("acme", nil, []Last{l}, t0.Add(2*time.Minute), th).Proxies[0].Health; h != wire.HealthLost {
		t.Fatalf("2m: %q", h)
	}
}

func TestViewSkipsOtherTenants(t *testing.T) {
	other := last("evil", "main", wire.StateEnforcing, 1, 0)
	other.Report.Tenant = "other"
	v := View("acme", map[wire.ID]uint64{"main": 1}, []Last{other, last("ok", "main", wire.StateEnforcing, 1, 0)}, t0, DefaultThresholds())
	if len(v.Proxies) != 1 || v.Proxies[0].ProxyID != "ok" {
		t.Fatalf("view: %+v", v.Proxies)
	}
}

func TestViewNeverSeen(t *testing.T) {
	l := Last{Group: "main", Report: rep("p", wire.StateBooting, 0)}
	v := View("acme", map[wire.ID]uint64{"main": 2}, []Last{l}, t0, DefaultThresholds())
	p := v.Proxies[0]
	if p.Health != wire.HealthLost || p.LastSeenUnixMs != 0 || p.Drift != 2 {
		t.Fatalf("p: %+v", p)
	}
}

func TestViewEmpty(t *testing.T) {
	v := View("acme", nil, nil, t0, DefaultThresholds())
	if v.Tenant != "acme" || v.Proxies == nil || len(v.Proxies) != 0 {
		t.Fatalf("empty view must have a non-nil empty slice (JSON [] not null): %+v", v)
	}
}
