package rollout

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const (
	dwell   = 5 * time.Minute
	ver     = 8
	prevVer = 7
)

// px builds one proxy row. Defaults: healthy, enforcing, applied = prevVer.
type px struct {
	id      wire.ID
	group   wire.ID
	health  wire.Health
	state   wire.ProxyState
	applied uint64
	err     *wire.ApplyError
}

func (p px) view() wire.ProxyView {
	if p.health == "" {
		p.health = wire.HealthHealthy
	}
	if p.state == "" {
		p.state = wire.StateEnforcing
	}
	return wire.ProxyView{
		ProxyID: p.id, Group: p.group, Health: p.health, State: p.state,
		AppliedVersion: p.applied, LastError: p.err,
	}
}

func fleetOf(ps ...px) wire.FleetView {
	v := wire.FleetView{Tenant: "acme"}
	for _, p := range ps {
		v.Proxies = append(v.Proxies, p.view())
	}
	return v
}

func canaryRollout() Rollout {
	return Start(wire.RolloutRequest{Tenant: "acme", Version: ver}, prevVer, t0, dwell)
}

func rollout(phase wire.RolloutPhase) Rollout {
	r := canaryRollout()
	r.Phase = phase
	if phase == wire.PhaseHalted {
		r.Reason = wire.ErrCanaryLost
	}
	return r
}

func TestStart(t *testing.T) {
	tests := []struct {
		name    string
		req     wire.RolloutRequest
		prev    uint64
		defDw   time.Duration
		phase   wire.RolloutPhase
		reason  wire.ErrorCode
		dwell   time.Duration
		version uint64
	}{
		{"default dwell", wire.RolloutRequest{Tenant: "acme", Version: 8}, 7, 5 * time.Minute, wire.PhaseCanary, "", 5 * time.Minute, 8},
		{"request dwell wins", wire.RolloutRequest{Tenant: "acme", Version: 8, CanaryDwellSeconds: 90}, 7, 5 * time.Minute, wire.PhaseCanary, "", 90 * time.Second, 8},
		{"zero default dwell", wire.RolloutRequest{Tenant: "acme", Version: 8}, 7, 0, wire.PhaseCanary, "", 0, 8},
		{"negative default dwell is zero", wire.RolloutRequest{Tenant: "acme", Version: 8}, 7, -time.Hour, wire.PhaseCanary, "", 0, 8},
		{"huge dwell is capped, no overflow", wire.RolloutRequest{Tenant: "acme", Version: 8, CanaryDwellSeconds: 1 << 62}, 7, time.Minute, wire.PhaseCanary, "", MaxDwell, 8},
		{"first ever rollout", wire.RolloutRequest{Tenant: "acme", Version: 1}, 0, time.Minute, wire.PhaseCanary, "", time.Minute, 1},
		{"same version is not newer", wire.RolloutRequest{Tenant: "acme", Version: 7}, 7, time.Minute, wire.PhaseHalted, wire.ErrNotNewer, time.Minute, 7},
		{"lower version is not newer (no in-place downgrade)", wire.RolloutRequest{Tenant: "acme", Version: 3}, 7, time.Minute, wire.PhaseHalted, wire.ErrNotNewer, time.Minute, 3},
		{"zero version", wire.RolloutRequest{Tenant: "acme", Version: 0}, 0, time.Minute, wire.PhaseHalted, wire.ErrBadRequest, time.Minute, 0},
		{"bad tenant", wire.RolloutRequest{Tenant: "ACME!", Version: 8}, 7, time.Minute, wire.PhaseHalted, wire.ErrBadRequest, time.Minute, 8},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Start(tc.req, tc.prev, t0, tc.defDw)
			if r.Phase != tc.phase || r.Reason != tc.reason || r.Dwell != tc.dwell || r.Version != tc.version ||
				r.Previous != tc.prev || r.Tenant != tc.req.Tenant || !r.CanaryOK.IsZero() {
				t.Fatalf("got %+v", r)
			}
		})
	}
}

func TestCanaryGroupName(t *testing.T) {
	if CanaryGroup != "canary" {
		t.Fatal(CanaryGroup)
	}
}

func TestStepCanary(t *testing.T) {
	c1 := func(applied uint64) px { return px{id: "c1", group: CanaryGroup, applied: applied} }
	m1 := px{id: "m1", group: "main", applied: prevVer}
	applyErr := &wire.ApplyError{Code: wire.ErrThreshold, Version: ver}

	tests := []struct {
		name      string
		r         func() Rollout
		fleet     wire.FleetView
		now       time.Time
		phase     wire.RolloutPhase
		reason    wire.ErrorCode
		canaryOK  time.Time
		canaryDes uint64
		mainDes   uint64
	}{
		{
			name: "no canary proxies: wait, never promote blind",
			r:    canaryRollout, fleet: fleetOf(m1), now: t0.Add(24 * time.Hour),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary has not applied yet",
			r:    canaryRollout, fleet: fleetOf(c1(prevVer), m1), now: t0.Add(time.Hour),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary just acked: dwell clock starts",
			r:    canaryRollout, fleet: fleetOf(c1(ver), m1), now: t0.Add(time.Minute),
			phase: wire.PhaseCanary, canaryOK: t0.Add(time.Minute), canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "dwell not over by 1ms",
			r: func() Rollout {
				r := canaryRollout()
				r.CanaryOK = t0
				return r
			},
			fleet: fleetOf(c1(ver), m1), now: t0.Add(dwell - time.Millisecond),
			phase: wire.PhaseCanary, canaryOK: t0, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "dwell over exactly: promote",
			r: func() Rollout {
				r := canaryRollout()
				r.CanaryOK = t0
				return r
			},
			fleet: fleetOf(c1(ver), m1), now: t0.Add(dwell),
			phase: wire.PhasePromoting, canaryOK: t0, canaryDes: ver, mainDes: ver,
		},
		{
			name: "zero dwell promotes on the first acked step",
			r: func() Rollout {
				r := canaryRollout()
				r.Dwell = 0
				return r
			},
			fleet: fleetOf(c1(ver), m1), now: t0,
			phase: wire.PhasePromoting, canaryOK: t0, canaryDes: ver, mainDes: ver,
		},
		{
			name: "canary went stale: dwell restarts",
			r: func() Rollout {
				r := canaryRollout()
				r.CanaryOK = t0
				return r
			},
			fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, health: wire.HealthStale}, m1), now: t0.Add(dwell + time.Hour),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary in safe mode does not count as healthy",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, state: wire.StateSafeMode}, m1), now: t0.Add(time.Hour),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "two canaries, only one acked",
			r:    canaryRollout, fleet: fleetOf(c1(ver), px{id: "c2", group: CanaryGroup, applied: prevVer}, m1), now: t0.Add(time.Hour),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary apply error for this version: halt with its code",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer, err: applyErr}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseHalted, reason: wire.ErrThreshold, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary apply error beats an acked second canary",
			r:    canaryRollout, fleet: fleetOf(c1(ver), px{id: "c2", group: CanaryGroup, applied: prevVer, err: &wire.ApplyError{Code: wire.ErrExpired, Version: ver}}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseHalted, reason: wire.ErrExpired, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary apply error for an older version is ignored",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer, err: &wire.ApplyError{Code: wire.ErrExpired, Version: prevVer}}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "error without a version cannot be tied to this rollout: ignored",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer, err: &wire.ApplyError{Code: wire.ErrMalformed}}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "stale error after a successful apply is ignored",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, err: applyErr}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseCanary, canaryOK: t0.Add(time.Second), canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary tampered: halt",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: 0, state: wire.StateTampered}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseHalted, reason: wire.ErrTampered, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary lost: halt canary_lost",
			r:    canaryRollout, fleet: fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, health: wire.HealthLost}, m1), now: t0.Add(time.Second),
			phase: wire.PhaseHalted, reason: wire.ErrCanaryLost, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "canary lost even though one canary acked and dwell is over",
			r: func() Rollout {
				r := canaryRollout()
				r.CanaryOK = t0
				return r
			},
			fleet: fleetOf(c1(ver), px{id: "c2", group: CanaryGroup, applied: prevVer, health: wire.HealthLost}, m1), now: t0.Add(dwell * 10),
			phase: wire.PhaseHalted, reason: wire.ErrCanaryLost, canaryOK: t0, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "main proxy error does not halt the canary phase",
			r:    canaryRollout, fleet: fleetOf(c1(prevVer), px{id: "m1", group: "main", applied: prevVer, err: applyErr}), now: t0.Add(time.Second),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
		{
			name: "main proxy lost does not halt the canary phase",
			r:    canaryRollout, fleet: fleetOf(c1(prevVer), px{id: "m1", group: "main", applied: prevVer, health: wire.HealthLost}), now: t0.Add(time.Second),
			phase: wire.PhaseCanary, canaryDes: ver, mainDes: prevVer,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.r()
			got, des := Step(in, tc.fleet, tc.now)
			if got.Phase != tc.phase || got.Reason != tc.reason || !got.CanaryOK.Equal(tc.canaryOK) {
				t.Fatalf("got phase=%q reason=%q canaryOK=%v; want phase=%q reason=%q canaryOK=%v",
					got.Phase, got.Reason, got.CanaryOK, tc.phase, tc.reason, tc.canaryOK)
			}
			if got.Tenant != in.Tenant || got.Version != in.Version || got.Previous != in.Previous || got.Dwell != in.Dwell {
				t.Fatalf("identity fields changed: %+v -> %+v", in, got)
			}
			want := map[wire.ID]uint64{}
			for _, p := range tc.fleet.Proxies {
				if p.Group == CanaryGroup {
					want[p.Group] = tc.canaryDes
				} else {
					want[p.Group] = tc.mainDes
				}
			}
			if !reflect.DeepEqual(des, want) {
				t.Fatalf("desired %v want %v", des, want)
			}
		})
	}
}

func TestStepPromoting(t *testing.T) {
	canaryOK := px{id: "c1", group: CanaryGroup, applied: ver}
	ok := func(id wire.ID) px { return px{id: id, group: "main", applied: ver} }
	behind := func(id wire.ID) px { return px{id: id, group: "main", applied: prevVer} }
	errored := func(id wire.ID, code wire.ErrorCode) px {
		return px{id: id, group: "main", applied: prevVer, err: &wire.ApplyError{Code: code, Version: ver}}
	}

	tests := []struct {
		name   string
		fleet  wire.FleetView
		phase  wire.RolloutPhase
		reason wire.ErrorCode
	}{
		{"all acked: complete", fleetOf(canaryOK, ok("m1"), ok("m2")), wire.PhaseComplete, ""},
		{"one still behind: keep promoting", fleetOf(canaryOK, ok("m1"), behind("m2")), wire.PhasePromoting, ""},
		{"canary behind: keep promoting", fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer}, ok("m1")), wire.PhasePromoting, ""},
		{"lost proxy does not block completion", fleetOf(canaryOK, ok("m1"), px{id: "m2", group: "main", applied: prevVer, health: wire.HealthLost}), wire.PhaseComplete, ""},
		{"stale proxy that has not acked blocks completion", fleetOf(canaryOK, ok("m1"), px{id: "m2", group: "main", applied: prevVer, health: wire.HealthStale}), wire.PhasePromoting, ""},
		{"everyone lost: cannot complete", fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, health: wire.HealthLost}, px{id: "m1", group: "main", applied: ver, health: wire.HealthLost}), wire.PhasePromoting, ""},
		{"empty fleet: cannot complete", fleetOf(), wire.PhasePromoting, ""},
		{"1 of 5 errors (20%) is at the threshold: keep promoting", fleetOf(errored("m1", wire.ErrPersist), behind("m2"), behind("m3"), behind("m4"), behind("m5")), wire.PhasePromoting, ""},
		{"2 of 5 errors (40%): halt", fleetOf(errored("m1", wire.ErrPersist), errored("m2", wire.ErrPersist), behind("m3"), behind("m4"), behind("m5")), wire.PhaseHalted, wire.ErrPersist},
		{"1 of 4 errors (25%): halt", fleetOf(errored("m1", wire.ErrExpired), behind("m2"), behind("m3"), behind("m4")), wire.PhaseHalted, wire.ErrExpired},
		{"1 of 1 errors: halt", fleetOf(errored("m1", wire.ErrThreshold)), wire.PhaseHalted, wire.ErrThreshold},
		{"halt reason comes from the lowest proxy id", fleetOf(errored("m9", wire.ErrExpired), errored("m2", wire.ErrThreshold)), wire.PhaseHalted, wire.ErrThreshold},
		{"errors for an older version do not count", fleetOf(px{id: "m1", group: "main", applied: prevVer, err: &wire.ApplyError{Code: wire.ErrExpired, Version: prevVer}}), wire.PhasePromoting, ""},
		{"canary errors are not counted in the main threshold", fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer, err: &wire.ApplyError{Code: wire.ErrExpired, Version: ver}}, behind("m1"), behind("m2")), wire.PhasePromoting, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, des := Step(rollout(wire.PhasePromoting), tc.fleet, t0.Add(time.Hour))
			if got.Phase != tc.phase || got.Reason != tc.reason {
				t.Fatalf("got phase=%q reason=%q want phase=%q reason=%q", got.Phase, got.Reason, tc.phase, tc.reason)
			}
			for g, v := range des {
				// M-D44: a halt while promoting freezes every group at the new
				// version; nothing goes back down.
				wantV := uint64(ver)
				if v != wantV {
					t.Errorf("group %q desired %d want %d", g, v, wantV)
				}
			}
		})
	}
}

// Halted never promotes, whatever the fleet looks like.
func TestHaltedNeverPromotes(t *testing.T) {
	fleets := map[string]wire.FleetView{
		"everyone acked and healthy": fleetOf(
			px{id: "c1", group: CanaryGroup, applied: ver},
			px{id: "m1", group: "main", applied: ver}),
		"canary recovered": fleetOf(
			px{id: "c1", group: CanaryGroup, applied: ver},
			px{id: "m1", group: "main", applied: prevVer}),
		"empty": fleetOf(),
		"main errors": fleetOf(
			px{id: "m1", group: "main", applied: prevVer, err: &wire.ApplyError{Code: wire.ErrExpired, Version: ver}}),
	}
	reasons := []wire.ErrorCode{wire.ErrCanaryLost, wire.ErrThreshold, wire.ErrTampered, wire.ErrNotNewer}
	for name, f := range fleets {
		for _, reason := range reasons {
			for _, dt := range []time.Duration{0, time.Second, dwell, 100 * dwell, 1000 * time.Hour} {
				r := rollout(wire.PhaseHalted)
				r.Reason = reason
				r.CanaryOK = t0
				got, des := Step(r, f, t0.Add(dt))
				if got != r {
					t.Fatalf("%s/%s/%v: halted rollout changed: %+v -> %+v", name, reason, dt, r, got)
				}
				for _, p := range f.Proxies {
					if p.Group != CanaryGroup && des[p.Group] != prevVer {
						t.Fatalf("%s: main group desired %d, want old version %d", name, des[p.Group], prevVer)
					}
				}
			}
		}
	}
}

func TestStepIsTerminalWhenComplete(t *testing.T) {
	r := rollout(wire.PhaseComplete)
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: 1, health: wire.HealthLost}, px{id: "m1", group: "main", applied: 1, err: &wire.ApplyError{Code: wire.ErrExpired, Version: ver}})
	got, des := Step(r, f, t0.Add(time.Hour))
	if got != r {
		t.Fatalf("complete rollout changed: %+v", got)
	}
	if des[CanaryGroup] != ver || des["main"] != ver {
		t.Fatalf("complete: desired %v", des)
	}
}

// A halt that happens in the same Step that would otherwise promote.
func TestHaltWinsOverPromote(t *testing.T) {
	r := canaryRollout()
	r.CanaryOK = t0
	f := fleetOf(
		px{id: "c1", group: CanaryGroup, applied: ver},
		px{id: "c2", group: CanaryGroup, applied: ver, health: wire.HealthLost},
		px{id: "m1", group: "main", applied: prevVer})
	got, des := Step(r, f, t0.Add(dwell))
	if got.Phase != wire.PhaseHalted || got.Reason != wire.ErrCanaryLost || des["main"] != prevVer {
		t.Fatalf("got %+v %v", got, des)
	}
}

func TestStepNeverLowersDesired(t *testing.T) {
	phases := []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete}
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: 1}, px{id: "m1", group: "main", applied: 1})
	for _, ph := range phases {
		// A malformed rollout whose Version is below Previous must not lower anything.
		r := Rollout{Tenant: "acme", Version: 3, Previous: 7, Phase: ph, Dwell: dwell}
		_, des := Step(r, f, t0)
		for g, v := range des {
			if v < 7 {
				t.Errorf("phase %s group %s desired %d lowered below previous 7", ph, g, v)
			}
		}
	}
	// Same for the normal case: every phase, every group >= Previous.
	for _, ph := range phases {
		_, des := Step(rollout(ph), f, t0)
		for g, v := range des {
			if v < prevVer {
				t.Errorf("phase %s group %s desired %d < %d", ph, g, v, prevVer)
			}
		}
	}
}

// M-D44: Halted freezes each group's desired version where it was when the
// rollout halted. A halt while promoting must not send moved groups back.
func TestPromotingThenHaltedKeepsDesired(t *testing.T) {
	canary := px{id: "c1", group: CanaryGroup, applied: ver}
	bad := func(id wire.ID) px {
		return px{id: id, group: "main", applied: prevVer, err: &wire.ApplyError{Code: wire.ErrPersist, Version: ver}}
	}
	r := rollout(wire.PhasePromoting)
	r, des := Step(r, fleetOf(canary, px{id: "m1", group: "main", applied: prevVer}), t0)
	if r.Phase != wire.PhasePromoting || des["main"] != ver {
		t.Fatalf("promoting: %+v %v", r, des)
	}
	r, des = Step(r, fleetOf(canary, bad("m1")), t0.Add(time.Second))
	if r.Phase != wire.PhaseHalted || r.Reason != wire.ErrPersist {
		t.Fatalf("want halt, got %+v", r)
	}
	if des["main"] != ver || des[CanaryGroup] != ver {
		t.Fatalf("halt lowered desired: %v", des)
	}
	for _, g := range []wire.ID{CanaryGroup, "main", "eu"} {
		if got := DesiredFor(r, g); got != ver {
			t.Errorf("DesiredFor(%s) = %d, want %d", g, got, ver)
		}
	}
	// Still frozen on later Steps, whatever the fleet looks like.
	r2, des := Step(r, fleetOf(), t0.Add(time.Hour))
	if r2 != r {
		t.Fatalf("halted rollout changed: %+v", r2)
	}
	if len(des) != 0 {
		t.Fatalf("empty fleet should yield no desired entries: %v", des)
	}
	_, des = Step(r, fleetOf(px{id: "m1", group: "main", applied: prevVer}), t0.Add(2*time.Hour))
	if des["main"] != ver {
		t.Fatalf("later step: %v", des)
	}
	// Halt in Canary still keeps main groups at Previous.
	rc, des := Step(canaryRollout(), fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer, health: wire.HealthLost}, px{id: "m1", group: "main", applied: prevVer}), t0)
	if rc.Phase != wire.PhaseHalted || des["main"] != prevVer || des[CanaryGroup] != ver {
		t.Fatalf("canary halt: %+v %v", rc, des)
	}
}

// Property (M-D44): over random fleets and random times, no group's desired
// version ever goes down between Steps, and DesiredFor agrees with Step.
func TestDesiredNeverDecreasesProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	groups := []wire.ID{CanaryGroup, "main", "eu"}
	healths := []wire.Health{wire.HealthHealthy, wire.HealthStale, wire.HealthLost}
	states := []wire.ProxyState{wire.StateEnforcing, wire.StateTampered}
	for iter := 0; iter < 3000; iter++ {
		r := Start(wire.RolloutRequest{Tenant: "acme", Version: ver, CanaryDwellSeconds: uint64(rng.IntN(3))}, prevVer, t0, dwell)
		last := map[wire.ID]uint64{}
		now := t0
		for step := 0; step < 12; step++ {
			var ps []px
			for i := 0; i < rng.IntN(7); i++ {
				p := px{id: wire.ID(fmt.Sprintf("p%d", i)), group: groups[rng.IntN(len(groups))],
					health: healths[rng.IntN(len(healths))], state: states[rng.IntN(len(states))]}
				if rng.IntN(2) == 0 {
					p.applied = ver
				} else {
					p.applied = prevVer
				}
				if rng.IntN(4) == 0 {
					p.err = &wire.ApplyError{Code: wire.ErrPersist, Version: ver}
				}
				ps = append(ps, p)
			}
			now = now.Add(time.Duration(rng.IntN(3)) * time.Second)
			var des map[wire.ID]uint64
			r, des = Step(r, fleetOf(ps...), now)
			for _, g := range groups {
				if d := DesiredFor(r, g); d < last[g] {
					t.Fatalf("iter %d step %d: group %s desired %d < %d (phase %s)", iter, step, g, d, last[g], r.Phase)
				} else {
					last[g] = d
				}
			}
			for g, d := range des {
				if d != DesiredFor(r, g) {
					t.Fatalf("Step desired %d != DesiredFor %d for %s", d, DesiredFor(r, g), g)
				}
			}
		}
	}
}

func TestStepMalformedRolloutHalts(t *testing.T) {
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: ver}, px{id: "m1", group: "main", applied: ver})
	tests := []struct {
		name   string
		r      Rollout
		reason wire.ErrorCode
	}{
		{"unknown phase", Rollout{Tenant: "acme", Version: ver, Previous: prevVer, Phase: "bogus"}, wire.ErrInternal},
		{"empty phase", Rollout{Tenant: "acme", Version: ver, Previous: prevVer}, wire.ErrInternal},
		{"version not above previous", Rollout{Tenant: "acme", Version: prevVer, Previous: prevVer, Phase: wire.PhasePromoting}, wire.ErrNotNewer},
		{"tenant differs from fleet", Rollout{Tenant: "other", Version: ver, Previous: prevVer, Phase: wire.PhasePromoting}, wire.ErrWrongTenant},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, des := Step(tc.r, f, t0)
			if got.Phase != wire.PhaseHalted || got.Reason != tc.reason {
				t.Fatalf("got %+v", got)
			}
			if des["main"] != prevVer {
				t.Fatalf("main group promoted by a malformed rollout: %v", des)
			}
		})
	}
}

func TestStepHaltedFromStartStaysHalted(t *testing.T) {
	r := Start(wire.RolloutRequest{Tenant: "acme", Version: 3}, 7, t0, dwell)
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: 3}, px{id: "m1", group: "main", applied: 3})
	got, des := Step(r, f, t0.Add(time.Hour))
	if got.Phase != wire.PhaseHalted || got.Reason != wire.ErrNotNewer {
		t.Fatalf("got %+v", got)
	}
	if des[CanaryGroup] != 7 || des["main"] != 7 {
		t.Fatalf("desired %v", des)
	}
}

func TestDesiredCoversEveryGroupInView(t *testing.T) {
	f := fleetOf(
		px{id: "c1", group: CanaryGroup, applied: prevVer},
		px{id: "m1", group: "main", applied: prevVer},
		px{id: "e1", group: "eu", applied: prevVer},
		px{id: "e2", group: "eu", applied: prevVer})
	_, des := Step(canaryRollout(), f, t0)
	want := map[wire.ID]uint64{CanaryGroup: ver, "main": prevVer, "eu": prevVer}
	if !reflect.DeepEqual(des, want) {
		t.Fatalf("got %v want %v", des, want)
	}
	r := rollout(wire.PhasePromoting)
	_, des = Step(r, f, t0)
	want = map[wire.ID]uint64{CanaryGroup: ver, "main": ver, "eu": ver}
	if !reflect.DeepEqual(des, want) {
		t.Fatalf("promoting: got %v want %v", des, want)
	}
}

// DesiredFor is the single rule the fleet page and Step both use (C-06).
func TestDesiredForMatchesStep(t *testing.T) {
	view := fleetOf(px{id: "c1", group: CanaryGroup}, px{id: "m1", group: "main"})
	for _, phase := range []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete} {
		r := rollout(phase)
		// Compare with desired() directly: Step may advance the phase first.
		want := desired(r, view)
		for _, g := range []wire.ID{CanaryGroup, "main"} {
			if got := DesiredFor(r, g); got != want[g] {
				t.Errorf("%s/%s: DesiredFor = %d, desired = %d", phase, g, got, want[g])
			}
		}
	}
	r := rollout(wire.PhaseHalted)
	if DesiredFor(r, CanaryGroup) != ver || DesiredFor(r, "main") != prevVer {
		t.Errorf("halted: canary stays at the new version, others at previous")
	}
}

func TestStepDoesNotMutateFleet(t *testing.T) {
	e := &wire.ApplyError{Code: wire.ErrExpired, Version: ver}
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: ver, err: e}, px{id: "m1", group: "main", applied: prevVer})
	want := wire.FleetView{Tenant: f.Tenant, Proxies: append([]wire.ProxyView(nil), f.Proxies...)}
	Step(canaryRollout(), f, t0)
	if !reflect.DeepEqual(f, want) || *e != (wire.ApplyError{Code: wire.ErrExpired, Version: ver}) {
		t.Fatal("fleet was modified")
	}
}

// Full journey and rollback by re-publishing as a higher version.
func TestJourneyHappyPath(t *testing.T) {
	r := Start(wire.RolloutRequest{Tenant: "acme", Version: 8, CanaryDwellSeconds: 60}, 7, t0, dwell)
	now := t0
	c := px{id: "c1", group: CanaryGroup, applied: 7}
	m := px{id: "m1", group: "main", applied: 7}

	r, des := Step(r, fleetOf(c, m), now)
	if r.Phase != wire.PhaseCanary || des["main"] != 7 || des[CanaryGroup] != 8 {
		t.Fatalf("t+0: %+v %v", r, des)
	}
	c.applied = 8
	now = now.Add(2 * time.Second)
	r, _ = Step(r, fleetOf(c, m), now)
	if r.Phase != wire.PhaseCanary || !r.CanaryOK.Equal(now) {
		t.Fatalf("acked: %+v", r)
	}
	now = now.Add(59 * time.Second)
	r, _ = Step(r, fleetOf(c, m), now)
	if r.Phase != wire.PhaseCanary {
		t.Fatalf("t+59: %+v", r)
	}
	now = now.Add(time.Second)
	r, des = Step(r, fleetOf(c, m), now)
	if r.Phase != wire.PhasePromoting || des["main"] != 8 {
		t.Fatalf("dwell over: %+v %v", r, des)
	}
	m.applied = 8
	r, des = Step(r, fleetOf(c, m), now.Add(time.Second))
	if r.Phase != wire.PhaseComplete || des["main"] != 8 || des[CanaryGroup] != 8 {
		t.Fatalf("complete: %+v %v", r, des)
	}
}

func TestJourneyHaltAndRollback(t *testing.T) {
	r := Start(wire.RolloutRequest{Tenant: "acme", Version: 8}, 7, t0, dwell)
	c := px{id: "c1", group: CanaryGroup, applied: 7, err: &wire.ApplyError{Code: wire.ErrThreshold, Version: 8}}
	m := px{id: "m1", group: "main", applied: 7}
	r, des := Step(r, fleetOf(c, m), t0.Add(time.Second))
	if r.Phase != wire.PhaseHalted || des["main"] != 7 {
		t.Fatalf("halt: %+v %v", r, des)
	}
	// Rollback: the same content re-published as version 9; rollout restarts at Canary.
	r2 := Start(wire.RolloutRequest{Tenant: "acme", Version: 9}, 7, t0.Add(time.Minute), dwell)
	c.err = nil
	r2, des = Step(r2, fleetOf(c, m), t0.Add(time.Minute))
	if r2.Phase != wire.PhaseCanary || r2.Version != 9 || des[CanaryGroup] != 9 || des["main"] != 7 {
		t.Fatalf("rollback: %+v %v", r2, des)
	}
}

// Q-D7: a request that cannot be a rollout must not raise any group, canary
// included.
func TestMalformedStartRaisesNothing(t *testing.T) {
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer}, px{id: "m1", group: "main", applied: prevVer})
	tests := []struct {
		name string
		req  wire.RolloutRequest
		prev uint64
	}{
		{"empty tenant", wire.RolloutRequest{Tenant: "", Version: ver}, prevVer},
		{"bad tenant", wire.RolloutRequest{Tenant: "ACME!", Version: ver}, prevVer},
		{"zero version", wire.RolloutRequest{Tenant: "acme", Version: 0}, prevVer},
		{"not newer", wire.RolloutRequest{Tenant: "acme", Version: prevVer}, prevVer},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := Start(tc.req, tc.prev, t0, dwell)
			if r.Phase != wire.PhaseHalted {
				t.Fatalf("phase %s", r.Phase)
			}
			for _, g := range []wire.ID{CanaryGroup, "main", "eu"} {
				if got := DesiredFor(r, g); got != tc.prev {
					t.Fatalf("DesiredFor(%s) = %d, want %d", g, got, tc.prev)
				}
			}
			got, des := Step(r, f, t0.Add(time.Hour))
			if got.Phase != wire.PhaseHalted {
				t.Fatalf("Step moved a halted rollout: %+v", got)
			}
			for g, v := range des {
				if v != tc.prev {
					t.Fatalf("Step desired %s = %d, want %d", g, v, tc.prev)
				}
			}
		})
	}
}

// A valid-looking request for a tenant that is not the fleet's halts on the
// first Step, and the canary must not have been raised for it.
func TestStepWrongTenantInCanaryRaisesNothing(t *testing.T) {
	r := Start(wire.RolloutRequest{Tenant: "other", Version: ver}, prevVer, t0, dwell)
	if r.Phase != wire.PhaseCanary {
		t.Fatalf("phase %s", r.Phase)
	}
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer}, px{id: "m1", group: "main", applied: prevVer})
	got, des := Step(r, f, t0)
	if got.Phase != wire.PhaseHalted || got.Reason != wire.ErrWrongTenant {
		t.Fatalf("got %+v", got)
	}
	if des[CanaryGroup] != prevVer || des["main"] != prevVer {
		t.Fatalf("desired %v", des)
	}
}

// A canary that was legitimately raised and then failed stays raised (M-D44).
func TestHaltedByCanaryFailureKeepsCanaryRaised(t *testing.T) {
	r := canaryRollout()
	f := fleetOf(px{id: "c1", group: CanaryGroup, applied: prevVer,
		err: &wire.ApplyError{Code: wire.ErrThreshold, Version: ver}}, px{id: "m1", group: "main", applied: prevVer})
	got, des := Step(r, f, t0)
	if got.Phase != wire.PhaseHalted || des[CanaryGroup] != ver || des["main"] != prevVer {
		t.Fatalf("got %+v %v", got, des)
	}
}
