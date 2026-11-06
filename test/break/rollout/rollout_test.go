// Package rolloutbreak holds black-box attack tests for the control-plane
// rollout package (task C-02). Sources: PRD G5/J6, ARCHITECTURE section 5 and the
// rollout LLD, M-D26, wire (RolloutRequest, FleetView), and the go doc of the
// rollout package.
package rolloutbreak

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const dwell = 5 * time.Minute

func req(version uint64, dwellSec uint64) wire.RolloutRequest {
	return wire.RolloutRequest{Tenant: "bank-a", Version: version, CanaryDwellSeconds: dwellSec}
}

type px struct {
	id      string
	group   wire.ID
	applied uint64
	health  wire.Health
	state   wire.ProxyState
	errv    uint64 // non-zero: LastError for that version
	errc    wire.ErrorCode
}

func fv(ps ...px) wire.FleetView {
	v := wire.FleetView{Tenant: "bank-a"}
	for _, p := range ps {
		pv := wire.ProxyView{ProxyID: wire.ID(p.id), Group: p.group, Health: p.health, State: p.state, AppliedVersion: p.applied}
		if p.errv != 0 {
			c := p.errc
			if c == "" {
				c = wire.ErrThreshold
			}
			pv.LastError = &wire.ApplyError{Code: c, Version: p.errv}
		}
		v.Proxies = append(v.Proxies, pv)
	}
	return v
}

func ok(id string, g wire.ID, applied uint64) px {
	return px{id: id, group: g, applied: applied, health: wire.HealthHealthy, state: wire.StateEnforcing}
}

func canaryOK(v uint64) px { return ok("c1", rollout.CanaryGroup, v) }

// invariantsHold checks the per-call guarantees of the LLD for any input.
func checkOutput(t *testing.T, label string, before, after rollout.Rollout, f wire.FleetView, des map[wire.ID]uint64) {
	t.Helper()
	for g, v := range des {
		if v < after.Previous {
			t.Fatalf("%s: group %q desired %d is below Previous %d (never lower a group)", label, g, v, after.Previous)
		}
	}
	for _, p := range f.Proxies {
		if _, ok := des[p.Group]; !ok {
			t.Fatalf("%s: group %q present in the fleet but missing from the desired map", label, p.Group)
		}
	}
	if after.Previous != before.Previous || after.Version != before.Version || after.Tenant != before.Tenant {
		t.Fatalf("%s: Step changed identity fields: %+v -> %+v", label, before, after)
	}
}

// --- Start --------------------------------------------------------------

func TestStartBasics(t *testing.T) {
	r := rollout.Start(req(8, 0), 7, t0, dwell)
	if r.Phase != wire.PhaseCanary || r.Tenant != "bank-a" || r.Version != 8 || r.Previous != 7 {
		t.Fatalf("bad start: %+v", r)
	}
	if !r.CanaryOK.IsZero() {
		t.Fatalf("CanaryOK must be zero until every canary acked: %v", r.CanaryOK)
	}
	if r.Dwell != dwell {
		t.Fatalf("zero request dwell must mean defaultDwell: got %v", r.Dwell)
	}
	r = rollout.Start(req(8, 90), 7, t0, dwell)
	if r.Dwell != 90*time.Second {
		t.Fatalf("request dwell not used: %v", r.Dwell)
	}
	if r.Reason != "" {
		t.Fatalf("Reason set on a healthy start: %q", r.Reason)
	}
}

func TestStartRejectsNonRollouts(t *testing.T) {
	cases := []struct {
		name string
		req  wire.RolloutRequest
		prev uint64
	}{
		{"same-version", req(7, 0), 7},
		{"lower-version (rollback by number)", req(3, 0), 7},
		{"version-zero", req(0, 0), 0},
		{"version-zero-prev-high", req(0, 0), 9},
		{"bad-tenant-empty", wire.RolloutRequest{Tenant: "", Version: 9}, 7},
		{"bad-tenant-upper", wire.RolloutRequest{Tenant: "BANK", Version: 9}, 7},
		{"max-prev", req(5, 0), math.MaxUint64},
		{"equal-max", req(math.MaxUint64, 0), math.MaxUint64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rollout.Start(c.req, c.prev, t0, dwell)
			if r.Phase != wire.PhaseHalted {
				t.Fatalf("Start(%+v, prev=%d) phase=%q, want halted", c.req, c.prev, r.Phase)
			}
			if r.Reason == "" || !r.Reason.Valid() {
				t.Fatalf("halted without a valid reason code: %q", r.Reason)
			}
			// A halted start never promotes and never lowers anything, whatever the fleet says.
			f := fv(canaryOK(c.req.Version), ok("m1", "main", c.req.Version), ok("m2", "main", c.prev))
			now := t0
			cur := r
			for i := 0; i < 20; i++ {
				now = now.Add(time.Hour)
				next, des := rollout.Step(cur, f, now)
				checkOutput(t, "halted-start", cur, next, f, des)
				if next.Phase != wire.PhaseHalted {
					t.Fatalf("halted start moved to %q", next.Phase)
				}
				if des["main"] != c.prev && des["main"] > c.prev {
					t.Fatalf("halted rollout widened non-canary group to %d (previous %d)", des["main"], c.prev)
				}
				cur = next
			}
		})
	}
}

func TestStartAcceptsMinimalAdvance(t *testing.T) {
	if r := rollout.Start(req(1, 0), 0, t0, dwell); r.Phase != wire.PhaseCanary {
		t.Fatalf("v1 over 0 should start: %+v", r)
	}
	if r := rollout.Start(req(math.MaxUint64, 0), math.MaxUint64-1, t0, dwell); r.Phase != wire.PhaseCanary {
		t.Fatalf("max over max-1 should start: %+v", r)
	}
}

func TestDwellOverflowAndCap(t *testing.T) {
	cases := []struct {
		name     string
		secs     uint64
		def      time.Duration
		wantDwel time.Duration
	}{
		{"exact-cap", uint64(rollout.MaxDwell / time.Second), dwell, rollout.MaxDwell},
		{"cap-plus-1s", uint64(rollout.MaxDwell/time.Second) + 1, dwell, rollout.MaxDwell},
		{"int64-seconds-overflow-boundary", math.MaxInt64/uint64(time.Second) + 1, dwell, rollout.MaxDwell},
		{"seconds-9223372037 (x1e9 wraps negative)", 9223372037, dwell, rollout.MaxDwell},
		{"2^63", 1 << 63, dwell, rollout.MaxDwell},
		{"max-uint64", math.MaxUint64, dwell, rollout.MaxDwell},
		{"wraps-to-small-positive (2^64/1e9 multiples)", 18446744074, dwell, rollout.MaxDwell},
		{"default-over-cap", 0, 100 * rollout.MaxDwell, rollout.MaxDwell},
		{"default-max-int64", 0, time.Duration(math.MaxInt64), rollout.MaxDwell},
		{"default-negative-clamped-to-zero", 0, -time.Hour, 0},
		{"default-min-int64-clamped-to-zero", 0, time.Duration(math.MinInt64), 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rollout.Start(req(2, c.secs), 1, t0, c.def)
			if r.Dwell < 0 || r.Dwell > rollout.MaxDwell {
				t.Fatalf("Dwell %v out of [0, MaxDwell]", r.Dwell)
			}
			if r.Dwell != c.wantDwel {
				t.Fatalf("Dwell = %v, want %v", r.Dwell, c.wantDwel)
			}
			// The dwell must actually hold promotion back: canary acked at t0,
			// one dwell-1ns later still no promotion.
			if r.Dwell > 0 {
				f := fv(canaryOK(2), ok("m", "main", 1))
				r1, _ := rollout.Step(r, f, t0)
				r2, des := rollout.Step(r1, f, t0.Add(r.Dwell-1))
				if r2.Phase != wire.PhaseCanary {
					t.Fatalf("promoted before dwell elapsed: %+v", r2)
				}
				if des["main"] > 1 {
					t.Fatalf("main desired %d before dwell elapsed", des["main"])
				}
			}
		})
	}
}

// --- Step: canary phase --------------------------------------------------

func TestCanaryPhaseDesiredVersions(t *testing.T) {
	r := rollout.Start(req(8, 300), 7, t0, dwell)
	f := fv(ok("c1", rollout.CanaryGroup, 7), ok("m1", "main", 7), ok("m2", "edge", 7))
	next, des := rollout.Step(r, f, t0)
	checkOutput(t, "canary", r, next, f, des)
	if des[rollout.CanaryGroup] != 8 || des["main"] != 7 || des["edge"] != 7 || len(des) != 3 {
		t.Fatalf("desired = %v, want canary 8, others 7", des)
	}
	if next.Phase != wire.PhaseCanary {
		t.Fatalf("phase = %q", next.Phase)
	}
}

func TestOnlyExactCanaryGroupIsCanary(t *testing.T) {
	r := rollout.Start(req(8, 1), 7, t0, dwell)
	for _, g := range []wire.ID{"canary-2", "canary1", "Canary", "canar", "canaryx", "main-canary"} {
		f := fv(ok("x1", g, 8), ok("m", "main", 7))
		now := t0
		cur := r
		for i := 0; i < 5; i++ {
			now = now.Add(time.Hour)
			var des map[wire.ID]uint64
			cur, des = rollout.Step(cur, f, now)
			if cur.Phase == wire.PhasePromoting || cur.Phase == wire.PhaseComplete {
				t.Fatalf("group %q treated as canary: phase %q", g, cur.Phase)
			}
			if des[g] != 7 {
				t.Fatalf("group %q desired %d, want previous 7", g, des[g])
			}
		}
	}
}

func TestNoCanaryProxiesWaitsForever(t *testing.T) {
	r := rollout.Start(req(8, 0), 7, t0, 0)
	for _, f := range []wire.FleetView{{Tenant: "bank-a"}, fv(ok("m1", "main", 8)), fv(ok("m1", "main", 7))} {
		cur := r
		now := t0
		for i := 0; i < 10; i++ {
			now = now.Add(24 * time.Hour)
			var des map[wire.ID]uint64
			cur, des = rollout.Step(cur, f, now)
			checkOutput(t, "no-canary", r, cur, f, des)
			if cur.Phase != wire.PhaseCanary {
				t.Fatalf("with no canary proxies phase = %q after %v", cur.Phase, now.Sub(t0))
			}
			if des["main"] > 7 {
				t.Fatalf("main desired %d with no canary", des["main"])
			}
		}
	}
}

func TestPromoteOnlyAfterDwell(t *testing.T) {
	r := rollout.Start(req(8, 300), 7, t0, 0)
	f := fv(canaryOK(8), ok("m1", "main", 7))

	r1, d1 := rollout.Step(r, f, t0)
	checkOutput(t, "ack", r, r1, f, d1)
	if r1.Phase != wire.PhaseCanary || r1.CanaryOK.IsZero() {
		t.Fatalf("first ack should start the dwell clock: %+v", r1)
	}
	if !r1.CanaryOK.Equal(t0) {
		t.Fatalf("CanaryOK = %v, want first-ack time %v", r1.CanaryOK, t0)
	}
	if d1["main"] != 7 {
		t.Fatalf("main desired %d during dwell", d1["main"])
	}

	// One nanosecond short of the dwell: no promotion.
	r2, d2 := rollout.Step(r1, f, t0.Add(300*time.Second-1))
	if r2.Phase != wire.PhaseCanary || d2["main"] != 7 {
		t.Fatalf("promoted 1ns early: %+v %v", r2, d2)
	}
	// The first-ack timestamp must not slide forward on later steps.
	if !r2.CanaryOK.Equal(t0) {
		t.Fatalf("CanaryOK moved from %v to %v", t0, r2.CanaryOK)
	}
	// Past the dwell: promote, and every group is desired the new version.
	r3, d3 := rollout.Step(r2, f, t0.Add(300*time.Second+time.Nanosecond))
	checkOutput(t, "promote", r2, r3, f, d3)
	if r3.Phase != wire.PhasePromoting {
		t.Fatalf("did not promote after dwell: %+v", r3)
	}
	if r3.Reason != "" {
		t.Fatalf("Reason set on promote: %q", r3.Reason)
	}
}

func TestCanaryBlipResetsDwell(t *testing.T) {
	r := rollout.Start(req(8, 300), 7, t0, 0)
	good := fv(canaryOK(8), ok("m1", "main", 7))
	stale := fv(px{id: "c1", group: rollout.CanaryGroup, applied: 8, health: wire.HealthStale, state: wire.StateEnforcing}, ok("m1", "main", 7))

	r1, _ := rollout.Step(r, good, t0)
	r2, _ := rollout.Step(r1, stale, t0.Add(100*time.Second))
	if r2.Phase != wire.PhaseCanary {
		t.Fatalf("stale canary should wait (not halt, not promote): %+v", r2)
	}
	r3, _ := rollout.Step(r2, good, t0.Add(200*time.Second))
	// "stayed healthy for Dwell": original first-ack + dwell has passed, but the
	// canary was not healthy in between.
	r4, d4 := rollout.Step(r3, good, t0.Add(300*time.Second+time.Second))
	if r4.Phase != wire.PhaseCanary || d4["main"] != 7 {
		t.Fatalf("promoted although the canary was stale mid-dwell (dwell must restart): %+v", r4)
	}
	// And it does promote once a full dwell has passed since it recovered.
	r5, _ := rollout.Step(r4, good, t0.Add(200*time.Second+300*time.Second+time.Second))
	if r5.Phase != wire.PhasePromoting {
		t.Fatalf("never promoted after recovery + full dwell: %+v", r5)
	}
}

func TestPromotionNeedsEveryCanaryHealthyEnforcingAndAcked(t *testing.T) {
	bad := map[string]px{
		"canary-behind":       {id: "c2", group: rollout.CanaryGroup, applied: 7, health: wire.HealthHealthy, state: wire.StateEnforcing},
		"canary-no-policy":    {id: "c2", group: rollout.CanaryGroup, applied: 0, health: wire.HealthHealthy, state: wire.StateEnforcing},
		"canary-stale":        {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthStale, state: wire.StateEnforcing},
		"canary-safe-mode":    {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: wire.StateSafeMode},
		"canary-deny-all":     {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: wire.StateDenyAll},
		"canary-booting":      {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: wire.StateBooting},
		"canary-bogus-state":  {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: "bogus"},
		"canary-empty-state":  {id: "c2", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: ""},
		"canary-bogus-health": {id: "c2", group: rollout.CanaryGroup, applied: 8, health: "bogus", state: wire.StateEnforcing},
		"canary-empty-health": {id: "c2", group: rollout.CanaryGroup, applied: 8, health: "", state: wire.StateEnforcing},
	}
	for name, second := range bad {
		t.Run(name, func(t *testing.T) {
			r := rollout.Start(req(8, 1), 7, t0, 0)
			f := fv(canaryOK(8), second, ok("m1", "main", 7))
			cur := r
			for i := 1; i <= 8; i++ {
				var des map[wire.ID]uint64
				cur, des = rollout.Step(cur, f, t0.Add(time.Duration(i)*time.Hour))
				checkOutput(t, name, r, cur, f, des)
				if cur.Phase == wire.PhasePromoting || cur.Phase == wire.PhaseComplete {
					t.Fatalf("promoted with one unhealthy/unacked canary proxy: %+v", cur)
				}
				if des["main"] > 7 {
					t.Fatalf("main group widened to %d without canary success", des["main"])
				}
			}
		})
	}
}

func TestCanaryHaltCases(t *testing.T) {
	cases := []struct {
		name   string
		canary px
		reason wire.ErrorCode // "" = any valid reason
	}{
		{"lost", px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthLost, state: wire.StateEnforcing}, wire.ErrCanaryLost},
		{"lost-after-ack", px{id: "c1", group: rollout.CanaryGroup, applied: 8, health: wire.HealthLost, state: wire.StateEnforcing}, wire.ErrCanaryLost},
		{"apply-error-this-version", px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthHealthy, state: wire.StateEnforcing, errv: 8, errc: wire.ErrThreshold}, wire.ErrThreshold},
		{"apply-error-expired", px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthHealthy, state: wire.StateEnforcing, errv: 8, errc: wire.ErrExpired}, wire.ErrExpired},
		{"apply-error-persist", px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthStale, state: wire.StateEnforcing, errv: 8, errc: wire.ErrPersist}, wire.ErrPersist},
		{"tampered", px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthHealthy, state: wire.StateTampered}, ""},
		{"tampered-after-ack", px{id: "c1", group: rollout.CanaryGroup, applied: 8, health: wire.HealthHealthy, state: wire.StateTampered}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := rollout.Start(req(8, 60), 7, t0, 0)
			f := fv(c.canary, canaryOK(8), ok("m1", "main", 7)) // second canary is perfect
			f.Proxies[1].ProxyID = "c2"
			next, des := rollout.Step(r, f, t0)
			checkOutput(t, c.name, r, next, f, des)
			if next.Phase != wire.PhaseHalted {
				t.Fatalf("phase = %q, want halted", next.Phase)
			}
			if !next.Reason.Valid() || next.Reason == "" {
				t.Fatalf("halted without a valid reason: %q", next.Reason)
			}
			if c.reason != "" && next.Reason != c.reason {
				t.Fatalf("reason = %q, want %q", next.Reason, c.reason)
			}
			if des["main"] != 7 || des[rollout.CanaryGroup] != 8 {
				t.Fatalf("halted desired = %v, want canary 8, main 7", des)
			}
			// Terminal: even a perfect fleet later does not resume.
			good := fv(canaryOK(8), ok("m1", "main", 8))
			n2, d2 := rollout.Step(next, good, t0.Add(48*time.Hour))
			if n2.Phase != wire.PhaseHalted || n2.Reason != next.Reason || d2["main"] != 7 {
				t.Fatalf("halted rollout resumed or changed reason: %+v %v", n2, d2)
			}
		})
	}
}

func TestHaltAfterDwellStartedAndOnLaterStep(t *testing.T) {
	r := rollout.Start(req(8, 600), 7, t0, 0)
	good := fv(canaryOK(8), ok("m1", "main", 7))
	r1, _ := rollout.Step(r, good, t0)
	bad := fv(px{id: "c1", group: rollout.CanaryGroup, applied: 8, health: wire.HealthLost, state: wire.StateEnforcing}, ok("m1", "main", 7))
	r2, d2 := rollout.Step(r1, bad, t0.Add(599*time.Second))
	if r2.Phase != wire.PhaseHalted || r2.Reason != wire.ErrCanaryLost {
		t.Fatalf("canary lost mid-dwell must halt with canary_lost: %+v", r2)
	}
	if d2["main"] != 7 {
		t.Fatalf("main desired %d after halt", d2["main"])
	}
	// Even if the dwell has elapsed in the same step in which the canary is found lost.
	r3, _ := rollout.Step(r1, bad, t0.Add(700*time.Second))
	if r3.Phase != wire.PhaseHalted {
		t.Fatalf("lost canary + elapsed dwell promoted: %+v", r3)
	}
}

func TestErrorForOtherVersionDoesNotHalt(t *testing.T) {
	// ARCH 10 rollout: "halts on a canary apply error for this version".
	r := rollout.Start(req(8, 60), 7, t0, 0)
	c := canaryOK(8)
	c.errv, c.errc = 6, wire.ErrExpired // stale error about an old attempt
	f := fv(c, ok("m1", "main", 7))
	next, _ := rollout.Step(r, f, t0)
	if next.Phase == wire.PhaseHalted {
		t.Fatalf("halted on an apply error for a different (older) version: %+v", next)
	}
}

// --- Step: promoting / complete ------------------------------------------

func promotingRollout(t *testing.T) rollout.Rollout {
	t.Helper()
	r := rollout.Start(req(8, 60), 7, t0, 0)
	f := fv(canaryOK(8), ok("m1", "main", 7))
	r1, _ := rollout.Step(r, f, t0)
	r2, d := rollout.Step(r1, f, t0.Add(2*time.Minute))
	if r2.Phase != wire.PhasePromoting {
		t.Fatalf("setup: did not reach promoting: %+v", r2)
	}
	_ = d
	return r2
}

func TestPromotingDesiredAndComplete(t *testing.T) {
	r := promotingRollout(t)
	f := fv(canaryOK(8), ok("m1", "main", 7), ok("e1", "edge", 8))
	next, des := rollout.Step(r, f, t0.Add(3*time.Minute))
	checkOutput(t, "promoting", r, next, f, des)
	if des[rollout.CanaryGroup] != 8 || des["main"] != 8 || des["edge"] != 8 {
		t.Fatalf("promoting: all groups must be desired 8, got %v", des)
	}
	if next.Phase != wire.PhasePromoting {
		t.Fatalf("complete too early (main still on 7): %+v", next)
	}
	done := fv(canaryOK(8), ok("m1", "main", 8), ok("e1", "edge", 8))
	n2, d2 := rollout.Step(next, done, t0.Add(4*time.Minute))
	if n2.Phase != wire.PhaseComplete {
		t.Fatalf("all applied but phase = %q", n2.Phase)
	}
	if d2["main"] != 8 || d2["edge"] != 8 || d2[rollout.CanaryGroup] != 8 {
		t.Fatalf("complete desired: %v", d2)
	}
	// Terminal: a later stale/regressed fleet does not undo it or lower desired.
	reg := fv(canaryOK(8), ok("m1", "main", 3), ok("e1", "edge", 1))
	n3, d3 := rollout.Step(n2, reg, t0.Add(time.Hour))
	if n3.Phase != wire.PhaseComplete || d3["main"] != 8 || d3["edge"] != 8 {
		t.Fatalf("complete is not terminal / lowered desired: %+v %v", n3, d3)
	}
}

func TestCompleteIgnoresLostButNotStaleOrBehind(t *testing.T) {
	r := promotingRollout(t)
	lost := px{id: "m2", group: "main", applied: 7, health: wire.HealthLost, state: wire.StateEnforcing}
	f := fv(canaryOK(8), ok("m1", "main", 8), lost)
	n, _ := rollout.Step(r, f, t0.Add(3*time.Minute))
	if n.Phase != wire.PhaseComplete {
		t.Fatalf("lost proxies must not block completion: %+v", n)
	}
	stale := px{id: "m2", group: "main", applied: 7, health: wire.HealthStale, state: wire.StateEnforcing}
	f2 := fv(canaryOK(8), ok("m1", "main", 8), stale)
	n2, _ := rollout.Step(r, f2, t0.Add(3*time.Minute))
	if n2.Phase != wire.PhasePromoting {
		t.Fatalf("a stale proxy still on 7 must block completion: %+v", n2)
	}
	nopol := px{id: "m2", group: "main", applied: 0, health: wire.HealthHealthy, state: wire.StateDenyAll}
	n3, _ := rollout.Step(r, fv(canaryOK(8), ok("m1", "main", 8), nopol), t0.Add(3*time.Minute))
	if n3.Phase != wire.PhasePromoting {
		t.Fatalf("a proxy with no policy must block completion: %+v", n3)
	}
}

func TestPromotingErrorThreshold(t *testing.T) {
	if rollout.PromoteErrorPercent != 20 {
		t.Fatalf("PromoteErrorPercent = %d, doc says 20", rollout.PromoteErrorPercent)
	}
	mk := func(nonCanary, failing int) wire.FleetView {
		ps := []px{canaryOK(8)}
		for i := 0; i < nonCanary; i++ {
			p := ok(fmt.Sprintf("m%03d", i), "main", 7)
			if i < failing {
				p.errv = 8
				p.errc = wire.ErrThreshold
			}
			ps = append(ps, p)
		}
		return fv(ps...)
	}
	cases := []struct {
		n, fail int
		halt    bool
	}{
		{5, 0, false}, {5, 1, false}, {5, 2, true}, {5, 5, true},
		{10, 2, false}, {10, 3, true},
		{100, 20, false}, {100, 21, true},
		{1, 0, false}, {1, 1, true},
		{4, 1, false}, // 25% > 20%: halts per doc "share ... exceeds"
		{3, 1, false},
	}
	// Exact arithmetic from the doc: halt iff share exceeds 20%, i.e. fail*100 > 20*n.
	for i := range cases {
		cases[i].halt = cases[i].fail*100 > rollout.PromoteErrorPercent*cases[i].n
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%d-of-%d", c.fail, c.n), func(t *testing.T) {
			r := promotingRollout(t)
			f := mk(c.n, c.fail)
			next, des := rollout.Step(r, f, t0.Add(3*time.Minute))
			checkOutput(t, "threshold", r, next, f, des)
			if c.halt && next.Phase != wire.PhaseHalted {
				t.Fatalf("%d of %d failing: want halted, got %q", c.fail, c.n, next.Phase)
			}
			if !c.halt && next.Phase == wire.PhaseHalted {
				t.Fatalf("%d of %d failing: halted but is within %d%%", c.fail, c.n, rollout.PromoteErrorPercent)
			}
			if c.halt {
				if !next.Reason.Valid() || next.Reason == "" {
					t.Fatalf("halted without reason: %q", next.Reason)
				}
				// M-D44: a halt while Promoting freezes every group at Version.
				if des["main"] != 8 || des[rollout.CanaryGroup] != 8 {
					t.Fatalf("halted-while-promoting desired = %v, want canary 8 / main 8 (M-D44: freeze, never lower)", des)
				}
				if !next.Promoted {
					t.Fatalf("halted by promotion errors but Promoted is false: %+v", next)
				}
			}
		})
	}
}

func TestPromotingErrorForOtherVersionIgnored(t *testing.T) {
	r := promotingRollout(t)
	var ps []px
	ps = append(ps, canaryOK(8))
	for i := 0; i < 5; i++ {
		p := ok(fmt.Sprintf("m%d", i), "main", 7)
		p.errv, p.errc = 5, wire.ErrExpired // old failures
		ps = append(ps, p)
	}
	next, _ := rollout.Step(r, fv(ps...), t0.Add(3*time.Minute))
	if next.Phase == wire.PhaseHalted {
		t.Fatalf("halted on errors about an older version: %+v", next)
	}
}

func TestCanaryErrorsDoNotCountAsMainShare(t *testing.T) {
	// The share is over non-canary proxies; a failing canary alone must not halt
	// a promoting rollout through the percentage rule (one canary of 1 = 100%).
	r := promotingRollout(t)
	c := canaryOK(8)
	c.errv, c.errc = 8, wire.ErrThreshold
	var ps []px
	ps = append(ps, c)
	for i := 0; i < 10; i++ {
		ps = append(ps, ok(fmt.Sprintf("m%d", i), "main", 8))
	}
	next, _ := rollout.Step(r, fv(ps...), t0.Add(3*time.Minute))
	if next.Phase == wire.PhaseHalted {
		t.Fatalf("go doc: Promoting halts on the share of NON-canary proxies; a canary error alone halted it: %+v", next)
	}
}

// --- Terminal phases, unknown phases, never lowering ----------------------

func TestTerminalPhasesNeverChange(t *testing.T) {
	perfect := fv(canaryOK(8), ok("m1", "main", 8), ok("e1", "edge", 8))
	broken := fv(px{id: "c1", group: rollout.CanaryGroup, applied: 0, health: wire.HealthLost, state: wire.StateTampered}, ok("m1", "main", 0))
	for _, phase := range []wire.RolloutPhase{wire.PhaseHalted, wire.PhaseComplete} {
		for name, f := range map[string]wire.FleetView{"perfect": perfect, "broken": broken, "empty": {}} {
			r := rollout.Rollout{Tenant: "bank-a", Version: 8, Previous: 7, Phase: phase, Reason: wire.ErrCanaryLost, Dwell: dwell, CanaryOK: t0}
			if phase == wire.PhaseComplete {
				r.Reason = ""
			}
			n, des := rollout.Step(r, f, t0.Add(100*time.Hour))
			checkOutput(t, string(phase)+"/"+name, r, n, f, des)
			if n.Phase != phase {
				t.Fatalf("%s/%s: phase changed to %q", phase, name, n.Phase)
			}
			if phase == wire.PhaseHalted {
				for g, v := range des {
					if g == rollout.CanaryGroup && v != 8 || g != rollout.CanaryGroup && v != 7 {
						t.Fatalf("halted desired wrong: %v", des)
					}
				}
				// Same state with Promoted set (a halt during Promoting): all groups at Version.
				rp := r
				rp.Promoted = true
				_, desP := rollout.Step(rp, f, t0.Add(100*time.Hour))
				for g, v := range desP {
					if v != 8 {
						t.Fatalf("halted+promoted %s: group %q desired %d, want 8 (M-D44)", name, g, v)
					}
				}
			} else {
				for g, v := range des {
					if v != 8 {
						t.Fatalf("complete: group %q desired %d, want 8", g, v)
					}
				}
			}
		}
	}
}

func TestUnknownOrZeroPhaseFailsClosed(t *testing.T) {
	perfect := fv(canaryOK(8), ok("m1", "main", 8))
	for _, ph := range []wire.RolloutPhase{"", "bogus", "CANARY", "Promoting", "complete ", "done"} {
		t.Run(string(ph), func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			r := rollout.Rollout{Tenant: "bank-a", Version: 8, Previous: 7, Phase: ph, Dwell: 0, CanaryOK: t0}
			n, des := rollout.Step(r, perfect, t0.Add(time.Hour))
			checkOutput(t, "unknown-phase", r, n, perfect, des)
			if n.Phase == wire.PhasePromoting || n.Phase == wire.PhaseComplete {
				t.Fatalf("unknown phase %q advanced to %q", ph, n.Phase)
			}
			if des["main"] > 7 {
				t.Fatalf("unknown phase %q widened main group to %d", ph, des["main"])
			}
		})
	}
}

func TestZeroValueAndNilInputs(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	n, des := rollout.Step(rollout.Rollout{}, wire.FleetView{}, time.Time{})
	if n.Phase == wire.PhasePromoting || n.Phase == wire.PhaseComplete {
		t.Fatalf("zero rollout advanced: %+v", n)
	}
	if len(des) != 0 {
		t.Fatalf("empty fleet should give empty desired map, got %v", des)
	}
	_ = rollout.Start(wire.RolloutRequest{}, 0, time.Time{}, 0)
}

func TestHandBuiltCorruptRolloutDoesNotPromoteEarly(t *testing.T) {
	// The rollout record lives in the CP store (a JSON file); a corrupted value must
	// fail closed, not promote.
	f := fv(canaryOK(8), ok("m1", "main", 7))
	cases := map[string]rollout.Rollout{
		"canaryok-in-future":      {Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: dwell, CanaryOK: t0.Add(24 * time.Hour)},
		"huge-dwell":              {Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: time.Duration(math.MaxInt64), CanaryOK: t0},
		"huge-dwell-canaryok-old": {Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: time.Duration(math.MaxInt64), CanaryOK: time.Unix(1, 0)},
		"min-int-dwell-ok":        {Tenant: "bank-a", Version: 8, Previous: 7, Phase: wire.PhaseCanary, Dwell: dwell, CanaryOK: time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for name, r := range cases {
		t.Run(name, func(t *testing.T) {
			n, des := rollout.Step(r, f, t0)
			checkOutput(t, name, r, n, f, des)
			if n.Phase == wire.PhasePromoting || n.Phase == wire.PhaseComplete {
				t.Fatalf("corrupt record promoted: %+v", n)
			}
			if des["main"] > 7 {
				t.Fatalf("main widened to %d", des["main"])
			}
		})
	}
}

func TestClockGoingBackwardsDoesNotPromote(t *testing.T) {
	r := rollout.Start(req(8, 300), 7, t0, 0)
	f := fv(canaryOK(8), ok("m1", "main", 7))
	r1, _ := rollout.Step(r, f, t0)
	// CP clock stepped back by an hour, then steps again: elapsed is negative.
	r2, d2 := rollout.Step(r1, f, t0.Add(-time.Hour))
	if r2.Phase != wire.PhaseCanary || d2["main"] != 7 {
		t.Fatalf("negative elapsed promoted: %+v %v", r2, d2)
	}
	if r2.Phase == wire.PhaseCanary && !r2.CanaryOK.IsZero() && r2.CanaryOK.Before(t0) {
		t.Fatalf("CanaryOK moved backwards to %v", r2.CanaryOK)
	}
}

func TestCrossTenantFleetDoesNotDriveRollout(t *testing.T) {
	// The FleetView names its tenant; a view for another tenant says nothing about
	// this rollout (PRD J4/tenant isolation, ARCH section 8 last row).
	r := rollout.Start(req(8, 0), 7, t0, 0)
	other := fv(canaryOK(8), ok("m1", "main", 8))
	other.Tenant = "city-b"
	cur := r
	now := t0
	for i := 0; i < 5; i++ {
		now = now.Add(time.Hour)
		var des map[wire.ID]uint64
		cur, des = rollout.Step(cur, other, now)
		if cur.Phase == wire.PhasePromoting || cur.Phase == wire.PhaseComplete {
			t.Fatalf("a FleetView of another tenant promoted this tenant's rollout: %+v", cur)
		}
		if des["main"] > 7 {
			t.Fatalf("a FleetView of another tenant widened main to %d", des["main"])
		}
	}
}

// --- Properties over random scenarios ------------------------------------

func TestRandomScenarioInvariants(t *testing.T) {
	healths := []wire.Health{wire.HealthHealthy, wire.HealthHealthy, wire.HealthHealthy, wire.HealthStale, wire.HealthLost}
	states := []wire.ProxyState{wire.StateEnforcing, wire.StateEnforcing, wire.StateEnforcing, wire.StateSafeMode, wire.StateDenyAll, wire.StateTampered, wire.StateBooting}
	groups := []wire.ID{rollout.CanaryGroup, rollout.CanaryGroup, "main", "main", "edge"}
	codes := []wire.ErrorCode{wire.ErrThreshold, wire.ErrExpired, wire.ErrNotNewer, wire.ErrMalformed, wire.ErrPersist}

	for seed := int64(1); seed <= 300; seed++ {
		rng := rand.New(rand.NewSource(seed))
		prev := uint64(rng.Intn(5))
		ver := prev + uint64(1+rng.Intn(3))
		if rng.Intn(10) == 0 {
			ver = prev // invalid start
		}
		r := rollout.Start(req(ver, uint64(rng.Intn(3))*60), prev, t0, time.Minute)
		now := t0
		lastDesired := map[wire.ID]uint64{}
		rank := map[wire.RolloutPhase]int{wire.PhaseCanary: 0, wire.PhasePromoting: 1, wire.PhaseComplete: 2, wire.PhaseHalted: 2}
		n := 3 + rng.Intn(12)
		var proxies []px
		for i := 0; i < n; i++ {
			proxies = append(proxies, px{id: fmt.Sprintf("p%02d", i), group: groups[rng.Intn(len(groups))], applied: prev})
		}
		for step := 0; step < 40; step++ {
			now = now.Add(time.Duration(rng.Intn(120)) * time.Second)
			// Randomly evolve the fleet.
			for i := range proxies {
				p := &proxies[i]
				if rng.Intn(4) == 0 {
					p.applied = []uint64{prev, ver, ver, 0}[rng.Intn(4)]
				}
				p.health = healths[rng.Intn(len(healths))]
				p.state = states[rng.Intn(len(states))]
				p.errv, p.errc = 0, ""
				if rng.Intn(8) == 0 {
					p.errv, p.errc = []uint64{ver, ver, prev}[rng.Intn(3)], codes[rng.Intn(len(codes))]
				}
			}
			f := fv(proxies...)
			// Pristine copy for the no-mutation check.
			snapshot := fv(proxies...)

			next, des := rollout.Step(r, f, now)
			label := fmt.Sprintf("seed %d step %d", seed, step)
			checkOutput(t, label, r, next, f, des)
			if !reflect.DeepEqual(f, snapshot) {
				t.Fatalf("%s: Step modified the fleet view", label)
			}
			// Phase graph: only canary->promoting|halted|canary, promoting->complete|halted|promoting.
			switch r.Phase {
			case wire.PhaseHalted, wire.PhaseComplete:
				if next.Phase != r.Phase {
					t.Fatalf("%s: terminal %q -> %q", label, r.Phase, next.Phase)
				}
			case wire.PhaseCanary:
				if next.Phase == wire.PhaseComplete {
					t.Fatalf("%s: canary jumped straight to complete", label)
				}
			case wire.PhasePromoting:
				if next.Phase == wire.PhaseCanary {
					t.Fatalf("%s: promoting went back to canary", label)
				}
			}
			if rank[next.Phase] < rank[r.Phase] {
				t.Fatalf("%s: phase went backwards %q -> %q", label, r.Phase, next.Phase)
			}
			// Non-canary groups only move beyond Previous in Promoting/Complete.
			for g, v := range des {
				if g != rollout.CanaryGroup && v > r.Previous && next.Phase != wire.PhasePromoting && next.Phase != wire.PhaseComplete && !(next.Phase == wire.PhaseHalted && next.Promoted) {
					t.Fatalf("%s: group %q desired %d > previous %d while phase %q", label, g, v, r.Previous, next.Phase)
				}
				if v > r.Version && v > r.Previous {
					t.Fatalf("%s: group %q desired %d above the rollout version %d", label, g, v, r.Version)
				}
				if old, ok := lastDesired[g]; ok && v < old {
					t.Fatalf("%s: group %q desired went DOWN %d -> %d", label, g, old, v)
				}
				lastDesired[g] = v
			}
			// DesiredFor must agree with what Step returned (the fleet page shows DesiredFor).
			for g, v := range des {
				if dv := rollout.DesiredFor(next, g); dv != v {
					t.Fatalf("%s: DesiredFor(next, %q) = %d but Step returned %d (phase %q promoted %v)", label, g, dv, v, next.Phase, next.Promoted)
				}
			}
			// Promoted is only ever set on a halted rollout, and only by a halt out of Promoting.
			if next.Promoted && (next.Phase != wire.PhaseHalted || r.Phase != wire.PhasePromoting && !r.Promoted) {
				t.Fatalf("%s: Promoted=true after %q -> %q (was %q)", label, r.Phase, next.Phase, r.Phase)
			}
			if r.Promoted && !next.Promoted {
				t.Fatalf("%s: Promoted flag cleared by Step", label)
			}
			// A halted rollout started invalid must stay halted; a rollout that was
			// never given a good canary must not leave the canary phase.
			if r.Phase == wire.PhaseHalted && next.Phase != wire.PhaseHalted {
				t.Fatalf("%s: halted resumed", label)
			}
			// Reason is set exactly when halted.
			if next.Phase == wire.PhaseHalted && (next.Reason == "" || !next.Reason.Valid()) {
				t.Fatalf("%s: halted without valid reason %q", label, next.Reason)
			}
			if next.Phase != wire.PhaseHalted && next.Reason != "" {
				t.Fatalf("%s: reason %q set while %q", label, next.Reason, next.Phase)
			}
			// Promotion to Promoting is only legal if every canary proxy was
			// healthy, enforcing and at/above ver in THIS fleet view, and at least one exists.
			if r.Phase == wire.PhaseCanary && next.Phase == wire.PhasePromoting {
				c := 0
				for _, p := range f.Proxies {
					if p.Group == rollout.CanaryGroup {
						c++
						if p.Health != wire.HealthHealthy || p.State != wire.StateEnforcing || p.AppliedVersion < ver {
							t.Fatalf("%s: promoted while canary %+v is not healthy/enforcing/acked", label, p)
						}
					}
				}
				if c == 0 {
					t.Fatalf("%s: promoted with zero canary proxies", label)
				}
			}
			// Complete only if every non-lost proxy has applied the version.
			if r.Phase == wire.PhasePromoting && next.Phase == wire.PhaseComplete {
				for _, p := range f.Proxies {
					if p.Health != wire.HealthLost && p.AppliedVersion < ver {
						t.Fatalf("%s: complete while %+v is behind", label, p)
					}
				}
			}
			r = next
		}
	}
}

func FuzzStepNeverPanicsNeverLowers(f *testing.F) {
	f.Add(uint64(8), uint64(7), uint64(60), uint8(1), uint64(8), uint8(0), int64(100))
	f.Add(uint64(0), uint64(0), uint64(math.MaxUint64), uint8(9), uint64(math.MaxUint64), uint8(200), int64(-5))
	f.Fuzz(func(t *testing.T, ver, prev, dwellSec uint64, phase uint8, applied uint64, hs uint8, dt int64) {
		r := rollout.Start(req(ver, dwellSec), prev, t0, time.Minute)
		phases := []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete, "x"}
		r.Phase = phases[int(phase)%len(phases)]
		hl := []wire.Health{wire.HealthHealthy, wire.HealthStale, wire.HealthLost, ""}
		f1 := fv(
			px{id: "c1", group: rollout.CanaryGroup, applied: applied, health: hl[int(hs)%4], state: wire.StateEnforcing},
			px{id: "m1", group: "main", applied: applied, health: hl[int(hs>>2)%4], state: wire.StateEnforcing},
		)
		now := t0.Add(time.Duration(dt))
		last := map[wire.ID]uint64{}
		for i := 0; i < 3; i++ {
			n, des := rollout.Step(r, f1, now)
			for g, v := range des {
				if v < n.Previous {
					t.Fatalf("group %q desired %d < previous %d", g, v, n.Previous)
				}
				if old, ok := last[g]; ok && v < old {
					t.Fatalf("group %q desired went down %d -> %d (M-D44) phase %q -> %q", g, old, v, r.Phase, n.Phase)
				}
				last[g] = v
				if dv := rollout.DesiredFor(n, g); dv != v {
					t.Fatalf("DesiredFor %d != Step %d for %q", dv, v, g)
				}
			}
			if r.Phase == wire.PhaseHalted && n.Phase != wire.PhaseHalted {
				t.Fatal("halted resumed")
			}
			if n.Dwell < 0 && n.Phase == wire.PhasePromoting && r.Phase == wire.PhaseCanary {
				t.Fatal("negative dwell promoted")
			}
			r = n
			now = now.Add(time.Minute)
		}
	})
}

func TestConcurrentStepIsPure(t *testing.T) {
	r := rollout.Start(req(8, 60), 7, t0, 0)
	f := fv(canaryOK(8), ok("m1", "main", 7))
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				n, des := rollout.Step(r, f, t0.Add(time.Duration(i)*time.Second))
				des["main"] = 99 // returned map must be the caller's own
				_ = n
			}
		}()
	}
	wg.Wait()
	n, des := rollout.Step(r, f, t0)
	if des["main"] != 7 || n.Phase != wire.PhaseCanary {
		t.Fatalf("shared state leaked between calls: %v %+v", des, n)
	}
}

func TestHugeFleet(t *testing.T) {
	ps := []px{canaryOK(8)}
	for i := 0; i < 150000; i++ {
		ps = append(ps, ok(fmt.Sprintf("m%06d", i), wire.ID(fmt.Sprintf("g%d", i%50)), 7))
	}
	f := fv(ps...)
	r := rollout.Start(req(8, 1), 7, t0, 0)
	start := time.Now()
	n, des := rollout.Step(r, f, t0)
	n, des = rollout.Step(n, f, t0.Add(time.Hour))
	if time.Since(start) > 60*time.Second {
		t.Fatalf("Step over 150k proxies took %v", time.Since(start))
	}
	if n.Phase != wire.PhasePromoting || len(des) != 51 {
		t.Fatalf("unexpected: phase %q groups %d", n.Phase, len(des))
	}
}

// --- Integration with the real fleet view (C-01 + C-02 together) ----------

func TestRolloutDrivenByRealFleetView(t *testing.T) {
	th := fleet.DefaultThresholds()
	mk := func(id string, group wire.ID, applied uint64, seen time.Time, st wire.ProxyState) fleet.Last {
		r := wire.StatusReport{Tenant: "bank-a", ProxyID: wire.ID(id), State: st, AppliedVersion: applied}
		if applied > 0 {
			r.PolicyHash = wire.Hash(fmt.Sprintf("%064x", applied))
		}
		return fleet.Last{Group: group, Report: r, SeenAt: seen}
	}
	desired := map[wire.ID]uint64{rollout.CanaryGroup: 7, "main": 7}
	r := rollout.Start(req(8, 60), 7, t0, 0)

	// A canary that has never reported is lost -> halt, never promote.
	now := t0
	v := fleet.View("bank-a", desired, []fleet.Last{
		mk("c1", rollout.CanaryGroup, 0, time.Time{}, wire.StateBooting),
		mk("m1", "main", 7, now, wire.StateEnforcing),
	}, now, th)
	n, des := rollout.Step(r, v, now)
	if n.Phase != wire.PhaseHalted || n.Reason != wire.ErrCanaryLost || des["main"] != 7 {
		t.Fatalf("never-seen canary: %+v %v", n, des)
	}

	// A canary that acked, then goes silent for 2 minutes (lost) halts the rollout.
	v = fleet.View("bank-a", desired, []fleet.Last{
		mk("c1", rollout.CanaryGroup, 8, t0, wire.StateEnforcing),
		mk("m1", "main", 7, t0.Add(2*time.Minute), wire.StateEnforcing),
	}, t0.Add(2*time.Minute), th)
	n, _ = rollout.Step(r, v, t0.Add(2*time.Minute))
	if n.Phase != wire.PhaseHalted || n.Reason != wire.ErrCanaryLost {
		t.Fatalf("silent canary: %+v", n)
	}

	// Healthy canary through a full dwell promotes; status arrives every 10s.
	cur := r
	promotedAt := time.Duration(-1)
	for s := 0; s <= 120; s += 10 {
		now := t0.Add(time.Duration(s) * time.Second)
		v := fleet.View("bank-a", desired, []fleet.Last{
			mk("c1", rollout.CanaryGroup, 8, now, wire.StateEnforcing),
			mk("m1", "main", 7, now, wire.StateEnforcing),
		}, now, th)
		cur, _ = rollout.Step(cur, v, now)
		if cur.Phase == wire.PhasePromoting && promotedAt < 0 {
			promotedAt = now.Sub(t0)
		}
	}
	if promotedAt < 60*time.Second || promotedAt > 80*time.Second {
		t.Fatalf("promoted at %v, want within [60s, 80s] for dwell 60s", promotedAt)
	}
}

// --- M-D44 / C-D6: Halted freezes, Promoted flag --------------------------

// ARCH LLD rollout: "never lowers a group's desired version"; M-D44.
func TestHaltInPromotingFreezesAtVersionAcrossLaterSteps(t *testing.T) {
	r := promotingRollout(t)
	bad := fv(canaryOK(8), ok("m1", "main", 7), ok("m2", "main", 7), ok("m3", "main", 7))
	for i := range bad.Proxies[1:] {
		bad.Proxies[i+1].LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 8}
	}
	h, des := rollout.Step(r, bad, t0.Add(3*time.Minute))
	if h.Phase != wire.PhaseHalted || !h.Promoted {
		t.Fatalf("setup: want halted+promoted, got %+v", h)
	}
	if des["main"] != 8 || des[rollout.CanaryGroup] != 8 {
		t.Fatalf("halt step desired = %v", des)
	}
	// Whatever the fleet does afterwards (everything recovers, everything lost, empty), desired stays 8.
	for name, f := range map[string]wire.FleetView{
		"recovered": fv(canaryOK(8), ok("m1", "main", 8)),
		"all-lost":  fv(px{id: "c1", group: rollout.CanaryGroup, health: wire.HealthLost}, px{id: "m1", group: "main", health: wire.HealthLost}),
		"new-group": fv(canaryOK(8), ok("e1", "edge", 0)),
		"empty":     {},
	} {
		h2, d2 := rollout.Step(h, f, t0.Add(time.Hour))
		if h2 != h {
			t.Fatalf("%s: halted rollout changed: %+v -> %+v", name, h, h2)
		}
		for g, v := range d2 {
			if v != 8 {
				t.Fatalf("%s: group %q desired %d after halt-in-promoting, want 8 (frozen, M-D44)", name, g, v)
			}
		}
	}
	for _, g := range []wire.ID{"main", "edge", "", "canary", "never-seen"} {
		if v := rollout.DesiredFor(h, g); v != 8 {
			t.Fatalf("DesiredFor(halted+promoted, %q) = %d, want 8", g, v)
		}
	}
}

// C-D6: a halt in Canary keeps mains at Previous and does not set Promoted.
func TestHaltInCanaryDoesNotSetPromoted(t *testing.T) {
	r := rollout.Start(req(8, 60), 7, t0, 0)
	f := fv(px{id: "c1", group: rollout.CanaryGroup, applied: 7, health: wire.HealthLost}, ok("m1", "main", 7))
	h, des := rollout.Step(r, f, t0)
	if h.Phase != wire.PhaseHalted {
		t.Fatalf("lost canary did not halt: %+v", h)
	}
	if h.Promoted {
		t.Fatal("Promoted set by a Canary-phase halt")
	}
	if des["main"] != 7 || des[rollout.CanaryGroup] != 8 {
		t.Fatalf("desired = %v, want canary 8 main 7", des)
	}
	if rollout.DesiredFor(h, "main") != 7 || rollout.DesiredFor(h, rollout.CanaryGroup) != 8 {
		t.Fatal("DesiredFor disagrees for halted-in-canary")
	}
}

// C-D6: malformed halts never raise a group.
func TestMalformedHaltNeverRaisesAnyGroup(t *testing.T) {
	for _, c := range []struct {
		name string
		req  wire.RolloutRequest
		prev uint64
	}{
		{"same-version", req(7, 0), 7},
		{"older", req(3, 0), 7},
		{"zero", req(0, 0), 0},
		{"wrong-tenant", wire.RolloutRequest{Tenant: "BAD TENANT", Version: 9}, 7},
		{"empty-tenant", wire.RolloutRequest{Version: 9}, 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := rollout.Start(c.req, c.prev, t0, time.Minute)
			if r.Phase != wire.PhaseHalted {
				t.Fatalf("not halted: %+v", r)
			}
			if r.Promoted {
				t.Fatalf("malformed halt has Promoted set: %+v", r)
			}
			for _, g := range []wire.ID{"main", "edge", rollout.CanaryGroup} {
				if v := rollout.DesiredFor(r, g); v > c.prev {
					t.Fatalf("malformed rollout raised group %q to %d (previous %d)", g, v, c.prev)
				}
			}
			f := fv(canaryOK(9), ok("m1", "main", 9))
			_, des := rollout.Step(r, f, t0.Add(time.Hour))
			for g, v := range des {
				if v > c.prev {
					t.Fatalf("Step of malformed rollout raised %q to %d", g, v)
				}
			}
		})
	}
}

// A hand-built (corrupt file) rollout: Promoted outside Halted must not widen anything.
func TestPromotedFlagOnlyMattersWhenHalted(t *testing.T) {
	for _, ph := range []wire.RolloutPhase{wire.PhaseCanary, wire.PhaseComplete, wire.PhasePromoting, "", "bogus"} {
		r := rollout.Rollout{Tenant: "bank-a", Version: 8, Previous: 7, Phase: ph, Dwell: dwell, Promoted: true}
		without := r
		without.Promoted = false
		for _, g := range []wire.ID{"main", rollout.CanaryGroup} {
			if a, b := rollout.DesiredFor(r, g), rollout.DesiredFor(without, g); a != b {
				t.Fatalf("phase %q group %q: Promoted changed DesiredFor %d -> %d outside Halted", ph, g, b, a)
			}
		}
	}
}

// "Never below Previous" even for a corrupt Halted+Promoted with Version < Previous.
func TestDesiredForNeverBelowPreviousOrAboveMax(t *testing.T) {
	phases := []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete, "", "x"}
	for _, ph := range phases {
		for _, prom := range []bool{false, true} {
			for _, vp := range [][2]uint64{{8, 7}, {7, 8}, {0, 0}, {math.MaxUint64, 0}, {0, math.MaxUint64}, {math.MaxUint64, math.MaxUint64}} {
				r := rollout.Rollout{Tenant: "bank-a", Version: vp[0], Previous: vp[1], Phase: ph, Promoted: prom}
				for _, g := range []wire.ID{"main", rollout.CanaryGroup, ""} {
					v := rollout.DesiredFor(r, g)
					if v < r.Previous {
						t.Fatalf("%+v group %q: DesiredFor %d below Previous", r, g, v)
					}
					if v > r.Version && v > r.Previous {
						t.Fatalf("%+v group %q: DesiredFor %d above both Version and Previous", r, g, v)
					}
				}
			}
		}
	}
}

// A halt in Promoting reached through Step from every error shape sets Promoted exactly once and DesiredFor agrees.
func TestPromotingHaltSetsPromotedForEveryErrorCode(t *testing.T) {
	for _, c := range []wire.ErrorCode{wire.ErrThreshold, wire.ErrExpired, wire.ErrMalformed, wire.ErrPersist, wire.ErrNotNewer} {
		r := promotingRollout(t)
		f := fv(canaryOK(8), px{id: "m1", group: "main", applied: 7, health: wire.HealthHealthy, state: wire.StateEnforcing, errv: 8, errc: c})
		h, des := rollout.Step(r, f, t0.Add(3*time.Minute))
		if h.Phase != wire.PhaseHalted {
			t.Fatalf("code %q: 1 of 1 failing main did not halt", c)
		}
		if !h.Promoted || des["main"] != 8 || rollout.DesiredFor(h, "main") != 8 {
			t.Fatalf("code %q: Promoted=%v desired=%v", c, h.Promoted, des)
		}
	}
}
