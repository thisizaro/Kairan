package cpapibreak

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"kairan/internal/cp/api"
	"kairan/internal/wire"
)

// C-D7 (4), M-D44: a rollout needs a published version; a version at or below what any group is
// heading for is 409 conflict, so no group is ever lowered.
func TestRolloutStartRules(t *testing.T) {
	e := newEnv(t)
	if r := e.startRollout("bank-a", 1); r.code != 404 {
		t.Fatalf("rollout of an unpublished version: %d %s, want 404", r.code, r.body)
	}
	e.publish("bank-a", 1)
	e.publish("bank-a", 2)
	r := e.startRollout("bank-a", 1)
	if r.code != 200 {
		t.Fatalf("rollout v1: %d %s", r.code, r.body)
	}
	var v wire.RolloutView
	if err := json.Unmarshal(r.body, &v); err != nil || v.Tenant != "bank-a" || v.Version != 1 || v.Phase != wire.PhaseCanary {
		t.Fatalf("view %+v err %v, want bank-a v1 canary", v, err)
	}
	// Same version again while it is running: not newer than the canary-desired version.
	if r := e.startRollout("bank-a", 1); r.code != 409 || r.errCode() != wire.ErrConflict {
		t.Fatalf("restart of v1: %d %s, want 409 conflict", r.code, r.body)
	}
}

func TestRolloutNeverLowersAGroup(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	e.bring(2)
	// v1 exists in the store but every group is at 2.
	if r := e.startRollout("bank-a", 1); r.code != 409 {
		t.Fatalf("rollout back to v1: %d %s, want 409", r.code, r.body)
	}
	if r := e.startRollout("bank-a", 2); r.code != 409 {
		t.Fatalf("rollout of the current version again: %d %s, want 409", r.code, r.body)
	}
	for _, id := range []string{"p1", "p2", "c1"} {
		if row := e.row("bank-a", id); row.DesiredVersion != 2 {
			t.Fatalf("%s desired %d after refused rollbacks, want 2", id, row.DesiredVersion)
		}
	}
	// A lower version is never served to a proxy that has v2.
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 2)
	e.clk.BlockUntil(1)
	e.clk.Advance(wire.PollHold)
	if got := waitPoll(t, ch, 3*time.Second); got.code != 304 {
		t.Fatalf("poll with have=desired: %d %s, want 304", got.code, got.body)
	}
}

func TestRolloutRequestStrictness(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	good := `"tenant":"bank-a","version":1`
	cases := map[string]string{
		"empty":             ``,
		"null":              `null`,
		"array":             `[]`,
		"empty-object":      `{}`,
		"version-zero":      `{"tenant":"bank-a","version":0}`,
		"version-negative":  `{"tenant":"bank-a","version":-1}`,
		"version-float":     `{"tenant":"bank-a","version":1.5}`,
		"version-string":    `{"tenant":"bank-a","version":"1"}`,
		"version-overflow":  `{"tenant":"bank-a","version":18446744073709551616}`,
		"tenant-missing":    `{"version":1}`,
		"tenant-uppercase":  `{"tenant":"BANK-A","version":1}`,
		"tenant-space":      `{"tenant":"bank a","version":1}`,
		"tenant-empty":      `{"tenant":"","version":1}`,
		"tenant-too-long":   `{"tenant":"` + strings.Repeat("a", 64) + `","version":1}`,
		"unknown-field":     `{` + good + `,"x":1}`,
		"trailing-object":   `{` + good + `}{}`,
		"trailing-garbage":  `{` + good + `}x`,
		"dwell-negative":    `{` + good + `,"canary_dwell_seconds":-1}`,
		"dwell-float":       `{` + good + `,"canary_dwell_seconds":1.5}`,
		"dwell-string":      `{` + good + `,"canary_dwell_seconds":"5"}`,
		"canary-field-hack": `{` + good + `,"group":"main"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.do("POST", wire.PathRollouts, adminTok, []byte(body))
			if r.code/100 == 2 || r.code >= 500 {
				t.Fatalf("got %d %s", r.code, r.body)
			}
			if !r.errCode().Valid() {
				t.Fatalf("not a wire error: %s", r.body)
			}
		})
	}
	// Nothing was started by the bad requests.
	if _, code := e.rolloutView("bank-a"); code != 404 {
		t.Fatalf("a refused request left a rollout behind: %d", code)
	}
}

// A huge canary_dwell_seconds must not overflow time.Duration into a negative dwell that promotes at once.
func TestHugeDwellDoesNotPromoteImmediately(t *testing.T) {
	for _, secs := range []uint64{3600, 9223372036, 9223372037, 1 << 40, 1 << 62, 1<<64 - 1} {
		t.Run(fmt.Sprint(secs), func(t *testing.T) {
			e := newEnv(t)
			e.publish("bank-a", 1)
			r := e.do("POST", wire.PathRollouts, adminTok, mustJSON(wire.RolloutRequest{Tenant: "bank-a", Version: 1, CanaryDwellSeconds: secs}))
			if r.code/100 != 2 {
				if r.code >= 500 {
					t.Fatalf("server error %d", r.code)
				}
				return // refusing an absurd dwell is fine
			}
			e.mustStatus("c1", report("bank-a", "c1", 1, 1))
			e.clk.Advance(30 * time.Second)
			e.mustStatus("c1", report("bank-a", "c1", 1, 2))
			e.mustStatus("c1", report("bank-a", "c1", 1, 3))
			v, code := e.rolloutView("bank-a")
			if code != 200 || (v.Phase != wire.PhaseCanary) {
				t.Fatalf("dwell %ds, 30s after the canary ack: %+v (%d), want still canary", secs, v, code)
			}
			ctx, cancel := ctxCancel(t)
			defer cancel()
			ch := e.pollAsync(ctx, "p1", "bank-a", 0)
			e.clk.BlockUntil(1)
			stillWaiting(t, ch, 200*time.Millisecond)
		})
	}
}

// The default dwell applies for dwell 0, and the canary stays alone until it has passed (PRD G5).
func TestCanaryDwellIsHonoured(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	if r := e.startRollout("bank-a", 1); r.code != 200 {
		t.Fatal(r.code)
	}
	e.mustStatus("c1", report("bank-a", "c1", 1, 1))
	e.mustStatus("p1", report("bank-a", "p1", 0, 1))
	e.clk.Advance(5 * time.Second) // dwell is 10s
	e.mustStatus("c1", report("bank-a", "c1", 1, 2))
	if v, _ := e.rolloutView("bank-a"); v.Phase != wire.PhaseCanary {
		t.Fatalf("5s into a 10s dwell: %+v", v)
	}
	if row := e.row("bank-a", "p1"); row.DesiredVersion != 0 {
		t.Fatalf("main proxy is being steered to %d during the canary phase", row.DesiredVersion)
	}
	e.clk.Advance(6 * time.Second)
	e.mustStatus("c1", report("bank-a", "c1", 1, 3))
	if v, _ := e.rolloutView("bank-a"); v.Phase != wire.PhasePromoting {
		t.Fatalf("after the dwell: %+v, want promoting", v)
	}
	if row := e.row("bank-a", "p1"); row.DesiredVersion != 1 {
		t.Fatalf("main desired %d after promotion, want 1", row.DesiredVersion)
	}
}

// I3/G5: only the canary group's acks count toward the canary; group membership comes from the registry.
func TestMainProxiesCannotAckTheCanary(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	e.startRollout("bank-a", 1)
	// c1 is silent. p1 and p2 claim version 1 (nobody asked them to).
	for i := uint64(1); i <= 3; i++ {
		e.mustStatus("p1", report("bank-a", "p1", 1, i))
		e.mustStatus("p2", report("bank-a", "p2", 1, i))
		e.clk.Advance(20 * time.Second)
	}
	v, _ := e.rolloutView("bank-a")
	if v.Phase == wire.PhasePromoting || v.Phase == wire.PhaseComplete {
		t.Fatalf("rollout advanced to %s on acks from the main group alone", v.Phase)
	}
}

// Canary apply error halts; the rollout then never promotes, and main stays put (PRD G5/J6, M-D44).
func TestCanaryApplyErrorHaltsAndNeverPromotes(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	e.publish("bank-a", 2)
	e.startRollout("bank-a", 2)
	bad := report("bank-a", "c1", 1, 100)
	bad.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 2}
	e.mustStatus("c1", bad)
	v, code := e.rolloutView("bank-a")
	if code != 200 || v.Phase != wire.PhaseHalted || !v.Reason.Valid() || v.Reason == "" {
		t.Fatalf("after a canary apply error: %+v (%d), want halted with a reason", v, code)
	}
	// Later the canary reports healthy v2; a halted rollout stays halted.
	e.clk.Advance(30 * time.Second)
	e.mustStatus("c1", report("bank-a", "c1", 2, 101))
	e.clk.Advance(30 * time.Second)
	e.mustStatus("c1", report("bank-a", "c1", 2, 102))
	if v, _ := e.rolloutView("bank-a"); v.Phase != wire.PhaseHalted {
		t.Fatalf("a halted rollout moved on: %+v", v)
	}
	for _, id := range []string{"p1", "p2"} {
		if row := e.row("bank-a", id); row.DesiredVersion != 1 {
			t.Fatalf("%s desired %d after halt, want 1", id, row.DesiredVersion)
		}
	}
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 1)
	e.clk.BlockUntil(1)
	e.clk.Advance(wire.PollHold)
	if got := waitPoll(t, ch, 3*time.Second); got.code != 304 {
		t.Fatalf("main proxy poll after halt: %d %s, want 304", got.code, got.body)
	}
	// A halted rollout blocks the same version but a higher one can start a new rollout.
	e.publish("bank-a", 3)
	if r := e.startRollout("bank-a", 3); r.code != 200 {
		t.Fatalf("new rollout after halt: %d %s", r.code, r.body)
	}
}

// An enrolled canary that never reports is lost: halt with canary_lost, via a status from any proxy
// (step on arrival) and via the timer (Run) when nothing arrives.
func TestLostCanaryHaltsOnStatusArrival(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	e.publish("bank-a", 2)
	e.startRollout("bank-a", 2)
	e.clk.Advance(3 * time.Minute) // c1 silent for longer than the 2m lost threshold
	e.mustStatus("p1", report("bank-a", "p1", 1, 500))
	v, _ := e.rolloutView("bank-a")
	if v.Phase != wire.PhaseHalted || v.Reason != wire.ErrCanaryLost {
		t.Fatalf("silent canary: %+v, want halted/canary_lost", v)
	}
	if row := e.row("bank-a", "p1"); row.DesiredVersion != 1 {
		t.Fatalf("main raised to %d by a rollout whose canary was lost", row.DesiredVersion)
	}
}

func TestRunStepsRolloutsOnTheTimer(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.TickInterval = 5 * time.Second })
	e.bring(1)
	e.publish("bank-a", 2)
	e.startRollout("bank-a", 2)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.Run(ctx); close(done) }()
	halted := false
	for i := 0; i < 60 && !halted; i++ {
		e.clk.BlockUntil(1)
		e.clk.Advance(5 * time.Second)
		time.Sleep(5 * time.Millisecond)
		if v, _ := e.rolloutView("bank-a"); v.Phase == wire.PhaseHalted {
			halted = true
			if v.Reason != wire.ErrCanaryLost {
				t.Errorf("reason %q, want canary_lost", v.Reason)
			}
		}
	}
	if !halted {
		t.Error("no status arrived and the timer did not halt a rollout whose canary went silent")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
}

func TestRolloutGetParams(t *testing.T) {
	e := newEnv(t)
	for name, qs := range map[string]string{
		"none":        "",
		"empty":       "tenant=",
		"two":         "tenant=bank-a&tenant=bank-b",
		"bad-id":      "tenant=BAD",
		"traversal":   "tenant=../bank-a",
		"encoded-nul": "tenant=bank-a%00",
	} {
		r := e.do("GET", wire.PathRollouts+"?"+qs, adminTok, nil)
		if r.code != 400 && r.code != 404 {
			t.Errorf("%s: got %d %s, want 400/404", name, r.code, r.body)
		}
		if !r.errCode().Valid() {
			t.Errorf("%s: not a wire error: %s", name, r.body)
		}
	}
	if r := e.do("GET", wire.PathRollouts+"?tenant=bank-zzz", adminTok, nil); r.code != 404 {
		t.Errorf("unknown tenant: %d", r.code)
	}
	if r := e.do("GET", wire.PathRollouts+"?tenant=bank-a", adminTok, nil); r.code != 404 {
		t.Errorf("no rollout yet: %d", r.code)
	}
}

// Tenants have independent rollouts: starting bank-b's changes nothing for bank-a.
func TestRolloutsAreTenantScoped(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	if r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-b", 7), keyD, keyE)); r.code != 200 {
		t.Fatalf("publish bank-b: %d %s", r.code, r.body)
	}
	if r := e.startRollout("bank-b", 7); r.code != 200 {
		t.Fatalf("bank-b rollout: %d %s", r.code, r.body)
	}
	// bank-b has no canary group: its only proxy q1 is in "main", so it waits (nothing is promoted yet).
	if v, code := e.rolloutView("bank-a"); code != 200 || v.Version != 1 || v.Phase != wire.PhaseComplete {
		t.Fatalf("bank-a rollout disturbed: %+v (%d)", v, code)
	}
	for _, id := range []string{"p1", "p2", "c1"} {
		if row := e.row("bank-a", id); row.DesiredVersion != 1 {
			t.Fatalf("%s desired %d, want 1", id, row.DesiredVersion)
		}
	}
	// bank-a's proxies never see bank-b's envelope, with any have.
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 0)
	if got := waitPoll(t, ch, 3*time.Second); got.code != 200 || got.pr.Version != 1 {
		t.Fatalf("p1 poll: %d %s", got.code, got.body)
	}
}
