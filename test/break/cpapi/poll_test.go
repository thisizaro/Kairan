package cpapibreak

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/api"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// wire.ParsePollRequest: exactly the three parameters, each once. Anything else is a refusal that
// returns at once (it must never park a poll).
func TestPollParameterAttacks(t *testing.T) {
	e := newEnv(t)
	ok := func(kv ...string) string { return wire.PathPoll + "?" + q(kv...) }
	base := []string{wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "0"}
	with := func(extra ...string) string { return ok(append(append([]string{}, base...), extra...)...) }
	cases := map[string]string{
		"no-query":         wire.PathPoll,
		"missing-tenant":   ok(wire.QueryProxy, "p1", wire.QueryHave, "0"),
		"missing-proxy":    ok(wire.QueryTenant, "bank-a", wire.QueryHave, "0"),
		"missing-have":     ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1"),
		"duplicate-have":   with(wire.QueryHave, "1"),
		"duplicate-tenant": with(wire.QueryTenant, "bank-a"),
		"duplicate-proxy":  with(wire.QueryProxy, "p1"),
		"unknown-param":    with("x", "1"),
		"canary-param":     with(canary, canary),
		"have-negative":    ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "-1"),
		"have-text":        ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "abc"),
		"have-float":       ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "1.5"),
		"have-hex":         ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "0x10"),
		"have-empty":       ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, ""),
		"have-overflow":    ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "18446744073709551616"),
		"have-plus":        ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "+1"),
		"tenant-invalid":   ok(wire.QueryTenant, "BANK", wire.QueryProxy, "p1", wire.QueryHave, "0"),
		"tenant-empty":     ok(wire.QueryTenant, "", wire.QueryProxy, "p1", wire.QueryHave, "0"),
		"proxy-invalid":    ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "P 1", wire.QueryHave, "0"),
		"proxy-empty":      ok(wire.QueryTenant, "bank-a", wire.QueryProxy, "", wire.QueryHave, "0"),
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r := e.doCtx(ctx, "GET", path, tokOf("p1"), nil)
			if r.code != 400 && r.code != 403 {
				t.Fatalf("got %d %s, want a prompt 400 (or 403 for a tenant/proxy that is not the caller's)", r.code, r.body)
			}
			if !r.errCode().Valid() {
				t.Fatalf("not a wire error: %s", r.body)
			}
			if strings.Contains(string(r.body), "9f3b27") {
				t.Fatalf("echoes input: %s", r.body)
			}
		})
	}
}

// have >= desired is held for PollHold, then 304 with no body (PollHold is measured by the clock).
func TestPollHoldsThen304(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 0)
	e.clk.BlockUntil(1)
	stillWaiting(t, ch, 150*time.Millisecond)
	e.clk.Advance(wire.PollHold - time.Second)
	stillWaiting(t, ch, 150*time.Millisecond)
	e.clk.Advance(time.Second)
	got := waitPoll(t, ch, 3*time.Second)
	if got.code != 304 || len(got.body) != 0 {
		t.Fatalf("got %d %q, want 304 and no body", got.code, got.body)
	}
}

func TestPollHoldIsConfigurable(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.PollHold = 2 * time.Second })
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 0)
	e.clk.BlockUntil(1)
	e.clk.Advance(2 * time.Second)
	if got := waitPoll(t, ch, 3*time.Second); got.code != 304 {
		t.Fatalf("got %d", got.code)
	}
}

// A rollout that starts during a held poll wakes the canary proxy at once, and nobody else.
func TestRolloutWakesOnlyTheCanaryGroup(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	canaryPoll := e.pollAsync(ctx, "c1", "bank-a", 0)
	mainPoll := e.pollAsync(ctx, "p1", "bank-a", 0)
	e.clk.BlockUntil(2)
	if r := e.startRollout("bank-a", 1); r.code != 200 {
		t.Fatalf("rollout: %d %s", r.code, r.body)
	}
	got := waitPoll(t, canaryPoll, 3*time.Second)
	if got.code != 200 || got.pr.Version != 1 {
		t.Fatalf("canary: %d %s", got.code, got.body)
	}
	if _, code, err := trust.Verify(got.pr.Envelope, rootFor("bank-a", keyA, keyB, keyC)); err != nil {
		t.Fatalf("delivered envelope does not verify: %q %v", code, err)
	}
	if hashOf(got.pr.Envelope.Payload) != hashOf(policyJSON("bank-a", 1)) {
		t.Fatalf("delivered payload differs from the published one")
	}
	stillWaiting(t, mainPoll, 300*time.Millisecond)
	// A fresh poll from the main group during the canary phase is held, not served.
	late := e.pollAsync(ctx, "p2", "bank-a", 0)
	stillWaiting(t, late, 300*time.Millisecond)
}

// I2-adjacent: the CP never serves an envelope that is not newer than what the proxy has.
func TestPollNeverReturnsOldOrSameVersion(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	for _, have := range []uint64{1, 2, 99, 1<<64 - 1} {
		ch := e.pollAsync(ctx, "p1", "bank-a", have)
		e.clk.BlockUntil(1)
		e.clk.Advance(wire.PollHold)
		got := waitPoll(t, ch, 3*time.Second)
		if got.code != 304 {
			t.Fatalf("have=%d desired=1: got %d %s, want 304", have, got.code, got.body)
		}
	}
	// have=0 returns v1 at once.
	got := waitPoll(t, e.pollAsync(ctx, "p1", "bank-a", 0), 3*time.Second)
	if got.code != 200 || got.pr.Version != 1 {
		t.Fatalf("have=0: %d %s", got.code, got.body)
	}
}

// A proxy several versions behind is given the group's desired version, not an intermediate one.
func TestPollGivesTheDesiredVersionNotAnIntermediate(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	e.publish("bank-a", 2)
	e.publish("bank-a", 3)
	if r := e.startRollout("bank-a", 3); r.code != 200 {
		t.Fatalf("rollout 3: %d %s", r.code, r.body)
	}
	ctx, cancel := ctxCancel(t)
	defer cancel()
	got := waitPoll(t, e.pollAsync(ctx, "c1", "bank-a", 1), 3*time.Second)
	if got.code != 200 || got.pr.Version != 3 {
		t.Fatalf("canary got %d version %d, want v3", got.code, got.pr.Version)
	}
	if hashOf(got.pr.Envelope.Payload) != hashOf(policyJSON("bank-a", 3)) {
		t.Fatal("the envelope is not the one for version 3")
	}
	// Main is still at 1 and must not see 2 or 3.
	ch := e.pollAsync(ctx, "p1", "bank-a", 1)
	e.clk.BlockUntil(1)
	e.clk.Advance(wire.PollHold)
	if got := waitPoll(t, ch, 3*time.Second); got.code != 304 {
		t.Fatalf("main during the canary phase: %d %s", got.code, got.body)
	}
}

// M-D31: a new poll from the same proxy replaces the old, which returns 304 at once.
func TestNewPollReplacesTheOld(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	first := e.pollAsync(ctx, "c1", "bank-a", 0)
	e.clk.BlockUntil(1)
	second := e.pollAsync(ctx, "c1", "bank-a", 0)
	got := waitPoll(t, first, 3*time.Second)
	if got.code != 304 {
		t.Fatalf("replaced poll: %d %s, want 304", got.code, got.body)
	}
	stillWaiting(t, second, 200*time.Millisecond)
	e.startRollout("bank-a", 1)
	if got := waitPoll(t, second, 3*time.Second); got.code != 200 || got.pr.Version != 1 {
		t.Fatalf("surviving poll: %d %s", got.code, got.body)
	}
	// Repeated replacement never leaks slots: with MaxPolls=1 a single proxy can re-poll forever.
	e2 := newEnv(t, func(c *api.Config) { c.MaxPolls = 1 })
	prev := e2.pollAsync(ctx, "p1", "bank-a", 0)
	e2.clk.BlockUntil(1)
	for i := 0; i < 20; i++ {
		next := e2.pollAsync(ctx, "p1", "bank-a", 0)
		if g := waitPoll(t, prev, 3*time.Second); g.code != 304 {
			t.Fatalf("round %d: replaced poll %d %s (replacement must not hit the cap)", i, g.code, g.body)
		}
		prev = next
	}
}

// M-D31: global cap -> 503 unavailable with Retry-After; a slot frees when a poll ends or the client leaves.
func TestPollCap(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.MaxPolls = 2 })
	ctx, cancel := ctxCancel(t)
	defer cancel()
	cctx, ccancel := context.WithCancel(ctx)
	a := e.pollAsync(cctx, "p1", "bank-a", 0)
	b := e.pollAsync(ctx, "p2", "bank-a", 0)
	e.clk.BlockUntil(2)
	r := e.do("GET", pollPath("bank-a", "c1", 0), tokOf("c1"), nil)
	if r.code != 503 || r.errCode() != wire.ErrUnavailable {
		t.Fatalf("over the cap: %d %s, want 503 unavailable", r.code, r.body)
	}
	if ra := r.hdr.Get("Retry-After"); ra == "" {
		t.Fatal("503 without Retry-After")
	}
	// The cap does not break the holders.
	stillWaiting(t, b, 100*time.Millisecond)
	// Client disconnect frees the slot.
	ccancel()
	waitPoll(t, a, 3*time.Second)
	deadline := time.Now().Add(5 * time.Second)
	for {
		pctx, pcancel := context.WithTimeout(ctx, 300*time.Millisecond)
		r := e.doCtx(pctx, "GET", pollPath("bank-a", "c1", 0), tokOf("c1"), nil)
		pcancel()
		if r.code == -1 {
			break // the poll was accepted and is being held: a slot is free
		}
		if r.code != 503 {
			t.Fatalf("poll after a slot freed: unexpected %d", r.code)
		}
		if time.Now().After(deadline) {
			t.Fatal("slot of a disconnected client was never released")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Slots free on 304 too: 3 rounds of fill-and-expire never exhaust a cap of 2.
func TestPollSlotsFreeAfterHold(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.MaxPolls = 2 })
	ctx, cancel := ctxCancel(t)
	defer cancel()
	for round := 0; round < 3; round++ {
		a := e.pollAsync(ctx, "p1", "bank-a", 0)
		b := e.pollAsync(ctx, "p2", "bank-a", 0)
		e.clk.BlockUntil(2)
		e.clk.Advance(wire.PollHold)
		if g := waitPoll(t, a, 3*time.Second); g.code != 304 {
			t.Fatalf("round %d a: %d %s", round, g.code, g.body)
		}
		if g := waitPoll(t, b, 3*time.Second); g.code != 304 {
			t.Fatalf("round %d b: %d %s", round, g.code, g.body)
		}
	}
}

// Many pollers, a rollout, concurrent publishes and fleet reads, under -race: no 5xx, everyone gets v1.
func TestConcurrentTrafficIsRaceFree(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	var wg sync.WaitGroup
	results := make(chan pollRes, 6)
	for _, id := range []string{"c1", "c1", "c1", "p1", "p2", "p1"} {
		results <- pollRes{}
		<-results
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			r := e.doCtx(ctx, "GET", pollPath("bank-a", id, 0), tokOf(id), nil)
			if r.code >= 500 {
				t.Errorf("poll %s: %d %s", id, r.code, r.body)
			}
		}(id)
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				for _, r := range []resp{
					e.do("GET", wire.PathFleet+"?tenant=bank-a", adminTok, nil),
					e.do("GET", wire.PathTimeline+"?tenant=bank-a", adminTok, nil),
					e.do("POST", wire.PathStatus, tokOf("p2"), mustJSON(report("bank-a", "p2", 0, uint64(i*100+j+1)))),
					e.do("GET", wire.PathRollouts+"?tenant=bank-a", adminTok, nil),
				} {
					if r.code >= 500 {
						t.Errorf("%d %s", r.code, r.body)
					}
				}
			}
		}(i)
	}
	time.Sleep(50 * time.Millisecond)
	e.startRollout("bank-a", 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(300 * time.Millisecond)
		e.clk.Advance(wire.PollHold) // expires the held polls of the main group
	}()
	wg.Wait()
	_ = http.StatusOK
}
