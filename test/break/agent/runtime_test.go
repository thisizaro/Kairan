package agentbreak

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

// The expiry watcher flips Enforcing to SafeMode at effective_now = expires_at + skew; the policy stays loaded;
// a newer policy lifts SafeMode (agent doc "Expiry and the clock guard").
func TestExpiryWatcherFlipsToSafeModeAndNewerLifts(t *testing.T) {
	cp := newCP(t)
	env1, _ := validEnv(1)
	env2 := signedEnv(policyDoc(tenant, 2, t0.Add(-time.Hour), t0.Add(96*time.Hour)), keyA, keyC)
	var offerTwo atomic.Bool
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env1, 1)
		}
		if offerTwo.Load() {
			return pollJSON(env2, 2)
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "v1", func() bool { return r.appliedVersion() == 1 })

	r.clk.Advance(24*time.Hour + time.Minute) // expires_at + 1 min: inside the 2 min skew
	settle()
	if r.state() != wire.StateEnforcing {
		t.Fatalf("state %s inside the skew window, want enforcing", r.state())
	}
	r.clk.Advance(2 * time.Minute) // now past expires_at + skew
	waitFor(t, "safe mode", func() bool { return r.state() == wire.StateSafeMode })
	if a := r.hold.Load(); a.Policy == nil || a.Policy.Version != 1 {
		t.Errorf("safe mode dropped the policy: %+v", a)
	}
	if r.stats.Count(agent.MetricExpired) != 1 {
		t.Errorf("%s = %d, want 1", agent.MetricExpired, r.stats.Count(agent.MetricExpired))
	}
	waitFor(t, "safe_mode status", func() bool { s, _, ok := cp.lastStatus(); return ok && s.State == wire.StateSafeMode })
	if s, _, _ := cp.lastStatus(); s.AppliedVersion != 1 {
		t.Errorf("report in safe mode applied=%d", s.AppliedVersion)
	}
	// a stale in-flight policy never lifts it; a newer one does
	offerTwo.Store(true)
	r.advance(10*time.Second, 500*time.Millisecond)
	waitFor(t, "v2 enforcing", func() bool { return r.appliedVersion() == 2 && r.state() == wire.StateEnforcing })
}

// The wall clock set back does not give an expired policy a second life (S7, THREATS #12): effective_now keeps
// the monotonic progress, and the proxy reports clock_untrusted.
func TestClockSetBackAtRuntime(t *testing.T) {
	cp := newCP(t)
	env, _ := validEnv(1)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env, 1)
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "v1", func() bool { return r.appliedVersion() == 1 })
	r.advance(23*time.Hour, time.Hour)
	if r.state() != wire.StateEnforcing {
		t.Fatalf("state %s", r.state())
	}
	r.clk.Set(t0) // wall clock set back by 23 hours; monotonic time unchanged
	settle()
	if !r.guard.Untrusted() {
		t.Errorf("a 23 h step back is not reported untrusted")
	}
	waitFor(t, "clock_untrusted in a status report", func() bool {
		r.advance(11*time.Second, time.Second)
		s, _, ok := cp.lastStatus()
		return ok && s.LastError != nil && s.LastError.Code == wire.ErrClockUntrusted
	})
	if r.guard.UntrustedCount() == 0 {
		t.Errorf("untrusted episode not counted")
	}
	// 1 h + 3 min of monotonic time later the policy (expiry at +24 h, skew 2 min) is over, though the wall
	// clock only reads t0 + ~1 h
	r.advance(time.Hour+3*time.Minute, time.Minute)
	waitFor(t, "safe mode despite the wall clock", func() bool { return r.state() == wire.StateSafeMode })
}

// A forward jump of the wall clock expires the policy at once, and a backward one never un-expires it.
func TestForwardJumpExpiresBackwardJumpDoesNotUndo(t *testing.T) {
	cp := newCP(t)
	env, _ := validEnv(1)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env, 1)
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "v1", func() bool { return r.appliedVersion() == 1 })
	r.clk.Set(t0.Add(30 * time.Hour))
	// the watcher needs some monotonic time to notice a wall-clock step; a minute is the longest the
	// persister waits (HighWaterInterval), so allow that plus a little
	r.advance(agent.HighWaterInterval+5*time.Second, time.Second)
	if r.state() != wire.StateSafeMode {
		t.Fatalf("state %s %v of monotonic time after the wall clock jumped 30 h past expiry; want safe_mode", r.state(), agent.HighWaterInterval)
	}
	r.clk.Set(t0) // back again
	r.advance(5*time.Second, time.Second)
	if r.state() != wire.StateSafeMode {
		t.Errorf("state %s: setting the clock back revived an expired policy", r.state())
	}
}

// Shutdown: Run returns nil, and the high-water mark is saved (>= the effective time reached).
func TestShutdownSavesHighWater(t *testing.T) {
	dir := t.TempDir()
	clk := clock.NewFake(t0)
	r := newRig(t, dir, clk, nil)
	r.boot()
	r.run()
	r.advance(3*time.Hour, 15*time.Minute)
	r.cancel()
	select {
	case err := <-r.done:
		if err != nil {
			t.Errorf("Run returned %v on a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	r.cancel = nil
	b, err := os.ReadFile(r.guard.Path())
	if err != nil || len(b) == 0 {
		t.Fatalf("no high-water file after shutdown: %v", err)
	}
	g2, gerr := agent.OpenClockGuard(clock.NewFake(t0), dir)
	if gerr != nil || g2 == nil {
		t.Fatalf("reopen: %v", gerr)
	}
	if g2.HighWater().Before(t0.Add(3 * time.Hour)) {
		t.Errorf("high-water %v after a 3 h run, want >= %v", g2.HighWater(), t0.Add(3*time.Hour))
	}
	if g2.Now().Before(t0.Add(3 * time.Hour)) {
		t.Errorf("a restart with the wall clock at t0 sees effective_now %v", g2.Now())
	}
}

// Run with the control plane never answering must still honour cancel promptly (no goroutine stuck in a poll).
func TestRunStopsWhileAPollIsHeld(t *testing.T) {
	cp := newCP(t)
	release := make(chan struct{})
	cp.poll = func(int, cpReq) cpAnswer {
		<-release
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "poll in flight", func() bool { return cp.pollCount() >= 1 })
	start := time.Now()
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Run did not return within 5 s while a poll was held")
	}
	close(release)
	r.cancel = nil
	if time.Since(start) > 3*time.Second {
		t.Errorf("shutdown took %v", time.Since(start))
	}
}
