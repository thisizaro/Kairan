package e2e

import (
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// mainsUntouched asserts that no non-canary proxy of the tenant was told to move or moved off `cur`.
func (w *world) mainsUntouched(t *testing.T, tenant string, cur uint64, when string) {
	t.Helper()
	fv, err := w.fleet(tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range fv.Proxies {
		if r.Group == "canary" {
			continue
		}
		if r.DesiredVersion != cur || r.AppliedVersion != cur {
			t.Errorf("%s (%s): %s has desired v%d applied v%d, want both v%d: a halted rollout must not reach the main group",
				when, tenant, r.ProxyID, r.DesiredVersion, r.AppliedVersion, cur)
		}
	}
}

func (w *world) currentVersion(t *testing.T, tenant string) uint64 {
	t.Helper()
	var cur uint64
	for _, p := range tenantProxies(tenant) {
		if s, err := w.self(p); err == nil && s.AppliedVersion > cur {
			cur = s.AppliedVersion
		}
	}
	return cur
}

// S8 canary failure auto-halt: a canary proxy rejects, or is lost, during a rollout.
// Pass: the rollout is Halted (reason shown), the non-canary proxies are untouched (desired and applied stay
// at the old version, calls keep the old answers), and a rollback by re-publishing the old content as a new
// higher version works and completes. G5, J6.
func TestS8CanaryAutoHalt(t *testing.T) {
	w := need(t)
	w.baseline(t)
	const tenant = "city-b"
	canary := proxyByID("city-b-canary")
	t.Cleanup(func() {
		if !containerRunning(canary.Container) {
			_, _ = docker("start", canary.Container)
		}
	})

	t.Run("canary rejects", func(t *testing.T) {
		cur := w.currentVersion(t, tenant)
		// an expired policy passes the control plane's publish check and is refused by the proxy (see S5)
		v := w.nextVersion(tenant)
		now := time.Now()
		w.releaseWith(t, tenant, v, w.envelope(payload(tenant, v, now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil), "admin-a", "admin-b"), 600)
		start := time.Now()
		var rv wire.RolloutView
		eventually(t, 60*time.Second, 300*time.Millisecond, "the rollout of v"+itoa(v)+" to halt", func() (bool, string) {
			var err error
			if rv, err = w.rolloutView(tenant); err != nil {
				return false, err.Error()
			}
			return rv.Version == v && rv.Phase == wire.PhaseHalted, "phase " + string(rv.Phase)
		})
		t.Logf("S8 canary rejects: halted %.1fs after the rollout started, reason %q", time.Since(start).Seconds(), rv.Reason)
		if rv.Reason == "" {
			t.Errorf("halted rollout shows no reason: %+v", rv)
		}
		w.mainsUntouched(t, tenant, cur, "canary rejects")
		for _, p := range tenantProxies(tenant) {
			for _, cm := range callMix {
				if r := w.call(p, w.keyFor(cm.role), cm.tool); r.Err != nil || r.Allowed != wantAllowed(cm.role, cm.tool, cur) {
					t.Errorf("%s %s/%s allowed=%v err=%v after a halted rollout (policy v%d)", p.ID, cm.role, cm.tool, r.Allowed, r.Err, cur)
				}
			}
		}
		// the halted state survives a look at the fleet page, which shows why
		if page, err := w.fleetPage(tenant, "en"); err != nil || !strings.Contains(strings.ToLower(page), "halt") {
			t.Errorf("fleet page does not show the halted rollout (%v)", err)
		}
		// rollback by re-publish: the old content as a new, higher version
		nv, hash, _ := w.release(t, tenant, 5)
		w.ackTimes(t, map[string]uint64{tenant: nv}, 60*time.Second)
		if rv, err := w.rolloutView(tenant); err != nil || rv.Phase != wire.PhaseComplete || rv.Version != nv {
			t.Errorf("after the fix: rollout %+v (%v), want complete at v%d", rv, err, nv)
		}
		fv, _ := w.fleet(tenant)
		for _, r := range fv.Proxies {
			if r.AppliedVersion != nv || r.PolicyHash != hash || r.Drift != 0 {
				t.Errorf("after the fix %s: %+v", r.ProxyID, r)
			}
		}
	})

	t.Run("canary lost", func(t *testing.T) {
		cur := w.currentVersion(t, tenant)
		v := w.nextVersion(tenant)
		// a long dwell: the canary may ack, but the rollout must not promote before the canary is judged
		w.releaseWith(t, tenant, v, w.envelope(goodPayload(tenant, v), "admin-a", "admin-b"), 600)
		mustDocker(t, "stop", "-t", "2", canary.Container)
		killedAt := time.Now()
		var rv wire.RolloutView
		eventually(t, 200*time.Second, time.Second, "the rollout to halt with the canary lost", func() (bool, string) {
			var err error
			if rv, err = w.rolloutView(tenant); err != nil {
				return false, err.Error()
			}
			return rv.Version == v && rv.Phase == wire.PhaseHalted, "phase " + string(rv.Phase)
		})
		haltedAfter := time.Since(killedAt)
		t.Logf("S8 canary lost: halted %.1fs after the canary was stopped, reason %q", haltedAfter.Seconds(), rv.Reason)
		if rv.Reason != wire.ErrCanaryLost {
			t.Errorf("halt reason %q, want %q", rv.Reason, wire.ErrCanaryLost)
		}
		if haltedAfter > 131*time.Second {
			t.Errorf("halted %v after the canary stopped, want within the lost threshold (131s, M3)", haltedAfter)
		}
		w.mainsUntouched(t, tenant, cur, "canary lost")

		// rollback by re-publish with the canary back
		mustDocker(t, "start", canary.Container)
		nv, hash, _ := w.release(t, tenant, 5)
		w.ackTimes(t, map[string]uint64{tenant: nv}, 90*time.Second)
		if rv, err := w.rolloutView(tenant); err != nil || rv.Phase != wire.PhaseComplete || rv.Version != nv {
			t.Errorf("after the fix: rollout %+v (%v), want complete at v%d", rv, err, nv)
		}
		fv, _ := w.fleet(tenant)
		for _, r := range fv.Proxies {
			if r.AppliedVersion != nv || r.PolicyHash != hash || r.Drift != 0 || r.Health != wire.HealthHealthy {
				t.Errorf("after the fix %s: %+v", r.ProxyID, r)
			}
		}
	})

	// the other tenant never noticed
	for _, p := range tenantProxies("bank-a") {
		if s, err := w.self(p); err != nil || s.State != string(wire.StateEnforcing) {
			t.Errorf("%s (other tenant): %+v (%v)", p.ID, s, err)
		}
	}
	w.baseline(t)
}
