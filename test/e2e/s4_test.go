package e2e

import (
	"testing"
	"time"

	"kairan/internal/wire"
)

// S4 network cut of one proxy (docker network disconnect from the control plane's network).
// Pass: fail-static while cut; stale within 41 s and lost within 131 s of the cut (M2); publish v+1 while it
// is cut; after reconnect it catches up within 6 s (M3). I3, M2, M3.
// The proxy stays on its customer network, so agents can still reach it while it cannot reach the control plane.
func TestS4NetworkCutStaleLostCatchUp(t *testing.T) {
	w := need(t)
	w.baseline(t)
	victim := proxyByID("bank-a-main-3")
	others := []string{}
	for _, p := range tenantProxies("bank-a") {
		if p.ID != victim.ID {
			others = append(others, p.ID)
		}
	}
	before, err := w.self(victim)
	if err != nil {
		t.Fatal(err)
	}
	policyVersion := before.AppliedVersion
	t.Cleanup(func() { _, _ = docker("network", "connect", cloudNet, victim.Container) })

	// cut
	mustDocker(t, "network", "disconnect", cloudNet, victim.Container)
	cutAt := time.Now()

	// watch the control plane's view of the victim until it is lost, checking the proxy is fail-static all along
	var staleAfter, lostAfter time.Duration
	deadline := cutAt.Add(150 * time.Second)
	lastCheck := time.Time{}
	for lostAfter == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("victim not lost 150s after the cut (stale after %v)", staleAfter)
		}
		row, err := w.fleetRow(victim.ID)
		if err != nil {
			t.Fatal(err)
		}
		el := time.Since(cutAt)
		switch row.Health {
		case wire.HealthStale:
			if staleAfter == 0 {
				staleAfter = el
			}
		case wire.HealthLost:
			if staleAfter == 0 {
				staleAfter = el // went straight to lost between two polls
			}
			lostAfter = el
		}
		if time.Since(lastCheck) > 10*time.Second {
			lastCheck = time.Now()
			// fail-static while cut: same version, same hash, enforcing, and the oracle still holds
			s, err := w.self(victim)
			if err != nil || s.AppliedVersion != before.AppliedVersion || s.PolicyHash != before.PolicyHash || s.State != string(wire.StateEnforcing) {
				t.Errorf("cut proxy changed: %+v (%v), before %+v", s, err, before)
			}
			for _, c := range callMix {
				r := w.call(victim, w.keyFor(c.role), c.tool)
				if r.Err != nil || r.Allowed != wantAllowed(c.role, c.tool, policyVersion) {
					t.Errorf("cut proxy: %s/%s allowed=%v err=%v, want %v", c.role, c.tool, r.Allowed, r.Err, wantAllowed(c.role, c.tool, policyVersion))
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("S4 detection: stale after %v, lost after %v (targets: stale <= 41s, lost <= 131s)", staleAfter.Round(100*time.Millisecond), lostAfter.Round(100*time.Millisecond))
	if staleAfter > 41*time.Second {
		t.Errorf("M2: stale after %v, want <= 41s", staleAfter)
	}
	if lostAfter > 131*time.Second {
		t.Errorf("M2: lost after %v, want <= 131s", lostAfter)
	}

	// the rest of the fleet is unaffected and the fleet page says so
	for _, id := range others {
		row, err := w.fleetRow(id)
		if err != nil || row.Health != wire.HealthHealthy {
			t.Errorf("%s should still be healthy: %+v (%v)", id, row, err)
		}
	}

	// publish a new version while the victim is lost
	v, hash, _ := w.release(t, "bank-a", 5)
	w.ackTimes(t, map[string]uint64{"bank-a": v}, 60*time.Second, others...)
	row, err := w.fleetRow(victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.AppliedVersion >= v || row.Drift == 0 || row.Health != wire.HealthLost {
		t.Errorf("cut proxy should be lost and behind v%d: %+v", v, row)
	}
	if s, err := w.self(victim); err != nil || s.AppliedVersion != before.AppliedVersion || s.PolicyHash != before.PolicyHash {
		t.Errorf("cut proxy applied something without a control plane: %+v (%v)", s, err)
	}

	// reconnect and measure the catch-up
	mustDocker(t, "network", "connect", cloudNet, victim.Container)
	reconnectAt := time.Now()
	var catchUp time.Duration
	eventually(t, 30*time.Second, 100*time.Millisecond, "the reconnected proxy to apply v"+itoa(v), func() (bool, string) {
		s, err := w.self(victim)
		if err != nil {
			return false, err.Error()
		}
		if s.AppliedVersion >= v {
			catchUp = time.Since(reconnectAt)
			if s.PolicyHash != string(hash) || s.State != string(wire.StateEnforcing) {
				t.Errorf("caught up with the wrong policy: %+v, want hash %s", s, hash)
			}
			return true, ""
		}
		return false, "applied v" + itoa(s.AppliedVersion)
	})
	t.Logf("S4 catch-up: %v after reconnect (target <= 6s)", catchUp.Round(10*time.Millisecond))
	if catchUp > 6*time.Second {
		t.Errorf("M3: catch-up took %v, want <= 6s", catchUp)
	}

	// the control plane sees it healthy and in sync again
	eventually(t, 30*time.Second, time.Second, "victim healthy and in sync on the fleet view", func() (bool, string) {
		r, err := w.fleetRow(victim.ID)
		if err != nil {
			return false, err.Error()
		}
		return r.Health == wire.HealthHealthy && r.Drift == 0 && r.AppliedVersion >= v && r.PolicyHash == hash, "row: " + string(r.Health)
	})
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}
