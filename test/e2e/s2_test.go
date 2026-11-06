package e2e

import (
	"testing"
	"time"

	"kairan/internal/wire"
)

// snapshot of every proxy's own view, taken before a fault, to prove nothing moved.
func (w *world) snapshotSelf(t *testing.T) map[string]self {
	t.Helper()
	out := map[string]self{}
	for _, p := range proxies {
		s, err := w.self(p)
		if err != nil {
			t.Fatalf("%s self: %v", p.ID, err)
		}
		out[p.ID] = s
	}
	return out
}

// sameAs fails the test for every proxy whose applied version, policy hash or state differs from before.
func (w *world) sameAs(t *testing.T, before map[string]self, when string) {
	t.Helper()
	for _, p := range proxies {
		s, err := w.self(p)
		if err != nil {
			t.Errorf("%s (%s): %v", p.ID, when, err)
			continue
		}
		b := before[p.ID]
		if s.AppliedVersion != b.AppliedVersion || s.PolicyHash != b.PolicyHash || s.State != string(wire.StateEnforcing) {
			t.Errorf("%s (%s): now v%d hash %.12s state %s, before v%d hash %.12s", p.ID, when,
				s.AppliedVersion, s.PolicyHash, s.State, b.AppliedVersion, b.PolicyHash)
		}
	}
}

// S2 control plane killed mid-traffic (docker kill), then restarted.
// Pass: 0 calls wrongly allowed; proxies keep their applied version; all re-sync after restart (I3, G3, M5).
func TestS2ControlPlaneKilledMidTraffic(t *testing.T) {
	w := need(t)
	w.baseline(t)
	before := w.snapshotSelf(t)
	policyVersion := before["bank-a-main-1"].AppliedVersion
	if policyVersion < 2 {
		t.Fatalf("precondition: expected policy v2 or later, got v%d", policyVersion)
	}

	tr := w.startTraffic(proxies, 16, policyVersion)
	time.Sleep(3 * time.Second) // traffic with the control plane up
	callsBefore := tr.total.Load()

	mustDocker(t, "kill", "kairan-cp") // SIGKILL: no graceful shutdown
	killedAt := time.Now()
	if _, err := w.fleet("bank-a"); err == nil {
		t.Fatal("control plane still answers after docker kill")
	}

	// outage: 20 s of mixed read/write traffic; every 4 s each proxy must still report the same version and hash
	for time.Since(killedAt) < 20*time.Second {
		time.Sleep(4 * time.Second)
		w.sameAs(t, before, "control plane down")
	}
	callsDuringOutage := tr.total.Load() - callsBefore
	t.Logf("calls during the outage window: %d", callsDuringOutage)

	mustDocker(t, "start", "kairan-cp")
	restartedAt := time.Now()
	// every proxy re-syncs: back to healthy at the same version, drift 0
	took := eventually(t, 60*time.Second, time.Second, "all proxies healthy at their version after the control plane restart", func() (bool, string) {
		var bad []string
		for _, tn := range tenants {
			fv, err := w.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			if len(fv.Proxies) != len(tenantProxies(tn)) {
				return false, "fleet incomplete"
			}
			for _, r := range fv.Proxies {
				b := before[string(r.ProxyID)]
				if r.Health != wire.HealthHealthy || r.Drift != 0 || r.AppliedVersion != b.AppliedVersion || r.State != wire.StateEnforcing {
					bad = append(bad, string(r.ProxyID)+":"+string(r.Health))
				}
			}
		}
		return len(bad) == 0, "not yet: " + joinStr(bad)
	})
	t.Logf("all 10 proxies healthy again %v after the control plane came back (restart began %v ago)", took.Round(100*time.Millisecond), time.Since(restartedAt).Round(100*time.Millisecond))
	time.Sleep(2 * time.Second)
	tr.halt()
	w.sameAs(t, before, "after restart")
	tr.check(t, true, 2000)

	// the restarted control plane kept its state and works: a new version still reaches every proxy
	for _, tn := range tenants {
		v, _, _ := w.release(t, tn, 5)
		w.ackTimes(t, map[string]uint64{tn: v}, 60*time.Second)
	}
}

func joinStr(a []string) string {
	s := ""
	for i, x := range a {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}
