package e2e

import (
	"sync"
	"testing"
	"time"

	"kairan/internal/wire"
)

// S3 proxy restart while the control plane is down.
// Pass: every restarted proxy re-verifies its stored policy and enforces the same version; never deny-all
// from a good file, never wider (I1, I3, G3). Half of the proxies are restarted with docker restart, the
// other half are killed (SIGKILL, no clean shutdown) and started again, all while the control plane is stopped.
func TestS3ProxyRestartWhileControlPlaneDown(t *testing.T) {
	w := need(t)
	w.baseline(t)
	before := w.snapshotSelf(t)
	policyVersion := before["bank-a-main-1"].AppliedVersion

	mustDocker(t, "stop", "kairan-cp")
	if _, err := w.fleet("bank-a"); err == nil {
		t.Fatal("control plane still answers after docker stop")
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failures []string
	for i, p := range proxies {
		wg.Add(1)
		go func(i int, p px) {
			defer wg.Done()
			var err error
			if i%2 == 0 {
				_, err = docker("restart", "-t", "5", p.Container)
			} else {
				if _, err = docker("kill", p.Container); err == nil {
					_, err = docker("start", p.Container)
				}
			}
			if err != nil {
				mu.Lock()
				failures = append(failures, p.ID+": "+err.Error())
				mu.Unlock()
			}
		}(i, p)
	}
	wg.Wait()
	if len(failures) > 0 {
		t.Fatalf("could not restart proxies: %v", failures)
	}

	// each proxy comes back from its own disk: same version, same hash, enforcing (not deny-all, not tampered)
	eventually(t, 40*time.Second, 500*time.Millisecond, "every restarted proxy to be enforcing its stored policy again", func() (bool, string) {
		var bad []string
		for _, p := range proxies {
			s, err := w.self(p)
			if err != nil {
				bad = append(bad, p.ID+": "+err.Error())
				continue
			}
			b := before[p.ID]
			if s.State != string(wire.StateEnforcing) || s.AppliedVersion != b.AppliedVersion || s.PolicyHash != b.PolicyHash {
				bad = append(bad, p.ID+": "+s.State)
			}
		}
		return len(bad) == 0, joinStr(bad)
	})
	if _, err := w.fleet("bank-a"); err == nil {
		t.Fatal("control plane came back by itself; the scenario needs it down")
	}
	w.sameAs(t, before, "restarted, control plane still down")

	// I1/I3 on the restarted proxies, with the control plane still down: the policy is enforced, not widened
	for _, p := range proxies {
		for _, c := range callMix {
			r := w.call(p, w.keyFor(c.role), c.tool)
			if r.Err != nil {
				t.Errorf("%s %s/%s: %v", p.ID, c.role, c.tool, r.Err)
				continue
			}
			if want := wantAllowed(c.role, c.tool, policyVersion); r.Allowed != want {
				t.Errorf("%s %s/%s: allowed=%v want %v (policy v%d, control plane down, proxy restarted)", p.ID, c.role, c.tool, r.Allowed, want, policyVersion)
			}
		}
		if names, err := w.listTools(p, w.internKey); err != nil || len(names) != 1 || names[0] != "notes.read" {
			t.Errorf("%s: intern tools/list after restart = %v (%v), want only notes.read", p.ID, names, err)
		}
	}
	tr := w.startTraffic(proxies, 12, policyVersion)
	time.Sleep(6 * time.Second)
	tr.halt()
	tr.check(t, true, 500)
	w.sameAs(t, before, "traffic after restart")

	// when the control plane returns, the fleet is healthy at the same versions
	mustDocker(t, "start", "kairan-cp")
	eventually(t, 60*time.Second, time.Second, "fleet healthy after the control plane returns", func() (bool, string) {
		var bad []string
		for _, tn := range tenants {
			fv, err := w.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			for _, r := range fv.Proxies {
				if r.Health != wire.HealthHealthy || r.Drift != 0 || r.AppliedVersion != before[string(r.ProxyID)].AppliedVersion {
					bad = append(bad, string(r.ProxyID))
				}
			}
			if len(fv.Proxies) != len(tenantProxies(tn)) {
				bad = append(bad, tn+":missing")
			}
		}
		return len(bad) == 0, joinStr(bad)
	})
}
