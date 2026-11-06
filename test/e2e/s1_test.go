package e2e

import (
	"sort"
	"testing"
	"time"

	"kairan/internal/wire"
)

// S1 happy rollout (ARCHITECTURE section 11: "every proxy acks v2; drift 0; propagation measured").
// Proves G1, G5, M1. demo.sh already put both tenants on v1; this publishes v2 with two signatures and a
// canary rollout, and checks the canary went first, every proxy converged on the same signed bytes, and the
// new policy changes behavior (sales may call notes.write from v2).
func TestS1HappyRollout(t *testing.T) {
	w := need(t)
	w.baseline(t)

	const dwell = 5 // seconds the canary must stay healthy before the main group gets the policy

	// before: v1 forbids notes.write for sales on every proxy
	for _, p := range proxies {
		if r := w.call(p, w.salesKey, "notes.write"); r.Allowed {
			t.Fatalf("precondition: %s allowed notes.write under v1: HTTP %d %.300s", p.ID, r.HTTP, r.Text)
		}
	}

	type published struct {
		version uint64
		hash    wire.Hash
		t0      time.Time
	}
	pub := map[string]published{}
	for _, tn := range tenants {
		v, h, t0 := w.release(t, tn, dwell)
		pub[tn] = published{v, h, t0}
		if v != 2 {
			t.Fatalf("%s: expected this to be version 2, got %d", tn, v)
		}
	}

	acks := w.ackTimes(t, map[string]uint64{"bank-a": 2, "city-b": 2}, 60*time.Second)
	var canaryStage, mainStage []time.Duration
	for _, tn := range tenants {
		pb := pub[tn]
		var canary time.Time
		for _, p := range tenantProxies(tn) {
			if p.Group == "canary" {
				canary = acks[p.ID]
			}
		}
		canaryStage = append(canaryStage, canary.Sub(pb.t0))
		for _, p := range tenantProxies(tn) {
			if p.Group != "main" {
				continue
			}
			gap := acks[p.ID].Sub(canary)
			// canary first: a main proxy must not get v2 before the canary has been healthy for the dwell time
			if gap < (dwell-2)*time.Second {
				t.Errorf("%s: main proxy %s acked v2 only %v after the canary; the canary dwell is %ds", tn, p.ID, gap.Round(time.Millisecond), dwell)
			}
			mainStage = append(mainStage, gap-dwell*time.Second)
		}
	}
	report := func(name string, ds []time.Duration) {
		t.Logf("S1 propagation %-24s n=%d p50=%v p95=%v p99=%v max=%v", name, len(ds),
			percentile(ds, .50).Round(time.Millisecond), percentile(ds, .95).Round(time.Millisecond),
			percentile(ds, .99).Round(time.Millisecond), percentile(ds, 1).Round(time.Millisecond))
	}
	report("publish -> canary ack", canaryStage)
	report("after dwell -> main ack", mainStage)
	// M1's target (p99 <= 1s per stage) is judged by make bench; here only a gross bound fails the scenario.
	if m := percentile(canaryStage, 1); m > 5*time.Second {
		t.Errorf("canary took %v to ack after publish", m)
	}
	if m := percentile(mainStage, 1); m > 7*time.Second {
		t.Errorf("main proxies took %v after the dwell to ack", m)
	}

	// every proxy converged: same version, same hash as the publish response, enforcing, drift 0, healthy
	for _, tn := range tenants {
		pb := pub[tn]
		fv, err := w.fleet(tn)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range fv.Proxies {
			if r.AppliedVersion != pb.version || r.DesiredVersion != pb.version || r.Drift != 0 ||
				r.PolicyHash != pb.hash || r.State != wire.StateEnforcing || r.Health != wire.HealthHealthy || r.LastError != nil {
				t.Errorf("%s fleet row not converged on v%d: %+v", r.ProxyID, pb.version, r)
			}
		}
		rv, err := w.rolloutView(tn)
		if err != nil {
			t.Fatal(err)
		}
		if rv.Phase != wire.PhaseComplete || rv.Version != pb.version {
			t.Errorf("%s rollout %+v, want complete at v%d", tn, rv, pb.version)
		}
		tv, err := w.timeline(tn)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, e := range tv.Entries {
			if e.Version == pb.version && e.PolicyHash == pb.hash {
				seen[string(e.ProxyID)] = true
			}
		}
		if len(seen) != len(tenantProxies(tn)) {
			t.Errorf("%s timeline has v%d for %d proxies, want %d", tn, pb.version, len(seen), len(tenantProxies(tn)))
		}
	}

	// the proxies themselves agree (their own view, not only the control plane's)
	for _, p := range proxies {
		pb := pub[p.Tenant]
		s, err := w.self(p)
		if err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		if s.AppliedVersion != pb.version || s.PolicyHash != string(pb.hash) || s.State != string(wire.StateEnforcing) {
			t.Errorf("%s self view %+v, want v%d hash %s enforcing", p.ID, s, pb.version, pb.hash)
		}
	}

	// behavior changed with the policy, on every proxy: v2 allows sales notes.write, never crm.export, never for interns
	var wrong []string
	for _, p := range proxies {
		for _, c := range callMix {
			r := w.call(p, w.keyFor(c.role), c.tool)
			if r.Err != nil || r.Allowed != wantAllowed(c.role, c.tool, 2) {
				wrong = append(wrong, p.ID+" "+c.role+"/"+c.tool)
			}
		}
	}
	sort.Strings(wrong)
	if len(wrong) > 0 {
		t.Errorf("%d calls behaved differently from policy v2: %v", len(wrong), wrong)
	}
	// tools/list is filtered per role
	names, err := w.listTools(proxyByID("bank-a-main-1"), w.internKey)
	if err != nil || len(names) != 1 || names[0] != "notes.read" {
		t.Errorf("intern tools/list = %v (%v), want only notes.read", names, err)
	}
}
