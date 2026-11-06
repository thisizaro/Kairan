package e2e

import (
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// releaseWith publishes the envelope for version v of tenant and starts its rollout. The rollout request
// must succeed; the HTTP status of a publish that the caller expects to fail is the caller's business.
func (w *world) releaseWith(t *testing.T, tenant string, v uint64, env wire.Envelope, dwell uint64) {
	t.Helper()
	code, ec, _, err := w.publish(env)
	if err != nil || code/100 != 2 {
		t.Fatalf("publish %s v%d: HTTP %d %s err=%v", tenant, v, code, ec, err)
	}
	var rv wire.RolloutView
	code, ec, err = w.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: wire.ID(tenant), Version: v, CanaryDwellSeconds: dwell}, &rv)
	if err != nil || code/100 != 2 {
		t.Fatalf("rollout start %s v%d: HTTP %d %s err=%v", tenant, v, code, ec, err)
	}
}

// releaseExpiring publishes a 2-signature policy that expires ttl from now and rolls it out. It returns the
// version and the expiry as written in the policy (second resolution).
func (w *world) releaseExpiring(t *testing.T, tenant string, ttl time.Duration, dwell uint64) (uint64, time.Time) {
	t.Helper()
	v := w.nextVersion(tenant)
	exp := time.Now().Add(ttl).UTC().Truncate(time.Second)
	w.releaseWith(t, tenant, v, w.envelope(payload(tenant, v, time.Now().Add(-time.Minute), exp, nil), "admin-a", "admin-b"), dwell)
	return v, exp
}

// stateSeries returns the labels of the kairan_proxy_state series that read 1 on the proxy's /metrics.
func (w *world) stateSeries(p px) ([]string, error) {
	res, err := w.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", p.Metrics))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var on []string
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(ln, "kairan_proxy_state{") {
			continue
		}
		f := strings.Fields(ln)
		if f[len(f)-1] == "1" {
			on = append(on, ln[strings.Index(ln, "{"):strings.LastIndex(ln, "}")+1])
		}
	}
	return on, nil
}

func isSafeMode(s string) bool { return strings.Contains(s, "safe") }

// wantSafeMode is the oracle for the demo policy in safe mode read_only (the default): only class R tools
// pass, whatever the policy says about writes. notes.write is W in v2 and later, crm.export is not allowed
// at all, so v1's oracle is exactly the safe-mode oracle.
func wantSafeMode(role, tool string) bool { return wantAllowed(role, tool, 1) }

func (w *world) checkSafeModeCalls(t *testing.T, p px, what string) {
	t.Helper()
	for _, c := range callMix {
		r := w.call(p, w.keyFor(c.role), c.tool)
		if r.Err != nil || r.Allowed != wantSafeMode(c.role, c.tool) {
			t.Errorf("%s (%s): %s/%s allowed=%v err=%v, safe mode (read_only) wants allowed=%v", p.ID, what, c.role, c.tool, r.Allowed, r.Err, wantSafeMode(c.role, c.tool))
		}
	}
}

// S7 freeze / expiry, and the clock set back.
// Pass: updates blocked until the policy expires -> safe mode (read_only, the default) at effective_now,
// shown in the proxy's state metric and on the control plane's fleet view and page; writes (class W) and
// exports (X) are denied, reads still pass; a newer valid policy lifts it. With the wall clock set back
// behind the high-water mark the policy still expires on time and clock_untrusted is reported (M-D30).
// I3, G4, THREATS #4, #12.
func TestS7FreezeExpiry(t *testing.T) {
	w := need(t)
	w.baseline(t)
	const tenant = "city-b"
	ps := tenantProxies(tenant)
	t.Cleanup(func() { _, _ = docker("start", "kairan-cp") })

	t.Run("freeze: no update arrives until the policy expires", func(t *testing.T) {
		v, exp := w.releaseExpiring(t, tenant, 50*time.Second, 5)
		w.ackTimes(t, map[string]uint64{tenant: v}, 40*time.Second)
		for _, p := range ps {
			if r := w.call(p, w.salesKey, "notes.write"); !r.Allowed {
				t.Fatalf("precondition: %s should allow notes.write under v%d before expiry: %+v", p.ID, v, r)
			}
		}

		// the freeze: the attacker (or an outage) keeps the control plane from reaching the proxies
		mustDocker(t, "stop", "-t", "5", "kairan-cp")
		stoppedAt := time.Now()
		if time.Until(exp) > 5*time.Second {
			// fail-static before expiry: still enforcing the same policy with the control plane gone
			for _, p := range ps {
				if r := w.call(p, w.salesKey, "notes.write"); !r.Allowed {
					t.Errorf("%s lost notes.write before the policy expired: %+v", p.ID, r)
				}
			}
		}

		// safe mode must arrive at effective_now = expires_at (+ the proxy's skew, at most 5 minutes)
		var enteredAfter time.Duration
		eventually(t, time.Until(exp)+5*time.Minute+30*time.Second, 500*time.Millisecond, "every city-b proxy in safe mode", func() (bool, string) {
			var not []string
			for _, p := range ps {
				s, err := w.self(p)
				if err != nil {
					return false, err.Error()
				}
				if s.State != string(wire.StateSafeMode) {
					not = append(not, p.ID+":"+s.State)
				}
			}
			enteredAfter = time.Since(exp)
			return len(not) == 0, strings.Join(not, " ")
		})
		t.Logf("S7 freeze: policy v%d expired at %s; all %d proxies in safe mode %.1fs after expiry (control plane stopped for %.0fs)",
			v, exp.Format(time.TimeOnly), len(ps), enteredAfter.Seconds(), time.Since(stoppedAt).Seconds())
		if enteredAfter < -2*time.Second {
			t.Errorf("safe mode %.1fs BEFORE the policy expired (I3 allows only stricter, but expiry is judged at effective_now)", -enteredAfter.Seconds())
		}
		for _, p := range ps {
			w.checkSafeModeCalls(t, p, "frozen past expiry")
			series, err := w.stateSeries(p)
			if err != nil || len(series) != 1 || !isSafeMode(series[0]) {
				t.Errorf("%s: kairan_proxy_state series at 1 = %v (%v), want the safe mode one only", p.ID, series, err)
			}
		}
		// a frozen tenant is not a reason to touch the other one
		for _, p := range tenantProxies("bank-a") {
			if s, err := w.self(p); err != nil || s.State != string(wire.StateEnforcing) {
				t.Errorf("%s (other tenant) state %+v (%v)", p.ID, s, err)
			}
		}

		// the control plane comes back and shows it: fleet view, and the fleet page in English and Japanese
		mustDocker(t, "start", "kairan-cp")
		eventually(t, 60*time.Second, time.Second, "the control plane to show city-b in safe mode", func() (bool, string) {
			fv, err := w.fleet(tenant)
			if err != nil {
				return false, err.Error()
			}
			var not []string
			for _, r := range fv.Proxies {
				if r.State != wire.StateSafeMode {
					not = append(not, string(r.ProxyID)+":"+string(r.State))
				}
			}
			return len(not) == 0 && len(fv.Proxies) == len(ps), strings.Join(not, " ")
		})
		for _, lang := range []string{"en", "ja"} {
			page, err := w.fleetPage(tenant, lang)
			if err != nil || !strings.Contains(strings.ToLower(page), "safe") {
				t.Errorf("fleet page (%s) does not show safe mode (%v)", lang, err)
			}
		}
		// still safe: the control plane has nothing newer, and its answer must not undo it
		time.Sleep(3 * time.Second)
		for _, p := range ps {
			if r := w.call(p, w.salesKey, "notes.write"); r.Allowed {
				t.Errorf("%s allowed notes.write in safe mode after the control plane came back", p.ID)
			}
		}

		// a newer valid policy lifts safe mode
		nv, hash, _ := w.release(t, tenant, 5)
		w.ackTimes(t, map[string]uint64{tenant: nv}, 60*time.Second)
		for _, p := range ps {
			s, err := w.self(p)
			if err != nil || s.State != string(wire.StateEnforcing) || s.AppliedVersion != nv || s.PolicyHash != string(hash) {
				t.Errorf("%s after the new policy: %+v (%v)", p.ID, s, err)
			}
			if r := w.call(p, w.salesKey, "notes.write"); !r.Allowed {
				t.Errorf("%s: notes.write should be allowed again under v%d: %+v", p.ID, nv, r)
			}
		}
	})

	t.Run("clock set back behind the high-water mark", func(t *testing.T) {
		// There is no faketime in the containers (read-only root, no capabilities), so the set-back is made
		// with the documented high-water file (M-D30): stop the proxy, put a mark one hour in the future in
		// its data dir, start it. To the proxy that is the same thing as a wall clock one hour behind.
		victim, control := proxyByID("city-b-main-3"), proxyByID("city-b-main-2")
		v, exp := w.releaseExpiring(t, tenant, 8*time.Minute, 5)
		w.ackTimes(t, map[string]uint64{tenant: v}, 40*time.Second)
		for _, p := range []px{victim, control} {
			if r := w.call(p, w.salesKey, "notes.write"); !r.Allowed {
				t.Fatalf("precondition: %s should allow notes.write under v%d: %+v", p.ID, v, r)
			}
		}
		stopProxy(t, victim) // a clean stop writes the real mark first; the next line replaces it
		t.Cleanup(func() {
			if containerRunning(victim.Container) {
				stopProxy(t, victim)
			}
			volumeShell(t, victim, "rm -f /data/highwater", "")
			startProxy(t, victim)
		})
		mark := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		volumeShell(t, victim, "cat > /data/highwater", mark+"\n")
		startProxy(t, victim)

		eventually(t, 60*time.Second, 500*time.Millisecond, victim.ID+" in safe mode although its wall clock says the policy is valid for "+time.Until(exp).Round(time.Second).String(), func() (bool, string) {
			s, err := w.self(victim)
			if err != nil {
				return false, err.Error()
			}
			return s.State == string(wire.StateSafeMode), "state " + s.State
		})
		s, _ := w.self(victim)
		if !s.ClockUntrusted {
			t.Errorf("%s: /v1/self clock_untrusted = false with the wall clock an hour behind the high-water mark", victim.ID)
		}
		w.checkSafeModeCalls(t, victim, "clock set back")
		if n, err := w.metricContaining(victim, "untrusted"); err != nil || n < 1 {
			t.Errorf("%s: no clock_untrusted counter on /metrics (sum of series named *untrusted* = %v, %v)", victim.ID, n, err)
		}
		eventually(t, 30*time.Second, 500*time.Millisecond, "the control plane to show clock_untrusted for "+victim.ID, func() (bool, string) {
			r, err := w.fleetRow(victim.ID)
			if err != nil {
				return false, err.Error()
			}
			if r.LastError == nil {
				return false, "no last_error, state " + string(r.State)
			}
			return r.LastError.Code == wire.ErrClockUntrusted && r.State == wire.StateSafeMode, "last_error " + string(r.LastError.Code) + " state " + string(r.State)
		})
		// the proxy whose clock is fine is not affected, and nothing got wider
		if cs, err := w.self(control); err != nil || cs.State != string(wire.StateEnforcing) || cs.ClockUntrusted {
			t.Errorf("control %s: %+v (%v)", control.ID, cs, err)
		}
		if r := w.call(control, w.salesKey, "notes.write"); !r.Allowed {
			t.Errorf("control %s should still allow notes.write: %+v", control.ID, r)
		}
		t.Logf("S7 clock set back: victim %s in safe mode with clock_untrusted, control %s enforcing, policy v%d valid by the wall clock for another %v",
			victim.ID, control.ID, v, time.Until(exp).Round(time.Second))

		// recovery as documented: delete the mark (a stop writes it again, so delete after the stop), publish
		// a fresh policy so nobody is left on the 8-minute one
		stopProxy(t, victim)
		volumeShell(t, victim, "rm -f /data/highwater", "")
		startProxy(t, victim)
		nv, _, _ := w.release(t, tenant, 5)
		w.ackTimes(t, map[string]uint64{tenant: nv}, 60*time.Second)
		if s, err := w.self(victim); err != nil || s.State != string(wire.StateEnforcing) || s.ClockUntrusted {
			t.Errorf("%s after deleting the mark and the new policy: %+v (%v)", victim.ID, s, err)
		}
	})

	w.baseline(t)
}
