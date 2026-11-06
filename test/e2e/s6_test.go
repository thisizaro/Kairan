package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// stopProxy stops a proxy cleanly so its data volume can be edited (one process per data_dir, kairan.lock).
func stopProxy(t *testing.T, p px) { t.Helper(); mustDocker(t, "stop", "-t", "5", p.Container) }

func startProxy(t *testing.T, p px) { t.Helper(); mustDocker(t, "start", p.Container) }

// readVolumeFile returns a file from the proxy's data volume (read-only mount, safe while it runs).
func readVolumeFile(t *testing.T, p px, name string) string {
	t.Helper()
	return volumeShell(t, p, "cat /data/"+name, "")
}

// expectTampered waits for the proxy to report the tampered state everywhere an operator looks, and checks
// that it is deny-all: no tool call is allowed and tools/list is empty. This is the S6 pass condition.
func (w *world) expectTampered(t *testing.T, p px, what string) {
	t.Helper()
	eventually(t, 45*time.Second, 500*time.Millisecond, what+": "+p.ID+" in the tampered state", func() (bool, string) {
		s, err := w.self(p)
		if err != nil {
			return false, err.Error()
		}
		return s.State == string(wire.StateTampered), "state " + s.State
	})
	for _, c := range callMix {
		if r := w.call(p, w.keyFor(c.role), c.tool); r.Err != nil || r.Allowed {
			t.Errorf("%s (%s): %s/%s allowed=%v err=%v in the tampered state; every call must be denied", p.ID, what, c.role, c.tool, r.Allowed, r.Err)
		}
	}
	for _, key := range []string{w.salesKey, w.internKey} {
		if names, err := w.listTools(p, key); err != nil || len(names) != 0 {
			t.Errorf("%s (%s): tools/list = %v (%v), want empty", p.ID, what, names, err)
		}
	}
	if v, err := w.metric(p, `kairan_proxy_state{state="tampered"}`); err != nil || v != 1 {
		t.Errorf("%s (%s): kairan_proxy_state{state=tampered} = %v (%v), want 1", p.ID, what, v, err)
	}
	if v, err := w.metric(p, "kairan_proxy_boot_tampered_total"); err != nil || v < 1 {
		t.Errorf("%s (%s): kairan_proxy_boot_tampered_total = %v (%v), want >= 1", p.ID, what, v, err)
	}
	// the tamper report reaches the control plane: fleet row and fleet page
	eventually(t, 30*time.Second, 500*time.Millisecond, what+": the control plane to show "+p.ID+" as tampered", func() (bool, string) {
		r, err := w.fleetRow(p.ID)
		if err != nil {
			return false, err.Error()
		}
		return r.State == wire.StateTampered, "fleet state " + string(r.State)
	})
	for _, lang := range []string{"en", "ja"} {
		page, err := w.fleetPage(p.Tenant, lang)
		if err != nil || !strings.Contains(strings.ToLower(page), "tampered") {
			t.Errorf("fleet page (%s) does not show %s as tampered (%v)", lang, p.ID, err)
		}
	}
}

// metricContaining sums the value of every series on the proxy's /metrics whose metric name contains substr.
func (w *world) metricContaining(p px, substr string) (float64, error) {
	res, err := w.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", p.Metrics))
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	var sum float64
	for _, ln := range strings.Split(string(b), "\n") {
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		name := ln
		if i := strings.IndexAny(ln, "{ "); i >= 0 {
			name = ln[:i]
		}
		if !strings.Contains(name, substr) {
			continue
		}
		f := strings.Fields(ln)
		var v float64
		if _, err := fmt.Sscanf(f[len(f)-1], "%g", &v); err == nil {
			sum += v
		}
	}
	return sum, nil
}

// recoverWithNewPolicy releases the next version for the proxy's tenant and waits until the proxy enforces it.
func (w *world) recoverWithNewPolicy(t *testing.T, p px) uint64 {
	t.Helper()
	v, hash, _ := w.release(t, p.Tenant, 5)
	eventually(t, 45*time.Second, 300*time.Millisecond, p.ID+" to leave the tampered state with the new valid policy", func() (bool, string) {
		s, err := w.self(p)
		if err != nil {
			return false, err.Error()
		}
		return s.State == string(wire.StateEnforcing) && s.AppliedVersion == v && s.PolicyHash == string(hash), "state " + s.State + " v" + itoa(s.AppliedVersion)
	})
	return v
}

// S6 tampered disk: edited policy file, edited apply log, older valid policy put back.
// Pass: Tampered state (deny-all) and a tamper report; never a wider policy (I3, I6, THREATS #5).
func TestS6TamperedDisk(t *testing.T) {
	w := need(t)
	w.baseline(t)

	t.Run("edited policy file", func(t *testing.T) {
		p := proxyByID("bank-a-main-4")
		stopProxy(t, p)
		raw := readVolumeFile(t, p, "policy.json")
		var env wire.Envelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("policy.json: %v\n%s", err, raw)
		}
		// widen the policy by hand (sales may run crm.export) and keep the old signatures
		var doc map[string]any
		if err := json.Unmarshal(env.Payload, &doc); err != nil {
			t.Fatal(err)
		}
		doc["roles"].(map[string]any)["sales"].(map[string]any)["crm.export"] = "X"
		widened, _ := json.Marshal(doc)
		env.Payload = widened
		out, _ := json.Marshal(env)
		volumeShell(t, p, "cat > /data/policy.json", string(out))
		startProxy(t, p)

		w.expectTampered(t, p, "policy file edited")
		if r := w.call(p, w.salesKey, "crm.export"); r.Allowed {
			t.Fatalf("I3: the hand-widened policy was enforced: %+v", r)
		}
		w.recoverWithNewPolicy(t, p)
		if r := w.call(p, w.salesKey, "crm.export"); r.Allowed || r.Err != nil {
			t.Errorf("after recovery crm.export must still be denied: %+v", r)
		}
	})

	var seqBeforeTamper uint64
	var editedLog string
	t.Run("edited apply log", func(t *testing.T) {
		p := proxyByID("bank-a-main-5")
		if s, err := w.self(p); err == nil {
			seqBeforeTamper = s.LogSeq
		}
		stopProxy(t, p)
		log := readVolumeFile(t, p, "apply.log")
		lines := strings.Split(strings.TrimRight(log, "\n"), "\n")
		if len(lines) < 2 {
			t.Fatalf("expected at least 2 apply-log entries after S1, got %d:\n%s", len(lines), log)
		}
		// rewrite history in the first entry (an earlier version number), leave the hashes alone
		if !strings.Contains(lines[0], `"to":1`) {
			t.Fatalf("unexpected first apply-log entry: %s", lines[0])
		}
		lines[0] = strings.Replace(lines[0], `"to":1`, `"to":7`, 1)
		editedLog = strings.Join(lines, "\n") + "\n"
		volumeShell(t, p, "cat > /data/apply.log", editedLog)
		startProxy(t, p)

		w.expectTampered(t, p, "apply log edited")
	})

	// ARCHITECTURE section 4: "Tampered --> Enforcing: valid policy from control plane". Section 8 says the
	// same for a hand-edited policy file ("deny-all until a valid policy arrives").
	t.Run("edited apply log: a newer valid policy ends the tampered state", func(t *testing.T) {
		p := proxyByID("bank-a-main-5")
		t.Cleanup(func() {
			// operator repair so later scenarios start clean: wipe the broken log and policy of this proxy
			if s, err := w.self(p); err == nil && s.State == string(wire.StateEnforcing) {
				return
			}
			stopProxy(t, p)
			volumeShell(t, p, "rm -f /data/apply.log /data/policy.json", "")
			startProxy(t, p)
		})
		v := w.recoverWithNewPolicy(t, p)

		// Q-D30 / P-13: Enforcing again at v+1 (recoverWithNewPolicy waited for it) ...
		if s, err := w.self(p); err != nil || s.State != string(wire.StateEnforcing) || s.AppliedVersion != v {
			t.Errorf("after the newer valid policy: %+v (%v), want enforcing at v%d", s, err, v)
		}
		// ... the broken log is kept as evidence, with the edit still in it, never deleted ...
		ls := strings.Fields(volumeShell(t, p, "ls /data", ""))
		var broken []string
		for _, f := range ls {
			if strings.HasPrefix(f, "apply.log.broken-") {
				broken = append(broken, f)
			}
		}
		if len(broken) != 1 {
			t.Fatalf("want exactly one apply.log.broken-<n> in the data dir, found %v (ls: %v)", broken, ls)
		}
		if kept := volumeShell(t, p, "cat /data/"+broken[0], ""); kept != editedLog {
			t.Errorf("%s is not the edited log byte for byte:\n%s\nwant:\n%s", broken[0], kept, editedLog)
		}
		editedFirst := strings.SplitN(editedLog, "\n", 2)[0]
		if fresh := volumeShell(t, p, "cat /data/apply.log", ""); strings.Contains(fresh, editedFirst) {
			t.Errorf("the new apply.log still carries the edited first entry")
		}
		// ... a reset is reported (P-13: kairan_proxy_apply_log_resets_total) and the new chain starts with a reset entry ...
		if n, err := w.metric(p, "kairan_proxy_apply_log_resets_total"); err != nil || n < 1 {
			t.Errorf("kairan_proxy_apply_log_resets_total = %v (%v) on %s, want >= 1", n, err, p.ID)
		}
		if first := volumeShell(t, p, "head -n 1 /data/apply.log", ""); !strings.Contains(first, `"reset":{`) || !strings.Contains(first, `"seq":1`) {
			t.Errorf("the new apply.log does not start with a reset entry: %s", first)
		}
		// ... and the control plane timeline shows the anchor regression as its own period (M-D48).
		tv, err := w.timeline(p.Tenant)
		if err != nil {
			t.Fatal(err)
		}
		var mine []wire.TimelineEntry
		for _, e := range tv.Entries {
			if string(e.ProxyID) == p.ID {
				mine = append(mine, e)
			}
		}
		regressed := false
		var maxSeq uint64
		for _, e := range mine { // entries are in the CP's order; the maximum seen so far is the anchor to beat
			if e.LogSeq != 0 && e.LogSeq < maxSeq {
				regressed = true
			}
			if e.LogSeq > maxSeq {
				maxSeq = e.LogSeq
			}
		}
		if !regressed {
			t.Errorf("timeline of %s shows no log_seq regression (seq before tamper %d); entries: %+v", p.ID, seqBeforeTamper, mine)
		}
	})

	t.Run("older valid policy put back", func(t *testing.T) {
		p := proxyByID("city-b-main-1")
		// a wider policy that was once valid and signed: sales may run crm.export
		wideV := w.nextVersion(p.Tenant)
		wide := w.envelope(payload(p.Tenant, wideV, time.Now().Add(-time.Minute), time.Now().Add(72*time.Hour), map[string]string{"crm.export": "X"}), "admin-a", "admin-b")
		if code, ec, _, err := w.publish(wide); err != nil || code/100 != 2 {
			t.Fatalf("publish wide v%d: HTTP %d %q (%v)", wideV, code, ec, err)
		}
		if code, ec, err := w.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: wire.ID(p.Tenant), Version: wideV, CanaryDwellSeconds: 5}, nil); err != nil || code/100 != 2 {
			t.Fatalf("rollout wide: HTTP %d %q (%v)", code, ec, err)
		}
		w.ackTimes(t, map[string]uint64{p.Tenant: wideV}, 60*time.Second)
		if r := w.call(p, w.salesKey, "crm.export"); !r.Allowed {
			t.Fatalf("precondition: the wide policy v%d should allow crm.export: %+v", wideV, r)
		}
		old := readVolumeFile(t, p, "policy.json") // the attacker's copy of the wide, valid file

		// the admins replace it with a narrower one
		narrowV, _, _ := w.release(t, p.Tenant, 5)
		w.ackTimes(t, map[string]uint64{p.Tenant: narrowV}, 60*time.Second)
		if r := w.call(p, w.salesKey, "crm.export"); r.Allowed {
			t.Fatalf("precondition: v%d should deny crm.export again", narrowV)
		}

		stopProxy(t, p)
		var envOld wire.Envelope
		if err := json.Unmarshal([]byte(old), &envOld); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(envOld.Payload), `"crm.export":"X"`) {
			t.Fatalf("saved file is not the wide policy: %s", envOld.Payload)
		}
		volumeShell(t, p, "cat > /data/policy.json", old)
		startProxy(t, p)

		w.expectTampered(t, p, "older valid policy put back")
		if r := w.call(p, w.salesKey, "crm.export"); r.Allowed {
			t.Fatalf("I2/I3: the rolled-back wide policy v%d was enforced", wideV)
		}
		w.recoverWithNewPolicy(t, p)
		if r := w.call(p, w.salesKey, "crm.export"); r.Allowed {
			t.Errorf("after recovery crm.export must be denied")
		}
	})

	// nobody else was disturbed and the whole fleet is back in sync
	w.baseline(t)
}
