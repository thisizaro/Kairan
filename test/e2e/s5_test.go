package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// fleetPage fetches the control plane's fleet page (HTTP basic auth, the admin token as password).
func (w *world) fleetPage(tenant, lang string) (string, error) {
	req, _ := http.NewRequest("GET", cpURL+"/?tenant="+tenant+"&lang="+lang, nil)
	req.SetBasicAuth("e2e", w.adminToken)
	res, err := w.hc.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != 200 {
		return "", io.ErrUnexpectedEOF
	}
	return string(b), nil
}

// extraTrusted gives the control plane two more admin keys for bank-a that the proxies do NOT trust. This is
// the only way to get an envelope past the control plane's publish check and in front of the proxies, which
// are the real judges (ARCHITECTURE: "sanity only; proxies are the judges"). It edits the generated cp.json in
// place and restarts the control plane; the cleanup restores both.
func (w *world) extraTrusted(t *testing.T) (x, y ed25519.PrivateKey) {
	t.Helper()
	path := filepath.Join(w.run, "cp.json")
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pubX, privX, _ := ed25519.GenerateKey(rand.Reader)
	pubY, privY, _ := ed25519.GenerateKey(rand.Reader)
	var cfg map[string]any
	if err := json.Unmarshal(orig, &cfg); err != nil {
		t.Fatal(err)
	}
	ten := cfg["tenants"].(map[string]any)["bank-a"].(map[string]any)
	ten["admin_keys"] = append(ten["admin_keys"].([]any), hex.EncodeToString(pubX), hex.EncodeToString(pubY))
	edited, _ := json.Marshal(cfg)
	restart := func(content []byte) {
		if err := os.WriteFile(path, content, 0o644); err != nil { // same inode: the bind mount sees it
			t.Fatal(err)
		}
		mustDocker(t, "restart", "-t", "5", "kairan-cp")
		eventually(t, 30*time.Second, 500*time.Millisecond, "control plane back", func() (bool, string) {
			_, err := w.fleet("bank-a")
			return err == nil, "no answer"
		})
	}
	t.Cleanup(func() { restart(orig) })
	restart(edited)
	return privX, privY
}

// cpMetrics returns every series of the control plane's /metrics whose name is `name`, keyed by its label text
// (for example `code="threshold-not-met",tenant="bank-a"`), value as float.
func (w *world) cpMetrics(name string) (map[string]float64, error) {
	res, err := w.hc.Get("http://127.0.0.1:19100/metrics")
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	out := map[string]float64{}
	for _, ln := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(ln, name+"{") && !strings.HasPrefix(ln, name+" ") {
			continue
		}
		f := strings.Fields(ln)
		var v float64
		if _, err := fmt.Sscanf(f[len(f)-1], "%g", &v); err != nil {
			continue
		}
		labels := ""
		if i := strings.Index(ln, "{"); i >= 0 {
			labels = ln[i+1 : strings.LastIndex(ln, "}")]
		}
		out[labels] = v
	}
	return out, nil
}

// rejectedSum adds up kairan_cp_publish_rejected_total series carrying code and (if non-empty) tenant.
func rejectedSum(m map[string]float64, code wire.ErrorCode, tenant string) float64 {
	var sum float64
	for labels, v := range m {
		// C-D13: the code label is the wire error code with hyphens (threshold-not-met), as obs label values must be wire IDs
		if !strings.Contains(labels, `code="`+strings.ReplaceAll(string(code), "_", "-")+`"`) {
			continue
		}
		if tenant != "" && !strings.Contains(labels, `tenant="`+tenant+`"`) {
			continue
		}
		sum += v
	}
	return sum
}

// S5 bad policies published: unsigned, 1-sig, old version, wrong tenant, expired, corrupted.
// Pass: 0 applied; every reason visible (fleet view, fleet page in English and Japanese, proxy metrics).
// Two layers judge: the control plane's publish check (sanity) and the proxies. Cases the control plane
// stops are asserted on its answer; cases that can only be stopped by the proxy are put in front of the
// proxies by giving the control plane two extra admin keys the proxies do not trust. I1, I2, M6.
func TestS5BadPolicies(t *testing.T) {
	w := need(t)
	w.baseline(t)
	canary := proxyByID("bank-a-canary")
	before := w.snapshotSelf(t)
	cur := before[canary.ID].AppliedVersion
	appliedBefore, err := w.metric(canary, "kairan_proxy_policies_applied_total")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// --- layer 1: the control plane's publish check ---
	good := goodPayload("bank-a", cur+1)
	corrupted := w.envelope(good, "admin-a", "admin-b")
	corrupted.Payload[len(corrupted.Payload)/2] ^= 0x20
	gate := []struct {
		name string
		env  wire.Envelope
		want []wire.ErrorCode
	}{
		{"unsigned", w.envelope(good), []wire.ErrorCode{wire.ErrMalformed, wire.ErrThreshold}},
		{"one signature", w.envelope(good, "admin-a"), []wire.ErrorCode{wire.ErrThreshold}},
		{"same signer twice", w.envelope(good, "admin-a", "admin-a"), []wire.ErrorCode{wire.ErrThreshold}},
		{"wrong tenant (not enrolled)", w.envelope(goodPayload("nope-x", cur+1), "admin-a", "admin-b"), []wire.ErrorCode{wire.ErrWrongTenant}},
		{"corrupted after signing", corrupted, []wire.ErrorCode{wire.ErrMalformed, wire.ErrThreshold}},
		{"old version (same as current)", w.envelope(goodPayload("bank-a", cur), "admin-a", "admin-b"), []wire.ErrorCode{wire.ErrConflict}},
		{"old version (v1 again)", w.envelope(goodPayload("bank-a", 1), "admin-a", "admin-b"), []wire.ErrorCode{wire.ErrConflict}},
	}
	badTried, badApplied := 0, 0 // M6 evidence: bad policies put in front of the fleet, and how many any proxy applied
	for _, g := range gate {
		badTried++
		rejBefore, mErr := w.cpMetrics("kairan_cp_publish_rejected_total")
		code, ec, _, err := w.publish(g.env)
		ok := false
		for _, want := range g.want {
			ok = ok || ec == want
		}
		if err != nil || code/100 != 4 || !ok {
			t.Errorf("gate %q: HTTP %d code %q (err %v), want 4xx with one of %v", g.name, code, ec, err, g.want)
		}
		// section 11 S5 "visible ... in metrics" (Q-D31, C-08): the CP counts each publish-time rejection by tenant and code
		tenant := "bank-a"
		if ec == wire.ErrWrongTenant || ec == wire.ErrMalformed { // malformed: the envelope is refused before its tenant is read
			tenant = "unknown" // C-D13: an unknown or unparsable tenant counts under tenant="unknown"
		}
		rejAfter, mErr2 := w.cpMetrics("kairan_cp_publish_rejected_total")
		if mErr != nil || mErr2 != nil {
			t.Errorf("gate %q: reading CP metrics: %v / %v", g.name, mErr, mErr2)
		} else if d := rejectedSum(rejAfter, ec, tenant) - rejectedSum(rejBefore, ec, tenant); d < 1 {
			t.Errorf("gate %q: kairan_cp_publish_rejected_total{tenant=%q,code=%q} grew by %v, want >= 1 (C-08); series now: %v", g.name, tenant, ec, d, rejAfter)
		}
	}
	if code, ec, _ := w.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: "bank-a", Version: 1}, nil); code != http.StatusConflict {
		t.Errorf("rollout of old version 1: HTTP %d %q, want 409 conflict", code, ec)
	}
	w.sameAs(t, before, "after publish-check rejections")

	// --- layer 2: the proxies ---
	x, y := w.extraTrusted(t)
	w.baseline(t)
	cases := []struct {
		name    string
		make    func(v uint64) wire.Envelope
		want    wire.ErrorCode
		comment string
	}{
		{"unsigned as far as the proxies are concerned (two untrusted signers)",
			func(v uint64) wire.Envelope {
				e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: goodPayload("bank-a", v), Signatures: []wire.Signature{}}
				trust.Sign(&e, x)
				trust.Sign(&e, y)
				return e
			}, wire.ErrThreshold, ""},
		{"one trusted signature plus one untrusted",
			func(v uint64) wire.Envelope {
				e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: goodPayload("bank-a", v), Signatures: []wire.Signature{}}
				trust.Sign(&e, w.keys["admin-a"])
				trust.Sign(&e, x)
				return e
			}, wire.ErrThreshold, ""},
		{"expired",
			func(v uint64) wire.Envelope {
				return w.envelope(payload("bank-a", v, now.Add(-48*time.Hour), now.Add(-24*time.Hour), nil), "admin-a", "admin-b")
			}, wire.ErrExpired, ""},
	}
	for _, c := range cases {
		badTried++
		t.Run(c.name, func(t *testing.T) {
			rejectedBefore, _ := w.metric(canary, "kairan_proxy_policies_rejected_total")
			v := w.nextVersion("bank-a")
			code, ec, _, err := w.publish(c.make(v))
			if err != nil || code/100 != 2 {
				t.Fatalf("publish should pass the control plane's check here: HTTP %d %q (%v)", code, ec, err)
			}
			if code, ec, err := w.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: "bank-a", Version: v, CanaryDwellSeconds: 5}, nil); err != nil || code/100 != 2 {
				t.Fatalf("rollout start: HTTP %d %q (%v)", code, ec, err)
			}
			eventually(t, 30*time.Second, 300*time.Millisecond, "canary to report "+string(c.want)+" for v"+itoa(v), func() (bool, string) {
				r, err := w.fleetRow(canary.ID)
				if err != nil {
					return false, err.Error()
				}
				if r.LastError == nil {
					return false, "no last_error yet"
				}
				return r.LastError.Code == c.want && r.LastError.Version == v, "last_error " + string(r.LastError.Code)
			})
			time.Sleep(2 * time.Second) // let a wrong main-group rollout show itself

			// 0 applied: nobody in the fleet moved off the current policy
			w.sameAs(t, before, "after "+c.name)
			fv, _ := w.fleet("bank-a")
			for _, r := range fv.Proxies {
				if r.AppliedVersion != cur || string(r.PolicyHash) != before[string(r.ProxyID)].PolicyHash {
					badApplied++
					t.Errorf("%s applied v%d (hash %.12s) after a bad policy; was v%d", r.ProxyID, r.AppliedVersion, r.PolicyHash, cur)
				}
				if r.Group == "main" && r.DesiredVersion != cur {
					t.Errorf("%s was told to move to v%d: a bad canary must not promote", r.ProxyID, r.DesiredVersion)
				}
			}
			// the canary still enforces the old policy
			for _, cm := range callMix {
				if r := w.call(canary, w.keyFor(cm.role), cm.tool); r.Err != nil || r.Allowed != wantAllowed(cm.role, cm.tool, cur) {
					t.Errorf("canary %s/%s allowed=%v err=%v after the bad policy", cm.role, cm.tool, r.Allowed, r.Err)
				}
			}
			// reason is visible: rollout halts with it, metrics count the rejection, the fleet page names it in both languages
			rv, err := w.rolloutView("bank-a")
			if err != nil || rv.Version != v || rv.Phase != wire.PhaseHalted {
				t.Errorf("rollout %+v (%v), want halted at v%d", rv, err, v)
			}
			if rejected, err := w.metric(canary, "kairan_proxy_policies_rejected_total"); err != nil || rejected < rejectedBefore+1 {
				t.Errorf("kairan_proxy_policies_rejected_total %v -> %v (%v), want it to grow", rejectedBefore, rejected, err)
			}
			if applied, _ := w.metric(canary, "kairan_proxy_policies_applied_total"); applied != appliedBefore {
				t.Errorf("kairan_proxy_policies_applied_total %v -> %v: something was applied", appliedBefore, applied)
			}
			for _, lang := range []string{"en", "ja"} {
				page, err := w.fleetPage("bank-a", lang)
				if err != nil || !strings.Contains(page, string(c.want)) {
					t.Errorf("fleet page (%s) does not show %q (%v)", lang, c.want, err)
				}
			}
		})
	}

	t.Logf("S5 result: %d bad policies, %d applied (a count of proxies that moved off the current policy after any of them)", badTried, badApplied)

	// recovery: a good, higher, two-signature version fixes the halted rollout and reaches every proxy
	v, hash, _ := w.release(t, "bank-a", 5)
	w.ackTimes(t, map[string]uint64{"bank-a": v}, 60*time.Second)
	rv, err := w.rolloutView("bank-a")
	if err != nil || rv.Phase != wire.PhaseComplete || rv.Version != v {
		t.Errorf("after the fix: rollout %+v (%v), want complete at v%d", rv, err, v)
	}
	fv, _ := w.fleet("bank-a")
	for _, r := range fv.Proxies {
		if r.AppliedVersion != v || r.PolicyHash != hash || r.Drift != 0 {
			t.Errorf("after the fix %s: %+v", r.ProxyID, r)
		}
	}
	// city-b never saw any of it
	for _, p := range tenantProxies("city-b") {
		if s, err := w.self(p); err != nil || s.AppliedVersion != before[p.ID].AppliedVersion {
			t.Errorf("%s moved: %+v (%v)", p.ID, s, err)
		}
	}
}
