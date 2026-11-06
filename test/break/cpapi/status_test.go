package cpapibreak

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// wire.StatusReport.Validate is the oracle for content: a report that passes it is accepted (204), one that
// fails is 400. Never 5xx, never an echo.
func TestStatusValidationFollowsWire(t *testing.T) {
	e := newEnv(t)
	mod := func(f func(*wire.StatusReport)) wire.StatusReport {
		r := report("bank-a", "p1", 3, 1)
		f(&r)
		return r
	}
	good := hashOf(policyJSON("bank-a", 3))
	cases := map[string]wire.StatusReport{
		"valid-enforcing": report("bank-a", "p1", 3, 1),
		"valid-denyall":   report("bank-a", "p1", 0, 1),
		"valid-safe-mode": mod(func(r *wire.StatusReport) { r.State = wire.StateSafeMode }),
		"valid-tampered": mod(func(r *wire.StatusReport) {
			r.State = wire.StateTampered
			r.AppliedVersion = 0
			r.PolicyHash = ""
			r.LogSeq = 0
			r.LogHead = ""
		}),
		"state-garbage":        mod(func(r *wire.StatusReport) { r.State = "weird" }),
		"state-empty":          mod(func(r *wire.StatusReport) { r.State = "" }),
		"state-canary":         mod(func(r *wire.StatusReport) { r.State = wire.ProxyState(canary) }),
		"version-without-hash": mod(func(r *wire.StatusReport) { r.PolicyHash = "" }),
		"hash-without-version": mod(func(r *wire.StatusReport) { r.AppliedVersion = 0 }),
		"hash-uppercase":       mod(func(r *wire.StatusReport) { r.PolicyHash = wire.Hash(strings.ToUpper(string(good))) }),
		"hash-short":           mod(func(r *wire.StatusReport) { r.PolicyHash = good[:63] }),
		"hash-not-hex":         mod(func(r *wire.StatusReport) { r.PolicyHash = wire.Hash(strings.Repeat("z", 64)) }),
		"denyall-with-version": mod(func(r *wire.StatusReport) { r.State = wire.StateDenyAll }),
		"enforcing-no-version": mod(func(r *wire.StatusReport) {
			r.State = wire.StateEnforcing
			r.AppliedVersion = 0
			r.PolicyHash = ""
			r.LogSeq = 0
			r.LogHead = ""
		}),
		"log-head-no-seq":     mod(func(r *wire.StatusReport) { r.LogSeq = 0 }),
		"log-seq-no-head":     mod(func(r *wire.StatusReport) { r.LogHead = "" }),
		"log-head-bad":        mod(func(r *wire.StatusReport) { r.LogHead = "nothex" }),
		"error-code-garbage":  mod(func(r *wire.StatusReport) { r.LastError = &wire.ApplyError{Code: "free text with " + canary} }),
		"error-code-valid":    mod(func(r *wire.StatusReport) { r.LastError = &wire.ApplyError{Code: wire.ErrNotNewer, Version: 2} }),
		"proxy-id-uppercase":  mod(func(r *wire.StatusReport) { r.ProxyID = "P1" }),
		"tenant-invalid":      mod(func(r *wire.StatusReport) { r.Tenant = "BANK" }),
		"tenant-empty":        mod(func(r *wire.StatusReport) { r.Tenant = "" }),
		"max-uint-version":    mod(func(r *wire.StatusReport) { r.AppliedVersion = 1<<64 - 1 }),
		"max-uint-seq-uptime": mod(func(r *wire.StatusReport) { r.Seq = 1<<64 - 1; r.UptimeSeconds = 1<<64 - 1 }),
		"max-uint-counters": mod(func(r *wire.StatusReport) {
			r.Counters = wire.Counters{CallsAllowed: 1<<64 - 1, CallsDenied: 1<<64 - 1, EnvelopesRejected: 1<<64 - 1}
		}),
	}
	for name, rep := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.status("p1", rep)
			verr := rep.Validate()
			want := 204
			if verr != nil || rep.Tenant != "bank-a" || rep.ProxyID != "p1" {
				want = 400
				if rep.Tenant != "bank-a" || rep.ProxyID != "p1" {
					if r.code != 400 && r.code != 403 {
						t.Fatalf("got %d %s, want 400/403", r.code, r.body)
					}
					return
				}
			}
			if r.code != want {
				t.Fatalf("Validate()=%v: got %d %s, want %d", verr, r.code, r.body, want)
			}
			if want == 204 && len(r.body) != 0 {
				t.Fatalf("204 with a body: %q", r.body)
			}
			if strings.Contains(string(r.body), "9f3b27") {
				t.Fatalf("echo: %s", r.body)
			}
		})
	}
	if x := contains(e.logText()+e.metricsText(), "9f3b27", canary); x != "" {
		t.Errorf("a rejected report's text reached logs or metrics (I4)")
	}
}

func TestStatusStrictBody(t *testing.T) {
	e := newEnv(t)
	good := mustJSON(report("bank-a", "p1", 0, 1))
	cases := map[string][]byte{
		"empty":            nil,
		"null":             []byte("null"),
		"array":            []byte("[]"),
		"unknown-prompt":   append(good[:len(good)-1:len(good)-1], []byte(`,"prompt":"`+canary+`"}`)...),
		"unknown-args":     append(good[:len(good)-1:len(good)-1], []byte(`,"arguments":{"q":"`+canary+`"}}`)...),
		"unknown-nested":   append(good[:len(good)-1:len(good)-1], []byte(`,"counters":{"calls_allowed":1,"tool":"`+canary+`"}}`)...),
		"trailing":         append(append([]byte{}, good...), []byte(`{}`)...),
		"trailing-garbage": append(append([]byte{}, good...), []byte(canary)...),
		"string-number":    []byte(strings.Replace(string(good), `"seq":1`, `"seq":"1"`, 1)),
		"negative-seq":     []byte(strings.Replace(string(good), `"seq":1`, `"seq":-1`, 1)),
		"float-seq":        []byte(strings.Replace(string(good), `"seq":1`, `"seq":1.5`, 1)),
		"huge-seq":         []byte(strings.Replace(string(good), `"seq":1`, `"seq":18446744073709551616`, 1)),
		"truncated":        good[:len(good)/2],
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := e.do("POST", wire.PathStatus, tokOf("p1"), body)
			if r.code != 400 || !r.errCode().Valid() {
				t.Fatalf("got %d %s, want 400", r.code, r.body)
			}
		})
	}
	// I4: nothing from the rejected bodies is anywhere: not in the fleet, the timeline, logs or metrics.
	for _, p := range []string{wire.PathFleet, wire.PathTimeline, wire.PathRollouts} {
		r := e.do("GET", p+"?tenant=bank-a", adminTok, nil)
		if strings.Contains(string(r.body), "9f3b27") {
			t.Errorf("%s shows rejected input", p)
		}
	}
	if x := contains(e.logText()+e.metricsText(), "9f3b27", canary); x != "" {
		t.Errorf("rejected status bodies reached logs or metrics (I4)")
	}
	// A rejected report leaves the proxy unseen.
	if row := e.row("bank-a", "p1"); row.LastSeenUnixMs != 0 {
		t.Errorf("rejected reports updated last_seen: %+v", row)
	}
}

// PRD G2: health from the CP clock: healthy -> stale (30s) -> lost (2m); the enrolled-but-silent proxy is lost.
func TestFleetHealthFollowsTheControlPlaneClock(t *testing.T) {
	e := newEnv(t)
	e.mustStatus("p1", report("bank-a", "p1", 0, 1))
	e.clk.Advance(time.Second)
	row := e.row("bank-a", "p1")
	if row.Health != wire.HealthHealthy || row.LastSeenUnixMs != t0.UnixMilli() {
		t.Fatalf("fresh: %+v (want last_seen %d)", row, t0.UnixMilli())
	}
	if p2 := e.row("bank-a", "p2"); p2.Health != wire.HealthLost || p2.LastSeenUnixMs != 0 {
		t.Fatalf("enrolled but never reported: %+v, want lost", p2)
	}
	e.clk.Advance(31 * time.Second)
	if row := e.row("bank-a", "p1"); row.Health != wire.HealthStale {
		t.Fatalf("after 32s: %+v", row)
	}
	e.clk.Advance(2 * time.Minute)
	if row := e.row("bank-a", "p1"); row.Health != wire.HealthLost {
		t.Fatalf("after 2m32s: %+v", row)
	}
	e.mustStatus("p1", report("bank-a", "p1", 0, 2))
	if row := e.row("bank-a", "p1"); row.Health != wire.HealthHealthy {
		t.Fatalf("after a new report: %+v", row)
	}
	// A proxy cannot make the CP trust its clock: the time shown is the CP's, whatever the report claims
	// (the report has no time field; an unknown field is a 400, checked in TestStatusStrictBody).
}

// The fleet lists enrolled proxies of the tenant only, with the group from the registry (M-D4, M-D26).
func TestFleetIsTenantScopedAndUsesRegistryGroups(t *testing.T) {
	e := newEnv(t)
	e.mustStatus("p1", report("bank-a", "p1", 0, 1))
	e.mustStatus("q1", report("bank-b", "q1", 0, 1))
	a := e.fleetView("bank-a")
	b := e.fleetView("bank-b")
	if a.Tenant != "bank-a" || b.Tenant != "bank-b" {
		t.Fatalf("tenants %q %q", a.Tenant, b.Tenant)
	}
	groups := map[wire.ID]wire.ID{}
	for _, p := range a.Proxies {
		groups[p.ProxyID] = p.Group
		if p.ProxyID == "q1" {
			t.Fatalf("bank-b proxy shown in bank-a: %+v", p)
		}
	}
	if groups["c1"] != "canary" || groups["p1"] != "main" || len(groups) != 3 {
		t.Fatalf("groups from the registry: %v", groups)
	}
	if len(b.Proxies) != 1 || b.Proxies[0].ProxyID != "q1" {
		t.Fatalf("bank-b view: %+v", b.Proxies)
	}
}

func TestFleetAndTimelineParams(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{wire.PathFleet, wire.PathTimeline} {
		for name, qs := range map[string]string{
			"none":    "",
			"empty":   "tenant=",
			"two":     "tenant=bank-a&tenant=bank-b",
			"bad-id":  "tenant=Bank_A",
			"unknown": "tenant=bank-zzz",
			"slash":   "tenant=bank-a/../bank-b",
		} {
			r := e.do("GET", path+"?"+qs, adminTok, nil)
			if r.code != 400 && r.code != 404 {
				t.Errorf("%s %s: got %d %s, want 400/404", path, name, r.code, r.body)
			}
			if !r.errCode().Valid() {
				t.Errorf("%s %s: not a wire error: %s", path, name, r.body)
			}
		}
	}
}

// M-D35/Q-D15 end to end: a log anchor that goes backwards starts a new timeline entry, so evidence sees
// 7 then 5 (tail truncation of the apply log, I6). Version changes also start entries.
func TestTimelineRecordsAnchorRegressionAndVersionChanges(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	r7 := report("bank-a", "p1", 1, 1)
	r7.LogSeq, r7.LogHead = 7, hashOf([]byte("head-7"))
	e.mustStatus("p1", r7)
	e.clk.Advance(10 * time.Second)
	r5 := report("bank-a", "p1", 1, 2)
	r5.LogSeq, r5.LogHead = 5, hashOf([]byte("head-5"))
	e.mustStatus("p1", r5)
	e.clk.Advance(10 * time.Second)
	e.mustStatus("p1", report("bank-a", "p1", 2, 3))
	r := e.do("GET", wire.PathTimeline+"?tenant=bank-a", adminTok, nil)
	if r.code != 200 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	var tv wire.TimelineView
	if err := json.Unmarshal(r.body, &tv); err != nil {
		t.Fatal(err)
	}
	if tv.Tenant != "bank-a" {
		t.Fatalf("tenant %q", tv.Tenant)
	}
	var mine []wire.TimelineEntry
	for _, en := range tv.Entries {
		if en.ProxyID == "p1" {
			mine = append(mine, en)
		}
	}
	if len(mine) != 3 {
		t.Fatalf("want 3 entries (7, then 5, then v2), got %+v", mine)
	}
	if mine[0].LogSeq != 7 || mine[1].LogSeq != 5 || mine[0].Version != 1 || mine[1].Version != 1 || mine[2].Version != 2 {
		t.Fatalf("timeline %+v", mine)
	}
	if mine[0].FirstSeenUnixMs != t0.UnixMilli() || mine[2].FirstSeenUnixMs <= mine[1].FirstSeenUnixMs {
		t.Fatalf("times use the CP clock and increase: %+v", mine)
	}
}

// A status from one tenant's proxy never shows up in another tenant's timeline.
func TestTimelineIsTenantScoped(t *testing.T) {
	e := newEnv(t)
	e.mustStatus("q1", report("bank-b", "q1", 0, 1))
	e.mustStatus("p1", report("bank-a", "p1", 0, 1))
	var tv wire.TimelineView
	r := e.do("GET", wire.PathTimeline+"?tenant=bank-a", adminTok, nil)
	if err := json.Unmarshal(r.body, &tv); err != nil {
		t.Fatalf("%v: %s", err, r.body)
	}
	for _, en := range tv.Entries {
		if en.ProxyID == "q1" {
			t.Fatalf("bank-b entry in bank-a timeline: %+v", en)
		}
	}
}

// Fleet rows carry desired vs applied and drift (PRD G2) from the rollout, and an apply error stays visible.
func TestFleetShowsDriftAndLastError(t *testing.T) {
	e := newEnv(t)
	e.bring(1)
	e.publish("bank-a", 2)
	e.startRollout("bank-a", 2)
	row := e.row("bank-a", "c1")
	if row.DesiredVersion != 2 || row.AppliedVersion != 1 || row.Drift != 1 {
		t.Fatalf("canary row %+v, want desired 2 applied 1 drift 1", row)
	}
	if row := e.row("bank-a", "p1"); row.DesiredVersion != 1 || row.Drift != 0 {
		t.Fatalf("main row %+v, want desired 1 drift 0", row)
	}
	bad := report("bank-a", "c1", 1, 200)
	bad.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 2}
	e.mustStatus("c1", bad)
	row = e.row("bank-a", "c1")
	if row.LastError == nil || row.LastError.Code != wire.ErrThreshold || row.LastError.Version != 2 {
		t.Fatalf("last error not shown: %+v", row)
	}
	if row.PolicyHash != hashOf(policyJSON("bank-a", 1)) {
		t.Fatalf("policy hash %q", row.PolicyHash)
	}
}
