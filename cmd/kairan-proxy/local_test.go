package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

var (
	testHash = wire.Hash(strings.Repeat("ab", 32))
	testHead = wire.Hash(strings.Repeat("cd", 32))
)

func get(t *testing.T, h http.Handler, method, path string) (int, http.Header, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	b, _ := io.ReadAll(rec.Result().Body)
	return rec.Code, rec.Header(), string(b)
}

func newLocal(snap agent.Snapshot, stats *agent.Stats) http.Handler {
	return newLocalHandler("bank-a", "proxy-1", func() agent.Snapshot { return snap }, stats)
}

func TestSelfView(t *testing.T) {
	snap := agent.Snapshot{State: wire.StateEnforcing, AppliedVersion: 7, PolicyHash: testHash, LogSeq: 3, LogHead: testHead}
	code, hdr, body := get(t, newLocal(snap, &agent.Stats{}), http.MethodGet, "/v1/self")
	if code != 200 || hdr.Get("Content-Type") != "application/json" {
		t.Fatalf("%d %v", code, hdr)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"tenant": "bank-a", "proxy_id": "proxy-1", "state": "enforcing", "applied_version": float64(7),
		"policy_hash": string(testHash), "log_seq": float64(3), "log_head": string(testHead), "clock_untrusted": false,
	}
	if len(got) != len(want) {
		t.Fatalf("fields %v, want exactly %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestSelfViewNoPolicyAndUntrustedClock(t *testing.T) {
	snap := agent.Snapshot{State: wire.StateDenyAll, ClockUntrusted: true}
	_, _, body := get(t, newLocal(snap, &agent.Stats{}), http.MethodGet, "/v1/self")
	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["state"] != "deny_all" || got["applied_version"] != float64(0) || got["policy_hash"] != "" || got["clock_untrusted"] != true {
		t.Fatalf("%v", got)
	}
}

func TestLocalRoutesAreReadOnly(t *testing.T) {
	h := newLocal(agent.Snapshot{State: wire.StateEnforcing}, &agent.Stats{})
	for _, path := range []string{"/v1/self", "/metrics"} {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			code, hdr, _ := get(t, h, m, path)
			if code != http.StatusMethodNotAllowed || hdr.Get("Allow") != "GET, HEAD" {
				t.Errorf("%s %s = %d %v", m, path, code, hdr)
			}
		}
		if code, _, body := get(t, h, http.MethodHead, path); code != 200 || body != "" {
			t.Errorf("HEAD %s = %d %q", path, code, body)
		}
	}
	for _, path := range []string{"/", "/v1/self/", "/v1", "/admin", "/metrics/x", "/v1/policy", "/debug/pprof/"} {
		if code, _, _ := get(t, h, http.MethodGet, path); code != http.StatusNotFound {
			t.Errorf("GET %s = %d", path, code)
		}
	}
}

func TestMetrics(t *testing.T) {
	stats := &agent.Stats{}
	for _, n := range []string{"enforce_allow", "enforce_allow", "enforce_allow", "enforce_deny", "agent_apply_ok", "agent_apply_rejected", "agent_apply_rejected",
		"agent_poll_errors", "agent_status_errors", "agent_policy_expired", "agent_boot_tampered", "enforce_reject", "enforce_auth_failed",
		"enforce_upstream_errors", "enforce_decision_log_errors", "declog_write_errors", "declog_rotate_errors", "test_only_trusted_key"} {
		stats.Inc(n)
	}
	stats.Inc("something_not_ours") // unknown names are not published
	snap := agent.Snapshot{State: wire.StateSafeMode, AppliedVersion: 9, PolicyHash: testHash, LogSeq: 5, LogHead: testHead, ClockUntrusted: true, ClockUntrustedCount: 2}
	code, hdr, body := get(t, newLocal(snap, stats), http.MethodGet, "/metrics")
	if code != 200 || !strings.HasPrefix(hdr.Get("Content-Type"), "text/plain; version=0.0.4") {
		t.Fatalf("%d %v", code, hdr)
	}
	for _, line := range []string{
		`kairan_proxy_state{state="safe-mode"} 1`,
		`kairan_proxy_state{state="enforcing"} 0`,
		`kairan_proxy_state{state="deny-all"} 0`,
		`kairan_proxy_state{state="tampered"} 0`,
		`kairan_proxy_state{state="booting"} 0`,
		"kairan_proxy_applied_version 9",
		"kairan_proxy_log_seq 5",
		"kairan_proxy_clock_untrusted 1",
		"kairan_proxy_clock_untrusted_total 2",
		"kairan_proxy_calls_allowed_total 3",
		"kairan_proxy_calls_denied_total 1",
		"kairan_proxy_policies_applied_total 1",
		"kairan_proxy_policies_rejected_total 2",
		"kairan_proxy_poll_errors_total 1",
		"kairan_proxy_status_errors_total 1",
		"kairan_proxy_policy_expired_total 1",
		"kairan_proxy_boot_tampered_total 1",
		"kairan_proxy_requests_rejected_total 1",
		"kairan_proxy_auth_failures_total 1",
		"kairan_proxy_upstream_errors_total 1",
		"kairan_proxy_decision_log_denied_total 1",
		"kairan_proxy_decision_log_write_errors_total 1",
		"kairan_proxy_decision_log_rotate_errors_total 1",
		"kairan_proxy_test_only_trusted_keys 1",
	} {
		if !strings.Contains("\n"+body, "\n"+line+"\n") {
			t.Errorf("missing line %q in:\n%s", line, body)
		}
	}
	// No hash, tenant, proxy or free text in the exposition (I4, M-D29).
	for _, leak := range []string{string(testHash), string(testHead), "bank-a", "proxy-1", "something_not_ours"} {
		if strings.Contains(body, leak) {
			t.Errorf("metrics contain %q", leak)
		}
	}
}

func TestMetricsEveryStateHasOneSeries(t *testing.T) {
	for _, st := range []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode} {
		_, _, body := get(t, newLocal(agent.Snapshot{State: st}, &agent.Stats{}), http.MethodGet, "/metrics")
		ones := 0
		for _, l := range strings.Split(body, "\n") {
			if strings.HasPrefix(l, "kairan_proxy_state{") && strings.HasSuffix(l, " 1") {
				ones++
			}
		}
		if ones != 1 || strings.Count(body, "kairan_proxy_state{") != 5 {
			t.Errorf("state %s: %d series at 1\n%s", st, ones, body)
		}
	}
}

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// The listener on the wire: the self view and metrics follow the proxy
// through deny-all, a delivered policy and the calls made, and show nothing
// the agent or the tools said (I4).
func TestRunServesSelfViewAndMetrics(t *testing.T) {
	w := newWorld(t)
	w.cfg["metrics_listen"] = "127.0.0.1:0"
	r := w.start()
	if r.metrics == "" {
		t.Fatal("no local listener")
	}
	self := func() map[string]any {
		code, body := httpGet(t, "http://"+r.metrics+"/v1/self")
		var m map[string]any
		if code != 200 || json.Unmarshal([]byte(body), &m) != nil {
			t.Fatalf("self: %d %s", code, body)
		}
		return m
	}
	if m := self(); m["state"] != "deny_all" || m["applied_version"] != float64(0) || m["policy_hash"] != "" || m["tenant"] != "bank-a" || m["proxy_id"] != "proxy-1" {
		t.Fatalf("before policy: %v", m)
	}
	if _, body := httpGet(t, "http://"+r.metrics+"/metrics"); !strings.Contains(body, `kairan_proxy_state{state="deny-all"} 1`) {
		t.Fatalf("metrics before policy:\n%s", body)
	}

	env := w.envelope(3, time.Hour)
	w.cpEnv.Store(&env)
	w.await("policy applied", func() bool {
		s, ok := w.lastStatus()
		return ok && s.State == wire.StateEnforcing && s.AppliedVersion == 3
	})
	w.call(r, "key-sales-123", "crm.read_contact")
	w.call(r, "key-sales-123", "crm.update_deal")
	w.call(r, "key-sales-123", "crm.export")

	s, _ := w.lastStatus()
	m := self()
	if m["state"] != "enforcing" || m["applied_version"] != float64(3) || m["policy_hash"] != string(s.PolicyHash) ||
		m["log_seq"] != float64(s.LogSeq) || m["log_head"] != string(s.LogHead) || m["clock_untrusted"] != false {
		t.Fatalf("self %v differs from status %+v", m, s)
	}
	_, body := httpGet(t, "http://"+r.metrics+"/metrics")
	for _, line := range []string{
		`kairan_proxy_state{state="enforcing"} 1`, "kairan_proxy_applied_version 3", "kairan_proxy_log_seq 1",
		"kairan_proxy_calls_allowed_total 2", "kairan_proxy_calls_denied_total 1", "kairan_proxy_policies_applied_total 1",
	} {
		if !strings.Contains("\n"+body, "\n"+line+"\n") {
			t.Errorf("missing %q in:\n%s", line, body)
		}
	}
	for _, leak := range []string{string(s.PolicyHash), string(s.LogHead), "crm.", "key-sales", "enroll-token", "sales"} {
		if strings.Contains(body, leak) {
			t.Errorf("metrics leak %q", leak)
		}
	}
	// The MCP listener does not serve the self view, and the local listener
	// does not proxy MCP.
	if code, _ := httpGet(t, "http://"+r.addr+"/v1/self"); code == 200 {
		t.Error("self view on the MCP listener")
	}
	resp, err := http.Post("http://"+r.metrics+"/", "application/json", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST / on the local listener = %d", resp.StatusCode)
	}
	if err := r.stop(t); err != nil {
		t.Fatalf("run = %v\n%s", err, r.stderr.String())
	}
	if _, err := http.Get("http://" + r.metrics + "/v1/self"); err == nil {
		t.Error("local listener still open after shutdown")
	}
}

func TestNoLocalListenerUnlessConfigured(t *testing.T) {
	w := newWorld(t)
	r := w.start()
	if r.metrics != "" {
		t.Fatalf("local listener at %s without metrics_listen", r.metrics)
	}
}

func TestLocalListenFailureIsAnError(t *testing.T) {
	w := newWorld(t)
	first := w.start()
	w.cfg["metrics_listen"] = first.addr // already taken
	var out syncBuf
	err := run(t.Context(), []string{"-config", w.writeConfig()}, &out, func(string) { t.Fatal("ready") })
	if err == nil || errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
}
