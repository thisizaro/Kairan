package main

import (
	"encoding/json"
	"net/http"
	"time"

	"kairan/internal/obs"
	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

// The local read-only listener (P-09, THREATS #2, M-D7). It answers two GET
// routes and nothing else:
//
//	/v1/self   the self view: tenant, proxy_id, state, applied_version,
//	           policy_hash, log_seq, log_head, clock_untrusted (JSON)
//	/metrics   counters and gauges in the Prometheus text format
//
// Both are built from agent.Snapshot and agent.Stats, so they carry wire
// types and counts only: never a payload, an argument, a result, a role or a
// user name (invariant I4). The self view is what the evidence export compares
// with the control plane's timeline.
//
// The listener has no authentication and no write route. It is inbound inside
// the customer network only (PRD J2, M-D51): bind it to an address on that
// network. It is off unless the config sets metrics_listen.

// Local listener limits, like the MCP listener's (M-D31).
const (
	localReadHeaderTimeout = 5 * time.Second
	localIdleTimeout       = 60 * time.Second
	localMaxHeaderBytes    = 8 << 10
)

// selfView is the JSON of /v1/self.
type selfView struct {
	Tenant         wire.ID         `json:"tenant"`
	ProxyID        wire.ID         `json:"proxy_id"`
	State          wire.ProxyState `json:"state"`
	AppliedVersion uint64          `json:"applied_version"`
	PolicyHash     wire.Hash       `json:"policy_hash"`
	LogSeq         uint64          `json:"log_seq"`
	LogHead        wire.Hash       `json:"log_head"`
	ClockUntrusted bool            `json:"clock_untrusted"`
}

// allStates is the closed set of proxy states, in the order they are listed.
var allStates = []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode}

// stateLabel turns a state into a metric label value. Label values must be
// wire.IDs (lowercase letters, digits, hyphens; M-D29), so deny_all is
// "deny-all" and safe_mode is "safe-mode" here.
func stateLabel(s wire.ProxyState) wire.ID {
	b := []byte(s)
	for i, c := range b {
		if c == '_' {
			b[i] = '-'
		}
	}
	return wire.ID(b)
}

// counterMetric maps a Stats counter to a published counter. Only the names
// listed here are published; any other name in Stats is ignored.
var counterMetrics = []struct{ stat, name, help string }{
	{"enforce_allow", "kairan_proxy_calls_allowed_total", "tools/call requests allowed."},
	{"enforce_deny", "kairan_proxy_calls_denied_total", "tools/call requests denied."},
	{"enforce_reject", "kairan_proxy_requests_rejected_total", "Requests refused as unreadable or malformed."},
	{"enforce_auth_failed", "kairan_proxy_auth_failures_total", "Requests refused for a missing or unknown API key."},
	{"enforce_upstream_errors", "kairan_proxy_upstream_errors_total", "Upstream MCP server failures, timeouts and redirects."},
	{"enforce_decision_log_errors", "kairan_proxy_decision_log_denied_total", "Decisions denied because the decision log could not store them."},
	{"declog_write_errors", "kairan_proxy_decision_log_write_errors_total", "Decision log records that were not stored."},
	{"declog_rotate_errors", "kairan_proxy_decision_log_rotate_errors_total", "Decision log rotations that failed."},
	{agent.MetricApplyOK, "kairan_proxy_policies_applied_total", "Policies applied."},
	{agent.MetricApplyRejected, "kairan_proxy_policies_rejected_total", "Envelopes rejected or not persisted."},
	{agent.MetricPollErrors, "kairan_proxy_poll_errors_total", "Failed polls of the control plane."},
	{agent.MetricStatusErrors, "kairan_proxy_status_errors_total", "Status reports that were not delivered."},
	{agent.MetricExpired, "kairan_proxy_policy_expired_total", "Times the policy in force expired into safe mode."},
	{agent.MetricBootTampered, "kairan_proxy_boot_tampered_total", "Boots that ended tampered."},
	{agent.MetricLogReset, "kairan_proxy_apply_log_resets_total", "Broken apply logs kept aside and replaced by a new chain."},
}

// newLocalHandler returns the read-only handler. snap is read on every
// request; stats may be nil.
func newLocalHandler(tenant, proxyID wire.ID, snap func() agent.Snapshot, stats *agent.Stats) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/self", func(w http.ResponseWriter, r *http.Request) {
		if !readOnly(w, r) {
			return
		}
		s := snap()
		b, _ := json.Marshal(selfView{
			Tenant: tenant, ProxyID: proxyID, State: s.State, AppliedVersion: s.AppliedVersion,
			PolicyHash: s.PolicyHash, LogSeq: s.LogSeq, LogHead: s.LogHead, ClockUntrusted: s.ClockUntrusted,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(b)
		}
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if !readOnly(w, r) {
			return
		}
		buildMetrics(snap(), stats).Handler().ServeHTTP(w, r)
	})
	return mux
}

// readOnly answers 405 to anything but GET and HEAD.
func readOnly(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}

// buildMetrics makes a fresh registry from the current snapshot and counters.
// There is no label that can carry call data: the only label is the state,
// from a closed set.
func buildMetrics(s agent.Snapshot, stats *agent.Stats) *obs.Registry {
	reg := obs.NewRegistry()
	st := reg.Gauge("kairan_proxy_state", "Proxy state: 1 for the current state, 0 for the others.", "state")
	for _, name := range allStates {
		v := 0.0
		if s.State == name {
			v = 1
		}
		st.With(stateLabel(name)).Set(v)
	}
	reg.Gauge("kairan_proxy_applied_version", "Version of the policy in force, 0 if none.").With().Set(float64(s.AppliedVersion))
	reg.Gauge("kairan_proxy_log_seq", "Sequence number of the last apply-log entry.").With().Set(float64(s.LogSeq))
	untrusted := 0.0
	if s.ClockUntrusted {
		untrusted = 1
	}
	reg.Gauge("kairan_proxy_clock_untrusted", "1 while the wall clock is more than 5 minutes behind effective time.").With().Set(untrusted)
	reg.Counter("kairan_proxy_clock_untrusted_total", "Episodes of an untrusted wall clock since start.").With().Add(s.ClockUntrustedCount)
	if stats != nil {
		for _, m := range counterMetrics {
			reg.Counter(m.name, m.help).With().Add(stats.Count(m.stat))
		}
		reg.Gauge("kairan_proxy_test_only_trusted_keys", "Trusted keys that are public TEST-ONLY fixture keys (should be 0).").With().Set(float64(stats.Count(metricTestOnlyKey)))
	}
	return reg
}
