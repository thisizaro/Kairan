// Package agent is the proxy's control-plane client (ARCHITECTURE section 10,
// proxy/agent): boot, long-poll, status reports, and the clock guard that
// bounds expiry against clock rollback.
//
// # Use
//
//	g, _ := agent.OpenClockGuard(clk, dataDir)
//	hc, _ := agent.NewHTTPClient(caFile)
//	a, err := agent.New(cfg, store, applyLog, holder, clk, hc, logger, stats)
//	a.Boot()          // reload and re-verify from disk, set the Holder
//	a.Run(ctx)        // poll, status, expiry and high-water loops
//
// New returns an error for a config that must not run: no control plane URL,
// http:// without AllowPlaintext, empty token, skew outside 0..5m, or a trust
// root below the floor (threshold under 2, fewer keys than the threshold,
// root for another tenant). Config.Validate says the same without building.
//
// # Boot (M-D33)
//
// Boot loads the stored envelope, re-checks it with trust.Verify against the
// local root, compares it with the apply log (store.DecideBoot) and decides
// expiry at effective_now (expires_at plus skew, as trust.Accept does). The
// outcome is one of DenyAll (nothing stored, nothing ever applied), Tampered
// (apply log or stored file failed, stored version below the log, file gone
// although the log applied something), Enforcing or SafeMode (expired).
// A stored version above the log's last applied is accepted with a repair
// entry appended (a crash fell between Save and Append); if that entry cannot
// be written the proxy stays Tampered. A bad disk is a state, not an error:
// Boot returns an error only if it is called twice. If the apply log did not
// open, pass a nil log and its error in Config.LogOpenErr; the proxy boots
// Tampered and applies nothing.
//
// # Apply
//
// Every envelope goes through trust.Accept (signatures from at least
// Threshold distinct trusted keys, tenant, version above the floor, not
// expired at effective_now), then store.Save, then applylog.Append, then the
// Holder swap. The floor is the larger of the version in force and the apply
// log's last applied, so a Tampered proxy also needs a version above
// everything it ever applied (I2). A failure at any step keeps the policy in
// force (I3) and is reported as last_error with a wire error code. The
// control plane's own version field is advisory and never used to decide.
// Rejected attempts are written to the apply log, except an exact repeat of
// the previous rejection (same version, hash and code), so a control plane
// that resends one bad envelope cannot fill the disk; the rejected counter
// still counts each one.
//
// # Poll loop
//
// The 200 body is decoded strictly, by the same rule as trust.DecodeEnvelope:
// the top-level keys are exactly "version" and "envelope", each once, spelled
// exactly (a duplicate or a variant such as "Envelope" is a rejected answer,
// counted and followed by a backoff, malformed_request in last_error).
//
// GET /v1/poll?tenant&proxy&have with the bearer token. The client deadline is
// wire.PollClientTimeout (45s, M-D40). 200 is applied; 304 polls again at once
// unless it came back faster than wire.RetryBackoffMin (a displaced poll or a
// misbehaving server must not become a hot loop). 503 waits at least the
// Retry-After (seconds or HTTP date, capped at 5 minutes, up to 20% jitter
// added; THREATS #8). Any other status, a network error, a timeout or a
// rejected envelope waits an exponential backoff from wire.RetryBackoffMin to
// wire.RetryBackoffMax with full jitter, reset by a good poll. Redirects are
// not followed, so the token only goes to the configured host.
//
// # Status reports
//
// POST /v1/status carries a wire.StatusReport and nothing else (I4): state,
// applied version and hash, log_seq and log_head (the apply-log anchor,
// M-D35), a last_error code, uptime, and three counters. One goes out at
// start, immediately after every apply attempt or state change, and
// otherwise every wire.StatusInterval (10s), each with a deadline of 10s. A
// failed report is counted and not retried until the next trigger. A 503
// holds further reports until its Retry-After has passed. last_error holds
// the latest rejected or failed apply until the next successful apply; while
// there is none it shows clock_untrusted if the wall clock is more than 5
// minutes behind effective_now.
//
// # Expiry and the clock guard
//
// Every expiry check uses effective_now from the ClockGuard (clockguard.go),
// never the raw wall clock. A watcher flips Enforcing to SafeMode when
// effective_now reaches expires_at plus skew; the policy stays loaded and
// SafeMode lets only the policy's R tools through (or nothing, with safe mode
// deny_all, which enforce applies). A newer policy lifts SafeMode.
//
// # Network
//
// NewHTTPClient honours HTTPS_PROXY, HTTP_PROXY and NO_PROXY (PRD J2; Go does
// not proxy loopback addresses), uses TLS 1.2 or newer, system roots plus an
// optional PEM ca_file, and never sets InsecureSkipVerify. All connections are
// outbound.
//
// # Counters
//
// Stats is the shared counter sink. It implements the Inc(name) hook of
// enforce.Metrics and declog, so one Stats goes to the MCP handler, the
// decision log and the agent; the status report's calls_allowed and
// calls_denied come from enforce_allow and enforce_deny, and
// envelopes_rejected from agent_apply_rejected. Agent counters are
// agent_apply_ok, agent_apply_rejected, agent_poll_errors,
// agent_status_errors, agent_policy_expired and agent_boot_tampered.
// Agent.Snapshot gives the gauges and the self view (state, applied version,
// policy hash, apply-log seq and head, clock untrusted) for the local
// listener of cmd/kairan-proxy (P-09); the hash and head are the same values
// the status report carries.
package agent
