// Command kairan-proxy is the MCP gateway proxy. It enforces the latest signed
// policy its control plane delivered, keeps enforcing it when the control plane
// is gone, and fails closed on anything it cannot verify.
//
// Usage:
//
//	kairan-proxy -config proxy.json
//
// This file is only wiring (ARCHITECTURE section 10, cmd/kairan-proxy). The
// logic is in internal/proxy/agent (boot, poll, status), internal/proxy/enforce
// (the MCP handler), internal/proxy/store, applylog and declog.
//
// # Config
//
// proxy.json is one JSON object. Unknown, duplicate and case-variant field
// names are errors. Required fields:
//
//	tenant        tenant ID this proxy serves
//	proxy_id      this proxy's ID
//	cp_url        control plane base URL (https; http only with allow_plaintext)
//	token         enrollment token (bearer; never logged, never in a status report)
//	trusted_keys  admin public keys, hex, 64 characters each, distinct
//	threshold     signatures needed from distinct trusted keys, at least 2 and
//	              at most len(trusted_keys)
//	listen        host:port for the MCP listener
//	upstream      the MCP server's URL; every request goes to exactly this URL
//	api_keys      object of API key to role
//	data_dir      directory for policy.json, apply.log, decisions.log, highwater
//
// Optional:
//
//	skew             expiry tolerance as a duration, default 2m, at most 5m
//	safe_mode        read_only (default) or deny_all: what an expired policy allows
//	ca_file          PEM certificates to trust for cp_url, added to the system roots
//	allow_plaintext  true allows an http:// cp_url (Docker demo only)
//	metrics_listen   host:port of the local read-only listener (self view and
//	                 metrics); not set means no such listener. Must differ from listen.
//
// The trust root comes only from this file. A config that fails any check
// (threshold under 2, skew over 5m, safe_mode outside the enum, a bad key, a
// non-regular file) stops the proxy before it listens: the process exits with
// status 2 and prints which field is wrong, never its value.
//
// # Boot and run
//
// 1. Load and check the config. 2. Open the data directory: the stored policy,
// the apply log, the clock guard's high-water file and the decision log.
// 3. Boot the agent: reload the stored policy, re-verify it with the local
// trust root, compare with the apply log, and decide the state (deny-all,
// tampered, enforcing or safe mode) from disk alone, with no network. 4. Bind
// the MCP listener and start serving with that state. 5. Start the agent's
// poll and status loops. SIGINT and SIGTERM stop the listener, then the
// agent, and save the high-water mark.
//
// An apply log that fails verification, or a decision log that cannot be
// opened, is not worked around: a bad apply log makes the proxy Tampered
// (deny-all, nothing applied), an unwritable decision log stops the proxy.
//
// If a trusted key is one of the repository's TEST-ONLY fixture keys, the
// proxy logs a loud warning at start and counts it (test_only_trusted_key).
//
// # Local self view and metrics (P-09)
//
// With metrics_listen set, a second listener serves two read-only routes, GET
// and HEAD only (anything else is 405, other paths 404), with no
// authentication: it is inbound inside the customer network only (PRD J2,
// M-D51), so bind it to an address on that network. A port already in use
// stops the proxy at start.
//
//	GET /v1/self   JSON with exactly: tenant, proxy_id, state, applied_version,
//	               policy_hash, log_seq, log_head, clock_untrusted. State is the
//	               wire state (booting, deny_all, tampered, enforcing,
//	               safe_mode). policy_hash is "" when no policy is in force. The
//	               evidence export compares this with the control plane's view
//	               and the apply log (M-D7, THREATS #2).
//	GET /metrics   Prometheus text format 0.0.4: gauges kairan_proxy_state{state}
//	               (one series per state, 1 for the current one; the label is
//	               the state with "_" written "-": deny-all, safe-mode, as
//	               metric labels are wire IDs, M-D29),
//	               kairan_proxy_applied_version, kairan_proxy_log_seq,
//	               kairan_proxy_clock_untrusted, kairan_proxy_test_only_trusted_keys;
//	               counters kairan_proxy_calls_allowed_total, _calls_denied_total,
//	               _requests_rejected_total, _auth_failures_total,
//	               _upstream_errors_total, _policies_applied_total,
//	               _policies_rejected_total, _poll_errors_total,
//	               _status_errors_total, _policy_expired_total,
//	               _boot_tampered_total, _clock_untrusted_total,
//	               _decision_log_denied_total, _decision_log_write_errors_total
//	               and _decision_log_rotate_errors_total.
//
// Both are built only from the agent's snapshot and counters: no payload,
// argument, result, role, API key or user data (invariant I4). The policy hash
// is in the self view and never a metric label.
//
// # Exit status
//
// 0 after a clean shutdown, 2 for a bad command line or config, 1 for a
// runtime failure at startup.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/store"
)

// Metric name for a TEST-ONLY trusted key (M-D37).
const metricTestOnlyKey = "test_only_trusted_key"

// File names inside data_dir (the agent and store packages own the others).
const (
	applyLogFile    = "apply.log"
	decisionLogFile = "decisions.log"
)

// errUsage marks a bad command line or config (exit status 2).
var errUsage = errors.New("usage")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kairan-proxy:", err)
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}

// run is main without the process: tests call it with a cancellable context.
// ready, if not nil, is called with the MCP listener's address once the proxy
// has booted and is accepting connections.
func run(ctx context.Context, args []string, stderr io.Writer, ready func(addr string)) error {
	return runLocal(ctx, args, stderr, ready, nil)
}

// runLocal is run with a second callback: localReady gets the local listener's
// address (metrics_listen) once it is bound, before ready is called. It is not
// called if metrics_listen is not set.
func runLocal(ctx context.Context, args []string, stderr io.Writer, ready, localReady func(addr string)) error {
	fs := flag.NewFlagSet("kairan-proxy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "path to proxy.json")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if fs.NArg() != 0 || *cfgPath == "" {
		fs.Usage()
		return fmt.Errorf("%w: need -config proxy.json", errUsage)
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	clk := clock.NewReal()
	stats := &agent.Stats{}

	noteTestOnlyKeys(cfg, stats, log)

	st, err := store.Open(cfg.DataDir)
	if err != nil {
		return fmt.Errorf("data_dir: %w", err)
	}
	guard, err := agent.OpenClockGuard(clk, cfg.DataDir)
	switch {
	case errors.Is(err, agent.ErrHighWaterCorrupt):
		log.Warn("high-water file is corrupt; it will be rewritten")
	case err != nil:
		return err
	}

	acfg := agent.Config{
		CP: cfg.CP, Tenant: cfg.Tenant, ProxyID: cfg.ProxyID, Token: cfg.Token, Root: cfg.Root,
		Skew: cfg.Skew, Guard: guard, AllowPlaintext: cfg.AllowPlaintext,
	}
	al, err := applylog.Open(filepath.Join(cfg.DataDir, applyLogFile), clk)
	if err != nil {
		// Do not repair or work around it: boot as Tampered, apply nothing.
		log.Error("apply log failed verification; starting tampered (deny-all)", "err", err)
		al, acfg.LogOpenErr = nil, err
	} else {
		defer al.Close()
	}
	dl, err := declog.Open(filepath.Join(cfg.DataDir, decisionLogFile), declog.Options{Metrics: stats})
	if err != nil {
		return fmt.Errorf("decision log: %w", err)
	}
	defer dl.Close()

	ecfg := enforce.Config{Upstream: cfg.Upstream, APIKeys: cfg.APIKeys, SafeMode: cfg.SafeMode}
	if err := ecfg.Validate(); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	hc, err := agent.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	holder := &enforce.Holder{}
	ag, err := agent.New(acfg, st, al, holder, clk, hc, log, stats)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if err := ag.Boot(); err != nil {
		return err
	}
	snap := ag.Snapshot()
	log.Info("booted", "state", string(snap.State), "applied_version", snap.AppliedVersion)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	// The local read-only listener (P-09): bound before anything is served, so
	// a bad address stops the proxy at start.
	var lsrv *http.Server
	var lln net.Listener
	if cfg.MetricsListen != "" {
		lln, err = net.Listen("tcp", cfg.MetricsListen)
		if err != nil {
			ln.Close()
			return fmt.Errorf("metrics_listen: %w", err)
		}
		lsrv = &http.Server{
			Handler:           newLocalHandler(cfg.Tenant, cfg.ProxyID, ag.Snapshot, stats),
			ReadHeaderTimeout: localReadHeaderTimeout,
			IdleTimeout:       localIdleTimeout,
			MaxHeaderBytes:    localMaxHeaderBytes,
		}
	}
	srv := enforce.NewServer(cfg.Listen, enforce.New(ecfg, holder, dl, clk, stats))
	serveErr := make(chan error, 2)
	go func() { serveErr <- srv.Serve(ln) }()
	if lsrv != nil {
		go func() { serveErr <- lsrv.Serve(lln) }()
		if localReady != nil {
			localReady(lln.Addr().String())
		}
		log.Info("local listener", "addr", lln.Addr().String())
	}

	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run(agentCtx) }()
	if ready != nil {
		ready(ln.Addr().String())
	}
	log.Info("listening", "addr", ln.Addr().String())

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		runErr = fmt.Errorf("listener: %w", err)
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	if lsrv != nil {
		if err := lsrv.Shutdown(sctx); err != nil {
			lsrv.Close()
		}
	}
	stopAgent()
	if err := <-agentDone; err != nil {
		log.Error("shutdown: high-water not saved", "err", err)
	}
	if errors.Is(runErr, http.ErrServerClosed) {
		runErr = nil
	}
	return runErr
}

// noteTestOnlyKeys warns loudly, and counts, when a trusted key is a public
// fixture key (M-D37).
func noteTestOnlyKeys(cfg *Config, stats *agent.Stats, log *slog.Logger) {
	n := cfg.TestOnlyKeys()
	for i := 0; i < n; i++ {
		stats.Inc(metricTestOnlyKey)
	}
	if n > 0 {
		log.Warn("TEST-ONLY KEY TRUSTED: a trusted key is a public fixture key; anyone can sign policies. Do not use outside tests.",
			"test_only_keys", n)
	}
}
