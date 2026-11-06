// Command kairan-proxy is the MCP gateway proxy. It enforces the latest signed
// policy its control plane delivered, keeps enforcing it when the control plane
// is gone, and fails closed on anything it cannot verify.
//
// Usage:
//
//	kairan-proxy -config proxy.json
//	kairan-proxy -config proxy.json -import bundle.json
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
// (deny-all, nothing enforced), an unwritable decision log stops the proxy.
// The file is never edited. A newer valid policy (above everything the
// verifiable part of the log and the stored policy show as applied), from the
// control plane or from -import, takes the proxy out of Tampered: the broken
// log is kept as apply.log.broken-<n> in data_dir (never deleted or
// overwritten), a new chain starts with a reset entry that records the old
// head, and the proxy enforces the new policy. The reset is counted
// (kairan_proxy_apply_log_resets_total), logged in English and Japanese, and
// reported to the control plane as last_error "tampered" with a smaller
// log_seq. The old chain can be checked only by hand, on the kept file.
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
// # Offline import (P-11, PRD J3)
//
// With -import, kairan-proxy does not serve and does not use the network. It
// reads one JSON-encoded signed envelope (what kairanctl sign and approve
// write) and applies it to data_dir by the same path as a policy from the
// control plane: the strict decoder, trust.Accept (a threshold of distinct
// trusted signatures, tenant, a version above everything applied before, not
// expired at effective_now), store.Save, then an apply-log entry. The trust
// root is the one in proxy.json. A rejected bundle (unsigned, one signature,
// old version, wrong tenant, expired, corrupted, not an envelope) applies
// nothing, leaves the policy in force and the stored file unchanged, and is
// written to the apply log with its reason. A bundle file that is not a
// regular file (a FIFO, a device, a directory) or is larger than an envelope
// may be is refused before it is read. An apply log that fails verification
// does not stop an import of a newer valid policy: it recovers as described
// under Boot and run, and a bundle that fails the checks changes nothing. The result is printed in English and Japanese on
// standard error; nothing from the bundle is printed. A proxy that starts
// afterwards enforces the imported policy from disk; an import does not
// change a proxy that is already running.
//
// # The data directory is locked
//
// A process takes an exclusive lock on data_dir/kairan.lock for its whole
// run (the proxy) or until it is done (an import), waiting up to 5 seconds. A
// second process (an import beside a running proxy, or two proxies) stops
// with "the data directory is in use", so two writers can never break the
// apply-log chain. The lock goes away with the process.
//
// # Exit status
//
// 0 after a clean shutdown, a successful import or -h, 2 for a bad command
// line or config, 1 for a runtime failure at startup or a rejected or
// unreadable bundle.
//
// # Messages are in English and Japanese (PRD J7)
//
// Every message for a person is printed in both languages. An error is an
// English line and a Japanese line ("kairan-proxy: error: ..." then
// "kairan-proxy: エラー: ..."); a bad command line also prints the usage; -h
// prints the usage, in both languages, on standard error. Log lines (JSON on
// standard error) keep the English text in msg and add the Japanese text in
// msg_ja. A message never holds a config value, a token, a key or bundle
// content.
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
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
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
	code := execute(ctx, os.Args[1:], os.Stderr)
	stop()
	os.Exit(code)
}

// execute is main without the exit: it runs the program, prints any error in
// both languages and returns the exit status (0, 1 or 2).
func execute(ctx context.Context, args []string, stderr io.Writer) int {
	err := run(ctx, args, stderr, nil)
	if err == nil {
		return 0
	}
	report(stderr, err)
	if errors.Is(err, errUsage) {
		return 2
	}
	return 1
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
	fs.SetOutput(io.Discard) // the flag package speaks English only; see flagError and usageText
	cfgPath := fs.String("config", "", "path to proxy.json")
	importPath := fs.String("import", "", "apply this offline signed bundle to the data directory and exit")
	if err := fs.Parse(args); err != nil {
		if isHelp(err) {
			fmt.Fprint(stderr, usageText)
			return nil
		}
		return flagError(err)
	}
	importSet := false
	fs.Visit(func(f *flag.Flag) { importSet = importSet || f.Name == "import" })
	switch {
	case fs.NArg() != 0:
		return cmdLineMsg("unexpected argument; usage: kairan-proxy -config FILE [-import FILE]",
			"余分な引数があります。使い方: kairan-proxy -config FILE [-import FILE]")
	case *cfgPath == "":
		return cmdLineMsg("-config is required", "-config は必須です")
	case importSet && *importPath == "":
		return cmdLineMsg("-import needs a file name", "-import にはファイル名が必要です")
	}
	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		return err
	}
	if importSet {
		return importBundle(cfg, *importPath, stderr)
	}
	log := slog.New(slog.NewJSONHandler(stderr, nil))
	clk := clock.NewReal()
	stats := &agent.Stats{}

	noteTestOnlyKeys(cfg, stats, log)

	unlock, err := lockDataDir(cfg.DataDir)
	if err != nil {
		return err
	}
	defer unlock()
	st, guard, al, logErr, err := openData(cfg, clk, log)
	if err != nil {
		return err
	}
	if al != nil {
		defer al.Close()
	}

	acfg := agent.Config{
		CP: cfg.CP, Tenant: cfg.Tenant, ProxyID: cfg.ProxyID, Token: cfg.Token, Root: cfg.Root,
		Skew: cfg.Skew, Guard: guard, AllowPlaintext: cfg.AllowPlaintext, LogOpenErr: logErr,
		LogPath: filepath.Join(cfg.DataDir, applyLogFile),
	}
	dl, err := declog.Open(filepath.Join(cfg.DataDir, decisionLogFile), declog.Options{Metrics: stats})
	if err != nil {
		return msg("cannot open the decision log: "+err.Error(), "判断ログを開けません: "+err.Error())
	}
	defer dl.Close()

	ecfg := enforce.Config{Upstream: cfg.Upstream, APIKeys: cfg.APIKeys, SafeMode: cfg.SafeMode}
	if err := ecfg.Validate(); err != nil {
		return usageMsg("invalid configuration: "+err.Error(), "設定が正しくありません: "+err.Error())
	}
	hc, err := agent.NewHTTPClient(cfg.CAFile)
	if err != nil {
		return usageMsg("invalid configuration: "+err.Error(), "設定が正しくありません: "+err.Error())
	}
	holder := &enforce.Holder{}
	ag, err := agent.New(acfg, st, al, holder, clk, hc, log, stats)
	if err != nil {
		return usageMsg("invalid configuration: "+err.Error(), "設定が正しくありません: "+err.Error())
	}
	if err := ag.Boot(); err != nil {
		return msg("cannot start: "+err.Error(), "起動できません: "+err.Error())
	}
	snap := ag.Snapshot()
	say(log, slog.LevelInfo, evBooted, "state", string(snap.State), "applied_version", snap.AppliedVersion)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return listenErr("listen", err)
	}
	// The local read-only listener (P-09): bound before anything is served, so
	// a bad address stops the proxy at start.
	var lsrv *http.Server
	var lln net.Listener
	if cfg.MetricsListen != "" {
		lln, err = net.Listen("tcp", cfg.MetricsListen)
		if err != nil {
			ln.Close()
			return listenErr("metrics_listen", err)
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
		say(log, slog.LevelInfo, evLocalListener, "addr", lln.Addr().String())
	}

	agentCtx, stopAgent := context.WithCancel(ctx)
	agentDone := make(chan error, 1)
	go func() { agentDone <- ag.Run(agentCtx) }()
	if ready != nil {
		ready(ln.Addr().String())
	}
	say(log, slog.LevelInfo, evListening, "addr", ln.Addr().String())

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-serveErr:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = msg("a listener failed: "+err.Error(), "待ち受けが失敗しました: "+err.Error())
		}
	}
	say(log, slog.LevelInfo, evShuttingDown)
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
		say(log, slog.LevelError, evHighWaterLost, "err", err.Error())
	}
	say(log, slog.LevelInfo, evStopped)
	return runErr
}

// listenErr says that an address cannot be bound. It names the config key and
// the system's reason, not the address.
func listenErr(key string, err error) error {
	reason := err.Error()
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		reason = oe.Err.Error()
	}
	return msg("cannot listen for "+key+": "+reason, key+" の待ち受けを開始できません: "+reason)
}

// noteTestOnlyKeys warns loudly, and counts, when a trusted key is a public
// fixture key (M-D37).
func noteTestOnlyKeys(cfg *Config, stats *agent.Stats, log *slog.Logger) {
	n := cfg.TestOnlyKeys()
	for i := 0; i < n; i++ {
		stats.Inc(metricTestOnlyKey)
	}
	if n > 0 {
		say(log, slog.LevelWarn, evTestOnlyKey, "test_only_keys", n)
	}
}
