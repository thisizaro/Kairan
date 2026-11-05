package agent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// ---- status reports ----

func TestStatusReportContents(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.reopen()
	cp := newFakeCP(t)
	a := r.begin(cp)
	r.stats.Inc("enforce_allow")
	r.stats.Inc("enforce_allow")
	r.stats.Inc("enforce_deny")
	r.clk.Advance(95 * time.Second)

	a.sendStatus(t.Context())
	a.sendStatus(t.Context())
	if cp.statusCount() != 2 {
		t.Fatalf("statuses = %d", cp.statusCount())
	}
	first, second := cp.statuses[0], cp.statuses[1]
	if second.Seq != first.Seq+1 || first.Seq != 1 {
		t.Fatalf("seq %d then %d", first.Seq, second.Seq)
	}
	act := r.active()
	want := wire.StatusReport{
		Tenant: tenant, ProxyID: proxyID, Seq: 2, State: wire.StateEnforcing, AppliedVersion: 3,
		PolicyHash: act.Hash, LogSeq: 1, UptimeSeconds: 95,
		Counters: wire.Counters{CallsAllowed: 2, CallsDenied: 1},
	}
	want.LogHead = second.LogHead
	if !want.LogHead.Valid() {
		t.Fatalf("log head %q", want.LogHead)
	}
	if second != want {
		t.Fatalf("report = %+v\nwant     %+v", second, want)
	}
	if cp.auths[0] != wire.BearerPrefix+"tok-secret" {
		t.Fatal("status request carries no token")
	}
}

// Invariant I4: the body is exactly the wire type, so only its fields can
// appear, and the token never does.
func TestStatusBodyIsMetadataOnly(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	cp.pollFn = serveEnv(signed(payload(9, tenant, start.Add(time.Hour)), r.keys.a), 9)
	a.pollOnce(t.Context())
	a.sendStatus(t.Context())
	raw := string(cp.rawStat[0])
	var generic map[string]any
	if err := json.Unmarshal(cp.rawStat[0], &generic); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"tenant": true, "proxy_id": true, "seq": true, "state": true, "applied_version": true,
		"policy_hash": true, "log_seq": true, "log_head": true, "last_error": true, "uptime_seconds": true, "counters": true}
	for k := range generic {
		if !allowed[k] {
			t.Fatalf("unexpected field %q in %s", k, raw)
		}
	}
	for _, leak := range []string{"tok-secret", "crm.", "sales", "Bearer"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("status body contains %q: %s", leak, raw)
		}
	}
	if len(cp.rawStat[0]) > wire.MaxStatusBytes {
		t.Fatal("status over the size cap")
	}
}

func TestStatusReportAlwaysValid(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	steps := []func(){
		func() {},
		func() { cp.pollFn = serveEnv(r.keys.goodEnv(2, 10*time.Minute), 2); a.pollOnce(t.Context()) },
		func() { r.clk.Advance(time.Hour); a.checkExpiry() },
		func() { cp.pollFn = serveEnv(r.keys.goodEnv(1, time.Hour), 1); a.pollOnce(t.Context()) },
		func() {
			cp.pollFn = serveEnv(signed(payload(9, tenant, r.clk.Now().Add(time.Hour)), r.keys.a, r.keys.b), 9)
			a.pollOnce(t.Context())
		},
	}
	for i, s := range steps {
		s()
		if err := a.report().Validate(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
}

func TestApplyErrorBeatsClockWarning(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	r.clk.Advance(time.Hour)
	r.guard.Now()
	r.clk.Set(start) // an hour back: untrusted
	if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrClockUntrusted {
		t.Fatalf("report = %+v", rep.LastError)
	}
	cp.pollFn = serveEnv(signed(payload(9, tenant, start.Add(time.Hour)), r.keys.a), 9)
	a.pollOnce(t.Context())
	if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrThreshold {
		t.Fatalf("report = %+v", rep.LastError)
	}
	if snap := a.Snapshot(); !snap.ClockUntrusted || snap.ClockUntrustedCount != 1 || snap.State != wire.StateDenyAll {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestStatusFailuresAreCountedAndRetriedLater(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.statusFn = func(n int, w http.ResponseWriter) {
		if n == 1 {
			http.Error(w, "", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	a := r.begin(cp)
	a.sendStatus(t.Context())
	if r.stats.Count(MetricStatusErrors) != 1 {
		t.Fatal("failure not counted")
	}
	a.sendStatus(t.Context())
	if r.stats.Count(MetricStatusErrors) != 1 || cp.statusCount() != 2 {
		t.Fatal("second report")
	}
}

func TestStatus503HoldsReports(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.statusFn = func(n int, w http.ResponseWriter) {
		if n == 1 {
			w.Header().Set("Retry-After", "20")
			http.Error(w, "", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	a := r.begin(cp)
	a.jitter = func() float64 { return 0 }
	a.sendStatus(t.Context())
	a.sendStatus(t.Context()) // held
	if len(cp.rawStat) != 1 {
		t.Fatalf("posted during Retry-After: %d", len(cp.rawStat))
	}
	r.clk.Advance(19 * time.Second)
	a.sendStatus(t.Context())
	if len(cp.rawStat) != 1 {
		t.Fatal("posted before Retry-After elapsed")
	}
	r.clk.Advance(time.Second)
	a.sendStatus(t.Context())
	if len(cp.rawStat) != 2 {
		t.Fatal("not posted after Retry-After")
	}
}

func TestStatusTimeout(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cp.statusFn = func(int, http.ResponseWriter) { <-release }
	a := r.begin(cp)
	a.statusTimeout = 50 * time.Millisecond
	done := make(chan struct{})
	go func() { a.sendStatus(t.Context()); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("status POST has no deadline")
	}
	if r.stats.Count(MetricStatusErrors) != 1 {
		t.Fatal("timeout not counted")
	}
}

// ---- Run ----

func TestRunEndToEnd(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	env := r.keys.goodEnv(3, 10*time.Minute)
	cp.pollFn = func(n int, q url.Values, w http.ResponseWriter, req *http.Request) {
		if n == 1 {
			serveEnv(env, 3)(n, q, w, req)
			return
		}
		w.WriteHeader(http.StatusNotModified)
	}
	a := r.begin(cp)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	await(t, "policy applied", func() bool { return r.active().State == wire.StateEnforcing })
	await(t, "status with the new version", func() bool {
		return cp.statusCount() > 0 && cp.lastStatus().AppliedVersion == 3
	})
	rep := cp.lastStatus()
	if rep.State != wire.StateEnforcing || rep.LogSeq != 1 || rep.PolicyHash != r.active().Hash {
		t.Fatalf("status = %+v", rep)
	}

	// Policy expiry flips the proxy to safe mode and reports it at once.
	r.clk.Advance(20 * time.Minute)
	await(t, "safe mode", func() bool { return r.active().State == wire.StateSafeMode })
	await(t, "safe mode report", func() bool { return cp.lastStatus().State == wire.StateSafeMode })

	// The periodic status: a fresh report appears each 10s.
	before := cp.statusCount()
	for i := 0; cp.statusCount() == before && i < 500; i++ {
		r.clk.Advance(wire.StatusInterval)
		time.Sleep(5 * time.Millisecond)
	}
	if cp.statusCount() == before {
		t.Fatal("no periodic status report")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if _, err := os.Stat(filepath.Join(r.dir, HighWaterFile)); err != nil {
		t.Fatalf("high-water not saved at shutdown: %v", err)
	}
}

func TestRunAppliesNewPolicyWhileRunning(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	defer func() { cancel(); <-done }()

	await(t, "first poll", func() bool { return cp.pollCount() >= 1 })
	cp.mu.Lock()
	cp.pollFn = serveEnv(r.keys.goodEnv(2, time.Hour), 2)
	cp.mu.Unlock()
	// Fast 304s wait RetryBackoffMin on the fake clock.
	await(t, "policy 2", func() bool {
		r.clk.Advance(wire.RetryBackoffMin)
		time.Sleep(2 * time.Millisecond)
		return r.active().State == wire.StateEnforcing
	})
}

// ---- transport ----

func TestNewHTTPClientTLSRules(t *testing.T) {
	c, err := NewHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	tr := c.Transport.(*http.Transport)
	if tr.Proxy == nil {
		t.Fatal("proxy-from-environment not set (HTTPS_PROXY ignored)")
	}
	if tr.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatalf("min TLS version %#x", tr.TLSClientConfig.MinVersion)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("InsecureSkipVerify set")
	}
	if c.Timeout != 0 {
		t.Fatal("client has a global timeout; the agent sets per-request deadlines")
	}
	if c.CheckRedirect == nil {
		t.Fatal("redirects followed")
	}
}

func TestNewHTTPClientCAFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "ca.pem")
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	defer srv.Close()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	os.WriteFile(good, pemBytes, 0o600)
	garbage := filepath.Join(dir, "bad.pem")
	os.WriteFile(garbage, []byte("not a cert"), 0o600)
	huge := filepath.Join(dir, "huge.pem")
	os.WriteFile(huge, make([]byte, maxCAFileBytes+1), 0o600)
	for name, tc := range map[string]struct {
		path string
		ok   bool
	}{
		"good": {good, true}, "garbage": {garbage, false}, "missing": {filepath.Join(dir, "none"), false},
		"huge": {huge, false}, "directory": {dir, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewHTTPClient(tc.path)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// PRD J2 / chaos S9: with HTTPS_PROXY set (TestMain does), the agent reaches an
// https control plane through a CONNECT tunnel, and verifies its certificate
// against ca_file.
func TestHTTPSThroughEnvironmentProxy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == wire.PathPoll {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)

	// example.com is on the httptest certificate; the proxy dials the real
	// listener on the same port.
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	target := "https://example.com:" + port

	connectProxy.mu.Lock()
	connectProxy.connects = nil
	connectProxy.mu.Unlock()

	r := newRig(t)
	hc, err := NewHTTPClient(caPath)
	if err != nil {
		t.Fatal(err)
	}
	r.hc = hc
	u, _ := url.Parse(target)
	r.cfg.CP = u
	r.cfg.AllowPlaintext = false
	a := r.build()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	a.pollOnce(t.Context())
	a.sendStatus(t.Context())
	if r.stats.Count(MetricPollErrors) != 0 || r.stats.Count(MetricStatusErrors) != 0 {
		t.Fatalf("poll errors %d status errors %d", r.stats.Count(MetricPollErrors), r.stats.Count(MetricStatusErrors))
	}
	connectProxy.mu.Lock()
	n := len(connectProxy.connects)
	connectProxy.mu.Unlock()
	if n == 0 {
		t.Fatal("no CONNECT reached the environment proxy")
	}

	// Without the CA the certificate is not trusted: the request must fail.
	hc2, _ := NewHTTPClient("")
	r.hc = hc2
	a = r.build()
	a.Boot()
	a.pollOnce(t.Context())
	if r.stats.Count(MetricPollErrors) != 1 {
		t.Fatal("a certificate from an unknown CA was accepted")
	}
}

// The self view (P-09) shows what the status report shows: state, version,
// policy hash and the apply-log anchor, read from the same place.
func TestSnapshotCarriesHashAndLogAnchor(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	if s := a.Snapshot(); s.PolicyHash != "" || s.LogSeq != 0 || s.LogHead != "" || s.AppliedVersion != 0 {
		t.Fatalf("empty proxy snapshot = %+v", s)
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(4, time.Hour), 4)
	a.pollOnce(t.Context())
	s, rep := a.Snapshot(), a.report()
	if s.State != wire.StateEnforcing || s.AppliedVersion != 4 {
		t.Fatalf("snapshot = %+v", s)
	}
	if !s.PolicyHash.Valid() || s.PolicyHash != rep.PolicyHash || s.LogSeq != rep.LogSeq || s.LogHead != rep.LogHead || s.LogSeq == 0 || !s.LogHead.Valid() {
		t.Fatalf("snapshot %+v differs from report %+v", s, rep)
	}
}
