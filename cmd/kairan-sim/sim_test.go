package main

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/wire"
)

// fakeCP is a minimal control plane that speaks the wire contract strictly.
type fakeCP struct {
	t      *testing.T
	tenant wire.ID
	hold   time.Duration

	mu          sync.Mutex
	version     uint64
	env         wire.Envelope
	changed     chan struct{}
	pollTimes   map[wire.ID][]time.Time
	pollHave    map[wire.ID][]uint64
	statuses    []wire.StatusReport
	statusAt    []time.Time
	unavailable int // next N polls get 503 + Retry-After: 1
	badToken    bool
	pollUA      string
	violations  []string
}

func newFakeCP(t *testing.T, tenant wire.ID, hold time.Duration) (*fakeCP, *httptest.Server) {
	f := &fakeCP{t: t, tenant: tenant, hold: hold, changed: make(chan struct{}),
		pollTimes: map[wire.ID][]time.Time{}, pollHave: map[wire.ID][]uint64{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCP) violate(msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.violations = append(f.violations, msg)
}

func fakeEnvelope(v uint64) wire.Envelope {
	return wire.Envelope{
		PayloadType: wire.PayloadTypePolicy,
		Payload:     []byte("policy-v" + strconv.FormatUint(v, 10)),
		Signatures: []wire.Signature{
			{KeyID: wire.Hash(strings.Repeat("a", 64)), Sig: make([]byte, wire.SignatureSize)},
			{KeyID: wire.Hash(strings.Repeat("b", 64)), Sig: make([]byte, wire.SignatureSize)},
		},
	}
}

func (f *fakeCP) publish(v uint64) {
	f.mu.Lock()
	f.version = v
	f.env = fakeEnvelope(v)
	close(f.changed)
	f.changed = make(chan struct{})
	f.mu.Unlock()
}

func proxyNum(id wire.ID) string { return strings.TrimPrefix(string(id), "sim-") }

func (f *fakeCP) tokenOK(r *http.Request, id wire.ID) bool {
	want := wire.BearerPrefix + "tok-" + proxyNum(id)
	return !f.badToken && r.Header.Get(wire.HeaderAuthorization) == want
}

func writeErr(w http.ResponseWriter, code int, c wire.ErrorCode) {
	w.Header().Set("Content-Type", wire.ContentTypeJSON)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Code: c})
}

func (f *fakeCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case wire.PathPoll:
		f.poll(w, r)
	case wire.PathStatus:
		f.status(w, r)
	default:
		writeErr(w, 404, wire.ErrNotFound)
	}
}

func (f *fakeCP) poll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeErr(w, 405, wire.ErrMethodNotAllowed)
		return
	}
	pr, err := wire.ParsePollRequest(r.URL.Query())
	if err != nil {
		f.violate("bad poll query")
		writeErr(w, 400, wire.ErrBadRequest)
		return
	}
	if !f.tokenOK(r, pr.ProxyID) {
		writeErr(w, 401, wire.ErrUnauthorized)
		return
	}
	if pr.Tenant != f.tenant {
		writeErr(w, 403, wire.ErrForbidden)
		return
	}
	f.mu.Lock()
	f.pollUA = r.UserAgent()
	f.pollTimes[pr.ProxyID] = append(f.pollTimes[pr.ProxyID], time.Now())
	f.pollHave[pr.ProxyID] = append(f.pollHave[pr.ProxyID], pr.Have)
	if f.unavailable > 0 {
		f.unavailable--
		f.mu.Unlock()
		w.Header().Set("Retry-After", "1")
		writeErr(w, 503, wire.ErrUnavailable)
		return
	}
	deadline := time.After(f.hold)
	for {
		if f.version > pr.Have {
			resp := wire.PollResponse{Version: f.version, Envelope: f.env}
			f.mu.Unlock()
			w.Header().Set("Content-Type", wire.ContentTypeJSON)
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		ch := f.changed
		f.mu.Unlock()
		select {
		case <-ch:
		case <-deadline:
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			return
		}
		f.mu.Lock()
	}
}

func (f *fakeCP) status(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, 405, wire.ErrMethodNotAllowed)
		return
	}
	var s wire.StatusReport
	if err := wire.Decode(r.Body, wire.MaxStatusBytes, &s); err != nil {
		f.violate("status decode")
		writeErr(w, 400, wire.ErrBadRequest)
		return
	}
	if err := s.Validate(); err != nil {
		f.violate("status validate: " + err.Error())
		writeErr(w, 400, wire.ErrBadRequest)
		return
	}
	if r.Header.Get("Content-Type") != wire.ContentTypeJSON {
		f.violate("status content type")
	}
	if !f.tokenOK(r, s.ProxyID) {
		writeErr(w, 401, wire.ErrUnauthorized)
		return
	}
	if s.Tenant != f.tenant {
		writeErr(w, 403, wire.ErrForbidden)
		return
	}
	f.mu.Lock()
	f.statuses = append(f.statuses, s)
	f.statusAt = append(f.statusAt, time.Now())
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeCP) snapshotStatuses() []wire.StatusReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]wire.StatusReport(nil), f.statuses...)
}

func testCfg(t *testing.T, srv *httptest.Server, n int, hold time.Duration) Config {
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		CP:             u,
		Tenant:         "sim",
		N:              n,
		TokenPattern:   "tok-{n}",
		PollHold:       hold,
		StatusInterval: 300 * time.Millisecond,
		BackoffMin:     10 * time.Millisecond,
		BackoffMax:     50 * time.Millisecond,
	}
}

func runSim(t *testing.T, cfg Config, d time.Duration) *Result {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return s.Run(ctx)
}

func TestAllProxiesApplyAndAck(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 200*time.Millisecond)
	cfg := testCfg(t, srv, 20, 200*time.Millisecond)
	cfg.UntilVersion = 1
	go func() { time.Sleep(150 * time.Millisecond); f.publish(1) }()
	res := runSim(t, cfg, 10*time.Second)

	if !res.Simulated || res.Tool != "kairan-sim" || !strings.Contains(strings.ToLower(res.Label), "simulated") {
		t.Fatalf("result not labelled simulated: %+v", res)
	}
	if res.Proxies != 20 || res.Tenant != "sim" {
		t.Fatalf("count/tenant wrong: %+v", res)
	}
	if res.Acks.Total != 20 || len(res.Acks.ByVersion) != 1 || res.Acks.ByVersion[0].Version != 1 || res.Acks.ByVersion[0].Proxies != 20 {
		t.Fatalf("acks wrong: %+v", res.Acks)
	}
	if res.FinalVersions["1"] != 20 {
		t.Fatalf("final versions: %v", res.FinalVersions)
	}
	if res.Polls.Modified < 20 || res.Polls.LatencyMS["200"].Count < 20 {
		t.Fatalf("poll stats: %+v", res.Polls)
	}
	if res.Errors.Total != 0 {
		t.Fatalf("unexpected errors: %+v", res.Errors)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.violations) != 0 {
		t.Fatalf("wire violations: %v", f.violations)
	}
	if !strings.Contains(strings.ToLower(f.pollUA), "sim") {
		t.Fatalf("user agent should say simulated, got %q", f.pollUA)
	}
	applied := map[wire.ID]bool{}
	for _, s := range f.statuses {
		if !strings.HasPrefix(string(s.ProxyID), "sim-") {
			t.Fatalf("proxy id not marked simulated: %s", s.ProxyID)
		}
		if s.Tenant != "sim" {
			t.Fatalf("tenant %s", s.Tenant)
		}
		if s.AppliedVersion == 1 {
			applied[s.ProxyID] = true
			if s.State != wire.StateEnforcing || s.PolicyHash == "" || s.LogSeq != 1 || s.LogHead == "" {
				t.Fatalf("bad ack report: %+v", s)
			}
		}
	}
	if len(applied) != 20 {
		t.Fatalf("only %d proxies reported v1", len(applied))
	}
}

func TestInitialReportIsDenyAllThenSeqIncreases(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	cfg := testCfg(t, srv, 1, 100*time.Millisecond)
	cfg.StatusInterval = 100 * time.Millisecond
	runSim(t, cfg, 700*time.Millisecond)
	st := f.snapshotStatuses()
	if len(st) < 3 {
		t.Fatalf("want >=3 periodic reports, got %d", len(st))
	}
	if st[0].State != wire.StateDenyAll || st[0].AppliedVersion != 0 {
		t.Fatalf("first report: %+v", st[0])
	}
	for i := 1; i < len(st); i++ {
		if st[i].Seq != st[i-1].Seq+1 {
			t.Fatalf("seq not +1: %d then %d", st[i-1].Seq, st[i].Seq)
		}
	}
}

func TestStatusImmediatelyAfterApply(t *testing.T) {
	f, srv := newFakeCP(t, "sim", time.Second)
	cfg := testCfg(t, srv, 1, time.Second)
	cfg.StatusInterval = 5 * time.Second // periodic would be far too late
	cfg.UntilVersion = 7
	pubCh := make(chan time.Time, 1)
	go func() { time.Sleep(300 * time.Millisecond); pubCh <- time.Now(); f.publish(7) }()
	res := runSim(t, cfg, 4*time.Second)
	if res.Acks.Total != 1 {
		t.Fatalf("no ack within 4s with a 5s interval: %+v", res.Acks)
	}
	pub := <-pubCh
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, s := range f.statuses {
		if s.AppliedVersion == 7 {
			if d := f.statusAt[i].Sub(pub); d > time.Second {
				t.Fatalf("ack took %v", d)
			}
			return
		}
	}
	t.Fatal("no status with v7")
}

func TestPollsCarryHaveAndOnlyNewerApplies(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 80*time.Millisecond)
	cfg := testCfg(t, srv, 1, 80*time.Millisecond)
	cfg.UntilVersion = 2
	go func() {
		time.Sleep(100 * time.Millisecond)
		f.publish(1)
		time.Sleep(300 * time.Millisecond)
		f.publish(2)
	}()
	res := runSim(t, cfg, 5*time.Second)
	if res.FinalVersions["2"] != 1 {
		t.Fatalf("final: %v", res.FinalVersions)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	h := f.pollHave["sim-0000"]
	if len(h) == 0 || h[0] != 0 {
		t.Fatalf("first have: %v", h)
	}
	saw1 := false
	for _, v := range h {
		saw1 = saw1 || v == 1
	}
	if !saw1 {
		t.Fatalf("never polled with have=1: %v", h)
	}
}

func TestIDsZeroPaddedAndValid(t *testing.T) {
	ids := proxyIDs(12)
	if ids[0] != "sim-0000" || ids[11] != "sim-0011" {
		t.Fatalf("ids: %v", ids)
	}
	for _, id := range proxyIDs(12000) {
		if !id.Valid() || !strings.HasPrefix(string(id), "sim-") {
			t.Fatalf("bad id %q", id)
		}
	}
}

func TestRetryAfter503BackoffHonoured(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	f.unavailable = 3
	cfg := testCfg(t, srv, 3, 100*time.Millisecond)
	res := runSim(t, cfg, 2500*time.Millisecond)
	if res.Polls.Unavailable != 3 {
		t.Fatalf("unavailable count: %+v", res.Polls)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	hit := 0
	for _, ts := range f.pollTimes {
		for i := 0; i+1 < len(ts); i++ {
			if ts[i+1].Sub(ts[i]) >= 900*time.Millisecond {
				hit++
				break
			}
		}
	}
	if hit != 3 {
		t.Fatalf("expected all 3 proxies to wait out Retry-After (>=1s); %d did", hit)
	}
}

func TestNoHotLoopOnErrors(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	f.badToken = true
	cfg := testCfg(t, srv, 1, 100*time.Millisecond)
	cfg.BackoffMin = 100 * time.Millisecond
	cfg.BackoffMax = 200 * time.Millisecond
	res := runSim(t, cfg, time.Second)
	if res.Errors.ByKind["http_401"] == 0 {
		t.Fatalf("401 not counted: %+v", res.Errors)
	}
	f.mu.Lock()
	n := len(f.pollTimes["sim-0000"])
	f.mu.Unlock()
	if n > 12 {
		t.Fatalf("hot loop: %d polls in 1s with backoff >= 100ms", n)
	}
	if len(res.FinalVersions) != 1 || res.FinalVersions["0"] != 1 {
		t.Fatalf("should still be at version 0: %v", res.FinalVersions)
	}
	if res.Acks.Total != 0 {
		t.Fatalf("acks with bad token: %+v", res.Acks)
	}
}

func TestMalformedEnvelopeNotApplied(t *testing.T) {
	cases := map[string]func(*wire.PollResponse){
		"no signatures":   func(p *wire.PollResponse) { p.Envelope.Signatures = nil },
		"wrong type":      func(p *wire.PollResponse) { p.Envelope.PayloadType = "text/plain" },
		"empty payload":   func(p *wire.PollResponse) { p.Envelope.Payload = nil },
		"short signature": func(p *wire.PollResponse) { p.Envelope.Signatures[0].Sig = []byte{1} },
		"not newer":       func(p *wire.PollResponse) { p.Version = 0 },
		"bad keyid":       func(p *wire.PollResponse) { p.Envelope.Signatures[0].KeyID = "xyz" },
		"too many sigs": func(p *wire.PollResponse) {
			for len(p.Envelope.Signatures) <= wire.MaxSignatures {
				p.Envelope.Signatures = append(p.Envelope.Signatures, p.Envelope.Signatures[0])
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == wire.PathStatus {
					w.WriteHeader(204)
					return
				}
				resp := wire.PollResponse{Version: 1, Envelope: fakeEnvelope(1)}
				mutate(&resp)
				_ = json.NewEncoder(w).Encode(resp)
			}))
			defer srv.Close()
			cfg := testCfg(t, srv, 1, 50*time.Millisecond)
			res := runSim(t, cfg, 600*time.Millisecond)
			if res.FinalVersions["0"] != 1 || res.Acks.Total != 0 {
				t.Fatalf("applied a bad response: %+v %+v", res.FinalVersions, res.Acks)
			}
			if res.Errors.ByKind["bad_body"] == 0 {
				t.Fatalf("not counted as bad_body: %+v", res.Errors)
			}
		})
	}
}

func TestUnknownFieldAndTrailingDataRejected(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `{"version":1,"extra":1,"envelope":{}}`,
		"trailing":      `{"version":1,"envelope":{}} {}`,
		"garbage":       `not json`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == wire.PathStatus {
					w.WriteHeader(204)
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			defer srv.Close()
			res := runSim(t, testCfg(t, srv, 1, 50*time.Millisecond), 500*time.Millisecond)
			if res.Acks.Total != 0 || res.Errors.ByKind["bad_body"] == 0 {
				t.Fatalf("%+v", res)
			}
		})
	}
}

func TestDefaultsFollowWireAndMD31(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	s, err := New(Config{CP: u, Tenant: "sim", N: 1})
	if err != nil {
		t.Fatal(err)
	}
	c := s.cfg
	if c.PollHold != wire.PollHold || c.StatusInterval != wire.StatusInterval ||
		c.BackoffMin != wire.RetryBackoffMin || c.BackoffMax != wire.RetryBackoffMax {
		t.Fatalf("timing defaults differ from wire: %+v", c)
	}
	if c.StatusTimeout != 10*time.Second {
		t.Fatalf("status timeout %v", c.StatusTimeout)
	}
	if c.PollTimeout() != wire.PollClientTimeout || c.PollTimeout() != 45*time.Second {
		t.Fatalf("poll timeout %v, want wire.PollClientTimeout (45s, M-D40)", c.PollTimeout())
	}
	// Independent of the configured hold (tests use short holds).
	short := Config{PollHold: 200 * time.Millisecond}
	if short.PollTimeout() != wire.PollClientTimeout {
		t.Fatalf("poll timeout depends on hold: %v", short.PollTimeout())
	}
}

func TestConfigValidation(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:1")
	bad := []Config{
		{Tenant: "sim", N: 1},
		{CP: u, Tenant: "Bad Tenant", N: 1},
		{CP: u, Tenant: "sim", N: 0},
		{CP: u, Tenant: "sim", N: -1},
		{CP: u, Tenant: "sim", N: 1_000_001},
		{CP: &url.URL{Scheme: "ftp", Host: "x"}, Tenant: "sim", N: 1},
	}
	for i, c := range bad {
		if _, err := New(c); err == nil {
			t.Errorf("case %d accepted: %+v", i, c)
		}
	}
}

func TestTokenPattern(t *testing.T) {
	if got := tokenFor("tok-{n}", 7); got != "tok-0007" {
		t.Fatalf("%q", got)
	}
	if got := tokenFor("shared", 7); got != "shared" {
		t.Fatalf("%q", got)
	}
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"1", time.Second, true},
		{"0", 0, true},
		{"3", 3 * time.Second, true},
		{"-1", 0, false},
		{"", 0, false},
		{"abc", 0, false},
		{"9999", 60 * time.Second, true}, // capped
		{now.Add(2 * time.Second).UTC().Format(http.TimeFormat), 2 * time.Second, true},
		{now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0, true},
	}
	for _, c := range cases {
		got, ok := parseRetryAfter(c.in, now)
		if got != c.want || ok != c.ok {
			t.Errorf("%q: got %v %v want %v %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestPercentiles(t *testing.T) {
	var ds []time.Duration
	for i := 1; i <= 100; i++ {
		ds = append(ds, time.Duration(i)*time.Millisecond)
	}
	l := summarize(ds)
	if l.Count != 100 || l.P50 != 50 || l.P95 != 95 || l.P99 != 99 || l.Max != 100 {
		t.Fatalf("%+v", l)
	}
	if z := summarize(nil); z.Count != 0 || z.P99 != 0 {
		t.Fatalf("%+v", z)
	}
}

func TestResultJSONShape(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	f.publish(1)
	cfg := testCfg(t, srv, 3, 100*time.Millisecond)
	cfg.UntilVersion = 1
	res := runSim(t, cfg, 5*time.Second)
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"simulated", "tool", "label", "cp", "tenant", "proxies", "id_prefix",
		"started_at", "duration_ms", "polls", "status", "acks", "errors", "final_versions"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
	}
	if m["simulated"] != true {
		t.Fatalf("simulated must be true")
	}
	if strings.Contains(string(b), "tok-") {
		t.Fatalf("tokens must not appear in output: %s", b)
	}
}

func TestUntilVersionStopsEarly(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 200*time.Millisecond)
	f.publish(3)
	cfg := testCfg(t, srv, 5, 200*time.Millisecond)
	cfg.UntilVersion = 3
	start := time.Now()
	res := runSim(t, cfg, 10*time.Second)
	if time.Since(start) > 5*time.Second {
		t.Fatalf("did not stop early")
	}
	if res.Acks.Total != 5 {
		t.Fatalf("%+v", res.Acks)
	}
}

func TestCancelStopsPromptlyWithoutCountingErrors(t *testing.T) {
	_, srv := newFakeCP(t, "sim", 5*time.Second)
	cfg := testCfg(t, srv, 10, 5*time.Second)
	start := time.Now()
	res := runSim(t, cfg, 300*time.Millisecond)
	if time.Since(start) > 3*time.Second {
		t.Fatalf("slow shutdown: %v", time.Since(start))
	}
	if res.Errors.Total != 0 {
		t.Fatalf("cancellation counted as errors: %+v", res.Errors)
	}
}

func TestRampStaggersStarts(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	cfg := testCfg(t, srv, 10, 100*time.Millisecond)
	cfg.Ramp = 600 * time.Millisecond
	runSim(t, cfg, 1500*time.Millisecond)
	f.mu.Lock()
	defer f.mu.Unlock()
	var first, last time.Time
	for _, ts := range f.pollTimes {
		if len(ts) == 0 {
			continue
		}
		if first.IsZero() || ts[0].Before(first) {
			first = ts[0]
		}
		if ts[0].After(last) {
			last = ts[0]
		}
	}
	if last.Sub(first) < 200*time.Millisecond {
		t.Fatalf("starts not staggered: spread %v", last.Sub(first))
	}
}

func TestRunCLIFlagErrors(t *testing.T) {
	var out, errb strings.Builder
	if code := runCLI([]string{"-n", "0"}, &out, &errb); code == 0 {
		t.Fatal("n=0 accepted")
	}
	if code := runCLI([]string{"-cp", "http://x", "-n", "1", "-tenant", "BAD"}, &out, &errb); code == 0 {
		t.Fatal("bad tenant accepted")
	}
	if code := runCLI([]string{"-nope"}, &out, &errb); code == 0 {
		t.Fatal("unknown flag accepted")
	}
}

func TestRunCLIPrintsOneJSONDocumentAndBanner(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 100*time.Millisecond)
	f.publish(1)
	var out, errb strings.Builder
	code := runCLI([]string{"-cp", srv.URL, "-n", "4", "-tenant", "sim", "-token-pattern", "tok-{n}",
		"-until-version", "1", "-duration", "10s"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if !strings.Contains(strings.ToUpper(errb.String()), "SIMULATED") {
		t.Fatalf("stderr banner missing: %q", errb.String())
	}
	var res Result
	dec := json.NewDecoder(strings.NewReader(out.String()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&res); err != nil {
		t.Fatalf("stdout is not one Result: %v\n%s", err, out.String())
	}
	if !res.Simulated || res.Acks.Total != 4 {
		t.Fatalf("%+v", res)
	}
}

// Black-box rule: kairan-sim may import only the standard library and the wire package.
func TestImportsOnlyStdlibAndWire(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	fset := token.NewFileSet()
	for _, fn := range files {
		src, err := os.ReadFile(fn)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, fn, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if strings.HasPrefix(p, "kairan/") && p != "kairan/internal/wire" {
				t.Errorf("%s imports %s", fn, p)
			}
			if !strings.HasPrefix(p, "kairan/") && strings.Contains(strings.Split(p, "/")[0], ".") {
				t.Errorf("%s imports third party %s", fn, p)
			}
		}
	}
}

// M7/S9 shape: 1000 simulated proxies against a control plane that first answers 503 + Retry-After
// (a storm), then serves a policy. All must catch up, with no errors counted for the 503s.
func TestThousandProxiesCatchUpAfterStorm(t *testing.T) {
	f, srv := newFakeCP(t, "sim", 300*time.Millisecond)
	f.unavailable = 300
	f.publish(1)
	cfg := testCfg(t, srv, 1000, 300*time.Millisecond)
	cfg.StatusInterval = time.Second
	cfg.UntilVersion = 1
	res := runSim(t, cfg, 40*time.Second)
	if res.Acks.Total != 1000 || res.FinalVersions["1"] != 1000 {
		t.Fatalf("not all caught up: acks=%d final=%v", res.Acks.Total, res.FinalVersions)
	}
	if res.Polls.Unavailable != 300 {
		t.Fatalf("503s seen: %d", res.Polls.Unavailable)
	}
	if res.Errors.Total != 0 {
		t.Fatalf("errors: %+v", res.Errors)
	}
}
