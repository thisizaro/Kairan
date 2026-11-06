// Package agentbreak holds black-box attack tests for the proxy's control-plane client (task P-05).
// Sources: ARCHITECTURE proxy/agent LLD and section 4 boot rule (M-D30, M-D31, M-D33, M-D35, M-D40),
// invariants I1-I6, THREATS #4, #5, #8, #12, the go doc of agent, store, applylog, enforce, trust, clock and wire.
// The control plane is an in-test httptest server; time is a clock.Fake.
package agentbreak

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/store"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

const (
	tenant = "bank-a"
	proxy  = "p1"
	token  = "tok-p1-0123456789abcdef-CANARY-TOKEN"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   wire.Hash
}

func loadKey(who string) keyPair {
	read := func(ext string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "TEST-ONLY-"+who+"."+ext))
		if err != nil {
			panic(err)
		}
		d, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			panic(err)
		}
		return d
	}
	priv := ed25519.NewKeyFromSeed(read("seed"))
	pub := priv.Public().(ed25519.PublicKey)
	return keyPair{pub, priv, trust.KeyID(pub)}
}

var keyA, keyB, keyC, keyOut = loadKey("admin-a"), loadKey("admin-b"), loadKey("admin-c"), loadKey("outsider")

func root(tn wire.ID, ks ...keyPair) trust.Root {
	m := map[wire.Hash]ed25519.PublicKey{}
	for _, k := range ks {
		m[k.id] = k.pub
	}
	return trust.Root{Tenant: tn, Keys: m, Threshold: 2}
}

func policyDoc(tn string, version uint64, issued, expires time.Time) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}}`,
		tn, version, issued.UTC().Format(time.RFC3339), expires.UTC().Format(time.RFC3339)))
}

func hashOf(b []byte) wire.Hash { s := sha256.Sum256(b); return wire.Hash(hex.EncodeToString(s[:])) }

func signedEnv(payload []byte, ks ...keyPair) wire.Envelope {
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, k := range ks {
		trust.Sign(&e, k.priv)
	}
	return e
}

// validEnv: bank-a, version v, issued 1h before t0, expires 24h after t0, signed by a and b.
func validEnv(v uint64) (wire.Envelope, wire.Hash) {
	p := policyDoc(tenant, v, t0.Add(-time.Hour), t0.Add(24*time.Hour))
	return signedEnv(p, keyA, keyB), hashOf(p)
}

// ---- fake control plane ----

type cpReq struct {
	Method string
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
	At     time.Time
}

type cpAnswer struct {
	status int
	header map[string]string
	body   []byte
	delay  func()
}

type fakeCP struct {
	t      testing.TB
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []cpReq
	poll   func(n int, r cpReq) cpAnswer
	status func(n int, r cpReq) cpAnswer
	polls  int
	stats  int
}

func newCP(t testing.TB) *fakeCP {
	c := &fakeCP{t: t}
	c.poll = func(int, cpReq) cpAnswer { return cpAnswer{status: 304} }
	c.status = func(int, cpReq) cpAnswer { return cpAnswer{status: 204} }
	c.srv = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	q := cpReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body}
	c.mu.Lock()
	var a cpAnswer
	switch {
	case r.URL.Path == wire.PathPoll:
		c.polls++
		n := c.polls
		f := c.poll
		c.reqs = append(c.reqs, q)
		c.mu.Unlock()
		a = f(n, q)
	case r.URL.Path == wire.PathStatus:
		c.stats++
		n := c.stats
		f := c.status
		c.reqs = append(c.reqs, q)
		c.mu.Unlock()
		a = f(n, q)
	default:
		c.reqs = append(c.reqs, q)
		c.mu.Unlock()
		a = cpAnswer{status: 404}
	}
	if a.delay != nil {
		a.delay()
	}
	for k, v := range a.header {
		w.Header().Set(k, v)
	}
	if a.status == 0 {
		a.status = 200
	}
	w.WriteHeader(a.status)
	_, _ = w.Write(a.body)
}

func (c *fakeCP) url() *url.URL { u, _ := url.Parse(c.srv.URL); return u }

func (c *fakeCP) pollCount() int   { c.mu.Lock(); defer c.mu.Unlock(); return c.polls }
func (c *fakeCP) statusCount() int { c.mu.Lock(); defer c.mu.Unlock(); return c.stats }
func (c *fakeCP) all() []cpReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cpReq(nil), c.reqs...)
}

func (c *fakeCP) lastStatus() (wire.StatusReport, []byte, bool) {
	rs := c.all()
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].Path == wire.PathStatus {
			var s wire.StatusReport
			err := json.Unmarshal(rs[i].Body, &s)
			return s, rs[i].Body, err == nil
		}
	}
	return wire.StatusReport{}, nil, false
}

func pollJSON(env wire.Envelope, version uint64) cpAnswer {
	b, _ := json.Marshal(wire.PollResponse{Version: version, Envelope: env})
	return cpAnswer{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: b}
}

// ---- the agent under test ----

type rig struct {
	t      testing.TB
	dir    string
	clk    *clock.Fake
	cp     *fakeCP
	st     *store.Store
	al     *applylog.Log
	hold   *enforce.Holder
	guard  *agent.ClockGuard
	stats  *agent.Stats
	ag     *agent.Agent
	logbuf *lockedBuf
	cfg    agent.Config
	cancel context.CancelFunc
	done   chan error
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func (r *rig) logPath() string { return filepath.Join(r.dir, "apply.log") }

// newRig builds everything on dir (a fresh temp dir when ""), without booting.
func newRig(t testing.TB, dir string, clk *clock.Fake, cp *fakeCP, mod ...func(*agent.Config)) *rig {
	t.Helper()
	if dir == "" {
		dir = t.TempDir()
	}
	if clk == nil {
		clk = clock.NewFake(t0)
	}
	if cp == nil {
		cp = newCP(t)
	}
	r := &rig{t: t, dir: dir, clk: clk, cp: cp, hold: &enforce.Holder{}, stats: &agent.Stats{}, logbuf: &lockedBuf{}}
	var err error
	if r.st, err = store.Open(dir); err != nil {
		t.Fatal(err)
	}
	var logErr error
	r.al, logErr = applylog.Open(r.logPath(), clk)
	if logErr != nil {
		r.al = nil
	}
	g, gerr := agent.OpenClockGuard(clk, dir)
	if g == nil {
		t.Fatalf("clock guard: %v", gerr)
	}
	r.guard = g
	r.cfg = agent.Config{
		CP: cp.url(), Tenant: tenant, ProxyID: proxy, Token: token, Root: root(tenant, keyA, keyB, keyC),
		Skew: 2 * time.Minute, Guard: g, AllowPlaintext: true, LogOpenErr: logErr,
	}
	for _, m := range mod {
		m(&r.cfg)
	}
	hc, err := agent.NewHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	r.ag, err = agent.New(r.cfg, r.st, r.al, r.hold, clk, hc, slog.New(slog.NewJSONHandler(r.logbuf, &slog.HandlerOptions{Level: slog.LevelDebug})), r.stats)
	if err != nil {
		t.Fatalf("agent.New: %v", err)
	}
	return r
}

func (r *rig) boot() *enforce.Active {
	r.t.Helper()
	if err := r.ag.Boot(); err != nil {
		r.t.Fatalf("Boot: %v", err)
	}
	return r.hold.Load()
}

func (r *rig) run() {
	r.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan error, 1)
	go func() { r.done <- r.ag.Run(ctx) }()
	r.t.Cleanup(r.stop)
}

func (r *rig) stop() {
	if r.cancel == nil {
		return
	}
	r.cancel()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		r.t.Error("Run did not return within 5 s of cancel")
	}
	r.cancel = nil
}

// settle gives the agent goroutines real time to react.
func settle() { time.Sleep(40 * time.Millisecond) }

// advance moves the fake clock in steps, letting the goroutines run between steps.
func (r *rig) advance(total, step time.Duration) {
	for done := time.Duration(0); done < total; done += step {
		s := step
		if total-done < s {
			s = total - done
		}
		r.clk.Advance(s)
		time.Sleep(15 * time.Millisecond)
	}
	settle()
}

func waitFor(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func (r *rig) appliedVersion() uint64 {
	a := r.hold.Load()
	if a == nil || a.Policy == nil {
		return 0
	}
	return a.Policy.Version
}

func (r *rig) state() wire.ProxyState {
	a := r.hold.Load()
	if a == nil {
		return ""
	}
	return a.State
}

func readLog(t testing.TB, path string) []applylog.Entry {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	es, err := applylog.Read(f)
	if err != nil {
		t.Fatalf("apply log does not verify: %v", err)
	}
	return es
}
