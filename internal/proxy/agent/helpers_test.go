package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/store"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

var (
	start   = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	tenant  = wire.ID("bank-a")
	proxyID = wire.ID("proxy-1")
)

// connectProxy is a tiny HTTP CONNECT proxy for the HTTPS_PROXY test. TestMain
// starts it and points HTTPS_PROXY at it before any transport reads the
// environment (net/http caches it on first use).
var connectProxy struct {
	mu       sync.Mutex
	connects []string
}

func TestMain(m *testing.M) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "connect only", http.StatusMethodNotAllowed)
			return
		}
		connectProxy.mu.Lock()
		connectProxy.connects = append(connectProxy.connects, r.Host)
		connectProxy.mu.Unlock()
		// The tests only tunnel to one local TLS server; r.Host names it as
		// example.com:<port>, so dial the real address on that port.
		_, port, _ := net.SplitHostPort(r.Host)
		up, err := net.Dial("tcp", "127.0.0.1:"+port)
		if err != nil {
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		hj := w.(http.Hijacker)
		c, _, err := hj.Hijack()
		if err != nil {
			up.Close()
			return
		}
		c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() { io.Copy(up, c); up.Close() }()
		go func() { io.Copy(c, up); c.Close() }()
	})}
	go srv.Serve(ln)
	os.Setenv("HTTPS_PROXY", "http://"+ln.Addr().String())
	os.Setenv("NO_PROXY", "")
	code := m.Run()
	srv.Close()
	os.Exit(code)
}

// ---- keys, policies, envelopes ----

func seedKey(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("kairan agent test " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

type keys struct {
	a, b, c ed25519.PrivateKey
}

func newKeys() keys { return keys{seedKey("a"), seedKey("b"), seedKey("c")} }

func (k keys) root() trust.Root {
	r := trust.Root{Tenant: tenant, Keys: map[wire.Hash]ed25519.PublicKey{}, Threshold: 2}
	for _, p := range []ed25519.PrivateKey{k.a, k.b, k.c} {
		pub := p.Public().(ed25519.PublicKey)
		r.Keys[trust.KeyID(pub)] = pub
	}
	return r
}

func payload(version uint64, tn wire.ID, expires time.Time) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}}`,
		tn, version, start.Add(-time.Hour).Format(time.RFC3339), expires.UTC().Format(time.RFC3339)))
}

func signed(p []byte, signers ...ed25519.PrivateKey) wire.Envelope {
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: p}
	for _, s := range signers {
		trust.Sign(&env, s)
	}
	return env
}

// goodEnv is a version signed by a and b, valid for ttl after start.
func (k keys) goodEnv(version uint64, ttl time.Duration) wire.Envelope {
	return signed(payload(version, tenant, start.Add(ttl)), k.a, k.b)
}

// ---- a proxy under test ----

type rig struct {
	t      *testing.T
	keys   keys
	clk    *clock.Fake
	dir    string
	st     *store.Store
	al     *applylog.Log
	guard  *ClockGuard
	holder *enforce.Holder
	stats  *Stats
	cfg    Config
	hc     *http.Client
	a      *Agent
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func plainClient() *http.Client {
	// Not NewHTTPClient: tests that use it are about TLS and the proxy.
	return &http.Client{Transport: &http.Transport{}}
}

// newRig builds an agent around a fresh data directory. cp may be nil; tests
// that talk HTTP set rig.cfg.CP before calling build.
func newRig(t *testing.T) *rig {
	t.Helper()
	dir := t.TempDir()
	clk := clock.NewFake(start)
	r := &rig{t: t, keys: newKeys(), clk: clk, dir: dir, holder: &enforce.Holder{}, stats: &Stats{}, hc: plainClient()}
	var err error
	if r.st, err = store.Open(dir); err != nil {
		t.Fatal(err)
	}
	if r.al, err = applylog.Open(dir+"/apply.log", clk); err != nil {
		t.Fatal(err)
	}
	if r.guard, err = OpenClockGuard(clk, dir); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse("http://127.0.0.1:1")
	r.cfg = Config{CP: u, Tenant: tenant, ProxyID: proxyID, Token: "tok-secret", Root: r.keys.root(),
		Skew: time.Minute, Guard: r.guard, AllowPlaintext: true}
	return r
}

// build (re)creates the agent from the rig's current parts.
func (r *rig) build() *Agent {
	r.t.Helper()
	a, err := New(r.cfg, r.st, r.al, r.holder, r.clk, r.hc, quietLog(), r.stats)
	if err != nil {
		r.t.Fatalf("New: %v", err)
	}
	r.a = a
	return a
}

// reopen simulates a restart: fresh log handle, guard and agent over the same
// directory.
func (r *rig) reopen() *Agent {
	r.t.Helper()
	r.al.Close()
	var err error
	if r.al, err = applylog.Open(r.dir+"/apply.log", r.clk); err != nil {
		r.t.Fatal(err)
	}
	if r.guard, err = OpenClockGuard(r.clk, r.dir); err != nil {
		r.t.Fatal(err)
	}
	r.cfg.Guard = r.guard
	r.holder = &enforce.Holder{}
	r.stats = &Stats{}
	return r.build()
}

func (r *rig) active() *enforce.Active { return r.holder.Load() }

func (r *rig) logEntries() []applylog.Entry {
	r.t.Helper()
	f, err := os.Open(r.dir + "/apply.log")
	if err != nil {
		r.t.Fatal(err)
	}
	defer f.Close()
	es, err := applylog.Read(f)
	if err != nil {
		r.t.Fatal(err)
	}
	return es
}

// ---- a fake control plane ----

type fakeCP struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	polls    []url.Values
	auths    []string
	statuses []wire.StatusReport
	rawStat  [][]byte

	// pollFn decides each poll; nil = 304.
	pollFn   func(n int, q url.Values, w http.ResponseWriter, r *http.Request)
	statusFn func(n int, w http.ResponseWriter)
}

func newFakeCP(t *testing.T) *fakeCP {
	cp := &fakeCP{t: t}
	mux := http.NewServeMux()
	mux.HandleFunc(wire.PathPoll, func(w http.ResponseWriter, r *http.Request) {
		cp.mu.Lock()
		cp.polls = append(cp.polls, r.URL.Query())
		cp.auths = append(cp.auths, r.Header.Get(wire.HeaderAuthorization))
		n := len(cp.polls)
		fn := cp.pollFn
		cp.mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "", http.StatusMethodNotAllowed)
			return
		}
		if fn == nil {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		fn(n, r.URL.Query(), w, r)
	})
	mux.HandleFunc(wire.PathStatus, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, wire.MaxStatusBytes+1))
		var rep wire.StatusReport
		err := wire.Decode(strings.NewReader(string(body)), wire.MaxStatusBytes, &rep)
		cp.mu.Lock()
		cp.rawStat = append(cp.rawStat, body)
		if err == nil {
			cp.statuses = append(cp.statuses, rep)
		}
		cp.auths = append(cp.auths, r.Header.Get(wire.HeaderAuthorization))
		n := len(cp.rawStat)
		fn := cp.statusFn
		cp.mu.Unlock()
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != wire.ContentTypeJSON || err != nil {
			http.Error(w, "", http.StatusBadRequest)
			return
		}
		if fn != nil {
			fn(n, w)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	cp.srv = httptest.NewServer(mux)
	t.Cleanup(cp.srv.Close)
	return cp
}

func (cp *fakeCP) url() *url.URL { u, _ := url.Parse(cp.srv.URL); return u }

func (cp *fakeCP) pollCount() int { cp.mu.Lock(); defer cp.mu.Unlock(); return len(cp.polls) }

func (cp *fakeCP) statusCount() int { cp.mu.Lock(); defer cp.mu.Unlock(); return len(cp.statuses) }

func (cp *fakeCP) lastStatus() wire.StatusReport {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if len(cp.statuses) == 0 {
		cp.t.Fatal("no status report received")
	}
	return cp.statuses[len(cp.statuses)-1]
}

// serveEnv answers a poll with an envelope.
func serveEnv(env wire.Envelope, version uint64) func(int, url.Values, http.ResponseWriter, *http.Request) {
	return func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", wire.ContentTypeJSON)
		json.NewEncoder(w).Encode(wire.PollResponse{Version: version, Envelope: env})
	}
}

// await polls cond in real time; the agent's goroutines run on real
// scheduling even though its clock is fake.
func await(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func newHolder() *enforce.Holder { return &enforce.Holder{} }
