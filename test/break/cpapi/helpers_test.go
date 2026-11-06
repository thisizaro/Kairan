// Package cpapibreak holds black-box attack tests for the control-plane HTTP API (task C-04).
// Sources: ARCHITECTURE cp/api LLD (limits M-D9, M-D31, M-D43), invariants I3/I4, decisions C-D7
// and M-D44, the go doc of api and wire. The server is driven only through its http.Handler or
// http.Server and the exported Config.
package cpapibreak

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/api"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/store"
	"kairan/internal/obs"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

const (
	adminTok = "ADMIN-TOKEN-0123456789abcdef"
	canary   = "CANARY-9f3b27-SECRET"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
	id   wire.Hash
}

func mkKey(name string) keyPair {
	seed := sha256.Sum256([]byte("kairan cpapi break " + name))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return keyPair{pub, priv, trust.KeyID(pub)}
}

var (
	keyA, keyB, keyC, keyOut = mkKey("a"), mkKey("b"), mkKey("c"), mkKey("outsider")
	keyD, keyE               = mkKey("d"), mkKey("e")
)

func rootFor(tenant wire.ID, ks ...keyPair) trust.Root {
	m := map[wire.Hash]ed25519.PublicKey{}
	for _, k := range ks {
		m[k.id] = k.pub
	}
	return trust.Root{Tenant: tenant, Keys: m, Threshold: 2}
}

// proxies: bank-a has p1, p2 (main) and c1 (canary); bank-b has q1 (main).
func tokOf(id string) string { return "tok-" + id + "-0123456789abcdef" }

type env struct {
	t   testing.TB
	srv *api.Server
	h   http.Handler
	ts  *httptest.Server
	st  store.Store
	clk *clock.Fake
	log *lockedBuf
	reg *obs.Registry
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

func newEnv(t testing.TB, mod ...func(*api.Config)) *env {
	t.Helper()
	st, err := store.OpenFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	clk := clock.NewFake(t0)
	cfg := api.Config{
		AdminToken: adminTok,
		Proxies: map[wire.ID]api.Enrollment{
			"p1": {Tenant: "bank-a", Group: "main", Token: tokOf("p1")},
			"p2": {Tenant: "bank-a", Group: "main", Token: tokOf("p2")},
			"c1": {Tenant: "bank-a", Group: "canary", Token: tokOf("c1")},
			"q1": {Tenant: "bank-b", Group: "main", Token: tokOf("q1")},
		},
		AdminKeys: map[wire.ID]trust.Root{
			"bank-a": rootFor("bank-a", keyA, keyB, keyC),
			"bank-b": rootFor("bank-b", keyD, keyE),
		},
		CanaryDwell: 10 * time.Second,
		Thresholds:  fleet.Thresholds{Stale: 30 * time.Second, Lost: 2 * time.Minute},
	}
	for _, m := range mod {
		m(&cfg)
	}
	lb := &lockedBuf{}
	reg := obs.NewRegistry()
	srv := api.New(cfg, st, clk, obs.NewLogger(lb, slog.LevelDebug), reg)
	e := &env{t: t, srv: srv, h: srv.Handler(), st: st, clk: clk, log: lb, reg: reg}
	e.ts = httptest.NewServer(e.h)
	t.Cleanup(e.ts.Close)
	return e
}

func (e *env) logText() string { return e.log.String() }

// metricsText renders the registry exposition.
func (e *env) metricsText() string {
	rec := httptest.NewRecorder()
	e.reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	return rec.Body.String()
}

type resp struct {
	code int
	hdr  http.Header
	body []byte
}

func (r resp) errCode() wire.ErrorCode {
	var er wire.ErrorResponse
	_ = json.Unmarshal(r.body, &er)
	return er.Code
}

func (e *env) do(method, path, token string, body []byte, hdr ...string) resp {
	e.t.Helper()
	return e.doCtx(context.Background(), method, path, token, body, hdr...)
}

func (e *env) doCtx(ctx context.Context, method, path, token string, body []byte, hdr ...string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return resp{code: -1, body: []byte(err.Error())}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

// ---- policies and envelopes ----

func policyJSON(tenant string, version uint64) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-12T11:00:00Z","default":"deny","roles":{"sales":{"crm.read_*":"R"}}}`, tenant, version))
}

func signed(payload []byte, ks ...keyPair) wire.Envelope {
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, k := range ks {
		trust.Sign(&e, k.priv)
	}
	return e
}

func hashOf(b []byte) wire.Hash {
	s := sha256.Sum256(b)
	return wire.Hash(hex.EncodeToString(s[:]))
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func (e *env) publish(tenant string, version uint64) wire.PublishResponse {
	e.t.Helper()
	r := e.do("POST", wire.PathPolicies, adminTok, mustJSON(signed(policyJSON(tenant, version), keyA, keyB)))
	if r.code != 200 {
		e.t.Fatalf("publish %s v%d: %d %s", tenant, version, r.code, r.body)
	}
	var pr wire.PublishResponse
	if err := json.Unmarshal(r.body, &pr); err != nil {
		e.t.Fatal(err)
	}
	return pr
}

func (e *env) startRollout(tenant string, version uint64) resp {
	e.t.Helper()
	return e.do("POST", wire.PathRollouts, adminTok, mustJSON(wire.RolloutRequest{Tenant: wire.ID(tenant), Version: version}))
}

func (e *env) rolloutView(tenant string) (wire.RolloutView, int) {
	e.t.Helper()
	r := e.do("GET", wire.PathRollouts+"?tenant="+tenant, adminTok, nil)
	var v wire.RolloutView
	if r.code == 200 {
		if err := json.Unmarshal(r.body, &v); err != nil {
			e.t.Fatalf("rollout view: %v: %s", err, r.body)
		}
	}
	return v, r.code
}

func (e *env) fleetView(tenant string) wire.FleetView {
	e.t.Helper()
	r := e.do("GET", wire.PathFleet+"?tenant="+tenant, adminTok, nil)
	if r.code != 200 {
		e.t.Fatalf("fleet: %d %s", r.code, r.body)
	}
	var v wire.FleetView
	if err := json.Unmarshal(r.body, &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) row(tenant, proxy string) wire.ProxyView {
	e.t.Helper()
	for _, p := range e.fleetView(tenant).Proxies {
		if p.ProxyID == wire.ID(proxy) {
			return p
		}
	}
	e.t.Fatalf("proxy %s not in fleet view of %s", proxy, tenant)
	return wire.ProxyView{}
}

// ---- status reports ----

func report(tenant, proxy string, version uint64, seq uint64) wire.StatusReport {
	r := wire.StatusReport{Tenant: wire.ID(tenant), ProxyID: wire.ID(proxy), Seq: seq, State: wire.StateEnforcing, AppliedVersion: version}
	if version > 0 {
		r.PolicyHash = hashOf(policyJSON(tenant, version))
		r.LogSeq = version
		r.LogHead = hashOf([]byte(fmt.Sprintf("head-%d", version)))
	} else {
		r.State = wire.StateDenyAll
	}
	return r
}

func (e *env) status(proxy string, r wire.StatusReport) resp {
	e.t.Helper()
	return e.do("POST", wire.PathStatus, tokOf(proxy), mustJSON(r))
}

func (e *env) mustStatus(proxy string, r wire.StatusReport) {
	e.t.Helper()
	if err := r.Validate(); err != nil {
		e.t.Fatalf("test bug: report invalid: %v", err)
	}
	if res := e.status(proxy, r); res.code != 204 {
		e.t.Fatalf("status %s: %d %s", proxy, res.code, res.body)
	}
}

// ---- polls ----

type pollRes struct {
	resp
	pr wire.PollResponse
}

func pollPath(tenant, proxy string, have uint64) string {
	return wire.PathPoll + "?" + wire.PollRequest{Tenant: wire.ID(tenant), ProxyID: wire.ID(proxy), Have: have}.Query().Encode()
}

func (e *env) pollAsync(ctx context.Context, proxy, tenant string, have uint64) <-chan pollRes {
	ch := make(chan pollRes, 1)
	go func() {
		r := e.doCtx(ctx, "GET", pollPath(tenant, proxy, have), tokOf(proxy), nil)
		pr := pollRes{resp: r}
		if r.code == 200 {
			_ = json.Unmarshal(r.body, &pr.pr)
		}
		ch <- pr
	}()
	return ch
}

func waitPoll(t *testing.T, ch <-chan pollRes, d time.Duration) pollRes {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(d):
		t.Fatalf("poll did not return within %v", d)
		return pollRes{}
	}
}

func stillWaiting(t *testing.T, ch <-chan pollRes, d time.Duration) {
	t.Helper()
	select {
	case r := <-ch:
		t.Fatalf("poll returned early: %d %s", r.code, r.body)
	case <-time.After(d):
	}
}

// bring takes tenant bank-a to version v through the whole API path:
// publish, rollout, canary ack, dwell, promote, everyone acks.
func (e *env) bring(v uint64) {
	e.t.Helper()
	e.publish("bank-a", v)
	if r := e.startRollout("bank-a", v); r.code != 200 {
		e.t.Fatalf("rollout v%d: %d %s", v, r.code, r.body)
	}
	seq := v * 10
	e.mustStatus("c1", report("bank-a", "c1", v, seq))
	e.clk.Advance(11 * time.Second)
	e.mustStatus("c1", report("bank-a", "c1", v, seq+1))
	e.mustStatus("p1", report("bank-a", "p1", v, seq))
	e.mustStatus("p2", report("bank-a", "p2", v, seq))
	e.mustStatus("c1", report("bank-a", "c1", v, seq+2))
	if rv, code := e.rolloutView("bank-a"); code != 200 || rv.Phase != wire.PhaseComplete {
		e.t.Fatalf("bring(%d): rollout %+v (%d), want complete", v, rv, code)
	}
}

func q(kv ...string) string {
	v := url.Values{}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Add(kv[i], kv[i+1])
	}
	return v.Encode()
}

func contains(s string, subs ...string) string {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return x
		}
	}
	return ""
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func ctxCancel(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 20*time.Second)
}
