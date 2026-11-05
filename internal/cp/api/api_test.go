package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/obs"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const (
	adminTok = "admin-secret-token"
	tenant   = wire.ID("acme")
)

type testEnv struct {
	t     *testing.T
	srv   *Server
	h     http.Handler
	st    store.Store
	clk   *clock.Fake
	reg   *obs.Registry
	keys  []ed25519.PrivateKey
	other ed25519.PrivateKey
	hash  map[uint64]wire.Hash
}

func privKey(n byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, ed25519.SeedSize))
}

func tok(id string) string { return "token-of-" + id }

func newEnv(t *testing.T, mut ...func(*Config)) *testEnv {
	t.Helper()
	e := &testEnv{t: t, clk: clock.NewFake(t0), reg: obs.NewRegistry(), hash: map[uint64]wire.Hash{}}
	for i := byte(1); i <= 3; i++ {
		e.keys = append(e.keys, privKey(i))
	}
	e.other = privKey(99)
	root := trust.Root{Tenant: tenant, Threshold: 2, Keys: map[wire.Hash]ed25519.PublicKey{}}
	for _, k := range e.keys {
		pub := k.Public().(ed25519.PublicKey)
		root.Keys[trust.KeyID(pub)] = pub
	}
	st, err := store.OpenFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	e.st = st
	cfg := Config{
		AdminToken: adminTok,
		Proxies: map[wire.ID]Enrollment{
			"p-canary": {Tenant: tenant, Group: rollout.CanaryGroup, Token: tok("p-canary")},
			"p-main1":  {Tenant: tenant, Group: "main", Token: tok("p-main1")},
			"p-main2":  {Tenant: tenant, Group: "main", Token: tok("p-main2")},
			"p-beta":   {Tenant: "beta", Group: "main", Token: tok("p-beta")},
		},
		AdminKeys:   map[wire.ID]trust.Root{tenant: root},
		CanaryDwell: 60 * time.Second,
		Thresholds:  fleet.Thresholds{Stale: 30 * time.Second, Lost: 2 * time.Minute},
	}
	for _, m := range mut {
		m(&cfg)
	}
	e.srv = New(cfg, st, e.clk, obs.NewLogger(io.Discard, 0), e.reg)
	e.h = e.srv.Handler()
	return e
}

func policyJSON(ten wire.ID, version uint64) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R"}}}`,
		ten, version, t0.Add(-time.Hour).Format(time.RFC3339), t0.Add(72*time.Hour).Format(time.RFC3339)))
}

func signedEnv(payload []byte, keys ...ed25519.PrivateKey) wire.Envelope {
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, k := range keys {
		trust.Sign(&env, k)
	}
	return env
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (e *testEnv) do(method, target, token string, body []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	if token != "" {
		req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+token)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func wantErr(t *testing.T, rec *httptest.ResponseRecorder, status int, code wire.ErrorCode) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d (body %q)", rec.Code, status, rec.Body.String())
	}
	if code == "" {
		return
	}
	want := `{"code":"` + string(code) + `"}`
	if got := strings.TrimSpace(rec.Body.String()); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

// publish signs and publishes a version of the tenant's policy.
func (e *testEnv) publish(version uint64) {
	e.t.Helper()
	rec := e.do(http.MethodPost, wire.PathPolicies, adminTok, mustJSON(e.t, signedEnv(policyJSON(tenant, version), e.keys[0], e.keys[1])))
	if rec.Code != 200 {
		e.t.Fatalf("publish v%d: %d %s", version, rec.Code, rec.Body)
	}
	var pr wire.PublishResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil || pr.Version != version || pr.Tenant != tenant || !pr.PolicyHash.Valid() {
		e.t.Fatalf("publish response %s (%v)", rec.Body, err)
	}
	e.hash[version] = pr.PolicyHash
}

func (e *testEnv) startRollout(version uint64) *httptest.ResponseRecorder {
	return e.do(http.MethodPost, wire.PathRollouts, adminTok,
		mustJSON(e.t, wire.RolloutRequest{Tenant: tenant, Version: version}))
}

func (e *testEnv) phase() wire.RolloutView {
	e.t.Helper()
	rec := e.do(http.MethodGet, wire.PathRollouts+"?tenant="+string(tenant), adminTok, nil)
	if rec.Code != 200 {
		e.t.Fatalf("get rollout: %d %s", rec.Code, rec.Body)
	}
	var v wire.RolloutView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		e.t.Fatal(err)
	}
	return v
}

// report posts a status for a proxy applied at version (0 = none).
func (e *testEnv) report(id wire.ID, ten wire.ID, applied uint64, mut ...func(*wire.StatusReport)) *httptest.ResponseRecorder {
	e.t.Helper()
	r := wire.StatusReport{Tenant: ten, ProxyID: id, State: wire.StateDenyAll, LogSeq: 1, LogHead: wire.Hash(strings.Repeat("a", 64))}
	if applied > 0 {
		r.State = wire.StateEnforcing
		r.AppliedVersion = applied
		r.PolicyHash = e.hash[applied]
	}
	for _, m := range mut {
		m(&r)
	}
	return e.do(http.MethodPost, wire.PathStatus, tok(string(id)), mustJSON(e.t, r))
}

func (e *testEnv) mustReport(id wire.ID, applied uint64, mut ...func(*wire.StatusReport)) {
	e.t.Helper()
	ten := tenant
	if id == "p-beta" {
		ten = "beta"
	}
	if rec := e.report(id, ten, applied, mut...); rec.Code != http.StatusNoContent {
		e.t.Fatalf("status %s: %d %s", id, rec.Code, rec.Body)
	}
}

func pollTarget(ten, proxy wire.ID, have uint64) string {
	return wire.PathPoll + "?" + wire.PollRequest{Tenant: ten, ProxyID: proxy, Have: have}.Query().Encode()
}

type pending struct {
	cancel context.CancelFunc
	done   chan *httptest.ResponseRecorder
}

func (e *testEnv) startPoll(id wire.ID, have uint64) *pending {
	ten := tenant
	if id == "p-beta" {
		ten = "beta"
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &pending{cancel: cancel, done: make(chan *httptest.ResponseRecorder, 1)}
	req := httptest.NewRequest(http.MethodGet, pollTarget(ten, id, have), nil).WithContext(ctx)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+tok(string(id)))
	go func() {
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		p.done <- rec
	}()
	return p
}

func (e *testEnv) waitActive(n int) {
	e.t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for e.srv.activePolls() != n {
		if time.Now().After(deadline) {
			e.t.Fatalf("active polls = %d, want %d", e.srv.activePolls(), n)
		}
		time.Sleep(time.Millisecond)
	}
}

func (p *pending) result(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	select {
	case rec := <-p.done:
		return rec
	case <-time.After(3 * time.Second):
		t.Fatal("poll did not return")
		return nil
	}
}

func (p *pending) stillHeld(t *testing.T) {
	t.Helper()
	select {
	case rec := <-p.done:
		t.Fatalf("poll returned early: %d %s", rec.Code, rec.Body)
	case <-time.After(40 * time.Millisecond):
	}
}

// ---- auth ----

// spy records whether the handler read the body.
type spy struct {
	r    io.Reader
	read *bool
}

func (s spy) Read(p []byte) (int, error) { *s.read = true; return s.r.Read(p) }

func TestAuthTable(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	basic := func(pw string) func(*http.Request) {
		return func(r *http.Request) { r.SetBasicAuth("anyone", pw) }
	}
	bearer := func(tk string) func(*http.Request) {
		return func(r *http.Request) { r.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+tk) }
	}
	none := func(*http.Request) {}
	goodStatus := string(mustJSON(t, wire.StatusReport{Tenant: tenant, ProxyID: "p-canary", State: wire.StateDenyAll}))
	otherProxy := string(mustJSON(t, wire.StatusReport{Tenant: tenant, ProxyID: "p-main1", State: wire.StateDenyAll}))
	otherTenant := string(mustJSON(t, wire.StatusReport{Tenant: "beta", ProxyID: "p-canary", State: wire.StateDenyAll}))
	polls := func(ten, proxy wire.ID) string { return pollTarget(ten, proxy, 0) }

	tests := []struct {
		name   string
		method string
		target string
		body   string
		auth   func(*http.Request)
		status int
		code   wire.ErrorCode
	}{
		{"poll no token", "GET", polls(tenant, "p-canary"), "", none, 401, wire.ErrUnauthorized},
		{"poll wrong token", "GET", polls(tenant, "p-canary"), "", bearer("nope"), 401, wire.ErrUnauthorized},
		{"poll empty bearer", "GET", polls(tenant, "p-canary"), "", bearer(""), 401, wire.ErrUnauthorized},
		{"poll basic refused", "GET", polls(tenant, "p-canary"), "", basic(tok("p-canary")), 401, wire.ErrUnauthorized},
		{"poll basic admin refused", "GET", polls(tenant, "p-canary"), "", basic(adminTok), 401, wire.ErrUnauthorized},
		{"poll token of another proxy", "GET", polls(tenant, "p-canary"), "", bearer(tok("p-main1")), 403, wire.ErrForbidden},
		{"poll cross tenant", "GET", polls("beta", "p-canary"), "", bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"poll proxy of another tenant, own token", "GET", polls(tenant, "p-beta"), "", bearer(tok("p-beta")), 403, wire.ErrForbidden},
		{"poll unknown proxy with valid token", "GET", polls(tenant, "ghost"), "", bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"poll admin token", "GET", polls(tenant, "p-canary"), "", bearer(adminTok), 403, wire.ErrForbidden},
		{"poll bad query after auth", "GET", wire.PathPoll + "?tenant=acme", "", bearer(tok("p-canary")), 400, wire.ErrBadRequest},
		{"poll wrong method", "POST", polls(tenant, "p-canary"), "", bearer(tok("p-canary")), 405, wire.ErrMethodNotAllowed},
		{"poll wrong method no token", "POST", polls(tenant, "p-canary"), "", none, 401, wire.ErrUnauthorized},

		{"status no token", "POST", wire.PathStatus, goodStatus, none, 401, wire.ErrUnauthorized},
		{"status wrong token", "POST", wire.PathStatus, goodStatus, bearer("x"), 401, wire.ErrUnauthorized},
		{"status basic refused", "POST", wire.PathStatus, goodStatus, basic(tok("p-canary")), 401, wire.ErrUnauthorized},
		{"status other proxy's id", "POST", wire.PathStatus, otherProxy, bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"status cross tenant", "POST", wire.PathStatus, otherTenant, bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"status admin token", "POST", wire.PathStatus, goodStatus, bearer(adminTok), 403, wire.ErrForbidden},
		{"status ok", "POST", wire.PathStatus, goodStatus, bearer(tok("p-canary")), 204, ""},
		{"status wrong method", "GET", wire.PathStatus, "", bearer(tok("p-canary")), 405, wire.ErrMethodNotAllowed},

		{"publish no token", "POST", wire.PathPolicies, "{}", none, 401, wire.ErrUnauthorized},
		{"publish basic refused", "POST", wire.PathPolicies, "{}", basic(adminTok), 401, wire.ErrUnauthorized},
		{"publish proxy token", "POST", wire.PathPolicies, "{}", bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"publish wrong method", "GET", wire.PathPolicies, "", bearer(adminTok), 405, wire.ErrMethodNotAllowed},
		{"rollout start no token", "POST", wire.PathRollouts, "{}", none, 401, wire.ErrUnauthorized},
		{"rollout start proxy token", "POST", wire.PathRollouts, "{}", bearer(tok("p-main1")), 403, wire.ErrForbidden},
		{"rollout get no token", "GET", wire.PathRollouts + "?tenant=acme", "", none, 401, wire.ErrUnauthorized},
		{"rollout wrong method", "DELETE", wire.PathRollouts, "", bearer(adminTok), 405, wire.ErrMethodNotAllowed},
		{"fleet no token", "GET", wire.PathFleet + "?tenant=acme", "", none, 401, wire.ErrUnauthorized},
		{"fleet basic refused", "GET", wire.PathFleet + "?tenant=acme", "", basic(adminTok), 401, wire.ErrUnauthorized},
		{"fleet proxy token", "GET", wire.PathFleet + "?tenant=acme", "", bearer(tok("p-canary")), 403, wire.ErrForbidden},
		{"fleet wrong method", "POST", wire.PathFleet, "", bearer(adminTok), 405, wire.ErrMethodNotAllowed},
		{"timeline no token", "GET", wire.PathTimeline + "?tenant=acme", "", none, 401, wire.ErrUnauthorized},
		{"timeline basic refused", "GET", wire.PathTimeline + "?tenant=acme", "", basic(adminTok), 401, wire.ErrUnauthorized},
		{"timeline wrong method", "PUT", wire.PathTimeline, "", bearer(adminTok), 405, wire.ErrMethodNotAllowed},
		{"unknown api path, bearer", "GET", "/v1/other", "", bearer(adminTok), 404, wire.ErrNotFound},
		{"unknown api path, basic refused", "GET", "/v1/other", "", basic(adminTok), 401, wire.ErrUnauthorized},
		{"unknown api path, no token", "GET", "/v1/other", "", none, 401, wire.ErrUnauthorized},

		{"page basic", "GET", "/?tenant=acme", "", basic(adminTok), 200, ""},
		{"page head basic", "HEAD", "/?tenant=acme", "", basic(adminTok), 200, ""},
		{"page bearer", "GET", "/?tenant=acme", "", bearer(adminTok), 200, ""},
		{"page static basic", "GET", "/static/fleet.css", "", basic(adminTok), 200, ""},
		{"page no auth", "GET", "/?tenant=acme", "", none, 401, wire.ErrUnauthorized},
		{"page wrong password", "GET", "/?tenant=acme", "", basic("nope"), 401, wire.ErrUnauthorized},
		{"page proxy token as password", "GET", "/?tenant=acme", "", basic(tok("p-canary")), 403, wire.ErrForbidden},
		{"page POST with basic", "POST", "/?tenant=acme", "", basic(adminTok), 405, wire.ErrMethodNotAllowed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			read := false
			var body io.Reader = http.NoBody
			if tc.body != "" {
				body = spy{strings.NewReader(tc.body), &read}
			}
			req := httptest.NewRequest(tc.method, tc.target, body)
			tc.auth(req)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			if tc.status == 200 {
				if rec.Code != 200 {
					t.Fatalf("status = %d", rec.Code)
				}
				return
			}
			wantErr(t, rec, tc.status, tc.code)
			if tc.status == 401 && read {
				t.Fatal("body read before authentication")
			}
			page := strings.HasPrefix(tc.target, "/?") || strings.HasPrefix(tc.target, "/static")
			if tc.status == 401 {
				want := ""
				if page {
					want = `Basic realm="kairan"`
				}
				if got := rec.Header().Get("WWW-Authenticate"); page && got != want {
					t.Fatalf("WWW-Authenticate = %q", got)
				} else if !page && strings.HasPrefix(got, "Basic") {
					t.Fatalf("API path offers Basic: %q", got)
				}
			}
			if tc.status == 405 && rec.Header().Get("Allow") == "" {
				t.Fatal("405 without Allow header")
			}
		})
	}
}

func TestAuthFailuresAreCounted(t *testing.T) {
	e := newEnv(t)
	e.do("GET", pollTarget(tenant, "p-canary", 0), "bad", nil)
	e.do("GET", pollTarget(tenant, "p-canary", 0), tok("p-main1"), nil)
	e.do("GET", pollTarget(tenant, "p-canary", 0), tok("p-main1"), nil)
	rec := httptest.NewRecorder()
	e.reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`kairan_cp_auth_failures_total{code="unauthorized"} 1`,
		`kairan_cp_auth_failures_total{code="forbidden"} 2`,
		`kairan_cp_active_polls 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
}

func TestPollAndStatusAreCounted(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	e.mustReport("p-canary", 0)
	e.startRollout(1)
	e.do("GET", pollTarget(tenant, "p-canary", 0), tok("p-canary"), nil)
	rec := httptest.NewRecorder()
	e.reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`kairan_cp_status_total{result="ok"} 1`,
		`kairan_cp_polls_total{result="update"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
}

// ---- timeouts and limits ----

func TestHTTPServerTimeouts(t *testing.T) {
	e := newEnv(t)
	s := e.srv.HTTPServer("127.0.0.1:0")
	if s.ReadHeaderTimeout != 5*time.Second || s.ReadTimeout != 10*time.Second || s.WriteTimeout != 40*time.Second ||
		s.IdleTimeout != 60*time.Second || s.MaxHeaderBytes != 8<<10 || s.Handler == nil {
		t.Fatalf("server limits wrong: %+v", s)
	}
	if s.WriteTimeout <= wire.PollHold {
		t.Fatal("WriteTimeout must exceed the poll hold")
	}
}

func TestSlowHeaderClientIsCutOff(t *testing.T) {
	e := newEnv(t)
	s := e.srv.HTTPServer("127.0.0.1:0")
	s.ReadHeaderTimeout = 150 * time.Millisecond // the production value is 5s; asserted above
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(ln)
	defer s.Close()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("GET /v1/fleet?tenant=acme HTTP/1.1\r\nHost: x\r\nX-Slow: "))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	start := time.Now()
	_, err = io.ReadAll(conn) // the server closes the connection once the header deadline passes
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("server kept a slow-header connection open")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("cut off after %v", time.Since(start))
	}
}

func TestOversizeBodies(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		name  string
		path  string
		token string
		limit int
	}{
		{"publish", wire.PathPolicies, adminTok, wire.MaxEnvelopeBytes},
		{"status", wire.PathStatus, tok("p-canary"), wire.MaxStatusBytes},
		{"rollout", wire.PathRollouts, adminTok, wire.MaxSmallRequestBytes},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(`{"x":"` + strings.Repeat("a", tc.limit) + `"}`) // longer than the limit
			wantErr(t, e.do("POST", tc.path, tc.token, body), 413, wire.ErrTooLarge)

			// Unknown length (chunked): the reader cap must still apply.
			req := httptest.NewRequest("POST", tc.path, io.MultiReader(bytes.NewReader(body)))
			req.ContentLength = -1
			req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+tc.token)
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			wantErr(t, rec, 413, wire.ErrTooLarge)
		})
	}
}

func TestStrictDecoding(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	st := string(mustJSON(t, wire.StatusReport{Tenant: tenant, ProxyID: "p-canary", State: wire.StateDenyAll}))
	rq := string(mustJSON(t, wire.RolloutRequest{Tenant: tenant, Version: 1}))
	envJSON := string(mustJSON(t, signedEnv(policyJSON(tenant, 9), e.keys[0], e.keys[1])))
	withExtra := func(j string) string { return strings.TrimSuffix(j, "}") + `,"prompt_leak":"SECRET-VALUE"}` }
	tests := []struct {
		name, path, token, body string
	}{
		{"status unknown field", wire.PathStatus, tok("p-canary"), withExtra(st)},
		{"status trailing data", wire.PathStatus, tok("p-canary"), st + `{}`},
		{"status trailing garbage", wire.PathStatus, tok("p-canary"), st + `x`},
		{"status empty", wire.PathStatus, tok("p-canary"), ``},
		{"status not json", wire.PathStatus, tok("p-canary"), `nope`},
		{"status invalid value", wire.PathStatus, tok("p-canary"), strings.Replace(st, "deny_all", "banana", 1)},
		{"status version without hash", wire.PathStatus, tok("p-canary"), `{"tenant":"acme","proxy_id":"p-canary","seq":1,"state":"enforcing","applied_version":3,"log_seq":0,"uptime_seconds":1,"counters":{"calls_allowed":0,"calls_denied":0,"envelopes_rejected":0}}`},
		{"rollout unknown field", wire.PathRollouts, adminTok, withExtra(rq)},
		{"rollout trailing data", wire.PathRollouts, adminTok, rq + rq},
		{"rollout invalid", wire.PathRollouts, adminTok, `{"tenant":"acme","version":0}`},
		{"publish unknown field", wire.PathPolicies, adminTok, withExtra(envJSON)},
		{"publish trailing data", wire.PathPolicies, adminTok, envJSON + `[]`},
		{"publish duplicate signatures key", wire.PathPolicies, adminTok, strings.TrimSuffix(envJSON, "}") + `,"signatures":[]}`},
		{"publish duplicate payload key", wire.PathPolicies, adminTok, strings.TrimSuffix(envJSON, "}") + `,"payload":"e30="}`},
		{"publish case-variant payloadType", wire.PathPolicies, adminTok, strings.Replace(envJSON, `"payloadType"`, `"PayloadType"`, 1)},
		{"publish case-variant payload", wire.PathPolicies, adminTok, strings.Replace(envJSON, `"payload"`, `"Payload"`, 1)},
		{"publish case-variant signatures", wire.PathPolicies, adminTok, strings.Replace(envJSON, `"signatures"`, `"Signatures"`, 1)},
		{"publish case-variant keyid", wire.PathPolicies, adminTok, strings.Replace(envJSON, `"keyid"`, `"KeyID"`, 1)},
		{"publish duplicate sig key", wire.PathPolicies, adminTok, strings.Replace(envJSON, `"keyid"`, `"sig":"AA==","keyid"`, 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := e.do("POST", tc.path, tc.token, []byte(tc.body))
			wantErr(t, rec, 400, wire.ErrBadRequest)
			if strings.Contains(rec.Body.String(), "SECRET-VALUE") {
				t.Fatal("error body echoes input")
			}
		})
	}
	if _, err := e.st.Envelope(tenant, 9); err == nil {
		t.Fatal("a rejected publish was stored")
	}
}

// ---- publish ----

func TestPublish(t *testing.T) {
	e := newEnv(t)
	a, b, c := e.keys[0], e.keys[1], e.keys[2]
	pay := policyJSON(tenant, 5)
	post := func(env wire.Envelope) *httptest.ResponseRecorder {
		return e.do("POST", wire.PathPolicies, adminTok, mustJSON(t, env))
	}
	tests := []struct {
		name   string
		env    wire.Envelope
		status int
		code   wire.ErrorCode
	}{
		{"one signature", signedEnv(pay, a), 400, wire.ErrThreshold},
		{"same key twice", signedEnv(pay, a, a), 400, wire.ErrThreshold},
		{"outsider signatures", signedEnv(pay, e.other, privKey(98)), 400, wire.ErrThreshold},
		{"one trusted one outsider", signedEnv(pay, a, e.other), 400, wire.ErrThreshold},
		{"unknown tenant", signedEnv(policyJSON("nobody", 5), a, b), 400, wire.ErrWrongTenant},
		{"malformed policy", signedEnv([]byte(`{"tenant":"acme"}`), a, b), 400, wire.ErrMalformed},
		{"not a policy", signedEnv([]byte(`garbage`), a, b), 400, wire.ErrMalformed},
		{"payload type", func() wire.Envelope { x := signedEnv(pay, a, b); x.PayloadType = "text/plain"; return x }(), 400, wire.ErrPayloadType},
		{"tampered payload", func() wire.Envelope {
			x := signedEnv(pay, a, b)
			x.Payload = policyJSON(tenant, 6)
			return x
		}(), 400, wire.ErrThreshold},
		{"good", signedEnv(pay, a, c), 200, ""},
		{"conflict", signedEnv(pay, a, b), 409, wire.ErrConflict},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(tc.env)
			if tc.status == 200 {
				if rec.Code != 200 {
					t.Fatalf("%d %s", rec.Code, rec.Body)
				}
				var pr wire.PublishResponse
				if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil || pr.Tenant != tenant || pr.Version != 5 || !pr.PolicyHash.Valid() {
					t.Fatalf("response %s %v", rec.Body, err)
				}
				return
			}
			wantErr(t, rec, tc.status, tc.code)
		})
	}
	got, err := e.st.Envelope(tenant, 5)
	if err != nil || !bytes.Equal(got.Payload, pay) {
		t.Fatalf("stored envelope %v %v", got, err)
	}
	if _, err := e.st.Envelope(tenant, 6); err == nil {
		t.Fatal("tampered envelope stored")
	}
	// Publishing only stores: nothing is desired, so a poll still waits.
	p := e.startPoll("p-canary", 0)
	e.waitActive(1)
	p.stillHeld(t)
	e.clk.Advance(wire.PollHold)
	wantErr(t, p.result(t), 304, "")
}

// ---- poll ----

func TestPollHoldAndImmediate(t *testing.T) {
	e := newEnv(t)
	e.publish(1)

	p := e.startPoll("p-canary", 0)
	e.waitActive(1)
	e.clk.BlockUntil(1)
	e.clk.Advance(wire.PollHold - time.Second)
	p.stillHeld(t)
	e.clk.Advance(time.Second)
	rec := p.result(t)
	if rec.Code != 304 || rec.Body.Len() != 0 {
		t.Fatalf("hold end: %d %q", rec.Code, rec.Body)
	}
	e.waitActive(0)

	if rec := e.startRollout(1); rec.Code != 200 {
		t.Fatalf("rollout: %d %s", rec.Code, rec.Body)
	}
	// Canary has a newer desired version: the answer is immediate, no clock movement.
	rec = e.do("GET", pollTarget(tenant, "p-canary", 0), tok("p-canary"), nil)
	if rec.Code != 200 {
		t.Fatalf("immediate poll: %d %s", rec.Code, rec.Body)
	}
	var pr wire.PollResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pr); err != nil || pr.Version != 1 || !bytes.Equal(pr.Envelope.Payload, policyJSON(tenant, 1)) {
		t.Fatalf("poll response %s %v", rec.Body, err)
	}
	if rec.Header().Get("Content-Type") != wire.ContentTypeJSON {
		t.Fatalf("content type %q", rec.Header().Get("Content-Type"))
	}
	// Up to date: held.
	q := e.startPoll("p-canary", 1)
	e.waitActive(1)
	q.stillHeld(t)
	// A main-group proxy is not yet offered the version.
	m := e.startPoll("p-main1", 0)
	e.waitActive(2)
	m.stillHeld(t)
	q.cancel()
	m.cancel()
	e.waitActive(0)
}

func TestPollWakesWhenRolloutStarts(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	p := e.startPoll("p-canary", 0)
	e.waitActive(1)
	if rec := e.startRollout(1); rec.Code != 200 {
		t.Fatalf("rollout: %d", rec.Code)
	}
	rec := p.result(t)
	if rec.Code != 200 {
		t.Fatalf("woken poll: %d %s", rec.Code, rec.Body)
	}
	e.waitActive(0)
}

func TestSecondPollDisplacesFirst(t *testing.T) {
	e := newEnv(t)
	first := e.startPoll("p-main1", 0)
	e.waitActive(1)
	second := e.startPoll("p-main1", 0)
	rec := first.result(t) // returns at once, without the clock moving
	if rec.Code != 304 || rec.Body.Len() != 0 {
		t.Fatalf("displaced poll: %d %q", rec.Code, rec.Body)
	}
	e.waitActive(1)
	second.stillHeld(t)
	e.clk.BlockUntil(1)
	e.clk.Advance(wire.PollHold)
	wantErr(t, second.result(t), 304, "")
	e.waitActive(0)
}

func TestPollCapReturns503(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxPolls = 2 })
	a := e.startPoll("p-canary", 0)
	b := e.startPoll("p-main1", 0)
	e.waitActive(2)
	rec := e.do("GET", pollTarget(tenant, "p-main2", 0), tok("p-main2"), nil)
	wantErr(t, rec, 503, wire.ErrUnavailable)
	if ra := rec.Header().Get("Retry-After"); ra == "" {
		t.Fatal("503 without Retry-After")
	}
	// A proxy that already holds a slot can poll again (it displaces itself).
	c := e.startPoll("p-main1", 0)
	b.result(t)
	e.waitActive(2)
	c.stillHeld(t)
	// A freed slot is usable.
	a.cancel()
	e.waitActive(1)
	d := e.startPoll("p-main2", 0)
	e.waitActive(2)
	d.stillHeld(t)
	c.cancel()
	d.cancel()
	e.waitActive(0)
}

func TestFailedAuthDoesNotRegisterAPoll(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.MaxPolls = 1 })
	for i := 0; i < 5; i++ {
		e.do("GET", pollTarget(tenant, "p-canary", 0), "bad", nil)
	}
	if n := e.srv.activePolls(); n != 0 {
		t.Fatalf("active polls = %d", n)
	}
}

// ---- rollout through the handlers ----

func TestRolloutCanaryPromoteComplete(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.PollHold = 10 * time.Minute }) // outlasts the dwell
	e.publish(1)
	for _, id := range []wire.ID{"p-canary", "p-main1", "p-main2", "p-beta"} {
		e.mustReport(id, 0)
	}
	// Unpublished versions cannot be rolled out.
	wantErr(t, e.startRollout(7), 404, wire.ErrNotFound)

	rec := e.startRollout(1)
	var v wire.RolloutView
	if err := json.Unmarshal(rec.Body.Bytes(), &v); rec.Code != 200 || err != nil || v.Phase != wire.PhaseCanary || v.Version != 1 || v.Tenant != tenant {
		t.Fatalf("start: %d %s", rec.Code, rec.Body)
	}
	main := e.startPoll("p-main1", 0)
	e.waitActive(1)

	// The canary applies version 1 and keeps reporting; the dwell is 60s.
	e.mustReport("p-canary", 1)
	if got := e.phase(); got.Phase != wire.PhaseCanary {
		t.Fatalf("phase %v", got)
	}
	e.clk.Advance(30 * time.Second)
	e.mustReport("p-canary", 1)
	e.mustReport("p-main1", 0)
	e.mustReport("p-main2", 0)
	if got := e.phase(); got.Phase != wire.PhaseCanary {
		t.Fatalf("dwell not over, phase %v", got)
	}
	main.stillHeld(t)
	e.clk.Advance(31 * time.Second)
	e.mustReport("p-canary", 1)
	if got := e.phase(); got.Phase != wire.PhasePromoting {
		t.Fatalf("want promoting, got %v", got)
	}
	// The held main-group poll is woken with the new version.
	rec = main.result(t)
	var pr wire.PollResponse
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &pr) != nil || pr.Version != 1 {
		t.Fatalf("main poll: %d %s", rec.Code, rec.Body)
	}
	// The beta tenant's proxy is untouched by acme's rollout.
	beta := e.startPoll("p-beta", 0)
	e.waitActive(1)
	beta.stillHeld(t) // not offered acme's policy
	beta.cancel()
	e.waitActive(0)

	e.mustReport("p-main1", 1)
	if got := e.phase(); got.Phase != wire.PhasePromoting {
		t.Fatalf("one main left, got %v", got)
	}
	e.mustReport("p-main2", 1)
	if got := e.phase(); got.Phase != wire.PhaseComplete {
		t.Fatalf("want complete, got %v", got)
	}

	// Fleet view: groups come from the registry; everything is at version 1.
	var fv wire.FleetView
	rec = e.do("GET", wire.PathFleet+"?tenant=acme", adminTok, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &fv); rec.Code != 200 || err != nil || len(fv.Proxies) != 3 {
		t.Fatalf("fleet %d %s", rec.Code, rec.Body)
	}
	for _, p := range fv.Proxies {
		wantGroup := wire.ID("main")
		if p.ProxyID == "p-canary" {
			wantGroup = rollout.CanaryGroup
		}
		if p.Group != wantGroup || p.DesiredVersion != 1 || p.AppliedVersion != 1 || p.Drift != 0 || p.PolicyHash != e.hash[1] {
			t.Errorf("row %+v", p)
		}
	}
	// A new rollout must beat the highest desired version.
	wantErr(t, e.startRollout(1), 409, wire.ErrConflict)

	// Timeline carries the apply-log anchor (M-D41).
	var tv wire.TimelineView
	rec = e.do("GET", wire.PathTimeline+"?tenant=acme", adminTok, nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &tv); rec.Code != 200 || err != nil || tv.Tenant != tenant {
		t.Fatalf("timeline %d %s", rec.Code, rec.Body)
	}
	found := false
	for _, en := range tv.Entries {
		if en.ProxyID == "p-canary" && en.Version == 1 {
			found = true
			if en.LogSeq != 1 || en.LogHead != wire.Hash(strings.Repeat("a", 64)) || en.PolicyHash != e.hash[1] {
				t.Errorf("entry %+v", en)
			}
		}
	}
	if !found {
		t.Fatalf("no timeline entry for the canary at v1: %+v", tv)
	}
}

func TestRolloutHaltsOnCanaryError(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	for _, id := range []wire.ID{"p-canary", "p-main1", "p-main2"} {
		e.mustReport(id, 0)
	}
	e.startRollout(1)
	e.mustReport("p-canary", 0, func(r *wire.StatusReport) {
		r.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 1}
	})
	got := e.phase()
	if got.Phase != wire.PhaseHalted || got.Reason != wire.ErrThreshold {
		t.Fatalf("want halted/threshold_not_met, got %+v", got)
	}
	// The main group is never offered version 1.
	p := e.startPoll("p-main1", 0)
	e.waitActive(1)
	p.stillHeld(t)
	p.cancel()
	e.waitActive(0)
	// Recovery: publish a higher version, start a new rollout.
	e.publish(2)
	rec := e.startRollout(2)
	if rec.Code != 200 {
		t.Fatalf("restart: %d %s", rec.Code, rec.Body)
	}
	if got := e.phase(); got.Version != 2 || got.Phase != wire.PhaseCanary {
		t.Fatalf("new rollout %+v", got)
	}
	// Cannot start version 1 again: not above the canary's desired version.
	wantErr(t, e.startRollout(1), 409, wire.ErrConflict)
}

func TestRunStepsRolloutOnTimer(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.CanaryDwell = 20 * time.Second; c.TickInterval = 5 * time.Second })
	e.publish(1)
	e.mustReport("p-canary", 0)
	e.mustReport("p-main1", 0)
	e.startRollout(1)
	e.mustReport("p-canary", 1) // dwell starts; no further status arrives
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.srv.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	for i := 0; i < 4; i++ {
		e.clk.BlockUntil(1)
		e.clk.Advance(5 * time.Second)
	}
	deadline := time.Now().Add(3 * time.Second)
	for e.phase().Phase != wire.PhasePromoting {
		if time.Now().After(deadline) {
			t.Fatalf("timer did not promote: %+v", e.phase())
		}
		time.Sleep(time.Millisecond)
	}
}

// ---- fleet and misc ----

func TestFleetAndRolloutQueries(t *testing.T) {
	e := newEnv(t)
	e.mustReport("p-main1", 0)
	rec := e.do("GET", wire.PathFleet+"?tenant=acme", adminTok, nil)
	var fv wire.FleetView
	if err := json.Unmarshal(rec.Body.Bytes(), &fv); rec.Code != 200 || err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	seen := map[wire.ID]wire.Health{}
	for _, p := range fv.Proxies {
		seen[p.ProxyID] = p.Health
	}
	// Enrolled proxies that never reported are listed as lost, not hidden.
	if seen["p-main1"] != wire.HealthHealthy || seen["p-canary"] != wire.HealthLost || seen["p-main2"] != wire.HealthLost || len(seen) != 3 {
		t.Fatalf("fleet %+v", seen)
	}
	for _, tc := range []struct {
		target string
		status int
		code   wire.ErrorCode
	}{
		{wire.PathFleet, 400, wire.ErrBadRequest},
		{wire.PathFleet + "?tenant=Bad_ID", 400, wire.ErrBadRequest},
		{wire.PathFleet + "?tenant=acme&tenant=beta", 400, wire.ErrBadRequest},
		{wire.PathFleet + "?tenant=acme&x=1", 400, wire.ErrBadRequest},
		{wire.PathFleet + "?tenant=nobody", 404, wire.ErrNotFound},
		{wire.PathTimeline + "?tenant=nobody", 404, wire.ErrNotFound},
		{wire.PathRollouts + "?tenant=nobody", 404, wire.ErrNotFound},
		{wire.PathRollouts + "?tenant=acme", 404, wire.ErrNotFound}, // no rollout yet
	} {
		wantErr(t, e.do("GET", tc.target, adminTok, nil), tc.status, tc.code)
	}
}

func TestStatusStoresMetadataAndGroupFromRegistry(t *testing.T) {
	e := newEnv(t)
	e.mustReport("p-main1", 0)
	lasts, err := e.st.Fleet(tenant)
	if err != nil || len(lasts) != 1 {
		t.Fatalf("%v %v", lasts, err)
	}
	if lasts[0].Group != "main" || !lasts[0].SeenAt.Equal(t0) || lasts[0].Report.ProxyID != "p-main1" {
		t.Fatalf("%+v", lasts[0])
	}
	// A proxy cannot choose its group: the field does not exist on the wire.
	body := `{"tenant":"acme","proxy_id":"p-main1","seq":2,"state":"deny_all","applied_version":0,"log_seq":0,"uptime_seconds":1,"group":"canary","counters":{"calls_allowed":0,"calls_denied":0,"envelopes_rejected":0}}`
	wantErr(t, e.do("POST", wire.PathStatus, tok("p-main1"), []byte(body)), 400, wire.ErrBadRequest)
}

// A held poll must outlive the server's ReadTimeout (10s in production, shorter
// than the 30s hold): this runs the real http.Server with a short ReadTimeout.
func TestLongPollOutlivesReadTimeout(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.PollHold = 500 * time.Millisecond })
	srv := New(Config{
		Proxies:  map[wire.ID]Enrollment{"p-main1": {Tenant: tenant, Group: "main", Token: tok("p-main1")}},
		PollHold: 500 * time.Millisecond,
	}, e.st, clock.NewReal(), nil, nil)
	hs := srv.HTTPServer("127.0.0.1:0")
	hs.ReadTimeout = 100 * time.Millisecond
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go hs.Serve(ln)
	defer hs.Close()
	req, _ := http.NewRequest("GET", "http://"+ln.Addr().String()+pollTarget(tenant, "p-main1", 0), nil)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+tok("p-main1"))
	start := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 304 || time.Since(start) < 450*time.Millisecond {
		t.Fatalf("status %d after %v", resp.StatusCode, time.Since(start))
	}
}

func TestConcurrentTraffic(t *testing.T) {
	e := newEnv(t)
	e.publish(1)
	e.publish(2)
	e.startRollout(1)
	done := make(chan struct{})
	var wg sync.WaitGroup
	ids := []wire.ID{"p-canary", "p-main1", "p-main2"}
	for _, id := range ids {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				e.report(id, tenant, 0)
				e.clk.Advance(time.Second)
			}
		}()
		go func() {
			defer wg.Done()
			for i := 0; i < 30; i++ {
				p := e.startPoll(id, uint64(i%3))
				time.Sleep(time.Millisecond)
				p.cancel()
				p.result(t)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 30; i++ {
			e.do("GET", wire.PathFleet+"?tenant=acme", adminTok, nil)
			e.do("GET", wire.PathTimeline+"?tenant=acme", adminTok, nil)
			e.startRollout(2)
		}
	}()
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("deadlock")
	}
	e.waitActive(0)
}

// An enrollment may carry the SHA-256 of the token instead of the token, so a
// config file holds no secret (C-07). It authenticates exactly like the token.
func TestEnrollmentByTokenDigest(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Proxies["p-digest"] = Enrollment{Tenant: tenant, Group: "main", TokenDigest: sha256.Sum256([]byte("digest-token-of-p-digest"))}
		c.Proxies["p-nothing"] = Enrollment{Tenant: tenant, Group: "main"} // neither: never authenticates
	})
	// A status report returns at once (a poll would be held on the fake clock).
	rep := mustJSON(t, wire.StatusReport{Tenant: tenant, ProxyID: "p-digest", State: wire.StateDenyAll})
	if rec := e.do("POST", wire.PathStatus, "digest-token-of-p-digest", rep); rec.Code != http.StatusNoContent {
		t.Fatalf("digest enrollment refused its own token: %d %s", rec.Code, rec.Body)
	}
	wantErr(t, e.do("GET", pollTarget(tenant, "p-digest", 0), "other-token", nil), http.StatusUnauthorized, wire.ErrUnauthorized)
	// The digest in hex is not a token.
	hexd := sha256.Sum256([]byte("digest-token-of-p-digest"))
	wantErr(t, e.do("GET", pollTarget(tenant, "p-digest", 0), hex.EncodeToString(hexd[:]), nil), http.StatusUnauthorized, wire.ErrUnauthorized)
	wantErr(t, e.do("GET", pollTarget(tenant, "p-nothing", 0), "", nil), http.StatusUnauthorized, wire.ErrUnauthorized)
}

// The enrolled count per tenant is a metric, 0 for a tenant without proxies.
func TestEnrolledProxiesMetric(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.AdminKeys["empty-tenant"] = trust.Root{Tenant: "empty-tenant"}
	})
	rec := httptest.NewRecorder()
	e.reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	out := rec.Body.String()
	for _, want := range []string{
		`kairan_cp_enrolled_proxies{tenant="empty-tenant"} 0`,
		fmt.Sprintf(`kairan_cp_enrolled_proxies{tenant=%q} 3`, tenant),
		`kairan_cp_enrolled_proxies{tenant="beta"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics lack %q:\n%s", want, out)
		}
	}
}

// Q-D21: past store.MaxTimeline entries for one proxy, the oldest are dropped
// and kairan_cp_timeline_dropped_total{tenant} counts them.
func TestTimelineDropsAreCounted(t *testing.T) {
	e := newEnv(t)
	const extra = 4
	for i := 0; i < store.MaxTimeline+extra; i++ {
		seq := uint64(1000 - i) // the anchor goes back every time: one new entry each report
		e.mustReport("p-main1", 0, func(r *wire.StatusReport) { r.LogSeq = seq })
	}
	e.mustReport("p-beta", 0)
	rec := httptest.NewRecorder()
	e.reg.Handler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if want := fmt.Sprintf(`kairan_cp_timeline_dropped_total{tenant="acme"} %d`, extra); !strings.Contains(rec.Body.String(), want) {
		t.Errorf("metrics lack %q:\n%s", want, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `kairan_cp_timeline_dropped_total{tenant="beta"}`) {
		t.Error("tenant beta dropped nothing but has a series")
	}
	rec = e.do("GET", wire.PathTimeline+"?tenant="+string(tenant), adminTok, nil)
	var tv wire.TimelineView
	if err := json.Unmarshal(rec.Body.Bytes(), &tv); err != nil || len(tv.Entries) != store.MaxTimeline {
		t.Fatalf("timeline: %d entries, err %v", len(tv.Entries), err)
	}
	d, err := e.st.(store.DropReporter).TimelineDropped(tenant)
	if err != nil || d["p-main1"] != extra {
		t.Fatalf("dropped = %v, err %v", d, err)
	}
}
