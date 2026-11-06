package cpapibreak

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"kairan/internal/cp/api"
	"kairan/internal/wire"
)

type pathCase struct {
	name   string
	method string
	path   string
	body   []byte
	admin  bool // admin path
}

func allPaths(e *env) []pathCase {
	return []pathCase{
		{"poll", "GET", pollPath("bank-a", "p1", 0), nil, false},
		{"status", "POST", wire.PathStatus, mustJSON(report("bank-a", "p1", 0, 1)), false},
		{"publish", "POST", wire.PathPolicies, mustJSON(signed(policyJSON("bank-a", 1), keyA, keyB)), true},
		{"rollout-post", "POST", wire.PathRollouts, mustJSON(wire.RolloutRequest{Tenant: "bank-a", Version: 1}), true},
		{"rollout-get", "GET", wire.PathRollouts + "?tenant=bank-a", nil, true},
		{"fleet", "GET", wire.PathFleet + "?tenant=bank-a", nil, true},
		{"timeline", "GET", wire.PathTimeline + "?tenant=bank-a", nil, true},
	}
}

// ARCH cp/api: "Missing or wrong token: 401 unauthorized." Every path, many bad tokens.
func TestMissingOrWrongTokenIs401OnEveryPath(t *testing.T) {
	e := newEnv(t)
	bad := map[string]string{
		"none":            "",
		"wrong":           "wrong-token-value",
		"admin-prefix":    adminTok[:len(adminTok)-1],
		"admin-plus-x":    adminTok + "x",
		"admin-upper":     strings.ToUpper(adminTok),
		"proxy-prefix":    tokOf("p1")[:10],
		"proxy-plus-x":    tokOf("p1") + "x",
		"empty-bearer":    "\x00EMPTY",
		"nul-byte":        adminTok + "\x00",
		"very-long-token": strings.Repeat("A", 4000),
	}
	for _, pc := range allPaths(e) {
		for name, tok := range bad {
			tok := tok
			t.Run(pc.name+"/"+name, func(t *testing.T) {
				var r resp
				switch tok {
				case "":
					r = e.do(pc.method, pc.path, "", pc.body)
				case "\x00EMPTY":
					r = e.do(pc.method, pc.path, "", pc.body, "Authorization", "Bearer ")
				default:
					r = e.do(pc.method, pc.path, tok, pc.body)
				}
				if r.code == -1 && name == "nul-byte" {
					return // the HTTP client refused to send it; nothing reached the server
				}
				if r.code != 401 || r.errCode() != wire.ErrUnauthorized {
					t.Fatalf("got %d %s, want 401 unauthorized", r.code, r.body)
				}
			})
		}
	}
}

// The token must come from the Authorization header: not from the query, not from other headers,
// and not through another auth scheme.
func TestTokenOnlyFromBearerHeader(t *testing.T) {
	e := newEnv(t)
	cases := map[string]func() resp{
		"query-token": func() resp { return e.do("GET", wire.PathFleet+"?tenant=bank-a&token="+adminTok, "", nil) },
		"x-api-key":   func() resp { return e.do("GET", wire.PathFleet+"?tenant=bank-a", "", nil, "X-Api-Key", adminTok) },
		"basic-on-api": func() resp {
			return e.do("GET", wire.PathFleet+"?tenant=bank-a", "", nil, "Authorization", "Basic YTphZG1pbg==")
		},
		"token-no-word": func() resp { return e.do("GET", wire.PathFleet+"?tenant=bank-a", "", nil, "Authorization", adminTok) },
		"cookie":        func() resp { return e.do("GET", wire.PathFleet+"?tenant=bank-a", "", nil, "Cookie", "token="+adminTok) },
	}
	for name, f := range cases {
		if r := f(); r.code/100 == 2 {
			t.Errorf("%s: authenticated (%d)", name, r.code)
		}
	}
}

// ARCH / doc: a valid token used where it does not belong is 403 forbidden (another proxy's ID, the
// admin token on a proxy path, a proxy token on an admin path, another tenant).
func TestValidTokenInTheWrongPlaceIs403(t *testing.T) {
	e := newEnv(t)
	type c struct {
		name   string
		method string
		path   string
		tok    string
		body   []byte
	}
	cases := []c{
		{"admin-token-on-poll", "GET", pollPath("bank-a", "p1", 0), adminTok, nil},
		{"admin-token-on-status", "POST", wire.PathStatus, adminTok, mustJSON(report("bank-a", "p1", 0, 1))},
		{"proxy-token-on-fleet", "GET", wire.PathFleet + "?tenant=bank-a", tokOf("p1"), nil},
		{"proxy-token-on-timeline", "GET", wire.PathTimeline + "?tenant=bank-a", tokOf("p1"), nil},
		{"proxy-token-on-publish", "POST", wire.PathPolicies, tokOf("p1"), mustJSON(signed(policyJSON("bank-a", 1), keyA, keyB))},
		{"proxy-token-on-rollout-post", "POST", wire.PathRollouts, tokOf("c1"), mustJSON(wire.RolloutRequest{Tenant: "bank-a", Version: 1})},
		{"proxy-token-on-rollout-get", "GET", wire.PathRollouts + "?tenant=bank-a", tokOf("c1"), nil},
		{"poll-as-other-proxy", "GET", pollPath("bank-a", "p2", 0), tokOf("p1"), nil},
		{"poll-as-other-tenant-proxy", "GET", pollPath("bank-a", "q1", 0), tokOf("p1"), nil},
		{"poll-other-tenant", "GET", pollPath("bank-b", "p1", 0), tokOf("p1"), nil},
		{"poll-own-id-other-tenant", "GET", pollPath("bank-b", "q1", 0), tokOf("p1"), nil},
		{"status-as-other-proxy", "POST", wire.PathStatus, tokOf("p1"), mustJSON(report("bank-a", "p2", 0, 1))},
		{"status-other-tenant", "POST", wire.PathStatus, tokOf("p1"), mustJSON(report("bank-b", "p1", 0, 1))},
		{"status-other-tenant-other-proxy", "POST", wire.PathStatus, tokOf("p1"), mustJSON(report("bank-b", "q1", 0, 1))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do(tc.method, tc.path, tc.tok, tc.body)
			if r.code != 403 || r.errCode() != wire.ErrForbidden {
				t.Fatalf("got %d %s, want 403 forbidden", r.code, r.body)
			}
		})
	}
	// None of the forbidden status reports may have left a row behind (bank-b only has q1, never seen).
	for _, p := range e.fleetView("bank-b").Proxies {
		if p.ProxyID != "q1" || p.LastSeenUnixMs != 0 || p.AppliedVersion != 0 {
			t.Errorf("a forbidden status wrote state: %+v", p)
		}
	}
}

// Doc: auth runs before any body is read. A wrong token with a body over every limit is 401, not 413,
// and a wrong token with malformed JSON is 401, not 400.
func TestAuthRunsBeforeBodyIsRead(t *testing.T) {
	e := newEnv(t)
	huge := []byte(strings.Repeat("A", wire.MaxEnvelopeBytes+1000))
	for _, pc := range []pathCase{
		{"publish", "POST", wire.PathPolicies, huge, true},
		{"status", "POST", wire.PathStatus, huge, false},
		{"rollout", "POST", wire.PathRollouts, huge, true},
		{"publish-garbage", "POST", wire.PathPolicies, []byte(`{{{`), true},
		{"status-garbage", "POST", wire.PathStatus, []byte(`{{{`), false},
	} {
		for tokName, tok := range map[string]string{"none": "", "wrong": "nope"} {
			r := e.do(pc.method, pc.path, tok, pc.body)
			if r.code != 401 {
				t.Errorf("%s/%s: got %d, want 401 before the body is read", pc.name, tokName, r.code)
			}
		}
	}
	// A valid token for the wrong place is 403 before the body too.
	if r := e.do("POST", wire.PathStatus, tokOf("p1"), huge); r.code != 403 && r.code != 413 {
		t.Errorf("status with huge body and proxy token: %d", r.code)
	}
	if r := e.do("POST", wire.PathPolicies, tokOf("p1"), huge); r.code != 403 {
		t.Errorf("publish with huge body and a proxy token: got %d, want 403 before any body read", r.code)
	}
}

// Doc: auth runs before a poll is registered. Failed polls must not occupy the cap or replace a poll.
func TestFailedAuthPollsAreNotRegistered(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.MaxPolls = 1 })
	for i := 0; i < 5; i++ {
		if r := e.do("GET", pollPath("bank-a", "p1", 0), "wrong", nil); r.code != 401 {
			t.Fatalf("wrong token poll: %d", r.code)
		}
		if r := e.do("GET", pollPath("bank-a", "p2", 0), tokOf("p1"), nil); r.code != 403 {
			t.Fatalf("other proxy's id poll: %d", r.code)
		}
	}
	ctx, cancel := ctxCancel(t)
	defer cancel()
	ch := e.pollAsync(ctx, "p1", "bank-a", 0)
	stillWaiting(t, ch, 300*time.Millisecond)
	// With MaxPolls=1 the slot is taken now; a second proxy gets 503 (not 401/403: it is authentic).
	if r := e.do("GET", pollPath("bank-a", "p2", 0), tokOf("p2"), nil); r.code != 503 {
		t.Fatalf("second poll with MaxPolls=1: got %d, want 503", r.code)
	}
}

// A 403 poll for someone else's ID must not replace that proxy's live poll (the "new poll replaces the
// old" rule is only for the authenticated owner).
func TestForbiddenPollDoesNotKillTheOwnersPoll(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	ctx, cancel := ctxCancel(t)
	defer cancel()
	victim := e.pollAsync(ctx, "c1", "bank-a", 0)
	// c1 is in the canary group and desired is 0 until a rollout starts.
	stillWaiting(t, victim, 200*time.Millisecond)
	if r := e.do("GET", pollPath("bank-a", "c1", 0), tokOf("p1"), nil); r.code != 403 {
		t.Fatalf("got %d", r.code)
	}
	if r := e.do("GET", pollPath("bank-a", "c1", 0), "", nil); r.code != 401 {
		t.Fatalf("got %d", r.code)
	}
	stillWaiting(t, victim, 200*time.Millisecond)
	if r := e.startRollout("bank-a", 1); r.code != 200 {
		t.Fatalf("rollout: %d %s", r.code, r.body)
	}
	got := waitPoll(t, victim, 3*time.Second)
	if got.code != 200 || got.pr.Version != 1 {
		t.Fatalf("victim's poll was disturbed: %d %s", got.code, got.body)
	}
}

// Doc: Admin disabled when AdminToken is empty; a proxy with an empty token can never authenticate.
func TestEmptyTokensNeverAuthenticate(t *testing.T) {
	e := newEnv(t, func(c *api.Config) {
		c.AdminToken = ""
		c.Proxies["p2"] = api.Enrollment{Tenant: "bank-a", Group: "main", Token: ""}
	})
	for _, pc := range allPaths(e) {
		for name, hdr := range map[string][]string{
			"no-header":    nil,
			"empty-bearer": {"Authorization", "Bearer "},
			"bearer-space": {"Authorization", "Bearer  "},
			"bare-bearer":  {"Authorization", "Bearer"},
		} {
			r := e.do(pc.method, pc.path, "", pc.body, hdr...)
			if r.code/100 == 2 || r.code == 304 {
				t.Errorf("%s/%s: empty credentials succeeded (%d)", pc.name, name, r.code)
			}
		}
	}
	// The admin page too.
	for _, h := range [][]string{nil, {"Authorization", "Bearer "}, {"Authorization", "Basic Og=="}, {"Authorization", "Basic YWRtaW46"}} {
		if r := e.do("GET", "/", "", nil, h...); r.code/100 == 2 {
			t.Errorf("page served with admin disabled and header %v: %d", h, r.code)
		}
	}
	// Other proxies still work.
	if r := e.do("POST", wire.PathStatus, tokOf("p1"), mustJSON(report("bank-a", "p1", 0, 1))); r.code != 204 {
		t.Errorf("a healthy enrollment broke: %d %s", r.code, r.body)
	}
}

// Doc: enrollments with invalid IDs are skipped and can never authenticate.
func TestInvalidEnrollmentIDsNeverAuthenticate(t *testing.T) {
	e := newEnv(t, func(c *api.Config) {
		c.Proxies["BAD ID"] = api.Enrollment{Tenant: "bank-a", Group: "main", Token: "tok-bad-id"}
		c.Proxies[""] = api.Enrollment{Tenant: "bank-a", Group: "main", Token: "tok-empty-id"}
		c.Proxies["p9"] = api.Enrollment{Tenant: "BAD TENANT", Group: "main", Token: "tok-bad-tenant"}
	})
	for _, tok := range []string{"tok-bad-id", "tok-empty-id", "tok-bad-tenant"} {
		for _, id := range []string{"BAD ID", "", "p9", "p1"} {
			r := e.do("GET", wire.PathPoll+"?"+q(wire.QueryTenant, "bank-a", wire.QueryProxy, id, wire.QueryHave, "0"), tok, nil)
			if r.code == 200 || r.code == 304 {
				t.Errorf("token %q id %q authenticated: %d", tok, id, r.code)
			}
		}
	}
}

// Doc: errors are wire.ErrorResponse codes and nothing else; input is never echoed (I4).
func TestErrorBodiesAreCodesOnlyAndNeverEchoInput(t *testing.T) {
	e := newEnv(t)
	type probe struct {
		name         string
		method, path string
		tok          string
		body         []byte
		hdr          []string
	}
	tenantCanary := "bank-" + strings.ToLower(canary)
	probes := []probe{
		{"query-canary-poll", "GET", wire.PathPoll + "?" + q(wire.QueryTenant, canary, wire.QueryProxy, "p1", wire.QueryHave, "0"), tokOf("p1"), nil, nil},
		{"query-canary-extra", "GET", wire.PathPoll + "?" + q(wire.QueryTenant, "bank-a", wire.QueryProxy, "p1", wire.QueryHave, "0", canary, canary), tokOf("p1"), nil, nil},
		{"path-canary", "GET", "/v1/" + canary, adminTok, nil, nil},
		{"body-canary-status", "POST", wire.PathStatus, tokOf("p1"), []byte(`{"tenant":"bank-a","proxy_id":"p1","prompt":"` + canary + `"}`), nil},
		{"body-canary-status-state", "POST", wire.PathStatus, tokOf("p1"), []byte(`{"tenant":"bank-a","proxy_id":"p1","state":"` + canary + `"}`), nil},
		{"body-canary-publish", "POST", wire.PathPolicies, adminTok, []byte(`{"payloadType":"` + canary + `","payload":"e30=","signatures":[]}`), nil},
		{"body-canary-publish-payload", "POST", wire.PathPolicies, adminTok, mustJSON(signed([]byte(`{"tenant":"`+tenantCanary+`","note":"`+canary+`"}`), keyA, keyB)), nil},
		{"body-canary-rollout", "POST", wire.PathRollouts, adminTok, []byte(`{"tenant":"` + canary + `","version":1}`), nil},
		{"hdr-canary-token", "GET", wire.PathFleet + "?tenant=bank-a", canary, nil, nil},
		{"hdr-canary-other", "GET", wire.PathFleet + "?tenant=bank-a", "", nil, []string{"X-Canary", canary, "Authorization", "Bearer " + canary}},
		{"method-canary", http.MethodPatch, wire.PathFleet + "?tenant=" + canary, adminTok, nil, nil},
	}
	for _, p := range probes {
		r := e.do(p.method, p.path, p.tok, p.body, p.hdr...)
		if strings.Contains(string(r.body), "9f3b27") {
			t.Errorf("%s: response echoes input: %s", p.name, r.body)
		}
		if r.code >= 400 {
			var er wire.ErrorResponse
			dec := json.NewDecoder(strings.NewReader(string(r.body)))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&er); err != nil || !er.Code.Valid() {
				t.Errorf("%s: %d body is not exactly a wire.ErrorResponse: %q", p.name, r.code, r.body)
			}
			if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, wire.ContentTypeJSON) {
				t.Errorf("%s: error content type %q", p.name, ct)
			}
		}
		if r.code >= 500 {
			t.Errorf("%s: server error %d for hostile input", p.name, r.code)
		}
	}
	if x := contains(e.logText(), "9f3b27", canary); x != "" {
		t.Errorf("hostile input reached the logs (I4): %s", e.logText())
	}
	if x := contains(e.metricsText(), "9f3b27", canary); x != "" {
		t.Errorf("hostile input reached the metrics (I4): %s", e.metricsText())
	}
}

// ARCH: wrong method 405 method_not_allowed, with Allow header (wire: "Send an Allow header too").
func TestWrongMethodIs405WithAllow(t *testing.T) {
	e := newEnv(t)
	type c struct {
		path   string
		tok    string
		method string
	}
	cases := []c{
		{pollPath("bank-a", "p1", 0), tokOf("p1"), "POST"},
		{pollPath("bank-a", "p1", 0), tokOf("p1"), "DELETE"},
		{pollPath("bank-a", "p1", 0), tokOf("p1"), "PUT"},
		{wire.PathStatus, tokOf("p1"), "GET"},
		{wire.PathStatus, tokOf("p1"), "PUT"},
		{wire.PathStatus, tokOf("p1"), "DELETE"},
		{wire.PathPolicies, adminTok, "GET"},
		{wire.PathPolicies, adminTok, "PUT"},
		{wire.PathPolicies, adminTok, "DELETE"},
		{wire.PathRollouts, adminTok, "PUT"},
		{wire.PathRollouts, adminTok, "DELETE"},
		{wire.PathFleet + "?tenant=bank-a", adminTok, "POST"},
		{wire.PathFleet + "?tenant=bank-a", adminTok, "DELETE"},
		{wire.PathTimeline + "?tenant=bank-a", adminTok, "POST"},
		{wire.PathTimeline + "?tenant=bank-a", adminTok, "PUT"},
	}
	for _, tc := range cases {
		r := e.do(tc.method, tc.path, tc.tok, []byte("{}"))
		if r.code != 405 || r.errCode() != wire.ErrMethodNotAllowed {
			t.Errorf("%s %s: got %d %s, want 405 method_not_allowed", tc.method, tc.path, r.code, r.body)
			continue
		}
		if r.hdr.Get("Allow") == "" {
			t.Errorf("%s %s: 405 without an Allow header", tc.method, tc.path)
		}
	}
}

// M-D43: the admin token as HTTP Basic password works for GET/HEAD on the page only; a 401 on the page
// asks for it with WWW-Authenticate: Basic realm="kairan". Basic never opens the API or any write.
func TestBasicAuthIsForTheFleetPageOnly(t *testing.T) {
	e := newEnv(t)
	basic := func(user, pass string) string {
		return "Basic " + b64(user+":"+pass)
	}
	if r := e.do("GET", "/", "", nil); r.code != 401 {
		t.Fatalf("page without credentials: %d, want 401", r.code)
	} else if got := r.hdr.Get("WWW-Authenticate"); got != `Basic realm="kairan"` {
		t.Fatalf("WWW-Authenticate = %q", got)
	}
	for _, user := range []string{"", "admin", "anything"} {
		r := e.do("GET", "/?tenant=bank-a", "", nil, "Authorization", basic(user, adminTok))
		if r.code != 200 {
			t.Errorf("page with Basic user %q + admin token: %d, want 200", user, r.code)
		}
	}
	r := e.do("HEAD", "/?tenant=bank-a", "", nil, "Authorization", basic("a", adminTok))
	if r.code != 200 {
		t.Errorf("HEAD page with Basic: %d", r.code)
	}
	for name, h := range map[string][]string{
		"wrong-pass":   {"Authorization", basic("a", "nope")},
		"proxy-token":  {"Authorization", basic("a", tokOf("p1"))},
		"empty-pass":   {"Authorization", basic("a", "")},
		"admin-prefix": {"Authorization", basic("a", adminTok[:8])},
		"bad-base64":   {"Authorization", "Basic !!!!"},
		"basic-no-b64": {"Authorization", "Basic"},
	} {
		r := e.do("GET", "/", "", nil, h...)
		if r.code/100 == 2 {
			t.Errorf("%s: page served (%d)", name, r.code)
		}
		if r.code == 401 && r.hdr.Get("WWW-Authenticate") != `Basic realm="kairan"` {
			t.Errorf("%s: 401 without the Basic challenge", name)
		}
	}
	// A proxy's Bearer token on the page is a valid token in the wrong place: 403.
	if r := e.do("GET", "/", tokOf("p1"), nil); r.code != 403 {
		t.Errorf("proxy bearer token on the page: %d, want 403", r.code)
	}
	// Basic must not open API paths or any non-GET/HEAD method.
	for _, pc := range allPaths(e) {
		if r := e.do(pc.method, pc.path, "", pc.body, "Authorization", basic("a", adminTok)); r.code/100 == 2 || r.code == 304 {
			t.Errorf("Basic auth opened API path %s: %d", pc.name, r.code)
		}
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		if r := e.do(m, "/", "", []byte("{}"), "Authorization", basic("a", adminTok)); r.code/100 == 2 {
			t.Errorf("Basic auth with %s on the page: %d", m, r.code)
		}
	}
	// The page and its stylesheet are never served unauthenticated (M-D43).
	for _, p := range []string{"/", "/static/style.css", "/style.css", "/index.html", "/?tenant=bank-a&lang=en"} {
		if r := e.do("GET", p, "", nil); r.code/100 == 2 {
			t.Errorf("unauthenticated GET %s: %d", p, r.code)
		}
	}
}
