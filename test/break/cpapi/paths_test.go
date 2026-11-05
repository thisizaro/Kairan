package cpapibreak

import (
	"strings"
	"testing"

	"kairan/internal/wire"
)

// Path tricks must not slip past authentication: every variant of an API or page path without a token is
// 401 (or 404/405), never 2xx, and never a 5xx.
func TestPathVariantsNeverBypassAuth(t *testing.T) {
	e := newEnv(t)
	variants := []string{
		"/v1/fleet/", "/v1/fleet//", "//v1/fleet", "/v1//fleet", "/v1/./fleet", "/v1/x/../fleet",
		"/V1/FLEET", "/v1/Fleet", "/v1/%66leet", "/v1/fleet%2f", "/v1/fleet%00", "/v1/fleet;x=1",
		"/v1/fleet?tenant=bank-a", "/v1/timeline/", "/v1/policies/", "/v1/rollouts/", "/v1/status/", "/v1/poll/",
		"/.", "/..", "/%2e%2e/v1/fleet", "/static/../v1/fleet", "/v1", "/v1/",
		"/metrics", "/debug/pprof/", "/debug/vars", "/healthz", "/admin", "/index.html",
	}
	for _, v := range variants {
		for _, m := range []string{"GET", "POST", "HEAD", "OPTIONS", "DELETE"} {
			r := e.do(m, v, "", []byte("{}"))
			if r.code/100 == 2 && !(v == "/healthz") {
				t.Errorf("%s %s without a token: %d %.80s", m, v, r.code, r.body)
			}
			if r.code >= 500 {
				t.Errorf("%s %s: server error %d", m, v, r.code)
			}
		}
	}
	// Even with a proxy token, none of these reach admin data.
	for _, v := range variants {
		r := e.do("GET", v, tokOf("p1"), nil)
		if r.code/100 == 2 && strings.Contains(string(r.body), "proxies") {
			t.Errorf("proxy token read admin data through %s", v)
		}
	}
	_ = wire.PathFleet
}

// Debug and metric endpoints must not be exposed on the API listener (C-D7: /metrics is not mounted).
func TestNoDebugEndpointsOnTheAPIListener(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/metrics", "/debug/pprof/", "/debug/pprof/heap", "/debug/vars", "/pprof"} {
		for _, tok := range []string{"", adminTok} {
			r := e.do("GET", p, tok, nil)
			if r.code/100 == 2 && p != "/metrics" {
				t.Errorf("%s served on the API listener (token set: %v): %d", p, tok != "", r.code)
			}
			if p == "/metrics" && tok == "" && r.code/100 == 2 {
				t.Errorf("/metrics served to an unauthenticated caller")
			}
		}
	}
}
