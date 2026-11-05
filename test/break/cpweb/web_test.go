package cpwebbreak

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/wire"
)

func seeded() *fakeStore {
	f := newFake()
	f.roll["bank-a"] = rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseCanary, Dwell: time.Minute}
	mk := func(id, group wire.ID, st wire.ProxyState, applied uint64, age time.Duration) fleet.Last {
		return lastOf("bank-a", id, group, st, applied, now0.Add(-age))
	}
	f.fleet["bank-a"] = []fleet.Last{
		mk("canary-1", "canary", wire.StateEnforcing, 4242, 5*time.Second),
		mk("main-ok", "main", wire.StateEnforcing, 41, 5*time.Second),
		mk("main-stale", "main", wire.StateSafeMode, 41, 45*time.Second),
		mk("main-lost", "main", wire.StateDenyAll, 0, 10*time.Minute),
		mk("main-tampered", "main", wire.StateTampered, 0, 3*time.Second),
		mk("main-booting", "main", wire.StateBooting, 0, 3*time.Second),
	}
	e := f.fleet["bank-a"]
	e[4].Report.LastError = &wire.ApplyError{Code: wire.ErrTampered}
	e[1].Report.LastError = &wire.ApplyError{Code: wire.ErrThreshold, Version: 4242}
	f.fleet["bank-a"] = e
	other := mk("city-proxy", "main", wire.StateEnforcing, 3, time.Second)
	other.Report.Tenant = "city-b"
	f.fleet["city-b"] = []fleet.Last{other}
	return f
}

var proxyIDs = []string{"canary-1", "main-ok", "main-stale", "main-lost", "main-tampered", "main-booting"}

func TestPageBasicsBothLanguages(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, lang := range []string{"ja", "en"} {
		r := get(t, h, "/?tenant=bank-a&lang="+lang)
		if r.code != 200 {
			t.Fatalf("%s: status %d: %.300s", lang, r.code, r.body)
		}
		if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || !strings.Contains(strings.ToLower(ct), "utf-8") {
			t.Fatalf("%s: Content-Type %q", lang, ct)
		}
		for _, id := range proxyIDs {
			if !strings.Contains(r.body, id) {
				t.Fatalf("%s: proxy %s missing from the page", lang, id)
			}
		}
		if strings.Contains(r.body, "city-proxy") {
			t.Fatalf("%s: another tenant's proxy on bank-a's page", lang)
		}
		m := reHTMLLang.FindStringSubmatch(r.body)
		if len(m) != 2 || !strings.HasPrefix(m[1], lang) {
			t.Fatalf("%s: <html lang> = %v", lang, m)
		}
		// J7 / LLD: auto-refresh
		ref := regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*"refresh"[^>]*content\s*=\s*"(\d+)`).FindStringSubmatch(r.body)
		if ref == nil {
			t.Fatalf("%s: no meta refresh (LLD: auto-refresh)", lang)
		}
		if n, _ := strconv.Atoi(ref[1]); n < 1 || n > 300 {
			t.Fatalf("%s: refresh interval %d s is unreasonable", lang, n)
		}
	}
}

func TestPageOffersNoScriptNoInlineStyleNoExternalLoads(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, lang := range []string{"ja", "en"} {
		r := get(t, h, "/?tenant=bank-a&lang="+lang)
		tags := tagSet(r.body)
		for _, bad := range []string{"script", "style", "iframe", "object", "embed", "form", "img", "svg", "base", "applet", "frame"} {
			if tags[bad] {
				t.Errorf("%s: page uses <%s>, forbidden by the CSP promise (no script, nothing from outside)", lang, bad)
			}
		}
		for a := range attrSet(r.body) {
			if a == "style" || strings.HasPrefix(a, "on") {
				t.Errorf("%s: attribute %q (inline style / handler) is blocked by the CSP and means the CSP is wrong or the page is", lang, a)
			}
		}
		for _, m := range reURLAttr.FindAllStringSubmatch(r.body, -1) {
			v := strings.ToLower(strings.TrimSpace(m[1]))
			if strings.Contains(v, "://") || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "javascript:") || strings.HasPrefix(v, "data:") {
				if !strings.Contains(m[0], "content") { // meta refresh content="5" never has a scheme
					t.Errorf("%s: external or scriptable URL %q", lang, m[1])
				}
			}
		}
	}
	css := get(t, h, "/static/fleet.css")
	if css.code != 200 {
		t.Fatalf("css status %d", css.code)
	}
	if ct := css.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("css Content-Type %q", ct)
	}
	lower := strings.ToLower(css.body)
	for _, bad := range []string{"@import", "url(http", "url(//", "url(\"http", "url('http", "expression(", "javascript:"} {
		if strings.Contains(lower, bad) {
			t.Fatalf("stylesheet loads from outside or is scriptable: contains %q", bad)
		}
	}
}

func cspOK(t *testing.T, name string, r resp) {
	t.Helper()
	csp := r.hdr.Get("Content-Security-Policy")
	if csp == "" {
		t.Errorf("%s (status %d): no Content-Security-Policy", name, r.code)
		return
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("%s: CSP %q lacks default-src 'self'", name, csp)
	}
	for _, bad := range []string{"unsafe-inline", "unsafe-eval", "default-src *", " * ", "data:", "http:", "https:"} {
		if strings.Contains(csp, bad) {
			t.Errorf("%s: CSP %q is weakened by %q", name, csp, bad)
		}
	}
}

// LLD + C-D5: the CSP is the page's security promise; it must be on every response, errors included.
func TestCSPOnEveryPath(t *testing.T) {
	f := seeded()
	h, _ := newHandler(f)
	type c struct {
		name, method, target string
		hdr                  map[string]string
		body                 string
	}
	cases := []c{
		{"page-ja", "GET", "/?tenant=bank-a&lang=ja", nil, ""},
		{"page-en", "GET", "/?tenant=bank-a&lang=en", nil, ""},
		{"page-head", "HEAD", "/?tenant=bank-a", nil, ""},
		{"css", "GET", "/static/fleet.css", nil, ""},
		{"css-head", "HEAD", "/static/fleet.css", nil, ""},
		{"no-tenant", "GET", "/", nil, ""},
		{"bad-tenant", "GET", "/?tenant=%3Cscript%3E", nil, ""},
		{"unknown-tenant", "GET", "/?tenant=nobody", nil, ""},
		{"404-path", "GET", "/nope", nil, ""},
		{"404-static", "GET", "/static/nope.css", nil, ""},
		{"404-dir", "GET", "/static/", nil, ""},
		{"post-page", "POST", "/?tenant=bank-a", nil, "x=1"},
		{"put-page", "PUT", "/?tenant=bank-a", nil, "x"},
		{"delete-page", "DELETE", "/?tenant=bank-a", nil, ""},
		{"options-page", "OPTIONS", "/?tenant=bank-a", nil, ""},
		{"patch-css", "PATCH", "/static/fleet.css", nil, ""},
		{"post-404", "POST", "/nope", nil, ""},
		{"huge-lang", "GET", "/?tenant=bank-a&lang=" + strings.Repeat("x", 100000), nil, ""},
		{"accept-lang", "GET", "/?tenant=bank-a", map[string]string{"Accept-Language": "fr-CH, fr;q=0.9"}, ""},
	}
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			r := do(t, h, x.method, x.target, x.hdr, x.body)
			cspOK(t, x.name, r)
			if r.code >= 500 {
				t.Errorf("%s: server error %d", x.name, r.code)
			}
			if r.hdr.Get("Content-Type") == "" {
				t.Errorf("%s: no Content-Type (sniffing risk)", x.name)
			}
		})
	}
	f.fleetErr = errBoom
	r := get(t, h, "/?tenant=bank-a")
	cspOK(t, "500-page", r)
	f.fleetErr = nil
	f.rollErr = errBoom
	r = get(t, h, "/?tenant=bank-a")
	cspOK(t, "500-rollout", r)
}

func TestMethodsOtherThanGetHeadAreWire405(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, target := range []string{"/?tenant=bank-a", "/static/fleet.css", "/", "/nope"} {
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND", "get", "BREW"} {
			r := do(t, h, m, target, nil, `{"tenant":"bank-a"}`)
			if r.code != http.StatusMethodNotAllowed {
				// an unknown path may answer 404 first, but never 2xx and never execute anything
				if r.code/100 == 2 || r.code >= 500 {
					t.Errorf("%s %s: status %d", m, target, r.code)
				}
				if target != "/nope" {
					t.Errorf("%s %s: status %d, want 405", m, target, r.code)
				}
				continue
			}
			var er wire.ErrorResponse
			if err := json.Unmarshal([]byte(r.body), &er); err != nil || er.Code != wire.ErrMethodNotAllowed {
				t.Errorf("%s %s: body %q is not the wire method_not_allowed JSON (%v)", m, target, r.body, err)
			}
			if ct := r.hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("%s %s: 405 Content-Type %q", m, target, ct)
			}
			allow := strings.ToUpper(r.hdr.Get("Allow"))
			if !strings.Contains(allow, "GET") || !strings.Contains(allow, "HEAD") || strings.Contains(allow, "POST") {
				t.Errorf("%s %s: Allow = %q", m, target, allow)
			}
		}
	}
}

func TestHeadHasNoBodyAndSameHeaders(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, target := range []string{"/?tenant=bank-a", "/static/fleet.css", "/?tenant=nope-x", "/"} {
		g := get(t, h, target)
		hd := do(t, h, "HEAD", target, nil, "")
		if hd.body != "" {
			t.Errorf("HEAD %s: %d body bytes", target, len(hd.body))
		}
		if hd.code != g.code {
			t.Errorf("HEAD %s: %d vs GET %d", target, hd.code, g.code)
		}
		if hd.hdr.Get("Content-Security-Policy") != g.hdr.Get("Content-Security-Policy") {
			t.Errorf("HEAD %s: CSP differs from GET", target)
		}
	}
}

func TestPathsAndEmbeddedFilesNotExposed(t *testing.T) {
	h, _ := newHandler(seeded())
	paths := []string{
		"/static", "/static/", "/static/..", "/static/../", "/static/../fleet.html", "/static/%2e%2e/fleet.html", "/static/fleet.css/", "/static/fleet.css/x",
		"/static//fleet.css", "/static/fleet.CSS", "/static/fleet.css%00", "/static/fleet.css%00.html", "/static/fleet.css?x=1#y", "/index.html", "/fleet.html", "/templates/", "/templates/fleet.html",
		"/fleet.tmpl", "/static/fleet.html", "/static/fleet.tmpl", "/static/fleet.css.map", "/..", "/../", "//", "///", "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd",
		"/static/..\\fleet.html", "/.git/config", "/go.mod", "/web.go", "/embed", "/favicon.ico", "/robots.txt", "/metrics", "/v1/fleet", "/v1/policies", "/healthz",
		"/static/%2e%2e%2f", "/%00", "/?tenant=bank-a/../city-b", "/static/fleet.css/..;/",
	}
	for _, p := range paths {
		r := do(t, h, "GET", p, nil, "")
		cspOK(t, p, r)
		if strings.Contains(r.body, "{{") || strings.Contains(r.body, "{{end}}") || strings.Contains(r.body, "package ") || strings.Contains(r.body, "{{template") {
			t.Errorf("GET %s leaks template or source text: %.200s", p, r.body)
		}
		if r.code >= 500 {
			t.Errorf("GET %s: status %d", p, r.code)
		}
		// a directory listing is a leak too
		if strings.Contains(r.body, "<pre>") || strings.Contains(r.body, "Index of") {
			t.Errorf("GET %s returned a directory listing", p)
		}
		isCSS := p == "/static/fleet.css" || p == "/static/fleet.css?x=1#y"
		if r.code == 200 && !isCSS && !strings.HasPrefix(p, "/?") && p != "/" {
			// 200 is only OK for the real stylesheet (and for the page itself, which needs a tenant)
			if p != "/static//fleet.css" && p != "/static/fleet.css/" && p != "//" && p != "///" {
				t.Errorf("GET %s: unexpected 200 (%d bytes)", p, len(r.body))
			}
		}
	}
	// the real stylesheet, plain and with a query
	for _, p := range []string{"/static/fleet.css", "/static/fleet.css?v=2"} {
		if r := get(t, h, p); r.code != 200 || len(r.body) < 10 {
			t.Errorf("GET %s = %d (%d bytes)", p, r.code, len(r.body))
		}
	}
	// missing page paths name the wire code (C-D5)
	if r := get(t, h, "/nope"); r.code != 404 || !strings.Contains(r.body, string(wire.ErrNotFound)) {
		t.Errorf("/nope = %d %.200s, want 404 naming %q", r.code, r.body, wire.ErrNotFound)
	}
}

// J7: errors readable in both languages; the wire code is named; the input is never echoed raw.
func TestTenantParameterAbuse(t *testing.T) {
	f := seeded()
	h, _ := newHandler(f)
	bad := []string{
		"", "%3Cscript%3Ealert(1)%3C/script%3E", "BANK-A", "bank-a%20", "bank-a%0A", "bank-a%00", "..", "..%2F..%2Fetc", "bank-a/..", "bank-a%2F",
		"-bank", "bank_a", strings.Repeat("a", 64), strings.Repeat("a", 100000), "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "%E3%83%86%E3%83%8A%E3%83%B3%E3%83%88",
		"bank-a%26tenant%3Dcity-b", "bank-a;city-b", "bank-a,city-b", "%FF%FE", "*", "%25", "%2e", "a%u0041",
	}
	for _, tv := range bad {
		for _, lang := range []string{"ja", "en"} {
			target := "/?tenant=" + tv + "&lang=" + lang
			r := get(t, h, target)
			label := fmt.Sprintf("tenant=%.40q lang=%s", tv, lang)
			cspOK(t, label, r)
			if r.code != 400 && r.code != 404 {
				t.Errorf("%s: status %d, want 400/404 for an invalid tenant", label, r.code)
				continue
			}
			code := string(wire.ErrBadRequest)
			if r.code == 404 {
				code = string(wire.ErrNotFound)
			}
			if !strings.Contains(r.body, code) {
				t.Errorf("%s: error page does not name the wire code %q: %.200s", label, code, r.body)
			}
			if len(r.body) > 4096 {
				t.Errorf("%s: error page is %d bytes (input echoed?)", label, len(r.body))
			}
			for _, raw := range []string{"<script", "<img", "onerror"} {
				if strings.Contains(strings.ToLower(r.body), raw) {
					t.Errorf("%s: raw %q in error page", label, raw)
				}
			}
			if strings.Contains(r.body, "city-proxy") || strings.Contains(r.body, "main-ok") {
				t.Errorf("%s: data of a tenant shown for an invalid tenant parameter", label)
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, tn := range f.tenants {
		if !tn.Valid() {
			t.Errorf("the page passed an invalid tenant %q to the store", tn)
		}
	}
}

func TestTenantParameterRepeatedOrMixed(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, target := range []string{
		"/?tenant=bank-a&tenant=city-b", "/?tenant=city-b&tenant=bank-a", "/?tenant=bank-a&tenant=", "/?tenant=&tenant=bank-a",
		"/?TENANT=bank-a", "/?tenant[]=bank-a", "/?tenant=bank-a&tenant=bank-a",
	} {
		r := get(t, h, target)
		cspOK(t, target, r)
		if r.code >= 500 {
			t.Errorf("%s: %d", target, r.code)
		}
		if r.code == 200 && strings.Contains(r.body, "city-proxy") && strings.Contains(r.body, "main-ok") {
			t.Errorf("%s: rows of two tenants on one page", target)
		}
	}
}

func TestUnknownValidTenantIsNotAnError500(t *testing.T) {
	h, _ := newHandler(seeded())
	r := get(t, h, "/?tenant=nobody")
	if r.code != 200 && r.code != 404 {
		t.Fatalf("status %d", r.code)
	}
	if strings.Contains(r.body, "main-ok") || strings.Contains(r.body, "city-proxy") {
		t.Fatal("rows from other tenants")
	}
}

func lang(t *testing.T, r resp) string {
	t.Helper()
	m := reHTMLLang.FindStringSubmatch(r.body)
	if len(m) != 2 {
		t.Fatalf("no <html lang> in %.200s", r.body)
	}
	return m[1]
}

// C-D5: ?lang wins; then Accept-Language; default ja.
func TestLanguageNegotiation(t *testing.T) {
	h, _ := newHandler(seeded())
	cases := []struct {
		name, query string
		accept      string
		want        string
	}{
		{"default", "", "", "ja"},
		{"query-en", "&lang=en", "", "en"},
		{"query-ja", "&lang=ja", "", "ja"},
		{"query-beats-header-1", "&lang=ja", "en", "ja"},
		{"query-beats-header-2", "&lang=en", "ja", "en"},
		{"header-en", "", "en", "en"},
		{"header-en-US", "", "en-US,en;q=0.9", "en"},
		{"header-ja-JP", "", "ja-JP,ja;q=0.9,en;q=0.8", "ja"},
		{"header-q-order", "", "ja;q=0.1,en;q=0.9", "en"},
		{"header-q-order-2", "", "fr;q=1.0,en;q=0.5,ja;q=0.2", "en"},
		{"header-unknown", "", "fr-CH, fr;q=0.9", "ja"},
		{"header-wildcard", "", "*", "ja"},
		{"header-garbage", "", ";;;,,,q=q", "ja"},
		{"header-case", "", "EN-us", "en"},
		{"header-en-refused", "", "en;q=0, ja", "ja"},
		{"query-unknown-falls-back", "&lang=fr", "", "ja"},
		{"query-unknown-then-header", "&lang=fr", "en", "en"},
		{"query-empty-uses-header", "&lang=", "en", "en"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r resp
			if c.accept == "" {
				r = get(t, h, "/?tenant=bank-a"+c.query)
			} else {
				r = get(t, h, "/?tenant=bank-a"+c.query, "Accept-Language", c.accept)
			}
			if r.code == 400 && strings.Contains(c.name, "unknown") {
				return // refusing an unknown ?lang is also defensible
			}
			if r.code != 200 {
				t.Fatalf("status %d", r.code)
			}
			if got := lang(t, r); !strings.HasPrefix(got, c.want) {
				t.Fatalf("lang = %q, want %q", got, c.want)
			}
			if got := lang(t, r); got != "ja" && got != "en" {
				t.Fatalf("<html lang=%q> is neither ja nor en", got)
			}
		})
	}
}

func TestLanguageAbuseIsCheapAndHarmless(t *testing.T) {
	h, _ := newHandler(seeded())
	long := strings.Repeat("en;q=0.001,", 100000) // ~1.1 MB header
	many := strings.Repeat("x-"+strings.Repeat("a", 8)+",", 20000)
	weird := []string{
		long, many, strings.Repeat(",", 1<<20), strings.Repeat(";q=", 100000), "en;q=1e999", "en;q=-1", "en;q=NaN", "en;q=0.0000000000000000000001", "en;q=" + strings.Repeat("9", 100000),
		"en\x00ja", "\xff\xfe", "ja, en, " + strings.Repeat("a", 100000), "<script>alert(1)</script>", "en;q=1;q=0", "en;x=" + strings.Repeat("\"", 1000), "*;q=0", "en,ja,en,ja;q=" + strconv.Itoa(1<<30),
	}
	for i, a := range weird {
		start := time.Now()
		r := get(t, h, "/?tenant=bank-a", "Accept-Language", a)
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("case %d: %v for one request (algorithmic blow-up in language parsing)", i, d)
		}
		if r.code != 200 {
			t.Errorf("case %d: status %d", i, r.code)
			continue
		}
		cspOK(t, fmt.Sprint("lang-abuse-", i), r)
		if l := lang(t, r); l != "ja" && l != "en" {
			t.Errorf("case %d: lang %q", i, l)
		}
		if strings.Contains(strings.ToLower(r.body), "<script") {
			t.Errorf("case %d: Accept-Language reached the page raw", i)
		}
	}
	for _, q := range []string{strings.Repeat("a", 1<<20), "%00", "<script>", "ja%0d%0aSet-Cookie:x=1", "ja\r\nX: y"} {
		r := get(t, h, "/?tenant=bank-a&lang="+url.QueryEscape(q))
		if r.code >= 500 {
			t.Errorf("lang=%.20q: %d", q, r.code)
		}
		if len(r.hdr.Values("Set-Cookie")) != 0 {
			t.Errorf("response splitting through lang: %v", r.hdr)
		}
		if strings.Contains(r.body, "Set-Cookie") {
			t.Errorf("lang value echoed")
		}
	}
}

var xssPayloads = []string{
	`<script>alert(1)</script>`,
	`"><img src=x onerror=alert(1)>`,
	`' onmouseover='alert(1)`,
	`" autofocus onfocus="alert(1)`,
	`javascript:alert(1)`,
	`</td></tr></table><script>alert(1)</script>`,
	`</title><script>alert(1)</script>`,
	`<style>body{display:none}</style>`,
	`<svg/onload=alert(1)>`,
	`<a href="javascript:alert(1)">x</a>`,
	`&lt;script&gt;alert(1)&lt;/script&gt;`,
	`{{.}}{{template "x"}}{{range .}}`,
	`<!--`,
	`-->`,
	" <script> ",
	"a\x00b<script>",
	`<iframe src=//evil.example></iframe>`,
	`<meta http-equiv="refresh" content="0;url=http://evil.example">`,
	`<base href="//evil.example/">`,
	"%3Cscript%3E",
	`<math><mi xlink:href="data:x,<script>alert(1)</script>">`,
	`</textarea><script>`,
	`<link rel=stylesheet href=//evil.example/x.css>`,
}

// "Every value goes through html/template's contextual escaping, even IDs that were validated elsewhere."
func TestXSSThroughEveryStoredField(t *testing.T) {
	// the baseline defines the tags and attributes the page is allowed to contain
	baseF := seeded()
	baseH, _ := newHandler(baseF)
	wantTags, wantAttrs, wantTokens := map[string]bool{}, map[string]bool{}, map[string]bool{}
	wantURLs := map[string]bool{}
	for _, l := range []string{"ja", "en"} {
		r := get(t, baseH, "/?tenant=bank-a&lang="+l)
		for k := range tagSet(r.body) {
			wantTags[k] = true
		}
		for k := range attrSet(r.body) {
			wantAttrs[k] = true
		}
		for k := range attrTokens(r.body) {
			wantTokens[k] = true
		}
		for _, m := range reURLAttr.FindAllStringSubmatch(r.body, -1) {
			wantURLs[m[1]] = true
		}
	}
	fields := []struct {
		name string
		set  func(f *fakeStore, v string)
	}{
		{"proxy-id", func(f *fakeStore, v string) {
			f.fleet["bank-a"][1].Report.ProxyID = wire.ID(v)
		}},
		{"group", func(f *fakeStore, v string) { f.fleet["bank-a"][1].Group = wire.ID(v) }},
		{"state", func(f *fakeStore, v string) { f.fleet["bank-a"][1].Report.State = wire.ProxyState(v) }},
		{"policy-hash", func(f *fakeStore, v string) { f.fleet["bank-a"][1].Report.PolicyHash = wire.Hash(v) }},
		{"log-head", func(f *fakeStore, v string) { f.fleet["bank-a"][1].Report.LogHead = wire.Hash(v) }},
		{"report-tenant", func(f *fakeStore, v string) { f.fleet["bank-a"][1].Report.Tenant = wire.ID(v) }},
		{"last-error-code", func(f *fakeStore, v string) {
			f.fleet["bank-a"][1].Report.LastError = &wire.ApplyError{Code: wire.ErrorCode(v), Version: 4242}
		}},
		{"rollout-phase", func(f *fakeStore, v string) {
			r := f.roll["bank-a"]
			r.Phase = wire.RolloutPhase(v)
			f.roll["bank-a"] = r
		}},
		{"rollout-reason", func(f *fakeStore, v string) {
			r := f.roll["bank-a"]
			r.Phase, r.Reason = wire.PhaseHalted, wire.ErrorCode(v)
			f.roll["bank-a"] = r
		}},
		{"rollout-tenant", func(f *fakeStore, v string) {
			r := f.roll["bank-a"]
			r.Tenant = wire.ID(v)
			f.roll["bank-a"] = r
		}},
	}
	for _, fld := range fields {
		for pi, payload := range xssPayloads {
			f := seeded()
			fld.set(f, payload)
			h, _ := newHandler(f)
			for _, l := range []string{"ja", "en"} {
				r := get(t, h, "/?tenant=bank-a&lang="+l)
				name := fmt.Sprintf("%s/payload%d/%s", fld.name, pi, l)
				cspOK(t, name, r)
				if r.code != 200 && r.code >= 500 {
					// a 5xx on hostile data is not an XSS but is a robustness failure
					t.Errorf("%s: status %d", name, r.code)
					continue
				}
				if extra := subset(tagSet(r.body), wantTags); len(extra) > 0 {
					t.Errorf("%s: injected tags %v", name, extra)
				}
				if extra := subset(attrSet(r.body), wantAttrs); len(extra) > 0 {
					t.Errorf("%s: injected attributes %v", name, extra)
				}
				if extra := subset(attrTokens(r.body), wantTokens); len(extra) > 0 {
					t.Errorf("%s: injected attribute tokens %v", name, extra)
				}
				for _, m := range reURLAttr.FindAllStringSubmatch(r.body, -1) {
					if !wantURLs[m[1]] {
						t.Errorf("%s: new URL attribute value %q", name, m[1])
					}
				}
				low := strings.ToLower(r.body)
				for _, raw := range []string{"<script", "<iframe", "<img", "<svg"} {
					if strings.Contains(low, raw) {
						t.Errorf("%s: contains raw %q", name, raw)
					}
				}
			}
		}
	}
}

func TestLongAndOddValuesDoNotBreakRendering(t *testing.T) {
	f := seeded()
	e := f.fleet["bank-a"]
	e[1].Report.ProxyID = wire.ID(strings.Repeat("a", 2<<20))
	e[2].Report.AppliedVersion = ^uint64(0)
	e[2].Report.Seq = ^uint64(0)
	e[2].Report.UptimeSeconds = ^uint64(0)
	e[2].Report.Counters = wire.Counters{CallsAllowed: ^uint64(0), CallsDenied: ^uint64(0), EnvelopesRejected: ^uint64(0)}
	e[3].SeenAt = time.Time{}
	e[4].SeenAt = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	e[5].SeenAt = time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
	e[0].SeenAt = now0.Add(24 * time.Hour) // clock skew: seen in the future
	f.fleet["bank-a"] = e
	f.roll["bank-a"] = rollout.Rollout{Tenant: "bank-a", Version: ^uint64(0), Previous: ^uint64(0) - 1, Phase: wire.PhasePromoting, Dwell: 1<<63 - 1}
	h, _ := newHandler(f)
	for _, l := range []string{"ja", "en"} {
		r := get(t, h, "/?tenant=bank-a&lang="+l)
		if r.code != 200 {
			t.Fatalf("%s: status %d", l, r.code)
		}
		if strings.Contains(r.body, "%!") || strings.Contains(r.body, "<no value>") || strings.Contains(r.body, "NaN") || strings.Contains(r.body, "-9223372036854775808") {
			t.Errorf("%s: formatting artefact in page", l)
		}
	}
}

// ---- I4 and 500s ----

func TestPageNeverShowsPolicyPayloadOrErrorText(t *testing.T) {
	f := seeded()
	h, _ := newHandler(f)
	for _, l := range []string{"ja", "en"} {
		r := get(t, h, "/?tenant=bank-a&lang="+l)
		if strings.Contains(r.body, canary) {
			t.Fatalf("%s: the stored policy payload reached the page (metadata only)", l)
		}
	}
}

func TestStoreErrorsGive500WithoutLeaks(t *testing.T) {
	for name, set := range map[string]func(f *fakeStore){
		"fleet-error":   func(f *fakeStore) { f.fleetErr = errBoom },
		"rollout-error": func(f *fakeStore) { f.rollErr = errBoom },
		"both":          func(f *fakeStore) { f.fleetErr, f.rollErr = errBoom, errBoom },
	} {
		for _, l := range []string{"ja", "en"} {
			t.Run(name+"/"+l, func(t *testing.T) {
				f := seeded()
				set(f)
				h, _ := newHandler(f)
				r := get(t, h, "/?tenant=bank-a&lang="+l)
				if r.code != 500 {
					t.Fatalf("status %d, want 500 when the store fails", r.code)
				}
				for _, leak := range []string{canary, "boom", "/var/lib", "permission denied", ".json", "goroutine", "runtime error", "panic", ".go:"} {
					if strings.Contains(r.body, leak) {
						t.Errorf("500 page leaks %q: %.300s", leak, r.body)
					}
					for k, v := range r.hdr {
						if strings.Contains(strings.Join(v, ","), leak) {
							t.Errorf("500 header %s leaks %q", k, leak)
						}
					}
				}
				if !strings.Contains(r.body, string(wire.ErrInternal)) {
					t.Errorf("500 page does not name the wire code %q: %.200s", wire.ErrInternal, r.body)
				}
				if len(r.body) > 4096 {
					t.Errorf("500 page is %d bytes", len(r.body))
				}
				// the page after the failure has recovered: no cached error
				f.fleetErr, f.rollErr = nil, nil
				if r2 := get(t, h, "/?tenant=bank-a&lang="+l); r2.code != 200 {
					t.Errorf("after the store recovered: %d", r2.code)
				}
			})
		}
	}
}

// ---- both languages complete ----

func textNodes(body string) []string {
	s := regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>|<!--.*?-->`).ReplaceAllString(body, " ")
	parts := reTagFull.Split(s, -1)
	var out []string
	for _, p := range parts {
		p = strings.Join(strings.Fields(unesc(p)), " ")
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func unesc(s string) string {
	r := strings.NewReplacer("&amp;", "&", "&lt;", "<", "&gt;", ">", "&#34;", `"`, "&#39;", "'", "&quot;", `"`)
	return r.Replace(s)
}

func TestBothLanguagesAreComplete(t *testing.T) {
	// One page per (state, health, last error) so every label that can appear does appear.
	f := newFake()
	var ps []fleet.Last
	states := []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode}
	ages := []time.Duration{time.Second, 45 * time.Second, 10 * time.Minute}
	codes := []wire.ErrorCode{
		wire.ErrBadRequest, wire.ErrUnauthorized, wire.ErrForbidden, wire.ErrNotFound, wire.ErrMethodNotAllowed, wire.ErrConflict, wire.ErrTooLarge, wire.ErrInternal, wire.ErrUnavailable,
		wire.ErrMalformed, wire.ErrPayloadType, wire.ErrThreshold, wire.ErrWrongTenant, wire.ErrNotNewer, wire.ErrExpired, wire.ErrPersist, wire.ErrTampered, wire.ErrCanaryLost, wire.ErrClockUntrusted,
	}
	i := 0
	for _, st := range states {
		for _, age := range ages {
			applied := uint64(0)
			if st == wire.StateEnforcing || st == wire.StateSafeMode {
				applied = 7
			}
			l := lastOf("bank-a", wire.ID(fmt.Sprintf("px-%02d", i)), "main", st, applied, now0.Add(-age))
			if i < len(codes) {
				l.Report.LastError = &wire.ApplyError{Code: codes[i], Version: 8}
			}
			ps = append(ps, l)
			i++
		}
	}
	for j, c := range codes {
		l := lastOf("bank-a", wire.ID(fmt.Sprintf("er-%02d", j)), "canary", wire.StateEnforcing, 7, now0.Add(-time.Second))
		l.Report.LastError = &wire.ApplyError{Code: c, Version: 8}
		ps = append(ps, l)
	}
	f.fleet["bank-a"] = ps
	h, _ := newHandler(f)

	phases := []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete}
	for _, ph := range phases {
		r := rollout.Rollout{Tenant: "bank-a", Version: 8, Previous: 7, Phase: ph, Dwell: time.Minute}
		if ph == wire.PhaseHalted {
			r.Reason = wire.ErrCanaryLost
		}
		f.roll["bank-a"] = r

		en := get(t, h, "/?tenant=bank-a&lang=en")
		ja := get(t, h, "/?tenant=bank-a&lang=ja")
		if en.code != 200 || ja.code != 200 {
			t.Fatalf("%s: en %d ja %d", ph, en.code, ja.code)
		}
		for name, body := range map[string]string{"en": en.body, "ja": ja.body} {
			for _, art := range []string{"{{", "}}", "%!", "<no value>", "<nil>", "MISSING", "TODO", "undefined", "???"} {
				if strings.Contains(body, art) {
					t.Errorf("%s/%s: template artefact %q", ph, name, art)
				}
			}
		}
		// English page: no Japanese text outside the language switch link.
		noLinks := regexp.MustCompile(`(?s)<a\b.*?</a>`).ReplaceAllString(en.body, " ")
		if n := countCJK(visibleText(noLinks)); n > 0 {
			t.Errorf("%s: English page contains %d Japanese characters outside the language switch: %.200s", ph, n, firstCJK(visibleText(noLinks)))
		}
		// Japanese page: must really be Japanese.
		if n := countCJK(visibleText(ja.body)); n < 20 {
			t.Errorf("%s: Japanese page has only %d Japanese characters", ph, n)
		}
		// Same structure: the languages differ in words, not in rows.
		if a, b := strings.Count(en.body, "<tr"), strings.Count(ja.body, "<tr"); a != b {
			t.Errorf("%s: %d rows in en vs %d in ja", ph, a, b)
		}
		// Untranslated UI strings: a text node identical in both languages, with 4+ Latin letters,
		// that is not data, means one language is missing a label.
		data := []string{"px-", "er-", "bank-a", "canary", "main", "kairan", "UTC", "JST"}
		for _, c := range codes {
			data = append(data, string(c))
		}
		for _, s := range states {
			data = append(data, string(s))
		}
		for _, p := range phases {
			data = append(data, string(p))
		}
		data = append(data, "healthy", "stale", "lost", "enforcing", "tampered", "booting", "safe_mode", "deny_all")
		enNodes, jaNodes := textNodes(en.body), textNodes(ja.body)
		jaSet := map[string]bool{}
		for _, n := range jaNodes {
			jaSet[n] = true
		}
		latin := regexp.MustCompile(`[A-Za-z]{4,}`)
		for _, n := range enNodes {
			if !jaSet[n] || !latin.MatchString(n) || regexp.MustCompile(`^[0-9a-f .…-]+$`).MatchString(n) {
				continue
			}
			isData := false
			for _, d := range data {
				if strings.Contains(n, d) {
					isData = true
				}
			}
			if !isData && !regexp.MustCompile(`^[\sA-Za-z0-9:./+_()-]*$`).MatchString(strings.ReplaceAll(n, "Kairan", "")) {
				continue
			}
			if !isData {
				t.Errorf("%s: text %q is identical in en and ja: untranslated label?", ph, n)
			}
		}
	}
}

func firstCJK(s string) string {
	for i, r := range s {
		if isCJK(r) {
			end := i + 60
			if end > len(s) {
				end = len(s)
			}
			return s[i:end]
		}
	}
	return ""
}

// The error pages are bilingual too (J7: errors readable in both languages).
func TestErrorPagesAreLocalized(t *testing.T) {
	h, _ := newHandler(seeded())
	for _, tc := range []struct {
		target string
		code   int
	}{{"/", 400}, {"/?tenant=BAD", 400}, {"/nope", 404}} {
		en := get(t, h, tc.target+sep(tc.target)+"lang=en")
		ja := get(t, h, tc.target+sep(tc.target)+"lang=ja")
		if en.code != tc.code || ja.code != tc.code {
			t.Fatalf("%s: en %d ja %d, want %d", tc.target, en.code, ja.code, tc.code)
		}
		enNoLink := regexp.MustCompile(`(?s)<a\b.*?</a>`).ReplaceAllString(en.body, " ")
		if n := countCJK(visibleText(enNoLink)); n > 0 {
			t.Errorf("%s: English error page has Japanese text outside the language switch", tc.target)
		}
		if n := countCJK(visibleText(ja.body)); n < 3 {
			t.Errorf("%s: Japanese error page has no Japanese text: %.200s", tc.target, visibleText(ja.body))
		}
		if reHTMLLang.FindStringSubmatch(en.body) == nil || !strings.HasPrefix(reHTMLLang.FindStringSubmatch(en.body)[1], "en") {
			t.Errorf("%s: English error page lacks <html lang=en>", tc.target)
		}
		cspOK(t, tc.target, ja)
	}
}

func sep(t string) string {
	if strings.Contains(t, "?") {
		return "&"
	}
	return "?"
}

// ---- JST and UTC ----

func TestTimesShownInJSTAndUTC(t *testing.T) {
	f := newFake()
	seen := time.Date(2026, 12, 31, 15, 30, 45, 0, time.UTC) // 2027-01-01 00:30:45 JST
	f.fleet["bank-a"] = []fleet.Last{lastOf("bank-a", "p1", "main", wire.StateEnforcing, 7, seen)}
	h, clk := newHandler(f)
	clk.Set(seen.Add(5 * time.Second))
	// a host zone that is neither must not leak into the page
	old := time.Local
	time.Local = time.FixedZone("PST", -8*3600)
	defer func() { time.Local = old }()
	for _, l := range []string{"ja", "en"} {
		r := get(t, h, "/?tenant=bank-a&lang="+l)
		txt := visibleText(r.body)
		if !strings.Contains(txt, "15:30:45") {
			t.Errorf("%s: UTC time 15:30:45 not on the page: %.400s", l, txt)
		}
		if !strings.Contains(txt, "00:30:45") {
			t.Errorf("%s: JST time 00:30:45 (next day) not on the page", l)
		}
		if !strings.Contains(txt, "JST") || !strings.Contains(txt, "UTC") {
			t.Errorf("%s: JST/UTC labels missing", l)
		}
		if strings.Contains(txt, "07:30:45") || strings.Contains(txt, "PST") {
			t.Errorf("%s: the host's local zone leaked into the page", l)
		}
		if !strings.Contains(txt, "2027") || !strings.Contains(txt, "2026") {
			t.Errorf("%s: dates for both sides of the year boundary expected", l)
		}
	}
}

// ---- desired version, sorting ----

func TestDesiredVersionComesFromDesiredFor(t *testing.T) {
	for _, tc := range []struct {
		name       string
		r          rollout.Rollout
		mainShows  bool // does "main-ok" show desired 4242?
		canaryOnly bool
	}{
		{"canary-phase", rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseCanary}, false, true},
		{"promoting", rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhasePromoting}, true, false},
		{"complete", rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseComplete}, true, false},
		{"halted-in-canary", rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseHalted, Reason: wire.ErrCanaryLost}, false, true},
		{"halted-after-promoting (M-D44)", rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseHalted, Reason: wire.ErrThreshold, Promoted: true}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.roll["bank-a"] = tc.r
			f.fleet["bank-a"] = []fleet.Last{
				lastOf("bank-a", "main-ok", "main", wire.StateEnforcing, 41, now0.Add(-time.Second)),
				lastOf("bank-a", "canary-1", "canary", wire.StateEnforcing, 41, now0.Add(-time.Second)),
			}
			h, _ := newHandler(f)
			r := get(t, h, "/?tenant=bank-a&lang=en")
			if r.code != 200 {
				t.Fatalf("status %d", r.code)
			}
			mainRow, canaryRow := rowFor(r.body, "main-ok"), rowFor(r.body, "canary-1")
			if mainRow == "" || canaryRow == "" {
				t.Fatalf("rows not found (main %v canary %v)", mainRow != "", canaryRow != "")
			}
			if has := strings.Contains(visibleText(mainRow), "4242"); has != tc.mainShows {
				t.Errorf("main row shows desired 4242 = %v, want %v (DesiredFor(%s, main) = %d): %s", has, tc.mainShows, tc.name, rollout.DesiredFor(tc.r, "main"), visibleText(mainRow))
			}
			if !strings.Contains(visibleText(canaryRow), "4242") {
				t.Errorf("canary row does not show desired 4242: %s", visibleText(canaryRow))
			}
		})
	}
}

func TestRowsFollowFleetViewOrder(t *testing.T) {
	f := seeded()
	h, _ := newHandler(f)
	r := get(t, h, "/?tenant=bank-a&lang=en")
	desired := map[wire.ID]uint64{}
	for _, g := range []wire.ID{"canary", "main"} {
		desired[g] = rollout.DesiredFor(f.roll["bank-a"], g)
	}
	view := fleet.View("bank-a", desired, f.fleet["bank-a"], now0, fleet.Thresholds{Stale: 30 * time.Second, Lost: 2 * time.Minute})
	last := -1
	for _, p := range view.Proxies {
		idx := strings.Index(r.body, ">"+string(p.ProxyID)+"<")
		if idx < 0 {
			idx = strings.Index(r.body, string(p.ProxyID))
		}
		if idx < 0 {
			t.Fatalf("%s not on the page", p.ProxyID)
		}
		if idx < last {
			t.Fatalf("page order differs from fleet.View order (drift desc, then health, then ID): %s appears too early", p.ProxyID)
		}
		last = idx
	}
}

// ---- volume and concurrency ----

func TestLargeFleetRendersInReasonableTime(t *testing.T) {
	f := newFake()
	var ps []fleet.Last
	for i := 0; i < 5000; i++ {
		ps = append(ps, lastOf("bank-a", wire.ID(fmt.Sprintf("p%05d", i)), "main", wire.StateEnforcing, 7, now0.Add(-time.Duration(i%200)*time.Second)))
	}
	f.fleet["bank-a"] = ps
	h, _ := newHandler(f)
	start := time.Now()
	r := get(t, h, "/?tenant=bank-a&lang=ja")
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("5000 rows took %v", d)
	}
	if !strings.Contains(r.body, "p04999") {
		t.Fatal("rows dropped silently")
	}
	if len(r.body) > 32<<20 {
		t.Fatalf("page is %d bytes", len(r.body))
	}
}

func TestConcurrentRequestsAreRaceFree(t *testing.T) {
	f := seeded()
	h, clk := newHandler(f)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				l := []string{"ja", "en"}[(i+j)%2]
				r := get(t, h, "/?tenant="+[]string{"bank-a", "city-b", "nobody", "BAD"}[(i+j)%4]+"&lang="+l)
				if r.code >= 500 {
					t.Errorf("status %d", r.code)
					return
				}
				if j%5 == 0 {
					clk.Advance(time.Second)
				}
				if j%7 == 0 {
					clk.Set(now0.Add(-time.Hour))
				}
			}
		}(i)
	}
	wg.Wait()
}

func FuzzPageInputs(f *testing.F) {
	f.Add("bank-a", "en", "en-US,en;q=0.9")
	f.Add("", "", "")
	f.Add("<script>", "\x00", ";;;")
	f.Add(strings.Repeat("a", 70), "ja", strings.Repeat("en,", 5000))
	st := seeded()
	h, _ := newHandler(st)
	f.Fuzz(func(t *testing.T, tenant, langQ, accept string) {
		target := "/?tenant=" + url.QueryEscape(tenant) + "&lang=" + url.QueryEscape(langQ)
		req, err := http.NewRequest("GET", "http://x"+target, nil)
		if err != nil {
			return
		}
		req.Header.Set("Accept-Language", accept)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code >= 500 {
			t.Fatalf("status %d for tenant=%q lang=%q accept=%q", rec.Code, tenant, langQ, accept)
		}
		if rec.Header().Get("Content-Security-Policy") == "" {
			t.Fatalf("no CSP for tenant=%q", tenant)
		}
		if strings.Contains(strings.ToLower(rec.Body.String()), "<script") {
			t.Fatalf("script tag for tenant=%q lang=%q", tenant, langQ)
		}
	})
}
