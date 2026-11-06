package web

import (
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

var update = flag.Bool("update", false, "rewrite golden files")

// now is 12:00 JST = 03:00 UTC.
var now = time.Date(2026, 11, 5, 3, 0, 0, 0, time.UTC)

func hash(c byte) wire.Hash { return wire.Hash(strings.Repeat(string(c), 64)) }

func seen(t *testing.T, st store.Store, group, proxy wire.ID, ago time.Duration, mod func(*wire.StatusReport)) {
	t.Helper()
	r := wire.StatusReport{
		Tenant: "bank-a", ProxyID: proxy, Seq: 1, State: wire.StateEnforcing,
		AppliedVersion: 7, PolicyHash: hash('a'), UptimeSeconds: 100,
	}
	if mod != nil {
		mod(&r)
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("test report: %v", err)
	}
	if err := st.RecordStatus(fleet.Last{Group: group, Report: r, SeenAt: now.Add(-ago)}); err != nil {
		t.Fatal(err)
	}
}

// smallFleet: a healthy canary on v8 (desired 8); main wants v7: main-1 is stale
// on v6, main-2 is lost and tampered, main-3 is in safe mode reporting an
// untrusted clock.
func smallFleet(t *testing.T) store.Store {
	t.Helper()
	st, err := store.OpenFiles(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	seen(t, st, "canary", "px-canary-1", 5*time.Second, func(r *wire.StatusReport) {
		r.AppliedVersion, r.PolicyHash = 8, hash('b')
	})
	seen(t, st, "main", "px-main-1", 45*time.Second, func(r *wire.StatusReport) {
		r.AppliedVersion, r.PolicyHash = 6, hash('c')
	})
	seen(t, st, "main", "px-main-2", 2*time.Hour, func(r *wire.StatusReport) {
		r.State, r.AppliedVersion, r.PolicyHash = wire.StateTampered, 0, ""
		r.LastError = &wire.ApplyError{Code: wire.ErrTampered}
	})
	seen(t, st, "main", "px-main-3", 3*time.Second, func(r *wire.StatusReport) {
		r.State = wire.StateSafeMode
		r.LastError = &wire.ApplyError{Code: wire.ErrClockUntrusted, Version: 8}
	})
	ro := rollout.Start(wire.RolloutRequest{Tenant: "bank-a", Version: 8}, 7, now.Add(-time.Minute), 5*time.Minute)
	if err := st.PutRollout(ro); err != nil {
		t.Fatal(err)
	}
	return st
}

func serve(h http.Handler, method, target string, hdr ...string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		r.Header.Set(hdr[i], hdr[i+1])
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func newHandler(st store.Store) http.Handler {
	return Handler(st, clock.NewFake(now), fleet.DefaultThresholds())
}

func TestGolden(t *testing.T) {
	h := newHandler(smallFleet(t))
	for _, lang := range []string{"ja", "en"} {
		t.Run(lang, func(t *testing.T) {
			w := serve(h, "GET", "/?tenant=bank-a&lang="+lang)
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body)
			}
			path := filepath.Join("testdata", "fleet."+lang+".golden.html")
			if *update {
				if err := os.WriteFile(path, w.Body.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := w.Body.String(); got != string(want) {
				t.Errorf("page differs from %s (run with -update to review)\n--- got ---\n%s", path, got)
			}
		})
	}
}

// The golden files say what the page looks like; these say what it must show.
func TestPageShowsTheFacts(t *testing.T) {
	h := newHandler(smallFleet(t))
	en := serve(h, "GET", "/?tenant=bank-a&lang=en").Body.String()
	for _, want := range []string{
		"px-canary-1", "px-main-1", "px-main-2", "px-main-3", // every proxy
		"2026-11-05 12:00:00 JST", "2026-11-05 03:00:00 UTC", // generated at, both zones
		"2026-11-05 11:59:15 JST", "2026-11-05 02:59:15 UTC", // px-main-1 last seen
		"tampered", "clock_untrusted", // as reported (M-D29, M-D30)
		"Canary",
	} {
		if !strings.Contains(en, want) {
			t.Errorf("en page lacks %q", want)
		}
	}
	// Sorted by drift (main-2: 7 behind, main-1: 1 behind), then health, then ID.
	order := []string{"px-main-2", "px-main-1", "px-canary-1", "px-main-3"}
	last := -1
	for _, id := range order {
		i := strings.Index(en, ">"+id+"<")
		if i < 0 || i < last {
			t.Fatalf("row order wrong at %s (index %d, previous %d)", id, i, last)
		}
		last = i
	}
	ja := serve(h, "GET", "/?tenant=bank-a&lang=ja").Body.String()
	for _, want := range []string{"改ざん", "セーフモード", "時計が信頼できません", "JST", "UTC", "カナリア"} {
		if !strings.Contains(ja, want) {
			t.Errorf("ja page lacks %q", want)
		}
	}
}

func TestHaltedRolloutReasonReadableInBothLanguages(t *testing.T) {
	st := smallFleet(t)
	ro := rollout.Start(wire.RolloutRequest{Tenant: "bank-a", Version: 8}, 7, now, time.Minute)
	ro.Phase, ro.Reason = wire.PhaseHalted, wire.ErrCanaryLost
	if err := st.PutRollout(ro); err != nil {
		t.Fatal(err)
	}
	h := newHandler(st)
	for lang, want := range map[string][]string{
		"en": {"Halted", "canary_lost", "Canary stopped reporting"},
		"ja": {"停止", "canary_lost", "カナリアが応答しません"},
	} {
		body := serve(h, "GET", "/?tenant=bank-a&lang="+lang).Body.String()
		for _, w := range want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: page lacks %q", lang, w)
			}
		}
	}
}

func TestNoRolloutAndEmptyFleet(t *testing.T) {
	st, err := store.OpenFiles(filepath.Join(t.TempDir(), "s"))
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(st)
	for _, lang := range []string{"en", "ja"} {
		w := serve(h, "GET", "/?tenant=bank-a&lang="+lang)
		if w.Code != 200 {
			t.Fatalf("%s: %d", lang, w.Code)
		}
		if !strings.Contains(w.Body.String(), tr(lang, "empty")) || !strings.Contains(w.Body.String(), tr(lang, "rollout.none")) {
			t.Errorf("%s: empty fleet or missing rollout not explained:\n%s", lang, w.Body)
		}
	}
}

func TestStringsTablesComplete(t *testing.T) {
	if len(strs["ja"]) != len(strs["en"]) {
		t.Errorf("ja has %d keys, en has %d", len(strs["ja"]), len(strs["en"]))
	}
	for lang, tab := range strs {
		for k, v := range tab {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %q is empty", lang, k)
			}
			if _, ok := strs[other(lang)][k]; !ok {
				t.Errorf("%s has %q, %s does not", lang, k, other(lang))
			}
		}
	}
	// Every enumerated value the page can print has a message in both.
	var keys []string
	for _, h := range []wire.Health{wire.HealthHealthy, wire.HealthStale, wire.HealthLost} {
		keys = append(keys, "health."+string(h))
	}
	for _, s := range []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode} {
		keys = append(keys, "state."+string(s))
	}
	for _, p := range []wire.RolloutPhase{wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete} {
		keys = append(keys, "phase."+string(p))
	}
	for _, c := range []wire.ErrorCode{
		wire.ErrBadRequest, wire.ErrUnauthorized, wire.ErrForbidden, wire.ErrNotFound, wire.ErrMethodNotAllowed,
		wire.ErrConflict, wire.ErrTooLarge, wire.ErrInternal, wire.ErrUnavailable, wire.ErrMalformed,
		wire.ErrPayloadType, wire.ErrThreshold, wire.ErrWrongTenant, wire.ErrNotNewer, wire.ErrExpired,
		wire.ErrPersist, wire.ErrTampered, wire.ErrCanaryLost, wire.ErrClockUntrusted,
	} {
		if !c.Valid() {
			t.Fatalf("test list has invalid code %q", c)
		}
		keys = append(keys, "err."+string(c))
	}
	for _, k := range keys {
		for lang := range strs {
			if _, ok := strs[lang][k]; !ok {
				t.Errorf("%s lacks %q", lang, k)
			}
		}
	}
}

// stub lets a test feed the page values the real store would refuse.
type stub struct {
	store.Store
	lasts []fleet.Last
	ro    *rollout.Rollout
	err   error
}

func (s stub) Fleet(wire.ID) ([]fleet.Last, error) { return s.lasts, s.err }
func (s stub) Rollout(wire.ID) (rollout.Rollout, bool, error) {
	if s.ro == nil {
		return rollout.Rollout{}, false, s.err
	}
	return *s.ro, true, s.err
}

func TestHostileValuesCannotInjectMarkup(t *testing.T) {
	const evil = `"><script>alert(1)</script><img src=x onerror=alert(2)>`
	r := wire.StatusReport{
		Tenant: "bank-a", ProxyID: wire.ID(evil), State: wire.ProxyState(evil), AppliedVersion: 3,
		PolicyHash: wire.Hash(evil), LogHead: wire.Hash(evil),
		LastError: &wire.ApplyError{Code: wire.ErrorCode(evil), Version: 3},
	}
	st := stub{
		lasts: []fleet.Last{{Group: wire.ID(evil), Report: r, SeenAt: now}},
		ro:    &rollout.Rollout{Tenant: "bank-a", Version: 3, Phase: wire.RolloutPhase(evil), Reason: wire.ErrorCode(evil)},
	}
	h := newHandler(st)
	for _, lang := range []string{"en", "ja"} {
		body := serve(h, "GET", "/?tenant=bank-a&lang="+lang).Body.String()
		for _, bad := range []string{"<script", "<img", "onerror=alert(2)>"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: page contains raw %q", lang, bad)
			}
		}
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Errorf("%s: hostile text should appear escaped", lang)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHandler(smallFleet(t))
	for _, target := range []string{
		"/?tenant=bank-a&lang=en", "/?tenant=BAD", "/", "/nope", "/static/fleet.css",
	} {
		w := serve(h, "GET", target)
		hd := w.Header()
		if csp := hd.Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'self'") || strings.Contains(csp, "unsafe") {
			t.Errorf("%s: CSP %q", target, csp)
		}
		if hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s: missing nosniff or DENY: %v", target, hd)
		}
	}
	w := serve(h, "POST", "/?tenant=bank-a")
	if w.Header().Get("X-Frame-Options") != "DENY" {
		t.Errorf("405 lacks security headers")
	}
}

func TestNoScriptNoExternalAssets(t *testing.T) {
	h := newHandler(smallFleet(t))
	for _, lang := range []string{"en", "ja"} {
		body := serve(h, "GET", "/?tenant=bank-a&lang="+lang).Body.String()
		for _, bad := range []string{"<script", "http://", "https://", "//cdn", "style=", "<style", "javascript:"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: page contains %q", lang, bad)
			}
		}
		if !strings.Contains(body, `http-equiv="refresh"`) {
			t.Errorf("%s: no auto-refresh", lang)
		}
	}
	css := serve(h, "GET", "/static/fleet.css")
	if css.Code != 200 || !strings.HasPrefix(css.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("css: %d %q", css.Code, css.Header().Get("Content-Type"))
	}
	if strings.Contains(css.Body.String(), "url(") || strings.Contains(css.Body.String(), "@import") {
		t.Errorf("css loads something else")
	}
}

func TestMethods(t *testing.T) {
	h := newHandler(smallFleet(t))
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS"} {
		w := serve(h, m, "/?tenant=bank-a")
		if w.Code != 405 {
			t.Errorf("%s: %d", m, w.Code)
		}
		if w.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: Allow %q", m, w.Header().Get("Allow"))
		}
		var e wire.ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Code != wire.ErrMethodNotAllowed {
			t.Errorf("%s: body %q (%v)", m, w.Body, err)
		}
	}
	get := serve(h, "GET", "/?tenant=bank-a&lang=en")
	head := serve(h, "HEAD", "/?tenant=bank-a&lang=en")
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Errorf("HEAD: %d, %d body bytes", head.Code, head.Body.Len())
	}
	if head.Header().Get("Content-Type") != get.Header().Get("Content-Type") {
		t.Errorf("HEAD content type differs")
	}
}

func TestBadRequestsAreReadableInBothLanguages(t *testing.T) {
	h := newHandler(smallFleet(t))
	cases := []struct {
		target string
		status int
		code   wire.ErrorCode
	}{
		{"/", 400, wire.ErrBadRequest},
		{"/?tenant=", 400, wire.ErrBadRequest},
		{"/?tenant=Bank_A", 400, wire.ErrBadRequest},
		{"/?tenant=" + strings.Repeat("a", 64), 400, wire.ErrBadRequest},
		{"/?tenant=a&tenant=b", 400, wire.ErrBadRequest},
		{"/nope?tenant=bank-a", 404, wire.ErrNotFound},
		{"/static/other.css", 404, wire.ErrNotFound},
	}
	for _, c := range cases {
		for _, lang := range []string{"en", "ja"} {
			sep := "&"
			if !strings.Contains(c.target, "?") {
				sep = "?"
			}
			w := serve(h, "GET", c.target+sep+"lang="+lang)
			if w.Code != c.status {
				t.Errorf("%s %s: status %d want %d", c.target, lang, w.Code, c.status)
			}
			body := w.Body.String()
			if !strings.Contains(body, string(c.code)) || !strings.Contains(body, tr(lang, "err."+string(c.code))) {
				t.Errorf("%s %s: error not readable:\n%s", c.target, lang, body)
			}
			if !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
				t.Errorf("%s: content type %q", c.target, w.Header().Get("Content-Type"))
			}
		}
	}
}

func TestStoreFailureIsInternalAndLeaksNothing(t *testing.T) {
	secret := "/var/lib/kairan/secret-path-xyz"
	for name, st := range map[string]stub{
		"fleet":   {err: errors.New(secret)},
		"rollout": {ro: &rollout.Rollout{}, err: errors.New(secret)},
	} {
		w := serve(newHandler(st), "GET", "/?tenant=bank-a&lang=en")
		if w.Code != 500 || strings.Contains(w.Body.String(), secret) || !strings.Contains(w.Body.String(), "internal") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body)
		}
	}
}

func TestLanguageChoice(t *testing.T) {
	cases := []struct {
		query, accept, want string
	}{
		{"ja", "", "ja"},
		{"en", "", "en"},
		{"en", "ja", "en"}, // query wins
		{"ja", "en", "ja"}, //
		{"", "en", "en"},   // header
		{"", "ja", "ja"},   //
		{"", "en-US,en;q=0.9,ja;q=0.8", "en"},
		{"", "ja-JP,ja;q=0.9,en;q=0.8", "ja"},
		{"", "fr,en;q=0.5,ja;q=0.7", "ja"},
		{"", "ja;q=0,en", "en"},
		{"", "fr,de", "ja"},                            // nothing we speak: default
		{"", "", "ja"},                                 // default
		{"xx", "en", "en"},                             // bad query falls back to the header
		{"JA", "en", "en"},                             // exact lowercase values only
		{"", "EN-gb", "en"},                            // header tags are case-insensitive
		{"", "en;q=abc", "en"},                         // junk q counts as 1... or is ignored, but en is still chosen
		{"", strings.Repeat("fr,", 1000) + "en", "ja"}, // oversized header is ignored
	}
	for _, c := range cases {
		if got := pickLang(c.query, c.accept); got != c.want {
			t.Errorf("pickLang(%q, %q) = %q, want %q", c.query, c.accept, got, c.want)
		}
	}
	h := newHandler(smallFleet(t))
	w := serve(h, "GET", "/?tenant=bank-a", "Accept-Language", "en-US")
	if w.Header().Get("Content-Language") != "en" || !strings.Contains(w.Body.String(), `<html lang="en">`) {
		t.Errorf("Accept-Language not used: %q", w.Header().Get("Content-Language"))
	}
	if w.Header().Get("Vary") != "Accept-Language" {
		t.Errorf("Vary %q", w.Header().Get("Vary"))
	}
}

func TestNeverTouchesStoreOnBadInput(t *testing.T) {
	// A nil Store would panic; bad requests must be answered before any read.
	h := Handler(nil, clock.NewFake(now), fleet.DefaultThresholds())
	if w := serve(h, "GET", "/?tenant=BAD"); w.Code != 400 {
		t.Errorf("status %d", w.Code)
	}
	if w := serve(h, "POST", "/?tenant=bank-a"); w.Code != 405 {
		t.Errorf("status %d", w.Code)
	}
}
