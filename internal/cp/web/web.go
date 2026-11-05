// Package web serves the fleet page: one HTML page, in Japanese or English,
// showing what the control plane knows about a tenant's proxies (PRD G2, J7).
//
// It shows metadata only (I4): the rows of wire.FleetView, the current
// rollout, and codes from wire. Every value goes through html/template's
// contextual escaping, even IDs that were validated elsewhere. The page needs
// no script and loads nothing from outside: the one stylesheet is embedded and
// served by the same handler, and the Content-Security-Policy says so.
//
// Authentication is not done here. The handler expects the caller (cp/api,
// wired in cmd/kairan-cp) to have checked the admin token already; mount it
// behind that check. It answers GET and HEAD only.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

//go:embed templates/*.tmpl static/fleet.css
var assets embed.FS

const cssPath = "/static/fleet.css"

// securityHeaders go on every response, errors included. The CSP allows only
// our own origin: no inline script or style, no outside assets, no framing.
var securityHeaders = map[string]string{
	"Content-Security-Policy": "default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options":  "nosniff",
	"X-Frame-Options":         "DENY",
	"Referrer-Policy":         "no-referrer",
	"Cache-Control":           "no-store",
}

// jst is a fixed zone so the page needs no timezone database.
var jst = time.FixedZone("JST", 9*60*60)

var (
	fleetTmpl = parsePages("templates/fleet.html.tmpl")
	errTmpl   = parsePages("templates/error.html.tmpl")
)

// parsePages parses one template per language; each has a t function bound to
// its own table. A key missing from the table fails the render, so a gap
// shows up in tests rather than as a blank on the page.
func parsePages(file string) map[string]*template.Template {
	src, err := assets.ReadFile(file)
	if err != nil {
		panic(err)
	}
	out := make(map[string]*template.Template, len(strs))
	for lang := range strs {
		t := func(key string) (string, error) {
			if s, ok := strs[lang][key]; ok {
				return s, nil
			}
			return "", &missingKey{lang, key}
		}
		out[lang] = template.Must(template.New(file).Funcs(template.FuncMap{"t": t}).Parse(string(src)))
	}
	return out
}

type missingKey struct{ lang, key string }

func (e *missingKey) Error() string { return "web: no " + e.lang + " text for " + e.key }

// Handler serves GET /?tenant=<id>&lang=ja|en and its stylesheet. The tenant
// is required. The caller must have authorized the request already.
func Handler(st store.Store, clk clock.Clock, th fleet.Thresholds) http.Handler {
	h := &handler{st: st, clk: clk, th: th}
	return http.HandlerFunc(h.serve)
}

type handler struct {
	st  store.Store
	clk clock.Clock
	th  fleet.Thresholds
}

func (h *handler) serve(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.Header().Set("Content-Type", wire.ContentTypeJSON)
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Code: wire.ErrMethodNotAllowed})
		return
	}
	q := r.URL.Query()
	lang := pickLang(q.Get("lang"), r.Header.Get("Accept-Language"))
	w.Header().Set("Vary", "Accept-Language")
	w.Header().Set("Content-Language", lang)

	switch r.URL.Path {
	case cssPath:
		css, err := assets.ReadFile("static/fleet.css")
		if err != nil {
			h.fail(w, r, lang, q, http.StatusInternalServerError, wire.ErrInternal)
			return
		}
		respond(w, r, http.StatusOK, "text/css; charset=utf-8", css)
	case "/":
		h.page(w, r, lang, q)
	default:
		h.fail(w, r, lang, q, http.StatusNotFound, wire.ErrNotFound)
	}
}

func setHeaders(w http.ResponseWriter) {
	for k, v := range securityHeaders {
		w.Header().Set(k, v)
	}
}

// respond writes a complete body; HEAD gets the headers and the length only.
func respond(w http.ResponseWriter, r *http.Request, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func (h *handler) page(w http.ResponseWriter, r *http.Request, lang string, q url.Values) {
	tenants := q["tenant"]
	if len(tenants) != 1 || !wire.ID(tenants[0]).Valid() {
		h.fail(w, r, lang, q, http.StatusBadRequest, wire.ErrBadRequest)
		return
	}
	tenant := wire.ID(tenants[0])
	now := h.clk.Now()

	lasts, err := h.st.Fleet(tenant)
	if err != nil {
		h.fail(w, r, lang, q, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	ro, haveRollout, err := h.st.Rollout(tenant)
	if err != nil {
		h.fail(w, r, lang, q, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	desired := map[wire.ID]uint64{}
	if haveRollout {
		for _, l := range lasts {
			desired[l.Group] = rollout.DesiredFor(ro, l.Group)
		}
	}
	view := fleet.View(tenant, desired, lasts, now, h.th)

	d := buildPage(lang, view, ro, haveRollout, now)
	var buf bytes.Buffer
	if err := fleetTmpl[lang].Execute(&buf, d); err != nil {
		h.fail(w, r, lang, q, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	respond(w, r, http.StatusOK, "text/html; charset=utf-8", buf.Bytes())
}

// fail answers with a small page that names the wire error code and says what
// it means in the chosen language.
func (h *handler) fail(w http.ResponseWriter, r *http.Request, lang string, q url.Values, status int, code wire.ErrorCode) {
	d := struct {
		Lang, SwitchLang, SwitchURL string
		Code                        wire.ErrorCode
		Text                        string
	}{
		Lang: lang, SwitchLang: other(lang), SwitchURL: switchURL(q, other(lang)),
		Code: code, Text: label(lang, "err.", string(code)),
	}
	var buf bytes.Buffer
	if err := errTmpl[lang].Execute(&buf, d); err != nil {
		w.Header().Set("Content-Type", wire.ContentTypeJSON)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Code: wire.ErrInternal})
		return
	}
	respond(w, r, status, "text/html; charset=utf-8", buf.Bytes())
}

// switchURL is a relative link to the same page in another language. Only a
// valid tenant ID is carried over.
func switchURL(q url.Values, lang string) string {
	v := url.Values{}
	if ts := q["tenant"]; len(ts) == 1 && wire.ID(ts[0]).Valid() {
		v.Set("tenant", ts[0])
	}
	v.Set("lang", lang)
	return "?" + v.Encode()
}

// label returns the text for a fixed enumeration value, or the raw value (the
// template escapes it) when the table does not know it.
func label(lang, prefix, value string) string {
	if has(lang, prefix+value) {
		return tr(lang, prefix+value)
	}
	return value
}

// class returns value if it is one of known, else "unknown". It keeps
// store-supplied text out of class attributes.
func class(value string, known ...string) string {
	for _, k := range known {
		if value == k {
			return value
		}
	}
	return "unknown"
}

type stamp struct{ JST, UTC string }

func stampOf(t time.Time) *stamp {
	return &stamp{
		JST: t.In(jst).Format("2006-01-02 15:04:05") + " JST",
		UTC: t.UTC().Format("2006-01-02 15:04:05") + " UTC",
	}
}

type stat struct {
	Label string
	N     int
	Alarm bool
}

type rolloutBox struct {
	Version    uint64
	Phase      string
	Class      string
	Reason     string
	ReasonCode string
}

type row struct {
	Proxy, Group        string
	Health, HealthClass string
	State, StateClass   string
	Desired, Applied    string
	Drift, DriftClass   string
	Hash                string
	Seen                *stamp
	ErrCode, ErrText    string
	ErrVersion          uint64
}

type page struct {
	Lang, SwitchLang, SwitchURL string
	Tenant                      wire.ID
	Now                         *stamp
	Stats                       []stat
	Rollout                     *rolloutBox
	Rows                        []row
}

func buildPage(lang string, v wire.FleetView, ro rollout.Rollout, haveRollout bool, now time.Time) page {
	p := page{
		Lang: lang, SwitchLang: other(lang),
		SwitchURL: switchURL(url.Values{"tenant": {string(v.Tenant)}}, other(lang)),
		Tenant:    v.Tenant, Now: stampOf(now),
	}
	var healthy, stale, lost, tampered, safe, clockBad int
	for _, pv := range v.Proxies {
		switch pv.Health {
		case wire.HealthHealthy:
			healthy++
		case wire.HealthStale:
			stale++
		case wire.HealthLost:
			lost++
		}
		switch pv.State {
		case wire.StateTampered:
			tampered++
		case wire.StateSafeMode:
			safe++
		}
		if pv.LastError != nil && pv.LastError.Code == wire.ErrClockUntrusted {
			clockBad++
		}
		p.Rows = append(p.Rows, buildRow(lang, pv))
	}
	p.Stats = []stat{
		{tr(lang, "stat.total"), len(v.Proxies), false},
		{tr(lang, "stat.healthy"), healthy, false},
		{tr(lang, "stat.stale"), stale, stale > 0},
		{tr(lang, "stat.lost"), lost, lost > 0},
		{tr(lang, "stat.tampered"), tampered, tampered > 0},
		{tr(lang, "stat.safe_mode"), safe, safe > 0},
		{tr(lang, "stat.clock"), clockBad, clockBad > 0},
	}
	if haveRollout {
		b := &rolloutBox{
			Version: ro.Version,
			Phase:   label(lang, "phase.", string(ro.Phase)),
			Class: class(string(ro.Phase), string(wire.PhaseCanary), string(wire.PhasePromoting),
				string(wire.PhaseHalted), string(wire.PhaseComplete)),
		}
		if ro.Reason != "" {
			b.ReasonCode = string(ro.Reason)
			b.Reason = label(lang, "err.", string(ro.Reason))
			if b.Reason == b.ReasonCode {
				b.Reason = ""
			}
			if b.Reason == "" {
				b.Reason = "-"
			}
		}
		p.Rollout = b
	}
	return p
}

func buildRow(lang string, pv wire.ProxyView) row {
	r := row{
		Proxy: string(pv.ProxyID), Group: string(pv.Group),
		Health:      label(lang, "health.", string(pv.Health)),
		HealthClass: class(string(pv.Health), string(wire.HealthHealthy), string(wire.HealthStale), string(wire.HealthLost)),
		State:       label(lang, "state.", string(pv.State)),
		StateClass: class(string(pv.State), string(wire.StateBooting), string(wire.StateDenyAll),
			string(wire.StateTampered), string(wire.StateEnforcing), string(wire.StateSafeMode)),
		Desired: versionText(pv.DesiredVersion), Applied: versionText(pv.AppliedVersion),
		Hash: shortHash(pv.PolicyHash),
	}
	switch {
	case pv.DesiredVersion == 0:
		r.Drift, r.DriftClass = tr(lang, "drift.notarget"), "none"
	case pv.Drift > 0:
		r.Drift, r.DriftClass = strconv.FormatUint(pv.Drift, 10)+" "+tr(lang, "drift.behind"), "behind"
	case pv.AppliedVersion > pv.DesiredVersion:
		r.Drift, r.DriftClass = tr(lang, "drift.ahead"), "ahead"
	default:
		r.Drift, r.DriftClass = tr(lang, "drift.sync"), "sync"
	}
	if pv.LastSeenUnixMs > 0 {
		r.Seen = stampOf(time.UnixMilli(pv.LastSeenUnixMs))
	}
	if e := pv.LastError; e != nil {
		r.ErrCode = string(e.Code)
		if has(lang, "err."+string(e.Code)) {
			r.ErrText = tr(lang, "err."+string(e.Code))
		}
		r.ErrVersion = e.Version
	}
	return r
}

func versionText(v uint64) string {
	if v == 0 {
		return "-"
	}
	return strconv.FormatUint(v, 10)
}

// shortHash is the first 12 characters, enough to compare by eye.
func shortHash(h wire.Hash) string {
	if h == "" {
		return "-"
	}
	rs := []rune(string(h))
	if len(rs) > 12 {
		rs = rs[:12]
	}
	return string(rs)
}
