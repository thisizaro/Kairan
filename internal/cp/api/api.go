// Package api serves every HTTP path in wire for kairan-cp: publish, rollout
// start and view, poll, status, fleet and timeline, plus the fleet page.
//
// Rules it keeps (M-D9, M-D31, M-D43, invariant I4):
//
//   - Authentication runs before any body is read and before a poll is
//     registered. A missing or wrong token is 401 unauthorized. A valid token
//     used where it does not belong (another proxy's ID, another tenant, the
//     admin token on a proxy path, a proxy token on an admin path) is 403
//     forbidden. Tokens are compared as SHA-256 digests with crypto/subtle.
//   - Every body goes through http.MaxBytesReader and wire.Decode: unknown
//     fields and trailing data are 400 bad_request, oversize is 413 too_large.
//     A published envelope goes through trust.DecodeEnvelope instead, as on a
//     proxy: a duplicate key or a key spelled in another case is 400 too (Q-D20).
//   - A proxy's timeline is capped at store.MaxTimeline entries; each entry
//     dropped adds to kairan_cp_timeline_dropped_total{tenant} (Q-D21). The
//     per-proxy dropped counts are in the store (store.DropReporter) but are
//     not yet in the timeline response: that needs a field in wire.TimelineView
//     (change-request logged).
//   - Errors are wire.ErrorResponse codes and nothing else; input is never
//     echoed. Logs and metrics carry validated IDs only.
//   - A proxy's group and tenant come from the enrollment registry, never from
//     the proxy (M-D4, M-D26).
//   - Publishing only stores a checked envelope. A rollout makes it desired.
//     The rollout state machine is stepped when a status arrives and on a
//     timer (Run).
//
// The package reads time only through clock.Clock.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/cp/web"
	"kairan/internal/obs"
	"kairan/internal/policy"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// Limits and defaults.
const (
	DefaultMaxPolls     = 5000
	DefaultTickInterval = 5 * time.Second
	retryAfterSeconds   = "5"
	basicChallenge      = `Basic realm="kairan"`
)

// Enrollment is what the control plane knows about one proxy ID.
//
// The proxy's token is given either as Token or, so that a config file holds
// no secret, as TokenDigest (the SHA-256 of the token). Token wins when both
// are set. An enrollment with neither can never authenticate.
type Enrollment struct {
	Tenant, Group wire.ID
	Token         string
	TokenDigest   [sha256.Size]byte
}

// Config is the control plane's API configuration.
type Config struct {
	AdminToken   string                 // empty disables every admin path
	Proxies      map[wire.ID]Enrollment // registry: proxy ID -> enrollment
	AdminKeys    map[wire.ID]trust.Root // per tenant, for the publish sanity check
	PollHold     time.Duration          // default wire.PollHold
	MaxPolls     int                    // default DefaultMaxPolls
	CanaryDwell  time.Duration
	Thresholds   fleet.Thresholds
	TickInterval time.Duration // rollout timer period for Run; default DefaultTickInterval
}

// emptyDigest is the SHA-256 of the empty token, which must never match.
var emptyDigest = sha256.Sum256(nil)

type enrolled struct {
	Enrollment
	digest [sha256.Size]byte
}

// Server holds the handlers' state. Create it with New.
type Server struct {
	st    store.Store
	clk   clock.Clock
	log   *slog.Logger
	roots map[wire.ID]trust.Root

	hold, tick time.Duration
	maxPolls   int
	dwell      time.Duration
	th         fleet.Thresholds

	adminDigest [sha256.Size]byte
	adminSet    bool
	proxies     map[wire.ID]enrolled
	byDigest    map[[sha256.Size]byte][]wire.ID
	tenants     map[wire.ID]bool
	page        http.Handler

	polls, status, authFail *obs.Counter
	active                  *obs.Gauge

	rmu sync.Mutex // serializes rollout read-modify-write

	mu   sync.Mutex // guards live and wake
	live map[wire.ID]*poll
	wake chan struct{}
}

// poll is one held long-poll. A newer poll for the same proxy closes displaced.
type poll struct {
	displaced chan struct{}
}

// New builds a Server. It never fails: an enrollment with an empty token or an
// invalid ID is skipped and can never authenticate. Nil log and registry are
// replaced by a discarding logger and a private registry.
func New(cfg Config, st store.Store, clk clock.Clock, log *slog.Logger, m *obs.Registry) *Server {
	if log == nil {
		log = obs.NewLogger(io.Discard, slog.LevelError)
	}
	if m == nil {
		m = obs.NewRegistry()
	}
	s := &Server{
		st: st, clk: clk, log: log,
		roots: map[wire.ID]trust.Root{},
		hold:  cfg.PollHold, tick: cfg.TickInterval, maxPolls: cfg.MaxPolls,
		dwell: cfg.CanaryDwell, th: cfg.Thresholds,
		proxies:  map[wire.ID]enrolled{},
		byDigest: map[[sha256.Size]byte][]wire.ID{},
		tenants:  map[wire.ID]bool{},
		live:     map[wire.ID]*poll{},
		wake:     make(chan struct{}),
	}
	if s.hold <= 0 {
		s.hold = wire.PollHold
	}
	if s.tick <= 0 {
		s.tick = DefaultTickInterval
	}
	if s.maxPolls <= 0 {
		s.maxPolls = DefaultMaxPolls
	}
	if cfg.AdminToken != "" {
		s.adminDigest = sha256.Sum256([]byte(cfg.AdminToken))
		s.adminSet = true
	}
	for t, r := range cfg.AdminKeys {
		s.roots[t] = r
		s.tenants[t] = true
	}
	ids := make([]wire.ID, 0, len(cfg.Proxies))
	for id := range cfg.Proxies {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		e := cfg.Proxies[id]
		d := e.TokenDigest
		if e.Token != "" {
			d = sha256.Sum256([]byte(e.Token))
		}
		if !id.Valid() || !e.Tenant.Valid() || !e.Group.Valid() || d == ([sha256.Size]byte{}) || d == emptyDigest {
			log.Warn("enrollment skipped", obs.Proxy(id))
			continue
		}
		s.proxies[id] = enrolled{Enrollment: e, digest: d}
		s.byDigest[d] = append(s.byDigest[d], id)
		s.tenants[e.Tenant] = true
	}
	enr := m.Gauge("kairan_cp_enrolled_proxies", "Proxies enrolled, by tenant (from the config).", "tenant")
	count := map[wire.ID]int{}
	for t := range s.tenants {
		count[t] = 0
	}
	for _, e := range s.proxies {
		count[e.Tenant]++
	}
	for t, n := range count {
		enr.With(t).Set(float64(n))
	}
	s.page = web.Handler(st, clk, cfg.Thresholds)
	s.polls = m.Counter("kairan_cp_polls_total", "Long-poll requests answered, by result.", "result")
	s.status = m.Counter("kairan_cp_status_total", "Status reports received, by result.", "result")
	s.authFail = m.Counter("kairan_cp_auth_failures_total", "Requests refused by authentication, by wire error code.", "code")
	s.active = m.Gauge("kairan_cp_active_polls", "Long-polls currently held.")
	s.active.With().Set(0)
	dropped := m.Counter("kairan_cp_timeline_dropped_total", "Oldest timeline entries dropped at the per-proxy cap, by tenant.", "tenant")
	if dn, ok := st.(store.DropNotifier); ok {
		dn.OnTimelineDrop(func(tenant wire.ID, n int) { dropped.With(tenant).Add(uint64(n)) })
	}
	return s
}

// HTTPServer returns an http.Server for addr with the limits of M-D9 and
// M-D31. WriteTimeout exceeds the 30s poll hold.
func (s *Server) HTTPServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

// Handler serves the API paths, which need a Bearer token, and everything else
// (the fleet page at "/" and its stylesheet) behind the admin token as Bearer
// or as the HTTP Basic password (M-D43).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(wire.PathPoll, s.handlePoll)
	mux.HandleFunc(wire.PathStatus, s.handleStatus)
	mux.HandleFunc(wire.PathPolicies, s.admin(s.handlePublish, http.MethodPost))
	mux.HandleFunc(wire.PathRollouts, s.admin(s.handleRollouts, http.MethodGet, http.MethodPost))
	mux.HandleFunc(wire.PathFleet, s.admin(s.handleFleet, http.MethodGet))
	mux.HandleFunc(wire.PathTimeline, s.admin(s.handleTimeline, http.MethodGet))
	mux.HandleFunc("/v1/", s.admin(func(w http.ResponseWriter, _ *http.Request) {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound)
	}))
	mux.HandleFunc("/", s.handlePage)
	return mux
}

// Run steps every active rollout every TickInterval until ctx is done, so a
// canary dwell ends even when no status arrives.
func (s *Server) Run(ctx context.Context) {
	tenants := make([]wire.ID, 0, len(s.tenants))
	for t := range s.tenants {
		tenants = append(tenants, t)
	}
	sort.Slice(tenants, func(i, j int) bool { return tenants[i] < tenants[j] })
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.clk.After(s.tick):
		}
		for _, t := range tenants {
			s.stepTenant(t)
		}
	}
}

// ---- responses ----

func setCommon(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Type", wire.ContentTypeJSON)
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
}

func writeErr(w http.ResponseWriter, status int, code wire.ErrorCode) {
	setCommon(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(wire.ErrorResponse{Code: code})
}

func writeJSON(w http.ResponseWriter, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	setCommon(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(b, '\n'))
}

func methodNotAllowed(w http.ResponseWriter, allow ...string) {
	w.Header().Set("Allow", strings.Join(allow, ", "))
	writeErr(w, http.StatusMethodNotAllowed, wire.ErrMethodNotAllowed)
}

// ---- authentication ----

// who says what a presented token is good for.
type who struct {
	admin   bool
	proxies []wire.ID // enrolled proxy IDs holding this token
}

func (w who) known() bool { return w.admin || len(w.proxies) > 0 }

// identify compares the token's digest with the admin digest in constant time
// and looks it up by digest in the registry. Looking up by a hash of the
// secret leaks nothing an attacker can use: the digest is not chosen by them.
func (s *Server) identify(token string) who {
	d := sha256.Sum256([]byte(token))
	var out who
	if s.adminSet && subtle.ConstantTimeCompare(d[:], s.adminDigest[:]) == 1 {
		out.admin = true
	}
	for _, id := range s.byDigest[d] {
		if e, ok := s.proxies[id]; ok && subtle.ConstantTimeCompare(d[:], e.digest[:]) == 1 {
			out.proxies = append(out.proxies, id)
		}
	}
	return out
}

func (w who) holds(id wire.ID) bool {
	for _, p := range w.proxies {
		if p == id {
			return true
		}
	}
	return false
}

// bearer returns the Bearer token of a request, if there is one.
func bearer(r *http.Request) (string, bool) {
	h := r.Header.Get(wire.HeaderAuthorization)
	if !strings.HasPrefix(h, wire.BearerPrefix) {
		return "", false
	}
	t := h[len(wire.BearerPrefix):]
	return t, t != ""
}

func (s *Server) refuse(w http.ResponseWriter, status int, code wire.ErrorCode, challenge string) {
	s.authFail.With(wire.ID(code)).Inc()
	if status == http.StatusUnauthorized && challenge != "" {
		w.Header().Set("WWW-Authenticate", challenge)
	}
	writeErr(w, status, code)
}

// authenticate checks that the request carries a valid token. For a token that
// is valid but unfit for the path it answers 403, for anything else 401. It
// reads no body.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request, wantAdmin bool) (who, bool) {
	token, ok := bearer(r)
	if !ok {
		s.refuse(w, http.StatusUnauthorized, wire.ErrUnauthorized, "Bearer")
		return who{}, false
	}
	id := s.identify(token)
	switch {
	case !id.known():
		s.refuse(w, http.StatusUnauthorized, wire.ErrUnauthorized, "Bearer")
	case wantAdmin && !id.admin, !wantAdmin && len(id.proxies) == 0:
		s.refuse(w, http.StatusForbidden, wire.ErrForbidden, "")
	default:
		return id, true
	}
	return who{}, false
}

// admin wraps an admin handler: authenticate, then check the method.
func (s *Server) admin(h http.HandlerFunc, methods ...string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.authenticate(w, r, true); !ok {
			return
		}
		if len(methods) > 0 {
			allowed := false
			for _, m := range methods {
				allowed = allowed || r.Method == m
			}
			if !allowed {
				methodNotAllowed(w, methods...)
				return
			}
		}
		h(w, r)
	}
}

// handlePage guards the fleet page: the admin token as Bearer or as the Basic
// password, for the page and its static files only (M-D43).
func (s *Server) handlePage(w http.ResponseWriter, r *http.Request) {
	token, ok := bearer(r)
	if !ok {
		if _, pw, hasBasic := r.BasicAuth(); hasBasic && pw != "" {
			token, ok = pw, true
		}
	}
	if !ok {
		s.refuse(w, http.StatusUnauthorized, wire.ErrUnauthorized, basicChallenge)
		return
	}
	id := s.identify(token)
	switch {
	case !id.known():
		s.refuse(w, http.StatusUnauthorized, wire.ErrUnauthorized, basicChallenge)
		return
	case !id.admin:
		s.refuse(w, http.StatusForbidden, wire.ErrForbidden, "")
		return
	}
	s.page.ServeHTTP(w, r)
}

// ---- body reading ----

// readBody decodes exactly one JSON value of at most limit bytes into v and
// writes the error response itself when it fails.
func readBody(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	if r.ContentLength > limit {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrTooLarge)
		return false
	}
	// One byte of slack lets wire.Decode see the overflow and say so.
	err := wire.Decode(http.MaxBytesReader(w, r.Body, limit+1), limit, v)
	switch {
	case err == nil:
		return true
	case errors.Is(err, wire.ErrBodyTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrTooLarge)
	default:
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
	}
	return false
}

// readEnvelope reads one signed envelope of at most wire.MaxEnvelopeBytes with
// trust.DecodeEnvelope, the decoder proxies use (Q-D20): beside the rules of
// readBody it rejects a duplicate key and a key that is not spelled exactly
// ("Payload" for "payload"), which encoding/json would accept. It writes the
// error response itself when it fails.
func readEnvelope(w http.ResponseWriter, r *http.Request) (wire.Envelope, bool) {
	if r.ContentLength > wire.MaxEnvelopeBytes {
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrTooLarge)
		return wire.Envelope{}, false
	}
	// One byte of slack lets DecodeEnvelope see the overflow and say so.
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, wire.MaxEnvelopeBytes+1))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrTooLarge)
		} else {
			writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
		}
		return wire.Envelope{}, false
	}
	env, err := trust.DecodeEnvelope(b)
	switch {
	case err == nil:
		return env, true
	case errors.Is(err, wire.ErrBodyTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, wire.ErrTooLarge)
	default:
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
	}
	return wire.Envelope{}, false
}

// ---- publish ----

func (s *Server) handlePublish(w http.ResponseWriter, r *http.Request) {
	env, ok := readEnvelope(w, r)
	if !ok {
		return
	}
	switch {
	case env.PayloadType != wire.PayloadTypePolicy:
		writeErr(w, http.StatusBadRequest, wire.ErrPayloadType)
		return
	case env.ValidateShape() != nil:
		writeErr(w, http.StatusBadRequest, wire.ErrMalformed)
		return
	}
	// The tenant comes from the payload; its root decides who may publish.
	// This is a sanity check: proxies are the judges (I1).
	pol, err := policy.Parse(env.Payload)
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrMalformed)
		return
	}
	root, ok := s.roots[pol.Tenant]
	if !ok {
		writeErr(w, http.StatusBadRequest, wire.ErrWrongTenant)
		return
	}
	v, code, err := trust.Verify(env, root)
	if err != nil {
		if errors.Is(err, trust.ErrBadRoot) {
			s.log.Error("publish: admin keys for tenant are below the trust floor", obs.Tenant(pol.Tenant))
			writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
			return
		}
		if !code.Valid() {
			code = wire.ErrMalformed
		}
		writeErr(w, http.StatusBadRequest, code)
		return
	}
	meta := store.EnvelopeMeta{Tenant: v.Policy.Tenant, Version: v.Policy.Version, Hash: v.Hash}
	switch err := s.st.PutEnvelope(env, meta); {
	case err == nil:
	case errors.Is(err, store.ErrConflict):
		writeErr(w, http.StatusConflict, wire.ErrConflict)
		return
	case errors.Is(err, wire.ErrInvalid):
		writeErr(w, http.StatusBadRequest, wire.ErrMalformed)
		return
	default:
		s.log.Error("publish: store failed", obs.Tenant(meta.Tenant))
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	s.log.Info("policy published", obs.Tenant(meta.Tenant), slog.Uint64("version", meta.Version))
	writeJSON(w, wire.PublishResponse{Tenant: meta.Tenant, Version: meta.Version, PolicyHash: meta.Hash})
}

// ---- rollouts ----

// otherGroup stands for any group that is not the canary group.
const otherGroup wire.ID = "other"

func rolloutView(r rollout.Rollout) wire.RolloutView {
	return wire.RolloutView{Tenant: r.Tenant, Version: r.Version, Phase: r.Phase, Reason: r.Reason}
}

func (s *Server) handleRollouts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.getRollout(w, r)
		return
	}
	var req wire.RolloutRequest
	if !readBody(w, r, wire.MaxSmallRequestBytes, &req) {
		return
	}
	if req.Validate() != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
		return
	}
	if !s.tenants[req.Tenant] {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound)
		return
	}
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if _, err := s.st.Envelope(req.Tenant, req.Version); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, wire.ErrNotFound)
			return
		}
		s.log.Error("rollout: store failed", obs.Tenant(req.Tenant))
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	cur, have, err := s.st.Rollout(req.Tenant)
	if err != nil {
		s.log.Error("rollout: store failed", obs.Tenant(req.Tenant))
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	// The new rollout replaces the current one. Non-canary groups keep what
	// they are desired now (the new Previous); the version must beat the
	// highest any group is desired, or the canary group would go down (M-D44).
	var previous, highest uint64
	if have {
		previous = rollout.DesiredFor(cur, otherGroup)
		highest = rollout.DesiredFor(cur, rollout.CanaryGroup)
	}
	if req.Version <= highest {
		writeErr(w, http.StatusConflict, wire.ErrConflict)
		return
	}
	next := rollout.Start(req, previous, s.clk.Now(), s.dwell)
	if err := s.st.PutRollout(next); err != nil {
		s.log.Error("rollout: store failed", obs.Tenant(req.Tenant))
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	s.log.Info("rollout started", obs.Tenant(req.Tenant), slog.Uint64("version", req.Version))
	s.notify()
	writeJSON(w, rolloutView(next))
}

func (s *Server) getRollout(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	ro, have, err := s.st.Rollout(t)
	switch {
	case err != nil:
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
	case !have:
		writeErr(w, http.StatusNotFound, wire.ErrNotFound)
	default:
		writeJSON(w, rolloutView(ro))
	}
}

// tenantParam reads the single "tenant" query parameter of a GET and answers
// 400 for anything else and 404 for a tenant this control plane does not know.
func (s *Server) tenantParam(w http.ResponseWriter, r *http.Request) (wire.ID, bool) {
	q := r.URL.Query()
	ts := q[wire.QueryTenant]
	if len(q) != 1 || len(ts) != 1 || !wire.ID(ts[0]).Valid() {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
		return "", false
	}
	t := wire.ID(ts[0])
	if !s.tenants[t] {
		writeErr(w, http.StatusNotFound, wire.ErrNotFound)
		return "", false
	}
	return t, true
}

// ---- fleet and timeline ----

// fleetView builds the tenant's fleet view from the store and the registry.
// Only enrolled proxies appear, with the group the registry gives them; an
// enrolled proxy that never reported is listed as lost, so a missing canary
// cannot be skipped.
func (s *Server) fleetView(tenant wire.ID, ro rollout.Rollout, haveRollout bool) (wire.FleetView, error) {
	lasts, err := s.st.Fleet(tenant)
	if err != nil {
		return wire.FleetView{}, err
	}
	byID := make(map[wire.ID]fleet.Last, len(lasts))
	for _, l := range lasts {
		byID[l.Report.ProxyID] = l
	}
	var all []fleet.Last
	desired := map[wire.ID]uint64{}
	ids := make([]wire.ID, 0, len(s.proxies))
	for id, e := range s.proxies {
		if e.Tenant == tenant {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		e := s.proxies[id]
		l, seen := byID[id]
		if !seen {
			l = fleet.Last{Report: wire.StatusReport{Tenant: tenant, ProxyID: id, State: wire.StateBooting}}
		}
		l.Group = e.Group
		all = append(all, l)
		if haveRollout {
			desired[e.Group] = rollout.DesiredFor(ro, e.Group)
		}
	}
	return fleet.View(tenant, desired, all, s.clk.Now(), s.th), nil
}

func (s *Server) handleFleet(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	ro, have, err := s.st.Rollout(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	v, err := s.fleetView(t, ro, have)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	writeJSON(w, v)
}

func (s *Server) handleTimeline(w http.ResponseWriter, r *http.Request) {
	t, ok := s.tenantParam(w, r)
	if !ok {
		return
	}
	entries, err := s.st.Timeline(t)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	if entries == nil {
		entries = []wire.TimelineEntry{}
	}
	writeJSON(w, wire.TimelineView{Tenant: t, Entries: entries})
}

// ---- status ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r, false)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	var rep wire.StatusReport
	if !readBody(w, r, wire.MaxStatusBytes, &rep) {
		return
	}
	if rep.Validate() != nil {
		s.status.With("rejected").Inc()
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
		return
	}
	// The token must belong to the proxy named in the report, and the report's
	// tenant must be that proxy's enrollment tenant.
	e, enrolledOK := s.proxies[rep.ProxyID]
	if !enrolledOK || !id.holds(rep.ProxyID) || e.Tenant != rep.Tenant {
		s.status.With("rejected").Inc()
		s.refuse(w, http.StatusForbidden, wire.ErrForbidden, "")
		return
	}
	last := fleet.Last{Group: e.Group, Report: rep, SeenAt: s.clk.Now()}
	if err := s.st.RecordStatus(last); err != nil {
		s.log.Error("status: store failed", obs.Tenant(rep.Tenant), obs.Proxy(rep.ProxyID))
		writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
		return
	}
	s.status.With("ok").Inc()
	s.stepTenant(rep.Tenant)
	w.WriteHeader(http.StatusNoContent)
}

// stepTenant advances the tenant's rollout if one is active, stores the
// result and wakes held polls when the desired versions may have changed.
func (s *Server) stepTenant(tenant wire.ID) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	ro, have, err := s.st.Rollout(tenant)
	if err != nil || !have || (ro.Phase != wire.PhaseCanary && ro.Phase != wire.PhasePromoting) {
		return
	}
	view, err := s.fleetView(tenant, ro, true)
	if err != nil {
		s.log.Error("rollout: fleet read failed", obs.Tenant(tenant))
		return
	}
	next, _ := rollout.Step(ro, view, s.clk.Now())
	if next.Phase == ro.Phase && next.Reason == ro.Reason && next.Promoted == ro.Promoted && next.CanaryOK.Equal(ro.CanaryOK) {
		return
	}
	if err := s.st.PutRollout(next); err != nil {
		s.log.Error("rollout: store failed", obs.Tenant(tenant))
		return
	}
	if next.Phase != ro.Phase {
		s.log.Info("rollout phase changed", obs.Tenant(tenant), slog.Uint64("version", next.Version),
			slog.String("phase", string(next.Phase)), slog.String("reason", string(next.Reason)))
		s.notify()
	}
}

// ---- long-poll ----

// notify wakes every held poll to look again.
func (s *Server) notify() {
	s.mu.Lock()
	close(s.wake)
	s.wake = make(chan struct{})
	s.mu.Unlock()
}

func (s *Server) wakeChan() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wake
}

func (s *Server) activePolls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.live)
}

// register records a held poll for the proxy. A poll already held for the same
// proxy is displaced. It reports false when the global cap is reached.
func (s *Server) register(id wire.ID) (*poll, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, had := s.live[id]
	if !had && len(s.live) >= s.maxPolls {
		return nil, false
	}
	if had {
		close(old.displaced)
	}
	p := &poll{displaced: make(chan struct{})}
	s.live[id] = p
	s.active.With().Set(float64(len(s.live)))
	return p, true
}

func (s *Server) unregister(id wire.ID, p *poll) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.live[id] == p {
		delete(s.live, id)
	}
	s.active.With().Set(float64(len(s.live)))
}

// offer returns the envelope the proxy should apply next, if its group's
// desired version is above have.
func (s *Server) offer(tenant wire.ID, group wire.ID, have uint64) (*wire.PollResponse, error) {
	ro, ok, err := s.st.Rollout(tenant)
	if err != nil || !ok {
		return nil, err
	}
	want := rollout.DesiredFor(ro, group)
	if want <= have {
		return nil, nil
	}
	env, err := s.st.Envelope(tenant, want)
	if err != nil {
		return nil, err
	}
	return &wire.PollResponse{Version: want, Envelope: env}, nil
}

func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request) {
	id, ok := s.authenticate(w, r, false)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	req, err := wire.ParsePollRequest(r.URL.Query())
	if err != nil {
		writeErr(w, http.StatusBadRequest, wire.ErrBadRequest)
		return
	}
	e, enrolledOK := s.proxies[req.ProxyID]
	if !enrolledOK || !id.holds(req.ProxyID) || e.Tenant != req.Tenant {
		s.refuse(w, http.StatusForbidden, wire.ErrForbidden, "")
		return
	}

	var mine *poll
	var timer <-chan time.Time
	for {
		// Take the wake channel before looking, so a change in between is not missed.
		wake := s.wakeChan()
		resp, err := s.offer(req.Tenant, e.Group, req.Have)
		if err != nil {
			s.log.Error("poll: store failed", obs.Tenant(req.Tenant), obs.Proxy(req.ProxyID))
			writeErr(w, http.StatusInternalServerError, wire.ErrInternal)
			return
		}
		if resp != nil {
			s.polls.With("update").Inc()
			writeJSON(w, resp)
			return
		}
		if mine == nil {
			timer = s.clk.After(s.hold)
			var ok bool
			if mine, ok = s.register(req.ProxyID); !ok {
				s.polls.With("unavailable").Inc()
				w.Header().Set("Retry-After", retryAfterSeconds)
				writeErr(w, http.StatusServiceUnavailable, wire.ErrUnavailable)
				return
			}
			defer s.unregister(req.ProxyID, mine)
		}
		select {
		case <-wake:
		case <-mine.displaced:
			s.polls.With("displaced").Inc()
			w.WriteHeader(http.StatusNotModified)
			return
		case <-timer:
			s.polls.With("not-modified").Inc()
			w.WriteHeader(http.StatusNotModified)
			return
		case <-r.Context().Done():
			s.polls.With("canceled").Inc()
			return
		}
	}
}
