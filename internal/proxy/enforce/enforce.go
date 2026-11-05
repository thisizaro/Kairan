package enforce

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

// Limits (M-D31, M-D33).
const (
	MaxBodyBytes           = 1 << 20          // request body cap; larger is 413
	DefaultUpstreamTimeout = 60 * time.Second // per-call upstream timeout
	maxListBody            = 4 << 20          // largest tools/list answer the filter will read
	bodyReadTimeout        = 30 * time.Second // slow-body guard; reset once the body is read
	ReadHeaderTimeout      = 5 * time.Second  // MCP listener
	IdleTimeout            = 60 * time.Second // MCP listener
	MaxHeaderBytes         = 8 << 10          // MCP listener
)

// Record is what one decision leaves behind: who, which tool, the verdict and
// the policy it came from (I5). It carries no arguments and no results
// (I4; THREATS #7). Tool is "tools/list" for a list request (no tool can
// have that name: the policy alphabet has no slash) and "" when the request
// could not be read or the name is not a valid tool name.
type Record struct {
	Time    time.Time
	Role    string
	Tool    string
	Allowed bool
	Class   policy.Class
	Version uint64
	Hash    wire.Hash
	State   wire.ProxyState
}

// DecisionLog stores decisions. The production implementation appends to a
// local JSONL file (P-06). An error means the decision was not stored, and
// the call is denied (fail closed, M-D33).
type DecisionLog interface {
	Record(Record) error
}

// Metrics is the counter sink. A nil Metrics is fine. Names used:
// enforce_allow, enforce_deny, enforce_reject, enforce_auth_failed,
// enforce_decision_log_errors, enforce_upstream_errors.
type Metrics interface {
	Inc(name string)
}

// Config configures New.
type Config struct {
	Upstream        *url.URL          // the MCP endpoint; every request goes to exactly this URL
	APIKeys         map[string]string // API key -> role (static, demo-grade)
	UpstreamTimeout time.Duration     // per call; 0 = DefaultUpstreamTimeout
	SafeMode        state.SafeMode    // read_only (default when empty) | deny_all; unknown = deny_all
}

// Validate says whether the config can serve at all. kairan-proxy calls it at
// start; New itself never panics and an unusable config denies everything.
func (c Config) Validate() error {
	if c.Upstream == nil || (c.Upstream.Scheme != "http" && c.Upstream.Scheme != "https") || c.Upstream.Host == "" {
		return errors.New("enforce: upstream must be an http or https URL")
	}
	if len(c.APIKeys) == 0 {
		return errors.New("enforce: no API keys configured")
	}
	for k, r := range c.APIKeys {
		if k == "" || !wire.ID(r).Valid() {
			return errors.New("enforce: API key must not be empty and a role must be an ID (1-63 of a-z, 0-9, -)")
		}
	}
	if _, err := state.ParseSafeMode(string(c.SafeMode)); err != nil {
		return err
	}
	if c.UpstreamTimeout < 0 {
		return errors.New("enforce: negative upstream timeout")
	}
	return nil
}

// NewServer wraps h in an http.Server with the MCP listener limits of M-D31:
// header timeout 5s, idle timeout 60s, header cap 8 KiB, and no global write
// timeout (a response may stream; the per-call upstream timeout bounds it).
func NewServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: ReadHeaderTimeout,
		IdleTimeout:       IdleTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
	}
}

type apiKey struct {
	sum  [sha256.Size]byte
	role string
}

type proxy struct {
	up      *url.URL
	keys    []apiKey
	mode    state.SafeMode
	timeout time.Duration
	h       *Holder
	dl      DecisionLog
	clk     clock.Clock
	m       Metrics
	client  *http.Client
}

// New returns the MCP-facing handler: it checks the API key, reads each
// request strictly, decides tools/call and filters tools/list from the
// Active policy, and forwards the rest. A nil DecisionLog denies every
// decision (it cannot be stored).
func New(cfg Config, h *Holder, dl DecisionLog, clk clock.Clock, m Metrics) http.Handler {
	p := &proxy{up: cfg.Upstream, h: h, dl: dl, clk: clk, m: m, timeout: cfg.UpstreamTimeout}
	if p.timeout <= 0 {
		p.timeout = DefaultUpstreamTimeout
	}
	mode, err := state.ParseSafeMode(string(cfg.SafeMode))
	if err != nil {
		mode = state.DenyAll
	}
	p.mode = mode
	for k, role := range cfg.APIKeys {
		if k != "" && role != "" {
			p.keys = append(p.keys, apiKey{sum: sha256.Sum256([]byte(k)), role: role})
		}
	}
	p.client = &http.Client{
		Transport: &http.Transport{
			DisableCompression:  true, // the proxy sees exactly what the upstream sent
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     IdleTimeout,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return p
}

func (p *proxy) inc(name string) {
	if p.m != nil {
		p.m.Inc(name)
	}
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	role, ok := p.authenticate(r)
	if !ok {
		p.inc("enforce_auth_failed")
		httpError(w, http.StatusUnauthorized, wire.ErrUnauthorized)
		return
	}
	switch r.Method {
	case http.MethodPost:
		p.post(w, r, role)
	case http.MethodGet, http.MethodDelete: // MCP session stream and session end: nothing to decide
		p.relay(w, r, r.Method, nil, nil, r.Method == http.MethodDelete)
	default:
		w.Header().Set("Allow", "POST, GET, DELETE")
		httpError(w, http.StatusMethodNotAllowed, wire.ErrMethodNotAllowed)
	}
}

// authenticate maps the presented API key to a role. The key comes from
// "Authorization: Bearer <key>" or "X-Api-Key: <key>"; if both are present
// they must agree. The comparison is constant time over every configured key.
func (p *proxy) authenticate(r *http.Request) (string, bool) {
	var presented []string
	if v := r.Header.Values("Authorization"); len(v) > 0 {
		if len(v) != 1 {
			return "", false
		}
		scheme, tok, found := strings.Cut(v[0], " ")
		if !found || !strings.EqualFold(scheme, "Bearer") {
			return "", false
		}
		presented = append(presented, tok)
	}
	if v := r.Header.Values("X-Api-Key"); len(v) > 0 {
		if len(v) != 1 {
			return "", false
		}
		presented = append(presented, v[0])
	}
	if len(presented) == 0 || (len(presented) == 2 && presented[0] != presented[1]) || presented[0] == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(presented[0]))
	role, found := "", 0
	for i := range p.keys {
		if subtle.ConstantTimeCompare(sum[:], p.keys[i].sum[:]) == 1 {
			role, found = p.keys[i].role, 1
		}
	}
	return role, subtle.ConstantTimeEq(int32(found), 1) == 1
}

// post handles a POST: read strictly, then decide.
func (p *proxy) post(w http.ResponseWriter, r *http.Request, role string) {
	if !jsonContentType(r.Header.Values("Content-Type")) {
		p.rejectRaw(w, role, http.StatusUnsupportedMediaType, "reject_content_type")
		return
	}
	if ce := r.Header.Values("Content-Encoding"); len(ce) > 1 || (len(ce) == 1 && !strings.EqualFold(strings.TrimSpace(ce[0]), "identity")) {
		p.rejectRaw(w, role, http.StatusUnsupportedMediaType, "reject_content_encoding")
		return
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(bodyReadTimeout)) // errors: not every ResponseWriter supports it
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	_ = rc.SetReadDeadline(time.Time{})
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			p.rejectRaw(w, role, http.StatusRequestEntityTooLarge, "reject_too_large")
		} else {
			p.rejectRaw(w, role, http.StatusBadRequest, "reject_body")
		}
		return
	}
	env, err := scanRequest(body)
	if err != nil {
		p.rejectRaw(w, role, http.StatusBadRequest, "reject_"+reason(err))
		return
	}
	switch env.Kind {
	case kindCall:
		p.call(w, r, role, env, body)
	case kindList:
		p.list(w, r, role, env, body)
	default:
		p.relay(w, r, http.MethodPost, body, env.ID, true)
	}
}

func reason(err error) string {
	switch {
	case errors.Is(err, errBatch):
		return "batch"
	case errors.Is(err, errDuplicateKey):
		return "duplicate_key"
	case errors.Is(err, errBadKey):
		return "bad_key"
	case errors.Is(err, errMethod):
		return "method"
	case errors.Is(err, errShape):
		return "shape"
	}
	return "syntax"
}

// jsonContentType: exactly one Content-Type, application/json, with no
// parameter or only charset=utf-8.
func jsonContentType(v []string) bool {
	if len(v) != 1 {
		return false
	}
	mt, params, err := mime.ParseMediaType(v[0])
	if err != nil || mt != "application/json" {
		return false
	}
	for k, val := range params {
		if k != "charset" || !strings.EqualFold(val, "utf-8") {
			return false
		}
	}
	return true
}

// stateOf: no Active means no policy, which is DenyAll.
func stateOf(a *Active) wire.ProxyState {
	if a == nil || a.State == "" {
		return wire.StateDenyAll
	}
	return a.State
}

// verdict is the one place a tool is judged, for tools/call and for the
// tools/list filter alike, so a tool is listed if and only if a call to it
// would be allowed.
func (p *proxy) verdict(a *Active, role, tool string) (policy.Decision, bool) {
	st := stateOf(a)
	var pol *policy.Policy
	if a != nil {
		pol = a.Policy
	}
	d := pol.Decide(role, tool, st == wire.StateSafeMode)
	return d, state.AllowsDecision(st, d, p.mode)
}

// record is the single exit for every decision: allow, deny, reject and list.
// If the decision cannot be stored, it returns false and the caller must deny.
func (p *proxy) record(a *Active, role, tool string, allowed bool, class policy.Class) bool {
	rec := Record{
		Time:    p.clk.Now(),
		Role:    role,
		Tool:    tool,
		Allowed: allowed,
		Class:   class,
		State:   stateOf(a),
	}
	if a != nil {
		rec.Hash = a.Hash
		if a.Policy != nil {
			rec.Version = a.Policy.Version
		}
	}
	if p.dl == nil {
		p.inc("enforce_decision_log_errors")
		return false
	}
	if err := p.dl.Record(rec); err != nil {
		p.inc("enforce_decision_log_errors")
		return false
	}
	if allowed {
		p.inc("enforce_allow")
	} else {
		p.inc("enforce_deny")
	}
	return true
}

// logName is the tool name as it goes in the log: only a valid tool name
// (1-128 of [A-Za-z0-9_.-]); anything else could be junk or an injection
// attempt and is logged as "".
func logName(s string) string {
	if len(s) == 0 || len(s) > policy.MaxToolNameLen {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return ""
		}
	}
	return s
}

// rejectRaw refuses a request that could not be read strictly. It is a
// logged deny: the request might have been a tools/call (M-D33 item 6).
func (p *proxy) rejectRaw(w http.ResponseWriter, role string, status int, counter string) {
	p.record(p.h.Load(), role, "", false, 0)
	p.inc("enforce_reject")
	p.inc("enforce_" + counter)
	switch status {
	case http.StatusRequestEntityTooLarge:
		httpError(w, status, wire.ErrTooLarge)
	case http.StatusUnsupportedMediaType:
		httpError(w, status, wire.ErrBadRequest)
	default:
		rpcError(w, status, nil, -32600, "invalid request")
	}
}

// call decides one tools/call.
func (p *proxy) call(w http.ResponseWriter, r *http.Request, role string, env envelope, body []byte) {
	a := p.h.Load() // one policy for the whole call
	d, allowed := p.verdict(a, role, env.Tool)
	if !p.record(a, role, logName(env.Tool), allowed, d.Class) {
		allowed = false
	}
	if !allowed {
		var v uint64
		if a != nil && a.Policy != nil {
			v = a.Policy.Version
		}
		denyResult(w, env.ID, v)
		return
	}
	p.relay(w, r, http.MethodPost, body, env.ID, true)
}

// list answers one tools/list: nothing at all unless the state serves reads,
// otherwise the upstream's list with the tools the role cannot call removed.
func (p *proxy) list(w http.ResponseWriter, r *http.Request, role string, env envelope, body []byte) {
	a := p.h.Load()
	st := stateOf(a)
	serve := state.AllowsDecision(st, policy.Decision{Allowed: true, Class: policy.ClassR}, p.mode)
	if !p.record(a, role, "tools/list", serve, 0) {
		serve = false
	}
	if !serve {
		writeJSON(w, http.StatusOK, emptyList(env.ID))
		return
	}
	visible := func(name string) bool { _, ok := p.verdict(a, role, name); return ok }

	resp, cancel, err := p.send(r, http.MethodPost, body, true, true)
	if err != nil {
		p.upstreamFailed(w, env.ID, err)
		return
	}
	defer cancel()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		p.upstreamFailed(w, env.ID, errBadStatus)
		return
	}
	ct := resp.Header.Get("Content-Type")
	if ce := resp.Header.Values("Content-Encoding"); len(ce) > 0 && !(len(ce) == 1 && strings.EqualFold(strings.TrimSpace(ce[0]), "identity")) {
		ct = "" // compressed: unreadable, so an empty list
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxListBody+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			p.upstreamFailed(w, env.ID, err)
			return
		}
		ct = "" // cut off or broken: unreadable, so an empty list
	}
	if len(data) > maxListBody {
		ct = ""
	}
	out, sse := filterList(visible, env.ID, ct, data)
	copyHeaders(w.Header(), resp.Header, rebuiltBack)
	if sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

var errRedirect = errors.New("upstream answered with a redirect")

var errBadStatus = errors.New("upstream answered with an unexpected status")

// send builds and sends the upstream request. body is the exact bytes that
// were inspected. The returned cancel must be called when the response has
// been read.
func (p *proxy) send(r *http.Request, method string, body []byte, timeout, identity bool) (*http.Response, context.CancelFunc, error) {
	if p.up == nil {
		return nil, func() {}, errors.New("no upstream configured")
	}
	ctx, cancel := r.Context(), context.CancelFunc(func() {})
	if timeout {
		ctx, cancel = context.WithTimeout(ctx, p.timeout)
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.up.String(), rd)
	if err != nil {
		cancel()
		return nil, func() {}, err
	}
	copyHeaders(req.Header, r.Header, toUpstream)
	if identity {
		req.Header.Set("Accept-Encoding", "identity")
	}
	resp, err := p.client.Do(req)
	if err != nil {
		cancel()
		return nil, func() {}, err
	}
	// Q-D19 (M-D55): the client never follows a redirect and the agent never
	// sees one (no Location, no body): a 3xx is an upstream error.
	if resp.StatusCode >= 300 && resp.StatusCode <= 399 {
		resp.Body.Close()
		cancel()
		return nil, func() {}, errRedirect
	}
	return resp, cancel, nil
}

// relay forwards a request that needs no decision (or one already allowed)
// and streams the answer back unchanged.
func (p *proxy) relay(w http.ResponseWriter, r *http.Request, method string, body []byte, id json.RawMessage, timeout bool) {
	resp, cancel, err := p.send(r, method, body, timeout, false)
	if err != nil {
		p.upstreamFailed(w, id, err)
		return
	}
	defer cancel()
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header, relayBack)
	w.WriteHeader(resp.StatusCode)
	rc := http.NewResponseController(w)
	buf := make([]byte, 32<<10)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

func (p *proxy) upstreamFailed(w http.ResponseWriter, id json.RawMessage, err error) {
	p.inc("enforce_upstream_errors")
	if errors.Is(err, context.DeadlineExceeded) {
		rpcError(w, http.StatusGatewayTimeout, id, -32603, "upstream timeout")
		return
	}
	rpcError(w, http.StatusBadGateway, id, -32603, "upstream unavailable")
}

var hopByHop = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
}

// Header copy modes.
const (
	toUpstream  = iota // agent request going upstream: credentials and Content-Length removed
	relayBack          // upstream answer streamed back as it is
	rebuiltBack        // upstream answer replaced by the filter: body headers are set by the caller
)

// copyHeaders copies end-to-end headers (not hop-by-hop ones).
func copyHeaders(dst, src http.Header, mode int) {
	drop := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			drop[http.CanonicalHeaderKey(strings.TrimSpace(tok))] = true
		}
	}
	for k, vs := range src {
		if hopByHop[k] || drop[k] {
			continue
		}
		switch {
		case mode == toUpstream && (k == "Authorization" || k == "X-Api-Key" || k == "Content-Length"):
			continue
		case mode == rebuiltBack && (k == "Content-Length" || k == "Content-Encoding" || k == "Content-Type"):
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func httpError(w http.ResponseWriter, status int, code wire.ErrorCode) {
	b, _ := json.Marshal(wire.ErrorResponse{Code: code})
	writeJSON(w, status, b)
}

// rpcError writes a JSON-RPC error with a fixed message (never any part of
// the request). A missing id is null.
func rpcError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	b, _ := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{JSONRPC: "2.0", ID: id, Error: struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}{code, msg}})
	writeJSON(w, status, b)
}

// denyResult is the MCP tool error the agent sees for a blocked call.
func denyResult(w http.ResponseWriter, id json.RawMessage, version uint64) {
	text, _ := json.Marshal(fmt.Sprintf("blocked by policy v%d", version))
	writeJSON(w, http.StatusOK, []byte(`{"jsonrpc":"2.0","id":`+string(id)+`,"result":{"content":[{"type":"text","text":`+string(text)+`}],"isError":true}}`))
}
