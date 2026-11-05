package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kairan/internal/wire"
)

const (
	// IDPrefix marks every simulated proxy ID.
	IDPrefix = "sim-"
	// Label is printed in the result and on stderr; never claim real proxies.
	Label = "SIMULATED proxies from kairan-sim: not real kairan-proxy processes; they do not verify signatures or enforce policy"

	maxProxies     = 1_000_000
	statusTimeout  = 10 * time.Second // M-D31: agent status POST timeout
	maxRetryAfter  = 60 * time.Second
	pollBodyLimit  = wire.MaxEnvelopeBytes + 4<<10
	defaultPattern = "sim-token-{n}"
)

// Config describes one simulation. Zero timing fields take the wire constants.
type Config struct {
	CP           *url.URL
	Tenant       wire.ID
	N            int
	TokenPattern string        // "{n}" is replaced by the zero-padded proxy number
	Ramp         time.Duration // stagger proxy start-up uniformly over this window
	UntilVersion uint64        // stop once every proxy has acked a version >= this (0 = never)

	PollHold       time.Duration
	StatusInterval time.Duration
	StatusTimeout  time.Duration
	BackoffMin     time.Duration
	BackoffMax     time.Duration

	Client *http.Client // optional; tests only
}

// PollTimeout is the per-poll client timeout: wire.PollClientTimeout, 45s (M-D40).
func (c Config) PollTimeout() time.Duration { return wire.PollClientTimeout }

func proxyIDs(n int) []wire.ID {
	ids := make([]wire.ID, n)
	for i := range ids {
		ids[i] = wire.ID(fmt.Sprintf("%s%04d", IDPrefix, i))
	}
	return ids
}

func tokenFor(pattern string, i int) string {
	return strings.ReplaceAll(pattern, "{n}", fmt.Sprintf("%04d", i))
}

// Sim runs the simulated proxies.
type Sim struct {
	cfg    Config
	client *http.Client
	col    *collector
	ids    []wire.ID

	cancel context.CancelFunc
}

// New validates cfg and fills defaults.
func New(cfg Config) (*Sim, error) {
	switch {
	case cfg.CP == nil || (cfg.CP.Scheme != "http" && cfg.CP.Scheme != "https") || cfg.CP.Host == "":
		return nil, errors.New("cp must be an http(s) URL with a host")
	case !cfg.Tenant.Valid():
		return nil, errors.New("tenant is not a valid ID")
	case cfg.N < 1 || cfg.N > maxProxies:
		return nil, fmt.Errorf("n must be 1..%d", maxProxies)
	case cfg.Ramp < 0:
		return nil, errors.New("ramp must not be negative")
	}
	if cfg.TokenPattern == "" {
		cfg.TokenPattern = defaultPattern
	}
	if cfg.PollHold == 0 {
		cfg.PollHold = wire.PollHold
	}
	if cfg.StatusInterval == 0 {
		cfg.StatusInterval = wire.StatusInterval
	}
	if cfg.StatusTimeout == 0 {
		cfg.StatusTimeout = statusTimeout
	}
	if cfg.BackoffMin == 0 {
		cfg.BackoffMin = wire.RetryBackoffMin
	}
	if cfg.BackoffMax == 0 {
		cfg.BackoffMax = wire.RetryBackoffMax
	}
	if cfg.BackoffMax < cfg.BackoffMin {
		cfg.BackoffMax = cfg.BackoffMin
	}
	s := &Sim{cfg: cfg, ids: proxyIDs(cfg.N), col: newCollector()}
	s.client = cfg.Client
	if s.client == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxIdleConns = 2 * cfg.N
		tr.MaxIdleConnsPerHost = 2 * cfg.N
		s.client = &http.Client{Transport: tr} // timeouts are per request, see pollOnce and post
	}
	return s, nil
}

// Run runs until ctx ends or UntilVersion is reached, then returns the results.
func (s *Sim) Run(parent context.Context) *Result {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	defer cancel()
	started := time.Now()

	var wg sync.WaitGroup
	proxies := make([]*proxy, len(s.ids))
	for i, id := range s.ids {
		p := &proxy{s: s, id: id, tok: tokenFor(s.cfg.TokenPattern, i), kick: make(chan struct{}, 1), start: time.Now()}
		proxies[i] = p
		wg.Add(1)
		go func() {
			defer wg.Done()
			if s.cfg.Ramp > 0 {
				if !sleep(ctx, time.Duration(rand.Int64N(int64(s.cfg.Ramp)))) {
					return
				}
			}
			p.start = time.Now()
			var inner sync.WaitGroup
			inner.Add(2)
			go func() { defer inner.Done(); p.pollLoop(ctx) }()
			go func() { defer inner.Done(); p.statusLoop(ctx) }()
			inner.Wait()
		}()
	}
	wg.Wait()

	final := map[string]int{}
	for _, p := range proxies {
		final[strconv.FormatUint(p.currentVersion(), 10)]++
	}
	return s.col.result(s.cfg, started, time.Since(started), final)
}

func (s *Sim) onAck(id wire.ID, v uint64) {
	if s.cfg.UntilVersion == 0 || v < s.cfg.UntilVersion {
		return
	}
	if s.col.markDone(id) >= s.cfg.N {
		s.cancel()
	}
}

// proxy is one simulated proxy.
type proxy struct {
	s     *Sim
	id    wire.ID
	tok   string
	kick  chan struct{}
	start time.Time

	mu       sync.Mutex
	version  uint64
	hash     wire.Hash
	logSeq   uint64
	logHead  wire.Hash
	seq      uint64
	lastErr  *wire.ApplyError
	rejected uint64
	acked    uint64
}

func (p *proxy) currentVersion() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

func (p *proxy) wake() {
	select {
	case p.kick <- struct{}{}:
	default:
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// backoff is exponential with full jitter between BackoffMin and BackoffMax.
func (c Config) backoff(fails int) time.Duration {
	hi := c.BackoffMin
	for i := 0; i < fails && hi < c.BackoffMax; i++ {
		hi *= 2
	}
	if hi > c.BackoffMax {
		hi = c.BackoffMax
	}
	if hi <= c.BackoffMin {
		return c.BackoffMin
	}
	return c.BackoffMin + time.Duration(rand.Int64N(int64(hi-c.BackoffMin)))
}

// parseRetryAfter reads delay-seconds or an HTTP date; the result is capped at 60s.
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	var d time.Duration
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n < 0 {
			return 0, false
		}
		if n > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter, true
		}
		d = time.Duration(n) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
		if d < 0 {
			d = 0
		}
	} else {
		return 0, false
	}
	if d > maxRetryAfter {
		d = maxRetryAfter
	}
	return d, true
}

type pollKind int

const (
	pollApplied pollKind = iota
	pollNotModified
	pollUnavailable
	pollFailed
)

func (p *proxy) pollLoop(ctx context.Context) {
	cfg := p.s.cfg
	fails := 0
	for ctx.Err() == nil {
		kind, retryAfter := p.pollOnce(ctx)
		switch kind {
		case pollApplied, pollNotModified:
			fails = 0
		case pollUnavailable:
			if retryAfter >= 0 {
				// Honour Retry-After, plus a little jitter so a storm does not return in lockstep.
				j := time.Duration(rand.Int64N(int64(cfg.BackoffMin) + 1))
				sleep(ctx, retryAfter+j)
				continue
			}
			fails++
			sleep(ctx, cfg.backoff(fails))
		default:
			fails++
			sleep(ctx, cfg.backoff(fails))
		}
	}
}

// pollOnce does one long-poll. retryAfter is -1 when no usable header was sent.
func (p *proxy) pollOnce(ctx context.Context) (pollKind, time.Duration) {
	cfg := p.s.cfg
	have := p.currentVersion()
	q := wire.PollRequest{Tenant: cfg.Tenant, ProxyID: p.id, Have: have}.Query()
	u := *cfg.CP
	u.Path = strings.TrimSuffix(u.Path, "/") + wire.PathPoll
	u.RawQuery = q.Encode()

	rctx, cancel := context.WithTimeout(ctx, cfg.PollTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		p.s.col.pollError("request")
		return pollFailed, -1
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+p.tok)
	req.Header.Set("User-Agent", "kairan-sim (simulated proxy)")

	t0 := time.Now()
	resp, err := p.s.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			p.s.col.pollError("transport")
		}
		return pollFailed, -1
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotModified:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		p.s.col.pollDone("304", time.Since(t0))
		return pollNotModified, 0
	case http.StatusOK:
		var pr wire.PollResponse
		derr := wire.Decode(resp.Body, pollBodyLimit, &pr)
		lat := time.Since(t0)
		if ctx.Err() != nil {
			return pollFailed, -1
		}
		if derr != nil {
			p.s.col.pollError("bad_body")
			return pollFailed, -1
		}
		p.s.col.pollDone("200", lat)
		if !p.apply(pr) {
			return pollFailed, -1
		}
		return pollApplied, 0
	case http.StatusServiceUnavailable:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		p.s.col.pollUnavailable()
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return pollUnavailable, d
		}
		return pollUnavailable, -1
	default:
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
		p.s.col.pollError("http_" + strconv.Itoa(resp.StatusCode))
		return pollFailed, -1
	}
}

// apply "applies" a polled envelope. It checks only the shape and that the version moves
// forward: kairan-sim holds no trusted keys, so it never verifies signatures.
func (p *proxy) apply(pr wire.PollResponse) bool {
	reject := func(code wire.ErrorCode) bool {
		p.mu.Lock()
		p.rejected++
		p.lastErr = &wire.ApplyError{Code: code, Version: pr.Version}
		p.mu.Unlock()
		p.s.col.pollError("bad_body")
		p.wake()
		return false
	}
	if err := pr.Envelope.ValidateShape(); err != nil {
		return reject(wire.ErrMalformed)
	}
	p.mu.Lock()
	if pr.Version <= p.version {
		p.mu.Unlock()
		return reject(wire.ErrNotNewer)
	}
	sum := sha256.Sum256(pr.Envelope.Payload)
	p.version = pr.Version
	p.hash = wire.Hash(hex.EncodeToString(sum[:]))
	p.logSeq++
	head := sha256.Sum256([]byte(string(p.logHead) + "|" + strconv.FormatUint(pr.Version, 10) + "|" + string(p.hash)))
	p.logHead = wire.Hash(hex.EncodeToString(head[:]))
	p.lastErr = nil
	p.mu.Unlock()
	p.s.col.applied(pr.Version, time.Now())
	p.wake()
	return true
}

func (p *proxy) report() wire.StatusReport {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seq++
	r := wire.StatusReport{
		Tenant:         p.s.cfg.Tenant,
		ProxyID:        p.id,
		Seq:            p.seq,
		State:          wire.StateDenyAll,
		AppliedVersion: p.version,
		PolicyHash:     p.hash,
		LogSeq:         p.logSeq,
		LogHead:        p.logHead,
		UptimeSeconds:  uint64(time.Since(p.start) / time.Second),
		Counters:       wire.Counters{EnvelopesRejected: p.rejected},
	}
	if p.version > 0 {
		r.State = wire.StateEnforcing
	}
	if p.lastErr != nil {
		e := *p.lastErr
		r.LastError = &e
	}
	return r
}

func (p *proxy) statusLoop(ctx context.Context) {
	timer := time.NewTimer(0) // first report right away
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-p.kick:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		p.sendStatus(ctx)
		timer.Reset(p.s.cfg.StatusInterval)
	}
}

// sendStatus retries with backoff (or Retry-After) until the control plane accepts a report.
func (p *proxy) sendStatus(ctx context.Context) {
	cfg := p.s.cfg
	fails := 0
	for ctx.Err() == nil {
		rep := p.report()
		d, ok := p.post(ctx, rep)
		if ok {
			p.afterAck(rep)
			return
		}
		if ctx.Err() != nil {
			return
		}
		fails++
		if d < 0 {
			d = cfg.backoff(fails)
		} else {
			d += time.Duration(rand.Int64N(int64(cfg.BackoffMin) + 1))
		}
		sleep(ctx, d)
	}
}

func (p *proxy) afterAck(rep wire.StatusReport) {
	p.mu.Lock()
	newer := rep.AppliedVersion > p.acked
	if newer {
		p.acked = rep.AppliedVersion
	}
	p.mu.Unlock()
	if newer {
		p.s.col.acked(rep.AppliedVersion, time.Now())
		p.s.onAck(p.id, rep.AppliedVersion)
	}
}

// post sends one report. On failure d is the Retry-After wait, or -1 for "use backoff".
func (p *proxy) post(ctx context.Context, rep wire.StatusReport) (d time.Duration, ok bool) {
	cfg := p.s.cfg
	body, err := marshalStatus(rep)
	if err != nil {
		p.s.col.statusError("encode")
		return -1, false
	}
	u := *cfg.CP
	u.Path = strings.TrimSuffix(u.Path, "/") + wire.PathStatus
	rctx, cancel := context.WithTimeout(ctx, cfg.StatusTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, u.String(), strings.NewReader(body))
	if err != nil {
		p.s.col.statusError("request")
		return -1, false
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+p.tok)
	req.Header.Set("Content-Type", wire.ContentTypeJSON)
	req.Header.Set("User-Agent", "kairan-sim (simulated proxy)")

	t0 := time.Now()
	resp, err := p.s.client.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			p.s.col.statusError("transport")
		}
		return -1, false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	lat := time.Since(t0)
	switch resp.StatusCode {
	case http.StatusNoContent:
		p.s.col.statusDone(lat)
		return 0, true
	case http.StatusServiceUnavailable:
		p.s.col.statusError("http_503")
		if ra, ok := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now()); ok {
			return ra, false
		}
		return -1, false
	default:
		p.s.col.statusError("http_" + strconv.Itoa(resp.StatusCode))
		return -1, false
	}
}

// ---- results ----

// Latency summarises durations in milliseconds (nearest-rank percentiles).
type Latency struct {
	Count int     `json:"count"`
	P50   float64 `json:"p50"`
	P95   float64 `json:"p95"`
	P99   float64 `json:"p99"`
	Max   float64 `json:"max"`
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

func summarize(ds []time.Duration) Latency {
	if len(ds) == 0 {
		return Latency{}
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	at := func(p float64) float64 {
		i := int(p*float64(len(s))+0.999999999) - 1
		if i < 0 {
			i = 0
		}
		if i >= len(s) {
			i = len(s) - 1
		}
		return ms(s[i])
	}
	return Latency{Count: len(s), P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: ms(s[len(s)-1])}
}

// PollStats counts long-polls. LatencyMS is keyed by "200" and "304"; a 304 includes the hold.
type PollStats struct {
	Total       int                `json:"total"`
	Modified    int                `json:"modified"`
	NotModified int                `json:"not_modified"`
	Unavailable int                `json:"unavailable"`
	Errors      int                `json:"errors"`
	LatencyMS   map[string]Latency `json:"latency_ms"`
}

// StatusStats counts status POSTs; latency is request to 204.
type StatusStats struct {
	Sent      int     `json:"sent"`
	OK        int     `json:"ok"`
	Errors    int     `json:"errors"`
	LatencyMS Latency `json:"latency_ms"`
}

// VersionAck aggregates one policy version across all proxies (Unix milliseconds, local clock).
type VersionAck struct {
	Version            uint64 `json:"version"`
	Proxies            int    `json:"proxies"`
	FirstAppliedUnixMS int64  `json:"first_applied_unix_ms"`
	LastAppliedUnixMS  int64  `json:"last_applied_unix_ms"`
	FirstAckedUnixMS   int64  `json:"first_acked_unix_ms"`
	LastAckedUnixMS    int64  `json:"last_acked_unix_ms"`
}

// AckStats counts acks: a status report accepted (204) that carries a newer applied version.
type AckStats struct {
	Total     int          `json:"total"`
	ByVersion []VersionAck `json:"by_version"`
}

// ErrorStats counts failures by kind: transport, bad_body, http_<code>, request, encode.
type ErrorStats struct {
	Total  int            `json:"total"`
	ByKind map[string]int `json:"by_kind"`
}

// Result is the one JSON document kairan-sim prints.
type Result struct {
	Simulated     bool           `json:"simulated"`
	Tool          string         `json:"tool"`
	Label         string         `json:"label"`
	CP            string         `json:"cp"`
	Tenant        wire.ID        `json:"tenant"`
	Proxies       int            `json:"proxies"`
	IDPrefix      string         `json:"id_prefix"`
	StartedAt     string         `json:"started_at"`
	DurationMS    int64          `json:"duration_ms"`
	Polls         PollStats      `json:"polls"`
	Status        StatusStats    `json:"status"`
	Acks          AckStats       `json:"acks"`
	Errors        ErrorStats     `json:"errors"`
	FinalVersions map[string]int `json:"final_versions"` // applied version -> number of proxies
}

type verAgg struct {
	proxies                   int
	firstApplied, lastApplied time.Time
	firstAcked, lastAcked     time.Time
	appliedCount              int
}

type collector struct {
	mu          sync.Mutex
	lat         map[string][]time.Duration
	pollUnavail int
	pollErrs    int
	statusLat   []time.Duration
	statusErrs  int
	errs        map[string]int
	versions    map[uint64]*verAgg
	ackTotal    int
	done        map[wire.ID]struct{}
}

func newCollector() *collector {
	return &collector{lat: map[string][]time.Duration{}, errs: map[string]int{},
		versions: map[uint64]*verAgg{}, done: map[wire.ID]struct{}{}}
}

func (c *collector) pollDone(kind string, d time.Duration) {
	c.mu.Lock()
	c.lat[kind] = append(c.lat[kind], d)
	c.mu.Unlock()
}

func (c *collector) pollUnavailable() {
	c.mu.Lock()
	c.pollUnavail++
	c.mu.Unlock()
}

func (c *collector) pollError(kind string) {
	c.mu.Lock()
	c.pollErrs++
	c.errs[kind]++
	c.mu.Unlock()
}

func (c *collector) statusDone(d time.Duration) {
	c.mu.Lock()
	c.statusLat = append(c.statusLat, d)
	c.mu.Unlock()
}

func (c *collector) statusError(kind string) {
	c.mu.Lock()
	c.statusErrs++
	c.errs[kind]++
	c.mu.Unlock()
}

func (c *collector) ver(v uint64) *verAgg {
	a := c.versions[v]
	if a == nil {
		a = &verAgg{}
		c.versions[v] = a
	}
	return a
}

func (c *collector) applied(v uint64, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.ver(v)
	if a.appliedCount == 0 || t.Before(a.firstApplied) {
		a.firstApplied = t
	}
	if t.After(a.lastApplied) {
		a.lastApplied = t
	}
	a.appliedCount++
}

func (c *collector) acked(v uint64, t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	a := c.ver(v)
	if a.proxies == 0 || t.Before(a.firstAcked) {
		a.firstAcked = t
	}
	if t.After(a.lastAcked) {
		a.lastAcked = t
	}
	a.proxies++
	c.ackTotal++
}

func (c *collector) markDone(id wire.ID) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.done[id] = struct{}{}
	return len(c.done)
}

func (c *collector) result(cfg Config, started time.Time, dur time.Duration, final map[string]int) *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	r := &Result{
		Simulated:  true,
		Tool:       "kairan-sim",
		Label:      Label,
		CP:         cfg.CP.String(),
		Tenant:     cfg.Tenant,
		Proxies:    cfg.N,
		IDPrefix:   IDPrefix,
		StartedAt:  started.UTC().Format(time.RFC3339Nano),
		DurationMS: dur.Milliseconds(),
	}
	r.Polls = PollStats{
		Modified:    len(c.lat["200"]),
		NotModified: len(c.lat["304"]),
		Unavailable: c.pollUnavail,
		Errors:      c.pollErrs,
		LatencyMS:   map[string]Latency{"200": summarize(c.lat["200"]), "304": summarize(c.lat["304"])},
	}
	r.Polls.Total = r.Polls.Modified + r.Polls.NotModified + r.Polls.Unavailable + r.Polls.Errors
	r.Status = StatusStats{OK: len(c.statusLat), Errors: c.statusErrs, LatencyMS: summarize(c.statusLat)}
	r.Status.Sent = r.Status.OK + r.Status.Errors
	r.Acks = AckStats{Total: c.ackTotal, ByVersion: []VersionAck{}}
	vs := make([]uint64, 0, len(c.versions))
	for v := range c.versions {
		vs = append(vs, v)
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i] < vs[j] })
	for _, v := range vs {
		a := c.versions[v]
		va := VersionAck{Version: v, Proxies: a.proxies}
		if a.appliedCount > 0 {
			va.FirstAppliedUnixMS, va.LastAppliedUnixMS = a.firstApplied.UnixMilli(), a.lastApplied.UnixMilli()
		}
		if a.proxies > 0 {
			va.FirstAckedUnixMS, va.LastAckedUnixMS = a.firstAcked.UnixMilli(), a.lastAcked.UnixMilli()
		}
		r.Acks.ByVersion = append(r.Acks.ByVersion, va)
	}
	kinds := make(map[string]int, len(c.errs))
	total := 0
	for k, n := range c.errs {
		kinds[k] = n
		total += n
	}
	r.Errors = ErrorStats{Total: total, ByKind: kinds}
	r.FinalVersions = final
	return r
}
