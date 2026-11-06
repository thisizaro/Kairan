package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"kairan/internal/wire"
)

// maxRetryAfter caps how long a Retry-After can park the agent.
const maxRetryAfter = 5 * time.Minute

// maxExpiryCheck bounds the sleep of the expiry loop, so a policy is noticed
// as expired within this long even if a timer were somehow missed.
const maxExpiryCheck = 30 * time.Second

// pollSlack is room for the PollResponse wrapper around a maximal envelope.
const pollSlack = 1 << 10

// Run starts the poll loop, the status loop, the expiry watcher and the
// clock-guard persister, and blocks until ctx is done. It returns the error
// of the final high-water save, nil on a clean shutdown. Boot must have run.
// All traffic is outbound (PRD J2).
func (a *Agent) Run(ctx context.Context) error {
	a.mu.Lock()
	booted := a.booted
	a.mu.Unlock()
	if !booted {
		return errors.New("agent: Run before Boot")
	}
	var wg sync.WaitGroup
	var guardErr error
	wg.Add(4)
	go func() { defer wg.Done(); guardErr = a.cfg.Guard.Run(ctx, a.log) }()
	go func() { defer wg.Done(); a.pollLoop(ctx) }()
	go func() { defer wg.Done(); a.statusLoop(ctx) }()
	go func() { defer wg.Done(); a.expiryLoop(ctx) }()
	wg.Wait()
	return guardErr
}

// sleep waits d on the agent's clock or until ctx ends. It reports whether
// the wait completed.
func (a *Agent) sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-a.clk.After(d):
		return true
	}
}

func (a *Agent) pollLoop(ctx context.Context) {
	for ctx.Err() == nil {
		if !a.sleep(ctx, a.pollOnce(ctx)) {
			return
		}
	}
}

func (a *Agent) expiryLoop(ctx context.Context) {
	for {
		a.checkExpiry()
		wait := maxExpiryCheck
		if d, ok := a.untilExpiry(); ok {
			wait = min(d, maxExpiryCheck)
		}
		if wait <= 0 {
			continue // expiry is due: loop and check again
		}
		select {
		case <-ctx.Done():
			return
		case <-a.wakeEx:
		case <-a.clk.After(wait):
		}
	}
}

func (a *Agent) statusLoop(ctx context.Context) {
	for {
		a.sendStatus(ctx)
		select {
		case <-ctx.Done():
			return
		case <-a.kick:
		case <-a.clk.After(wire.StatusInterval):
		}
	}
}

// backoff is the next delay after a failure: exponential from RetryBackoffMin
// to RetryBackoffMax with full jitter. It counts the failure.
func (a *Agent) backoff() time.Duration {
	a.mu.Lock()
	n := min(a.failures, 16)
	a.failures++
	a.mu.Unlock()
	return a.backoffFor(n)
}

func (a *Agent) backoffFor(n int) time.Duration {
	ceil := wire.RetryBackoffMax
	if n < 16 {
		ceil = min(wire.RetryBackoffMin<<n, wire.RetryBackoffMax)
	}
	return wire.RetryBackoffMin + time.Duration(a.jitter()*float64(ceil-wire.RetryBackoffMin))
}

// pollWait is the delay after a poll answered 503 (or any status with a
// Retry-After): at least what the control plane asked, plus up to 20% jitter
// so a fleet does not return in one wave (THREATS #8). With no usable header
// it is the normal backoff.
func (a *Agent) retryAfterDelay(h http.Header) time.Duration {
	d, ok := parseRetryAfter(h.Get("Retry-After"), a.clk.Now())
	if !ok {
		return a.backoff()
	}
	d = max(d, wire.RetryBackoffMin)
	return d + time.Duration(a.jitter()*float64(d)/5)
}

// parseRetryAfter reads delta-seconds or an HTTP date, clamped to
// [0, maxRetryAfter].
func parseRetryAfter(v string, now time.Time) (time.Duration, bool) {
	if v == "" {
		return 0, false
	}
	if n, err := strconv.ParseUint(v, 10, 32); err == nil {
		return min(time.Duration(n)*time.Second, maxRetryAfter), true
	}
	if t, err := http.ParseTime(v); err == nil {
		return min(max(t.Sub(now), 0), maxRetryAfter), true
	}
	return 0, false
}

// pollOnce makes one long-poll request, applies what it returns, and says how
// long to wait before the next one. Network errors, bad statuses and rejected
// envelopes all keep the current policy and back off; 503 honours
// Retry-After (THREATS #8).
func (a *Agent) pollOnce(ctx context.Context) time.Duration {
	a.mu.Lock()
	have := a.floorLocked()
	a.mu.Unlock()

	t0 := a.clk.Mono()
	u := a.cfg.CP.JoinPath(wire.PathPoll)
	u.RawQuery = wire.PollRequest{Tenant: a.cfg.Tenant, ProxyID: a.cfg.ProxyID, Have: have}.Query().Encode()
	rctx, cancel := context.WithTimeout(ctx, a.pollTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodGet, u.String(), nil)
	if err != nil {
		a.stats.Inc(MetricPollErrors)
		return a.backoff()
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+a.cfg.Token)
	resp, err := a.hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		a.stats.Inc(MetricPollErrors)
		say(a.log, slog.LevelWarn, evPollFailed, "kind", errKind(err))
		return a.backoff()
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return a.onPollBody(resp.Body)
	case http.StatusNotModified:
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
		a.mu.Lock()
		a.failures = 0
		a.mu.Unlock()
		// A hold normally lasts ~30s. A 304 that comes back at once (a
		// displaced poll, a misbehaving server) must not become a hot loop.
		if a.clk.Mono()-t0 < wire.RetryBackoffMin {
			return wire.RetryBackoffMin
		}
		return 0
	case http.StatusServiceUnavailable:
		a.stats.Inc(MetricPollErrors)
		say(a.log, slog.LevelWarn, evCPDown)
		return a.retryAfterDelay(resp.Header)
	default:
		a.stats.Inc(MetricPollErrors)
		say(a.log, slog.LevelWarn, evPollRefuse, "http", resp.StatusCode, "code", string(readErrorCode(resp.Body)))
		return a.backoff()
	}
}

// onPollBody decodes a 200 body and applies it. The envelope inside is read
// with the strict decoder (M-D46), and so is the wrapper around it (duplicate
// and case-variant keys are a rejected answer, Q-D27); the outer version is
// advisory only.
func (a *Agent) onPollBody(body io.Reader) time.Duration {
	version, env, err := decodePoll(body)
	if err != nil {
		a.reject(wire.ErrMalformed, 0, "", a.lastApplied())
		return a.rejectDelay()
	}
	if a.apply(env, version) {
		return 0
	}
	return a.rejectDelay()
}

// rejectDelay is the wait after a rejection, which has already been counted
// as a failure by reject.
func (a *Agent) rejectDelay() time.Duration {
	return a.backoffFor(max(a.failuresNow()-1, 0))
}

func (a *Agent) failuresNow() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return min(a.failures, 16)
}

// readErrorCode reads a wire.ErrorResponse code from a small body, "" if it
// is not one. Only the validated code is ever logged, never the body.
func readErrorCode(r io.Reader) wire.ErrorCode {
	var e wire.ErrorResponse
	if wire.Decode(r, wire.MaxSmallRequestBytes, &e) != nil || !e.Code.Valid() {
		return ""
	}
	return e.Code
}

// errKind names a transport error class without echoing the URL or text.
func errKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	return "network"
}

// report builds the status report from current state. It carries wire types
// only: state, version, hash, apply-log anchor, an error code, uptime and
// three counters. Nothing a caller or a tool said can get in (I4).
func (a *Agent) report() wire.StatusReport {
	var seq uint64
	var head wire.Hash
	if al := a.alog(); al != nil {
		seq, head = al.Head()
	}
	untrusted := a.cfg.Guard.Untrusted()
	a.mu.Lock()
	defer a.mu.Unlock()
	a.seq++
	r := wire.StatusReport{
		Tenant:         a.cfg.Tenant,
		ProxyID:        a.cfg.ProxyID,
		Seq:            a.seq,
		State:          a.st8,
		AppliedVersion: a.appliedVersionLocked(),
		LogSeq:         seq,
		LogHead:        head,
		UptimeSeconds:  uint64(max(a.clk.Mono()-a.started, 0) / time.Second),
		Counters:       a.stats.Counters(),
	}
	if a.view != nil {
		r.PolicyHash = a.view.active.Hash
	}
	// An apply error stays until the next successful apply and wins over the
	// live clock warning: a rollout needs to see why its version failed.
	switch {
	case a.lastErr != nil:
		e := *a.lastErr
		r.LastError = &e
	case untrusted:
		r.LastError = &wire.ApplyError{Code: wire.ErrClockUntrusted}
	}
	return r
}

// sendStatus POSTs one report. A failure is counted and logged; the next
// tick (or the next apply) sends a fresh one. A 503 holds further reports
// until its Retry-After has passed.
func (a *Agent) sendStatus(ctx context.Context) {
	a.mu.Lock()
	held := a.clk.Mono() < a.statusHld
	a.mu.Unlock()
	if held || ctx.Err() != nil {
		return
	}
	rep := a.report()
	if err := rep.Validate(); err != nil {
		a.stats.Inc(MetricStatusErrors)
		say(a.log, slog.LevelError, evStatusBad, "state", string(rep.State))
		return
	}
	body, err := json.Marshal(rep)
	if err != nil || len(body) > wire.MaxStatusBytes {
		a.stats.Inc(MetricStatusErrors)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, a.statusTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, http.MethodPost, a.cfg.CP.JoinPath(wire.PathStatus).String(), bytes.NewReader(body))
	if err != nil {
		a.stats.Inc(MetricStatusErrors)
		return
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+a.cfg.Token)
	req.Header.Set("Content-Type", wire.ContentTypeJSON)
	resp, err := a.hc.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			a.stats.Inc(MetricStatusErrors)
			say(a.log, slog.LevelWarn, evStatusFail, "kind", errKind(err))
		}
		return
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<10))
	switch resp.StatusCode {
	case http.StatusNoContent, http.StatusOK:
	case http.StatusServiceUnavailable:
		a.stats.Inc(MetricStatusErrors)
		d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), a.clk.Now())
		if !ok {
			d = wire.RetryBackoffMax
		}
		d = max(d, wire.RetryBackoffMin)
		a.mu.Lock()
		a.statusHld = a.clk.Mono() + d + time.Duration(a.jitter()*float64(d)/5)
		a.mu.Unlock()
	default:
		a.stats.Inc(MetricStatusErrors)
		say(a.log, slog.LevelWarn, evStatusNo, "http", resp.StatusCode)
	}
}
