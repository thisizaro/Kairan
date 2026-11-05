package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// begin points the rig at cp, builds the agent and boots it.
func (r *rig) begin(cp *fakeCP) *Agent {
	r.t.Helper()
	r.cfg.CP = cp.url()
	a := r.build()
	if err := a.Boot(); err != nil {
		r.t.Fatal(err)
	}
	return a
}

func TestPollRequestShape(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.begin(cp)
	d := a.pollOnce(t.Context())
	if d != wire.RetryBackoffMin {
		t.Fatalf("instant 304 gave delay %v, want the minimum backoff (no hot loop)", d)
	}
	if cp.pollCount() != 1 {
		t.Fatalf("polls = %d", cp.pollCount())
	}
	q := cp.polls[0]
	req, err := wire.ParsePollRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	if req.Tenant != tenant || req.ProxyID != proxyID || req.Have != 0 {
		t.Fatalf("query = %+v", req)
	}
	if got := cp.auths[0]; got != wire.BearerPrefix+"tok-secret" {
		t.Fatalf("auth header = %q", got)
	}
}

func TestPollTimeoutIsWireConstant(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if a.pollTimeout != wire.PollClientTimeout || wire.PollClientTimeout != 45*time.Second {
		t.Fatalf("poll timeout = %v", a.pollTimeout)
	}
	if a.statusTimeout != 10*time.Second {
		t.Fatalf("status timeout = %v", a.statusTimeout)
	}
}

// A slow 304 (a real hold) is not delayed again.
func TestPollHeldThen304ReturnsAtOnce(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) {
		r.clk.Advance(wire.PollHold) // the hold passed
		w.WriteHeader(http.StatusNotModified)
	}
	a := r.begin(cp)
	if d := a.pollOnce(t.Context()); d != 0 {
		t.Fatalf("delay after a full hold = %v", d)
	}
}

func TestPollAppliesEnvelope(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	env := r.keys.goodEnv(3, time.Hour)
	cp.pollFn = serveEnv(env, 3)
	a := r.begin(cp)
	if d := a.pollOnce(t.Context()); d != 0 {
		t.Fatalf("delay after apply = %v", d)
	}
	act := r.active()
	if act.State != wire.StateEnforcing || act.Policy.Version != 3 {
		t.Fatalf("active = %+v", act)
	}
	stored, found, err := r.st.Load()
	if err != nil || !found || string(stored.Payload) != string(env.Payload) {
		t.Fatalf("stored = %v %v", found, err)
	}
	es := r.logEntries()
	if len(es) != 1 || es[0].To != 3 || es[0].Result != "" || es[0].Hash != act.Hash {
		t.Fatalf("log = %+v", es)
	}
	if r.stats.Count(MetricApplyOK) != 1 || r.stats.Count(MetricApplyRejected) != 0 {
		t.Fatal("counters")
	}
	// The next poll asks for newer than 3.
	cp.pollFn = nil
	a.pollOnce(t.Context())
	if got := cp.polls[1].Get(wire.QueryHave); got != "3" {
		t.Fatalf("have = %q", got)
	}
	rep := a.report()
	if rep.LastError != nil || rep.AppliedVersion != 3 || rep.LogSeq != 1 {
		t.Fatalf("report = %+v", rep)
	}
}

func TestPollRejections(t *testing.T) {
	r0 := newRig(t)
	k := r0.keys
	tests := []struct {
		name string
		env  func() wire.Envelope
		code wire.ErrorCode
	}{
		{"one signature", func() wire.Envelope { return signed(payload(9, tenant, start.Add(time.Hour)), k.a) }, wire.ErrThreshold},
		{"same key twice", func() wire.Envelope { return signed(payload(9, tenant, start.Add(time.Hour)), k.a, k.a) }, wire.ErrThreshold},
		{"outsider keys", func() wire.Envelope {
			return signed(payload(9, tenant, start.Add(time.Hour)), seedKey("x"), seedKey("y"))
		}, wire.ErrThreshold},
		{"wrong tenant", func() wire.Envelope { return signed(payload(9, "other", start.Add(time.Hour)), k.a, k.b) }, wire.ErrWrongTenant},
		{"expired", func() wire.Envelope { return signed(payload(9, tenant, start.Add(-30*time.Minute)), k.a, k.b) }, wire.ErrExpired},
		{"same version", func() wire.Envelope { return k.goodEnv(2, time.Hour) }, wire.ErrNotNewer},
		{"older version", func() wire.Envelope { return k.goodEnv(1, time.Hour) }, wire.ErrNotNewer},
		{"payload type", func() wire.Envelope {
			e := k.goodEnv(9, time.Hour)
			e.PayloadType = "text/plain"
			return e
		}, wire.ErrPayloadType},
		{"payload changed after signing", func() wire.Envelope {
			e := k.goodEnv(9, time.Hour)
			e.Payload = payload(9, tenant, start.Add(24*time.Hour))
			return e
		}, wire.ErrThreshold},
		{"malformed policy", func() wire.Envelope { return signed([]byte(`{"tenant":"bank-a"}`), k.a, k.b) }, wire.ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.seedDisk(r.keys.goodEnv(2, time.Hour), true)
			r = reopenRig(r)
			cp := newFakeCP(t)
			cp.pollFn = serveEnv(tc.env(), 9)
			a := r.begin(cp)
			before := r.active()
			d := a.pollOnce(t.Context())
			if d < wire.RetryBackoffMin || d > wire.RetryBackoffMax {
				t.Fatalf("delay = %v", d)
			}
			if r.active() != before || r.active().Policy.Version != 2 || r.active().State != wire.StateEnforcing {
				t.Fatalf("policy in force changed: %+v", r.active())
			}
			stored, _, _ := r.st.Load()
			if v := string(stored.Payload); !strings.Contains(v, `"version":2`) {
				t.Fatalf("stored policy changed: %s", v)
			}
			rep := a.report()
			if rep.LastError == nil || rep.LastError.Code != tc.code {
				t.Fatalf("last_error = %+v, want %s", rep.LastError, tc.code)
			}
			if rep.Validate() != nil || rep.AppliedVersion != 2 || rep.Counters.EnvelopesRejected != 1 {
				t.Fatalf("report = %+v", rep)
			}
			es := r.logEntries()
			last := es[len(es)-1]
			if len(es) != 2 || last.Result != tc.code || last.From != 2 {
				t.Fatalf("log = %+v", es)
			}
		})
	}
}

func reopenRig(r *rig) *rig {
	r.reopen()
	return r
}

func TestPollGarbageBody(t *testing.T) {
	bodies := map[string]string{
		"not json":        `<html>`,
		"empty":           ``,
		"unknown field":   `{"version":1,"envelope":{},"extra":1}`,
		"envelope string": `{"version":1,"envelope":"x"}`,
		"trailing":        `{"version":1,"envelope":{"payloadType":"x","payload":"","signatures":[]}} {}`,
		"huge":            `{"version":1,"envelope":"` + strings.Repeat("a", wire.MaxEnvelopeBytes+2000) + `"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			cp := newFakeCP(t)
			cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }
			a := r.begin(cp)
			if d := a.pollOnce(t.Context()); d < wire.RetryBackoffMin {
				t.Fatalf("delay = %v", d)
			}
			if act := r.active(); act.State != wire.StateDenyAll || act.Policy != nil {
				t.Fatalf("active = %+v", act)
			}
			if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrMalformed {
				t.Fatalf("report = %+v", rep.LastError)
			}
		})
	}
}

// A repeat of the same bad envelope is counted every time but written to the
// apply log once.
func TestRejectionLogDedupe(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(signed(payload(9, tenant, start.Add(time.Hour)), r.keys.a), 9)
	a := r.begin(cp)
	for i := 0; i < 5; i++ {
		a.pollOnce(t.Context())
	}
	if n := len(r.logEntries()); n != 1 {
		t.Fatalf("log has %d entries for 5 identical rejections", n)
	}
	if got := r.stats.Count(MetricApplyRejected); got != 5 {
		t.Fatalf("rejected counter = %d", got)
	}
	// A different failure is a new entry.
	cp.pollFn = serveEnv(signed(payload(9, "other", start.Add(time.Hour)), r.keys.a, r.keys.b), 9)
	a.pollOnce(t.Context())
	if n := len(r.logEntries()); n != 2 {
		t.Fatalf("log entries = %d", n)
	}
}

func TestBackoffSchedule(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":"internal"}`, http.StatusInternalServerError)
	}
	a := r.begin(cp)
	a.jitter = func() float64 { return 1 }
	var got []time.Duration
	for i := 0; i < 6; i++ {
		got = append(got, a.pollOnce(t.Context()))
	}
	want := []time.Duration{500 * time.Millisecond, time.Second, 2 * time.Second, 4 * time.Second, 5 * time.Second, 5 * time.Second}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("delays = %v, want %v", got, want)
		}
	}
	a.jitter = func() float64 { return 0 }
	if d := a.pollOnce(t.Context()); d != wire.RetryBackoffMin {
		t.Fatalf("zero jitter delay = %v", d)
	}
	// A success resets it.
	cp.pollFn = nil
	a.jitter = func() float64 { return 1 }
	a.pollOnce(t.Context())
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) }
	if d := a.pollOnce(t.Context()); d != wire.RetryBackoffMin {
		t.Fatalf("delay after success then failure = %v", d)
	}
	if r.stats.Count(MetricPollErrors) != 8 {
		t.Fatalf("poll errors = %d", r.stats.Count(MetricPollErrors))
	}
}

func TestBackoffAlwaysWithinBounds(t *testing.T) {
	r := newRig(t)
	a := r.build()
	for n := 0; n < 40; n++ {
		for _, j := range []float64{0, 0.3, 0.999999} {
			a.jitter = func() float64 { return j }
			if d := a.backoffFor(n); d < wire.RetryBackoffMin || d > wire.RetryBackoffMax {
				t.Fatalf("n=%d j=%v delay %v out of range", n, j, d)
			}
		}
	}
}

func TestPoll503HonoursRetryAfter(t *testing.T) {
	httpDate := func(d time.Duration) string { return start.Add(d).UTC().Format(http.TimeFormat) }
	tests := []struct {
		name     string
		header   string
		min, max time.Duration
	}{
		{"seconds", "30", 30 * time.Second, 36 * time.Second},
		{"zero is raised to the minimum", "0", wire.RetryBackoffMin, wire.RetryBackoffMin + wire.RetryBackoffMin/5},
		{"capped", "86400", maxRetryAfter, maxRetryAfter + maxRetryAfter/5},
		{"http date", httpDate(60 * time.Second), 60 * time.Second, 72 * time.Second},
		{"date in the past", httpDate(-time.Hour), wire.RetryBackoffMin, wire.RetryBackoffMin + wire.RetryBackoffMin/5},
		{"missing header: normal backoff", "", wire.RetryBackoffMin, wire.RetryBackoffMax},
		{"garbage header: normal backoff", "soon", wire.RetryBackoffMin, wire.RetryBackoffMax},
		{"negative: normal backoff", "-5", wire.RetryBackoffMin, wire.RetryBackoffMax},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for _, j := range []float64{0, 0.5, 0.999} {
				r := newRig(t)
				cp := newFakeCP(t)
				cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) {
					if tc.header != "" {
						w.Header().Set("Retry-After", tc.header)
					}
					w.Header().Set("Content-Type", wire.ContentTypeJSON)
					w.WriteHeader(http.StatusServiceUnavailable)
					json.NewEncoder(w).Encode(wire.ErrorResponse{Code: wire.ErrUnavailable})
				}
				a := r.begin(cp)
				a.jitter = func() float64 { return j }
				d := a.pollOnce(t.Context())
				if d < tc.min || d > tc.max {
					t.Fatalf("jitter %v: delay %v not in [%v, %v]", j, d, tc.min, tc.max)
				}
			}
		})
	}
}

func TestPollNetworkErrorKeepsPolicy(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(2, time.Hour), true)
	r.reopen()
	cp := newFakeCP(t)
	a := r.begin(cp)
	cp.srv.Close()
	d := a.pollOnce(t.Context())
	if d < wire.RetryBackoffMin || d > wire.RetryBackoffMax {
		t.Fatalf("delay = %v", d)
	}
	if r.active().State != wire.StateEnforcing || r.active().Policy.Version != 2 {
		t.Fatal("policy changed by a network error")
	}
	if r.stats.Count(MetricPollErrors) != 1 {
		t.Fatal("poll error not counted")
	}
}

func TestPollClientTimeout(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	release := make(chan struct{})
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, req *http.Request) {
		select {
		case <-req.Context().Done():
		case <-release:
		}
	}
	t.Cleanup(func() { close(release) })
	a := r.begin(cp)
	a.pollTimeout = 50 * time.Millisecond
	if d := a.pollOnce(t.Context()); d < wire.RetryBackoffMin {
		t.Fatalf("delay = %v", d)
	}
	if r.stats.Count(MetricPollErrors) != 1 {
		t.Fatal("timeout not counted")
	}
}

func TestPollCancelReturnsPromptly(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, req *http.Request) { <-req.Context().Done() }
	a := r.begin(cp)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan time.Duration)
	go func() { done <- a.pollOnce(ctx) }()
	cancel()
	select {
	case d := <-done:
		if d != 0 || r.stats.Count(MetricPollErrors) != 0 {
			t.Fatalf("shutdown counted as a poll failure: %v", d)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pollOnce ignored cancellation")
	}
}

func TestPollRefusesRedirectWithToken(t *testing.T) {
	r := newRig(t)
	hit := make(chan string, 1)
	other := newFakeCP(t)
	other.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, req *http.Request) {
		hit <- req.Header.Get("Authorization")
	}
	cp := newFakeCP(t)
	cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, other.srv.URL+wire.PathPoll, http.StatusTemporaryRedirect)
	}
	r.hc, _ = NewHTTPClient("")
	a := r.begin(cp)
	if d := a.pollOnce(t.Context()); d < wire.RetryBackoffMin {
		t.Fatalf("delay %v", d)
	}
	select {
	case <-hit:
		t.Fatal("agent followed a redirect and sent its token")
	default:
	}
}

// ---- failure windows of apply ----

func TestApplyPersistFailureKeepsPolicy(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(r.keys.goodEnv(4, time.Hour), 4)
	a := r.begin(cp)
	// A directory where the file should go makes the final rename fail.
	if err := os.Mkdir(r.st.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.st.Path()+"/x", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if d := a.pollOnce(t.Context()); d < wire.RetryBackoffMin {
		t.Fatalf("delay %v", d)
	}
	if act := r.active(); act.State != wire.StateDenyAll || act.Policy != nil {
		t.Fatalf("active = %+v", act)
	}
	rep := a.report()
	if rep.LastError == nil || rep.LastError.Code != wire.ErrPersist || rep.LastError.Version != 4 {
		t.Fatalf("report = %+v", rep.LastError)
	}
	es := r.logEntries()
	if len(es) != 1 || es[0].Result != wire.ErrPersist || es[0].To != 4 {
		t.Fatalf("log = %+v", es)
	}
}

// Save worked but the log is dead: the old policy stays; after a restart the
// newer file is accepted and a repair entry is written (the M-D33 window).
func TestApplyLogAppendFailureThenBootRepair(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(2, time.Hour), true)
	r.reopen()
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(r.keys.goodEnv(3, time.Hour), 3)
	a := r.begin(cp)
	r.al.Close() // appends now fail
	a.pollOnce(t.Context())
	if act := r.active(); act.Policy.Version != 2 {
		t.Fatalf("v%d in force after a failed append", act.Policy.Version)
	}
	if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrPersist {
		t.Fatalf("report = %+v", rep.LastError)
	}
	a = r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if act := r.active(); act.Policy.Version != 3 || act.State != wire.StateEnforcing {
		t.Fatalf("after restart: %+v", act)
	}
	es := r.logEntries()
	if last := es[len(es)-1]; last.To != 3 || last.Result != "" {
		t.Fatalf("log = %+v", es)
	}
}

func TestNoApplyWithoutLog(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(r.keys.goodEnv(3, time.Hour), 3)
	r.cfg.CP = cp.url()
	r.cfg.LogOpenErr = os.ErrInvalid
	a, err := New(r.cfg, r.st, nil, r.holder, r.clk, r.hc, quietLog(), r.stats)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	a.pollOnce(t.Context())
	if act := r.active(); act.State != wire.StateTampered {
		t.Fatalf("active = %+v", act)
	}
	if _, found, _ := r.st.Load(); found {
		t.Fatal("policy saved although it could not be logged")
	}
	if rep := a.report(); rep.LogSeq != 0 || rep.Validate() != nil {
		t.Fatalf("report = %+v", rep)
	}
}

// Tampered recovers only through a version above everything the log applied.
func TestTamperedRecoversOnlyWithNewerVersion(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(5, time.Hour), true)
	if err := os.WriteFile(r.st.Path(), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reopen()
	cp := newFakeCP(t)
	a := r.begin(cp)
	if r.active().State != wire.StateTampered {
		t.Fatal("not tampered")
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(5, time.Hour), 5)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateTampered {
		t.Fatal("v5 (already applied once) lifted tampered")
	}
	if got := cp.polls[0].Get(wire.QueryHave); got != "5" {
		t.Fatalf("have = %q, want the log's floor", got)
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 6 {
		t.Fatalf("active = %+v", act)
	}
	if rep := a.report(); rep.LastError != nil || rep.Validate() != nil {
		t.Fatalf("report = %+v", rep)
	}
}

// ---- expiry ----

func TestExpiryMovesToSafeModeAndNewPolicyLiftsIt(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(r.keys.goodEnv(3, 10*time.Minute), 3)
	a := r.begin(cp)
	a.pollOnce(t.Context())
	a.checkExpiry()
	if r.active().State != wire.StateEnforcing {
		t.Fatal("expired too early")
	}
	r.clk.Advance(10*time.Minute + time.Minute - time.Nanosecond) // expires_at + skew - 1ns
	a.checkExpiry()
	if r.active().State != wire.StateEnforcing {
		t.Fatal("expired before expires_at + skew")
	}
	r.clk.Advance(time.Nanosecond)
	a.checkExpiry()
	act := r.active()
	if act.State != wire.StateSafeMode || act.Policy == nil || act.Policy.Version != 3 {
		t.Fatalf("active = %+v", act)
	}
	if rep := a.report(); rep.State != wire.StateSafeMode || rep.AppliedVersion != 3 || rep.Validate() != nil {
		t.Fatalf("report = %+v", rep)
	}
	if r.stats.Count(MetricExpired) != 1 {
		t.Fatal("expiry not counted")
	}
	a.checkExpiry()
	if r.stats.Count(MetricExpired) != 1 {
		t.Fatal("expiry counted twice")
	}
	cp.pollFn = serveEnv(signed(payload(4, tenant, r.clk.Now().Add(time.Hour)), r.keys.a, r.keys.b), 4)
	a.pollOnce(t.Context())
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 4 {
		t.Fatalf("active = %+v", act)
	}
}

// Setting the wall clock back must not extend a policy (M-D30).
func TestExpiryIgnoresWallClockSetBack(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	cp.pollFn = serveEnv(r.keys.goodEnv(3, 10*time.Minute), 3)
	a := r.begin(cp)
	a.pollOnce(t.Context())
	r.clk.Set(start.Add(-24 * time.Hour)) // an attacker steps the clock back a day
	a.checkExpiry()
	if r.active().State != wire.StateEnforcing {
		t.Fatal("expired by the step alone")
	}
	r.clk.Advance(12 * time.Minute) // monotonic time moves 12 minutes
	a.checkExpiry()
	if got := r.active().State; got != wire.StateSafeMode {
		t.Fatalf("state = %s; a clock set back extended the policy", got)
	}
	if rep := a.report(); rep.State != wire.StateSafeMode {
		t.Fatalf("report %+v", rep)
	}
}

func TestUntilExpiry(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.untilExpiry(); ok {
		t.Fatal("deny-all has no expiry")
	}
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	a = r.reopen()
	a.Boot()
	d, ok := a.untilExpiry()
	if !ok || d != time.Hour+time.Minute {
		t.Fatalf("until expiry = %v %v", d, ok)
	}
	r.clk.Advance(3 * time.Hour)
	a.checkExpiry()
	if _, ok := a.untilExpiry(); ok {
		t.Fatal("safe mode has no expiry")
	}
}

func TestParseRetryAfterTable(t *testing.T) {
	now := start
	tests := []struct {
		in   string
		want time.Duration
		ok   bool
	}{
		{"", 0, false}, {"0", 0, true}, {"7", 7 * time.Second, true}, {"300", 5 * time.Minute, true},
		{"301", 5 * time.Minute, true}, {"-1", 0, false}, {"1.5", 0, false}, {" 5", 0, false},
		{"99999999999999999999", 0, false}, {"4294967295", maxRetryAfter, true},
		{now.Add(20 * time.Second).UTC().Format(http.TimeFormat), 20 * time.Second, true},
		{now.Add(-time.Hour).UTC().Format(http.TimeFormat), 0, true},
		{strconv.Itoa(1 << 40), 0, false},
	}
	for _, tc := range tests {
		got, ok := parseRetryAfter(tc.in, now)
		if ok != tc.ok || got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, %v; want %v, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func FuzzParseRetryAfter(f *testing.F) {
	for _, s := range []string{"", "0", "30", "-1", "Mon, 02 Jan 2006 15:04:05 GMT", "99999999999999999999", "1e3", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		d, ok := parseRetryAfter(s, start)
		if ok && (d < 0 || d > maxRetryAfter) {
			t.Fatalf("parseRetryAfter(%q) = %v", s, d)
		}
		if !ok && d != 0 {
			t.Fatalf("not ok but %v", d)
		}
	})
}

// Whatever the control plane sends, the policy in force is only ever replaced
// by a verified one.
func FuzzPollBody(f *testing.F) {
	f.Add([]byte(`{"version":1,"envelope":{"payloadType":"x","payload":"e30=","signatures":[]}}`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"version":1,"envelope":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		r := newRig(t)
		a := r.build()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		a.onPollBody(strings.NewReader(string(body)))
		if act := r.active(); act.State != wire.StateDenyAll || act.Policy != nil {
			t.Fatalf("garbage body changed the policy: %+v", act)
		}
	})
}
