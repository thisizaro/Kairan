package agentbreak

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

// No hot loop (THREATS #8): with the fake clock frozen, a server that answers instantly with any non-success
// must be asked only a handful of times, because every wait is on the clock.
func TestNoHotLoopOnAnyAnswer(t *testing.T) {
	answers := map[string]cpAnswer{
		"500":                  {status: 500},
		"502":                  {status: 502},
		"401":                  {status: 401, body: []byte(`{"code":"unauthorized"}`)},
		"403":                  {status: 403},
		"404":                  {status: 404},
		"400":                  {status: 400},
		"429":                  {status: 429, header: map[string]string{"Retry-After": "0"}},
		"503 no Retry-After":   {status: 503},
		"503 Retry-After 0":    {status: 503, header: map[string]string{"Retry-After": "0"}},
		"503 Retry-After -5":   {status: 503, header: map[string]string{"Retry-After": "-5"}},
		"503 Retry-After junk": {status: 503, header: map[string]string{"Retry-After": "soon"}},
		"503 Retry-After NaN":  {status: 503, header: map[string]string{"Retry-After": "NaN"}},
		"503 Retry-After huge": {status: 503, header: map[string]string{"Retry-After": "99999999999999999999"}},
		"304 instantly":        {status: 304},
		"200 empty body":       {status: 200},
		"200 not json":         {status: 200, body: []byte("<html>")},
		"200 json null":        {status: 200, body: []byte("null")},
		"200 empty object":     {status: 200, body: []byte("{}")},
		"302 redirect":         {status: 302, header: map[string]string{"Location": "http://127.0.0.1:1/x"}},
		"204":                  {status: 204},
		"301":                  {status: 301, header: map[string]string{"Location": "/v1/poll"}},
		"307":                  {status: 307, header: map[string]string{"Location": "/v1/poll"}},
	}
	for name, ans := range answers {
		t.Run(name, func(t *testing.T) {
			cp := newCP(t)
			cp.poll = func(int, cpReq) cpAnswer { return ans }
			r := newRig(t, "", nil, cp)
			r.boot()
			r.run()
			time.Sleep(400 * time.Millisecond) // real time; the fake clock does not move
			if n := cp.pollCount(); n > 4 {
				t.Fatalf("%d polls in 400 ms of frozen time: a hot loop", n)
			}
			if r.appliedVersion() != 0 {
				t.Errorf("a policy was applied from %s", name)
			}
		})
	}
}

// Backoff is exponential with full jitter between Min and Max: no retry before RetryBackoffMin, one within
// RetryBackoffMax each time, and the whole minute stays within the arithmetic bound.
func TestBackoffBounds(t *testing.T) {
	cp := newCP(t)
	var at []time.Time
	var atMu sync.Mutex
	r := newRig(t, "", nil, cp)
	cp.poll = func(int, cpReq) cpAnswer {
		atMu.Lock()
		at = append(at, r.clk.Now())
		atMu.Unlock()
		return cpAnswer{status: 500}
	}
	r.boot()
	r.run()
	waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
	settle()
	base := cp.pollCount()
	r.advance(wire.RetryBackoffMin-100*time.Millisecond, 50*time.Millisecond)
	if n := cp.pollCount(); n != base {
		t.Errorf("retried %v early: %d -> %d (minimum is %v)", 100*time.Millisecond, base, n, wire.RetryBackoffMin)
	}
	r.advance(wire.RetryBackoffMax, 100*time.Millisecond)
	if n := cp.pollCount(); n < base+1 {
		t.Errorf("no retry within RetryBackoffMax (%v)", wire.RetryBackoffMax)
	}
	// drive 120 virtual seconds
	start := cp.pollCount()
	r.advance(120*time.Second, 100*time.Millisecond)
	n := cp.pollCount() - start
	if n > 120*2 { // Min = 0.5 s would allow 240; exponential growth must beat that by far
		t.Errorf("%d retries in 120 s", n)
	}
	if n > 60 {
		t.Errorf("%d retries in 120 s: backoff did not grow towards the %v cap", n, wire.RetryBackoffMax)
	}
	if n < 120/6 {
		t.Errorf("only %d retries in 120 s: waits exceed the %v cap", n, wire.RetryBackoffMax)
	}
	// gaps must be at least Min
	atMu.Lock()
	defer atMu.Unlock()
	for i := 1; i < len(at); i++ {
		if g := at[i].Sub(at[i-1]); g < wire.RetryBackoffMin && g != 0 {
			t.Errorf("gap %v between polls %d and %d is below the minimum %v", g, i-1, i, wire.RetryBackoffMin)
		}
	}
}

// A good poll resets the backoff (doc: reset by a good poll).
func TestBackoffResetsAfterGoodPoll(t *testing.T) {
	cp := newCP(t)
	env, _ := validEnv(1)
	cp.poll = func(n int, q cpReq) cpAnswer {
		switch {
		case n <= 8:
			return cpAnswer{status: 500}
		case n == 9:
			return pollJSON(env, 1)
		case n == 10:
			return cpAnswer{status: 500}
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	for i := 0; i < 400 && cp.pollCount() < 10; i++ {
		r.advance(500*time.Millisecond, 250*time.Millisecond)
	}
	if cp.pollCount() < 10 {
		t.Fatalf("scenario did not reach the tenth poll (%d)", cp.pollCount())
	}
	settle()
	base := cp.pollCount()
	// after the good poll the very next failure waits again from the minimum: a retry arrives within Max
	r.advance(wire.RetryBackoffMax+time.Second, 100*time.Millisecond)
	if cp.pollCount() <= base {
		t.Errorf("no poll within %v after a failure that followed a good poll: backoff was not reset", wire.RetryBackoffMax)
	}
}

// Retry-After on 503 (seconds and HTTP date), capped at 5 minutes, plus up to 20% jitter.
func TestRetryAfterIsHonouredAndCapped(t *testing.T) {
	t.Run("seconds", func(t *testing.T) {
		cp := newCP(t)
		cp.poll = func(n int, q cpReq) cpAnswer {
			if n == 1 {
				return cpAnswer{status: 503, header: map[string]string{"Retry-After": "30"}}
			}
			return cpAnswer{status: 304}
		}
		r := newRig(t, "", nil, cp)
		r.boot()
		r.run()
		waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
		r.advance(29*time.Second, 500*time.Millisecond)
		if n := cp.pollCount(); n != 1 {
			t.Fatalf("polled again after 29 s of a 30 s Retry-After (%d polls)", n)
		}
		r.advance(10*time.Second, 500*time.Millisecond) // 30 + 20% = 36
		if n := cp.pollCount(); n < 2 {
			t.Errorf("did not poll again 39 s after Retry-After: 30 (jitter is at most 20%%)")
		}
	})
	t.Run("http date", func(t *testing.T) {
		cp := newCP(t)
		r := newRig(t, "", nil, cp)
		cp.poll = func(n int, q cpReq) cpAnswer {
			if n == 1 {
				return cpAnswer{status: 503, header: map[string]string{"Retry-After": r.clk.Now().Add(60 * time.Second).UTC().Format(http.TimeFormat)}}
			}
			return cpAnswer{status: 304}
		}
		r.boot()
		r.run()
		waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
		r.advance(55*time.Second, time.Second)
		if n := cp.pollCount(); n != 1 {
			t.Fatalf("polled again 55 s into a 60 s Retry-After date (%d polls)", n)
		}
		r.advance(25*time.Second, time.Second)
		if n := cp.pollCount(); n < 2 {
			t.Errorf("did not poll again after the Retry-After date + 20%%")
		}
	})
	t.Run("cap 5 minutes", func(t *testing.T) {
		cp := newCP(t)
		cp.poll = func(n int, q cpReq) cpAnswer {
			if n == 1 {
				return cpAnswer{status: 503, header: map[string]string{"Retry-After": strconv.Itoa(24 * 3600)}}
			}
			return cpAnswer{status: 304}
		}
		r := newRig(t, "", nil, cp)
		r.boot()
		r.run()
		waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
		r.advance(5*time.Minute+time.Minute+10*time.Second, 5*time.Second) // 5 min + 20% jitter
		if n := cp.pollCount(); n < 2 {
			t.Errorf("Retry-After of one day was honoured; the cap is 5 minutes (THREATS #8: a hostile control plane must not park a proxy)")
		}
	})
}

// A 304 that returns at once is not a reason to hammer: the wait is at least RetryBackoffMin.
func TestFast304WaitsMinimum(t *testing.T) {
	cp := newCP(t)
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
	settle()
	base := cp.pollCount()
	r.advance(wire.RetryBackoffMin-100*time.Millisecond, 50*time.Millisecond)
	if n := cp.pollCount(); n != base {
		t.Errorf("repolled after a fast 304 before %v: %d -> %d", wire.RetryBackoffMin, base, n)
	}
}

// A slow 304 (a normal held poll) polls again at once, with have unchanged.
func TestHeldPoll304RepollsAtOnce(t *testing.T) {
	cp := newCP(t)
	r := newRig(t, "", nil, cp)
	cp.poll = func(n int, q cpReq) cpAnswer {
		return cpAnswer{status: 304, delay: func() { r.clk.Advance(wire.PollHold) }}
	}
	r.boot()
	r.run()
	waitFor(t, "several polls", func() bool { return cp.pollCount() >= 3 })
}

// Redirects are never followed: the bearer token must not go to a host the operator did not configure.
func TestRedirectIsNotFollowed(t *testing.T) {
	var hits atomic.Int64
	var gotAuth atomic.Value
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		gotAuth.Store(r.Header.Get("Authorization"))
		w.WriteHeader(200)
	}))
	defer attacker.Close()
	for _, code := range []int{301, 302, 303, 307, 308} {
		t.Run(strconv.Itoa(code), func(t *testing.T) {
			hits.Store(0)
			cp := newCP(t)
			cp.poll = func(int, cpReq) cpAnswer {
				return cpAnswer{status: code, header: map[string]string{"Location": attacker.URL + wire.PathPoll}}
			}
			cp.status = func(int, cpReq) cpAnswer {
				return cpAnswer{status: code, header: map[string]string{"Location": attacker.URL + wire.PathStatus}}
			}
			r := newRig(t, "", nil, cp)
			r.boot()
			r.run()
			waitFor(t, "poll and status", func() bool { return cp.pollCount() >= 1 && cp.statusCount() >= 1 })
			r.advance(30*time.Second, time.Second)
			if hits.Load() != 0 {
				t.Fatalf("the redirect target received %d requests (Authorization %v): the token leaked", hits.Load(), gotAuth.Load())
			}
		})
	}
}

// Oversized or hostile 200 bodies are errors, not applied, and do not exhaust memory.
func TestHostileBodies(t *testing.T) {
	env, _ := validEnv(1)
	good := pollJSON(env, 1).body
	big := make([]byte, 40<<20)
	for i := range big {
		big[i] = 'a'
	}
	cases := map[string][]byte{
		"40 MiB garbage":            big,
		"valid then trailing":       append(append([]byte(nil), good...), []byte(` {}`)...),
		"unknown field":             []byte(strings.Replace(string(good), `"version":1`, `"version":1,"extra":true`, 1)),
		"duplicate version":         []byte(strings.Replace(string(good), `"version":1`, `"version":1,"version":2`, 1)),
		"case-variant envelope key": []byte(strings.Replace(string(good), `"payload"`, `"Payload"`, 1)),
		"case-variant payloadType":  []byte(strings.Replace(string(good), `"payloadType"`, `"PAYLOADTYPE"`, 1)),
		"case-variant top key":      []byte(strings.Replace(string(good), `"envelope"`, `"Envelope"`, 1)),
		"duplicate payload key": func() []byte {
			i := strings.Index(string(good), `"payload"`)
			return []byte(string(good[:i]) + `"payload":"e30=",` + string(good[i:]))
		}(),
		"duplicate signatures key": func() []byte {
			i := strings.Index(string(good), `"signatures"`)
			return []byte(string(good[:i]) + `"signatures":[],` + string(good[i:]))
		}(),
		"envelope null":      []byte(`{"version":1,"envelope":null}`),
		"bare array":         []byte(`[]`),
		"deep nesting":       []byte(strings.Repeat("[", 200000)),
		"payload not base64": []byte(`{"version":1,"envelope":{"payloadType":"` + wire.PayloadTypePolicy + `","payload":"!!!","signatures":[]}}`),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			cp := newCP(t)
			cp.poll = func(n int, q cpReq) cpAnswer {
				return cpAnswer{status: 200, header: map[string]string{"Content-Type": "application/json"}, body: body}
			}
			r := newRig(t, "", nil, cp)
			r.boot()
			r.run()
			waitFor(t, "poll", func() bool { return cp.pollCount() >= 1 })
			r.advance(3*time.Second, 250*time.Millisecond)
			if r.appliedVersion() != 0 || r.state() != wire.StateDenyAll {
				t.Errorf("state %s version %d after a hostile body (I3)", r.state(), r.appliedVersion())
			}
			if cp.pollCount() > 40 {
				t.Errorf("%d polls in 3 s", cp.pollCount())
			}
			_ = agent.MetricPollErrors
		})
	}
}
