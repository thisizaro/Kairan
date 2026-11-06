package agentbreak

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

// The poll request: exactly the three wire parameters, bearer token, no body (wire PollRequest, I4).
func TestPollRequestShape(t *testing.T) {
	cp := newCP(t)
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
	var first cpReq
	for _, q := range cp.all() {
		if q.Path == wire.PathPoll {
			first = q
			break
		}
	}
	if first.Method != "GET" {
		t.Errorf("poll method %s", first.Method)
	}
	pr, err := wire.ParsePollRequest(first.Query)
	if err != nil {
		t.Fatalf("poll query is not a valid PollRequest: %v (%v)", err, first.Query)
	}
	if pr.Tenant != tenant || pr.ProxyID != proxy || pr.Have != 0 {
		t.Errorf("poll request %+v", pr)
	}
	if got := first.Header.Get("Authorization"); got != "Bearer "+token {
		t.Errorf("Authorization %q", got)
	}
	if len(first.Body) != 0 {
		t.Errorf("poll carries a body")
	}
	for k, v := range first.Query {
		for _, x := range v {
			if strings.Contains(x, token) {
				t.Errorf("token in query %s", k)
			}
		}
	}
}

// Status report: decodes strictly into wire.StatusReport, passes Validate, and carries only metadata (I4).
func TestStatusReportIsMetadataOnly(t *testing.T) {
	cp := newCP(t)
	env, h := validEnv(1)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env, 1)
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "applied", func() bool { return r.appliedVersion() == 1 })
	waitFor(t, "status after apply", func() bool { s, _, ok := cp.lastStatus(); return ok && s.AppliedVersion == 1 })
	_, body, _ := cp.lastStatus()
	var s wire.StatusReport
	if err := wire.Decode(bytes.NewReader(body), wire.MaxStatusBytes, &s); err != nil {
		t.Fatalf("status body is not a strict StatusReport: %v: %s", err, body)
	}
	if err := s.Validate(); err != nil {
		t.Errorf("status report fails Validate: %v: %s", err, body)
	}
	if s.Tenant != tenant || s.ProxyID != proxy || s.State != wire.StateEnforcing || s.AppliedVersion != 1 || s.PolicyHash != h {
		t.Errorf("report content %+v", s)
	}
	seq, head := r.al.Head()
	if s.LogSeq != seq || s.LogHead != head || seq == 0 {
		t.Errorf("anchor in report (%d,%s) != apply log head (%d,%s) (M-D35)", s.LogSeq, s.LogHead, seq, head)
	}
	// only wire keys; no payload, no token
	var m map[string]json.RawMessage
	_ = json.Unmarshal(body, &m)
	allowed := map[string]bool{"tenant": true, "proxy_id": true, "seq": true, "state": true, "applied_version": true, "policy_hash": true,
		"log_seq": true, "log_head": true, "last_error": true, "uptime_seconds": true, "counters": true}
	for k := range m {
		if !allowed[k] {
			t.Errorf("status report has key %q outside the wire contract (I4)", k)
		}
	}
	if bytes.Contains(body, []byte(token)) || bytes.Contains(body, env.Payload) || bytes.Contains(body, []byte("crm.")) {
		t.Errorf("status body carries token or policy content: %s", body)
	}
	for _, q := range cp.all() {
		if q.Path == wire.PathStatus {
			if q.Method != "POST" || q.Header.Get("Authorization") != "Bearer "+token {
				t.Errorf("status request %s auth %q", q.Method, q.Header.Get("Authorization"))
			}
			if !strings.HasPrefix(q.Header.Get("Content-Type"), wire.ContentTypeJSON) {
				t.Errorf("status content type %q", q.Header.Get("Content-Type"))
			}
		}
	}
}

// Status timing: one at start, one immediately after an apply attempt, otherwise every 10 s (wire.StatusInterval).
func TestStatusTiming(t *testing.T) {
	cp := newCP(t)
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "initial status", func() bool { return cp.statusCount() >= 1 })
	settle()
	if n := cp.statusCount(); n != 1 {
		t.Fatalf("%d status reports at start, want exactly 1", n)
	}
	r.advance(wire.StatusInterval-time.Second, time.Second)
	if n := cp.statusCount(); n != 1 {
		t.Errorf("%d reports 9 s in, want 1 (interval is 10 s)", n)
	}
	r.advance(2*time.Second, time.Second)
	if n := cp.statusCount(); n != 2 {
		t.Errorf("%d reports after 11 s, want 2", n)
	}
	// seq grows by one per report within a process (wire)
	prev := uint64(0)
	for _, q := range cp.all() {
		if q.Path != wire.PathStatus {
			continue
		}
		var s wire.StatusReport
		_ = json.Unmarshal(q.Body, &s)
		if s.Seq != prev+1 {
			t.Errorf("seq %d after %d", s.Seq, prev)
		}
		prev = s.Seq
	}
	// a failing status endpoint is not retried before the next trigger
	cp.status = func(int, cpReq) cpAnswer { return cpAnswer{status: 500} }
	before := cp.statusCount()
	r.advance(5*time.Second, time.Second)
	if n := cp.statusCount(); n != before {
		t.Errorf("failed report retried within the interval: %d -> %d", before, n)
	}
}

// A status 503 with Retry-After holds further reports until it passes.
func TestStatus503HoldsReports(t *testing.T) {
	cp := newCP(t)
	cp.status = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return cpAnswer{status: 503, header: map[string]string{"Retry-After": "60"}}
		}
		return cpAnswer{status: 204}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "first status", func() bool { return cp.statusCount() >= 1 })
	r.advance(40*time.Second, time.Second)
	if n := cp.statusCount(); n != 1 {
		t.Errorf("%d reports during the Retry-After window, want 1", n)
	}
	r.advance(40*time.Second, time.Second)
	if n := cp.statusCount(); n < 2 {
		t.Errorf("reports did not resume after Retry-After (cap 5 min): %d", n)
	}
}

// Applying: Save then Append then Holder; the apply log entry, the stored file and the holder agree; the next poll
// carries have = applied version; the advisory Version field never decides.
func TestApplyAndAdvisoryVersion(t *testing.T) {
	cp := newCP(t)
	env, h := validEnv(3)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env, 99) // the control plane lies about the version
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "applied", func() bool { return r.appliedVersion() != 0 })
	if v := r.appliedVersion(); v != 3 {
		t.Fatalf("applied version %d: the advisory field (99) must never be used, payload says 3", v)
	}
	a := r.hold.Load()
	if a.Hash != h || a.State != wire.StateEnforcing {
		t.Errorf("active hash %s state %s", a.Hash, a.State)
	}
	es := readLog(t, r.logPath())
	if len(es) != 1 || es[0].To != 3 || es[0].Result != "" || es[0].Hash != h {
		t.Errorf("apply log %+v", es)
	}
	if _, found, err := r.st.Load(); err != nil || !found {
		t.Errorf("stored policy: found=%v err=%v", found, err)
	}
	waitFor(t, "second poll with have=3", func() bool {
		for _, q := range cp.all() {
			if q.Path == wire.PathPoll && q.Query.Get(wire.QueryHave) == "3" {
				return true
			}
		}
		return false
	})
}

// Rejections keep the policy in force (I3), are logged with their code, counted, and reported as last_error.
func TestRejectionsKeepCurrentPolicy(t *testing.T) {
	good, _ := validEnv(5)
	mk := func(f func() wire.Envelope) func() wire.Envelope { return f }
	flip := func() wire.Envelope {
		e, _ := validEnv(6)
		e.Signatures[0].Sig[0] ^= 0xff
		return e
	}
	cases := []struct {
		name string
		env  func() wire.Envelope
		code wire.ErrorCode
	}{
		// zero signatures: ValidateShape (malformed) or threshold_not_met are both defensible; only "rejected" is required
		{"unsigned", mk(func() wire.Envelope { return signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour))) }), ""},
		{"one signature", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA)
		}), wire.ErrThreshold},
		{"same key twice", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA, keyA)
		}), wire.ErrThreshold},
		{"one trusted one outsider", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA, keyOut)
		}), wire.ErrThreshold},
		{"flipped signature", flip, wire.ErrThreshold},
		{"wrong tenant", mk(func() wire.Envelope {
			return signedEnv(policyDoc("bank-b", 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA, keyB)
		}), wire.ErrWrongTenant},
		{"same version", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 5, t0.Add(-time.Hour), t0.Add(48*time.Hour)), keyA, keyB)
		}), wire.ErrNotNewer},
		{"older version", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 2, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA, keyB)
		}), wire.ErrNotNewer},
		{"expired", mk(func() wire.Envelope {
			return signedEnv(policyDoc(tenant, 6, t0.Add(-48*time.Hour), t0.Add(-24*time.Hour)), keyA, keyB)
		}), wire.ErrExpired},
		{"malformed policy", mk(func() wire.Envelope { return signedEnv([]byte(`{"tenant":"bank-a"}`), keyA, keyB) }), wire.ErrMalformed},
		{"wrong payload type", mk(func() wire.Envelope {
			e := signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA, keyB)
			e.PayloadType = "text/plain"
			return e
		}), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cp := newCP(t)
			bad := c.env()
			cp.poll = func(n int, q cpReq) cpAnswer {
				switch n {
				case 1:
					return pollJSON(good, 5)
				case 2:
					return pollJSON(bad, 6)
				}
				return cpAnswer{status: 304}
			}
			r := newRig(t, "", nil, cp)
			r.boot()
			r.run()
			waitFor(t, "v5 applied", func() bool { return r.appliedVersion() == 5 })
			// the second answer is only requested after backoff or the next poll; drive time
			for i := 0; i < 40 && r.stats.Count(agent.MetricApplyRejected) == 0; i++ {
				r.advance(time.Second, 250*time.Millisecond)
			}
			if r.stats.Count(agent.MetricApplyRejected) == 0 {
				t.Fatalf("the bad envelope was never offered/rejected; polls=%d", cp.pollCount())
			}
			if v := r.appliedVersion(); v != 5 {
				t.Fatalf("version in force changed to %d after a rejected envelope (I3)", v)
			}
			if a := r.hold.Load(); a.State != wire.StateEnforcing {
				t.Errorf("state %s after a rejection, want enforcing", a.State)
			}
			waitFor(t, "rejection in the apply log", func() bool { return len(readLog(t, r.logPath())) >= 2 })
			es := readLog(t, r.logPath())
			if len(es) < 2 {
				t.Fatalf("rejection not written to the apply log: %+v", es)
			}
			last := es[len(es)-1]
			if last.Result == "" {
				t.Errorf("rejected attempt logged as applied: %+v", last)
			}
			if c.code != "" && last.Result != c.code {
				t.Errorf("logged code %q, want %q", last.Result, c.code)
			}
			waitFor(t, "status with last_error", func() bool {
				s, _, ok := cp.lastStatus()
				return ok && s.LastError != nil
			})
			s, _, _ := cp.lastStatus()
			if s.AppliedVersion != 5 {
				t.Errorf("report says applied %d", s.AppliedVersion)
			}
			if s.LastError.Code != last.Result {
				t.Errorf("last_error %q != logged %q", s.LastError.Code, last.Result)
			}
			if got := r.stats.Counters().EnvelopesRejected; got == 0 {
				t.Errorf("rejected counter not incremented")
			}
		})
	}
}

// A control plane that resends the same bad envelope must not fill the disk: exact repeats count but are not
// logged again (agent doc), and the proxy does not hot-loop on it.
func TestRepeatedRejectionDoesNotGrowApplyLog(t *testing.T) {
	cp := newCP(t)
	good, _ := validEnv(5)
	bad := signedEnv(policyDoc(tenant, 6, t0.Add(-time.Hour), t0.Add(24*time.Hour)), keyA)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(good, 5)
		}
		return pollJSON(bad, 6)
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	waitFor(t, "applied", func() bool { return r.appliedVersion() == 5 })
	r.advance(120*time.Second, 500*time.Millisecond)
	if cp.pollCount() < 6 {
		t.Fatalf("only %d polls in 2 virtual minutes; the test cannot judge the log", cp.pollCount())
	}
	es := readLog(t, r.logPath())
	if len(es) > 3 {
		t.Errorf("%d apply-log entries after %d identical rejections; exact repeats must not be logged again", len(es), cp.pollCount()-1)
	}
	if r.stats.Count(agent.MetricApplyRejected) < 3 {
		t.Errorf("rejected counter %d: every rejection still counts", r.stats.Count(agent.MetricApplyRejected))
	}
}

// The token never reaches the agent's log, whatever the control plane does.
func TestTokenNeverLogged(t *testing.T) {
	cp := newCP(t)
	n := 0
	cp.poll = func(i int, q cpReq) cpAnswer {
		n++
		switch n % 4 {
		case 0:
			return cpAnswer{status: 500, body: []byte("echo " + token)}
		case 1:
			return cpAnswer{status: 200, body: []byte(`{"version":1,"envelope":` + token + `}`)}
		case 2:
			return cpAnswer{status: 302, header: map[string]string{"Location": "http://127.0.0.1:1/" + token}}
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, "", nil, cp)
	r.boot()
	r.run()
	r.advance(60*time.Second, 500*time.Millisecond)
	if strings.Contains(r.logbuf.String(), token) {
		t.Errorf("token in the agent log:\n%s", r.logbuf.String())
	}
	if cp.pollCount() < 3 {
		t.Errorf("only %d polls: the scenario did not run", cp.pollCount())
	}
}
