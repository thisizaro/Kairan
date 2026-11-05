package kairanproxybreak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/declog"
	"kairan/internal/wire"
)

// life describes one process lifetime of a proxy on a shared data dir.
type life struct {
	t        *testing.T
	dir      string
	cp       *fakeCP
	up       *upstream
	p        *proc
	listen   string
	cfg      pcfg
	envelope wire.Envelope
}

func newLife(t *testing.T, dir string) *life {
	t.Helper()
	if dir == "" {
		dir = filepath.Join(t.TempDir(), "data")
	}
	return &life{t: t, dir: dir, cp: newCP(t), up: newUpstream(t)}
}

// start runs the proxy against l.cp (or cpURL when set) and waits for it to listen.
func (l *life) start(cpURL string, mod func(c pcfg) pcfg, env []string) {
	l.t.Helper()
	if cpURL == "" {
		cpURL = l.cp.url()
	}
	l.listen = freePort(l.t)
	c := baseCfg(l.t, l.dir, cpURL, l.up.srv.URL+"/mcp", l.listen)
	if mod != nil {
		c = mod(c)
	}
	l.cfg = c
	l.p = startServing(l.t, c, env)
}

func (l *life) offer(version uint64, signers ...string) {
	var ks []keyPair
	for _, s := range signers {
		ks = append(ks, key(l.t, s))
	}
	env := envelopeOf(validPolicy(version), ks...)
	l.envelope = env
	l.cp.mu.Lock()
	l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) { return env, have < version }
	l.cp.mu.Unlock()
}

func (l *life) waitAllowed() {
	l.t.Helper()
	waitFor(l.t, "the policy to be enforced", 10*time.Second, func() bool {
		return allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`)))
	})
}

func (l *life) stop() {
	l.t.Helper()
	l.p.signal(syscall.SIGTERM)
	if code, ok := l.p.waitExit(10 * time.Second); !ok || code != 0 {
		l.t.Fatalf("SIGTERM: exited=%v code=%d: %s", ok, code, l.p.out.String())
	}
}

func (l *life) files() map[string]string {
	ents, err := os.ReadDir(l.dir)
	if err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range ents {
		out[e.Name()] = filepath.Join(l.dir, e.Name())
	}
	return out
}

// policyFile is the stored policy, "policy.json" (documented in go doc of the store package). It fails the test
// when that file is missing, so a tamper test can never act on a different file (a lock file, a log).
func (l *life) policyFile() string {
	l.t.Helper()
	p := filepath.Join(l.dir, "policy.json")
	st, err := os.Lstat(p)
	if err != nil || !st.Mode().IsRegular() {
		l.t.Fatalf("no policy.json in %v: %v", l.files(), err)
	}
	return p
}

func (l *life) decisions() []string {
	b, err := os.ReadFile(filepath.Join(l.dir, "decisions.log"))
	if err != nil {
		l.t.Fatal(err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// ---- tests ----

// End to end: apply from the control plane, enforce, decide, log with the exact version and hash (I5), report
// metadata only (I4), keep secrets out of every output.
func TestEndToEnd(t *testing.T) {
	l := newLife(t, "")
	l.offer(7, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	h := hashOf(l.envelope.Payload)
	// waitAllowed probes during DenyAll before the apply; its last probe is the first allowed call.
	preApply := l.decisions()
	if len(preApply) < 1 {
		t.Fatal("waitAllowed left no decision line")
	}
	nPre := len(preApply) - 1

	if r := l.p.call(keySales, callBody("crm.update_deal", `{"note":"`+canary+`"}`)); !allowed(r) {
		t.Errorf("W tool for sales denied: %+v", r)
	}
	if r := l.p.call(keySales, callBody("admin.shutdown", `{"why":"`+canary+`"}`)); allowed(r) {
		t.Errorf("tool outside the policy allowed (I3): %+v", r)
	}
	if r := l.p.call(keyIntrn, callBody("crm.read_contact", `{}`)); allowed(r) {
		t.Errorf("intern reached a sales tool")
	}
	list := l.p.call(keySales, listBody)
	if !strings.Contains(list.body, "crm.read_contact") || strings.Contains(list.body, "admin.shutdown") {
		t.Errorf("tools/list not filtered by role: %s", list.body)
	}
	if r := l.p.call("wrong-key", callBody("crm.read_contact", `{}`)); r.code != 401 {
		t.Errorf("unknown key: %d", r.code)
	}

	// I5: decisions.log lines decode and carry version 7 and the payload hash
	lines := l.decisions()
	if len(lines) < 4 {
		t.Fatalf("%d decision lines", len(lines))
	}
	for i, ln := range lines {
		rc, err := declog.Decode([]byte(ln))
		if err != nil {
			t.Fatalf("decision line does not decode: %v: %q", err, ln)
		}
		if i < nPre {
			// decided before the policy applied: stamped with what was in force then (I5)
			if rc.Version != 0 || rc.Hash != "" || rc.State != wire.StateDenyAll || rc.Allowed {
				t.Errorf("pre-apply decision %d stamped %+v, want version 0, no hash, deny_all, denied (I5)", i, rc)
			}
			continue
		}
		if rc.Version != 7 || rc.Hash != h || rc.State != wire.StateEnforcing {
			t.Errorf("decision %d stamped version=%d hash=%s state=%s, want 7 %s enforcing (I5)", i, rc.Version, rc.Hash, rc.State, h)
		}
	}
	// apply log verifies and records the apply
	f, err := os.Open(filepath.Join(l.dir, "apply.log"))
	if err != nil {
		t.Fatal(err)
	}
	last, n, err := applylog.Verify(f)
	f.Close()
	if err != nil || n < 1 || last.To != 7 || last.Hash != h || last.Result != "" {
		t.Fatalf("apply log: last=%+v n=%d err=%v", last, n, err)
	}
	// the status report carries the anchor of that log and no more
	waitFor(t, "status with the policy", 15*time.Second, func() bool {
		for _, s := range l.cp.statuses() {
			if s.AppliedVersion == 7 {
				return true
			}
		}
		return false
	})
	var got wire.StatusReport
	for _, s := range l.cp.statuses() {
		if s.AppliedVersion == 7 {
			got = s
		}
	}
	if got.PolicyHash != h || got.State != wire.StateEnforcing || got.LogSeq != last.Seq || got.LogHead != last.Self {
		t.Errorf("report %+v does not match apply log head (%d,%s) and hash %s", got, last.Seq, last.Self, h)
	}
	for _, q := range l.cp.all() {
		if q.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("request to %s with Authorization %q", q.Path, q.Header.Get("Authorization"))
		}
		if bytes.Contains(q.Body, []byte(canary)) || bytes.Contains(q.Body, []byte(keySales)) || bytes.Contains(q.Body, []byte("crm.")) {
			t.Errorf("control-plane traffic carries call data (I4): %s", q.Body)
		}
		for k, v := range q.Query {
			for _, x := range v {
				if strings.Contains(x, token) || strings.Contains(x, canary) {
					t.Errorf("secret in query %s", k)
				}
			}
		}
	}
	// secrets stay out of everything the proxy writes
	l.stop()
	for _, secret := range []string{token, keySales, keyIntrn, canary} {
		if strings.Contains(l.p.out.String(), secret) {
			t.Errorf("process output contains %q", secret)
		}
	}
	for name, p := range l.files() {
		b, _ := os.ReadFile(p)
		for _, secret := range []string{token, keySales, canary} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("data file %s contains %q", name, secret)
			}
		}
	}
	// the data directory and its files are private
	if st, err := os.Stat(l.dir); err == nil && st.Mode().Perm()&0o077 != 0 {
		t.Errorf("data dir mode %v", st.Mode().Perm())
	}
	for name, p := range l.files() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s mode %v, want owner-only", name, st.Mode().Perm())
		}
	}
}

// S3: a restarted proxy with the control plane down enforces the same version from disk (never deny-all from a
// good file, never wider), after a clean stop and after SIGKILL.
func TestRestartWithControlPlaneDown(t *testing.T) {
	for _, how := range []string{"SIGTERM", "SIGKILL"} {
		t.Run(how, func(t *testing.T) {
			l := newLife(t, "")
			l.offer(3, "admin-a", "admin-c")
			l.start("", nil, nil)
			l.waitAllowed()
			if how == "SIGTERM" {
				l.stop()
			} else {
				l.p.signal(syscall.SIGKILL)
				l.p.waitExit(5 * time.Second)
			}
			dead := httptest.NewServer(http.NotFoundHandler())
			deadURL := dead.URL
			dead.Close()
			l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
			l2.start(deadURL, nil, nil)
			if !allowed(l2.p.call(keySales, callBody("crm.read_contact", `{}`))) {
				t.Fatalf("restart with the control plane down did not enforce the stored policy: %s", l2.p.out.String())
			}
			if allowed(l2.p.call(keySales, callBody("admin.shutdown", `{}`))) {
				t.Errorf("restarted proxy allows a tool outside the policy")
			}
			if allowed(l2.p.call(keyIntrn, callBody("crm.read_contact", `{}`))) {
				t.Errorf("restarted proxy let intern use a sales tool")
			}
			rc, err := declog.Decode([]byte(l2.decisions()[len(l2.decisions())-1]))
			if err != nil || rc.Version != 3 {
				t.Errorf("last decision after restart: %+v %v", rc, err)
			}
		})
	}
}

// S6: tampered disk. Every kind of damage ends with nothing allowed and nothing reaching the upstream.
func TestTamperedDiskDeniesEverything(t *testing.T) {
	cases := []struct {
		name string
		do   func(t *testing.T, l *life, older []byte)
	}{
		{"policy payload edited", func(t *testing.T, l *life, older []byte) {
			p := l.policyFile()
			b, _ := os.ReadFile(p)
			nb := bytes.Replace(b, []byte("e"), []byte("f"), 1)
			if bytes.Equal(nb, b) {
				t.Fatal("nothing replaced")
			}
			os.WriteFile(p, nb, 0o600)
		}},
		{"policy replaced by garbage", func(t *testing.T, l *life, older []byte) { os.WriteFile(l.policyFile(), []byte("garbage"), 0o600) }},
		{"policy emptied", func(t *testing.T, l *life, older []byte) { os.WriteFile(l.policyFile(), nil, 0o600) }},
		{"policy deleted", func(t *testing.T, l *life, older []byte) { os.Remove(l.policyFile()) }},
		{"older valid policy put back", func(t *testing.T, l *life, older []byte) { os.WriteFile(l.policyFile(), older, 0o600) }},
		{"apply log field edited", func(t *testing.T, l *life, older []byte) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			nb := bytes.Replace(b, []byte(`"to":2`), []byte(`"to":1`), 1)
			if bytes.Equal(nb, b) {
				t.Fatalf("edit did not apply to %q", b)
			}
			os.WriteFile(p, nb, 0o600)
		}},
		{"apply log last line cut", func(t *testing.T, l *life, older []byte) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)-7], 0o600)
		}},
		{"apply log garbage appended", func(t *testing.T, l *life, older []byte) {
			p := filepath.Join(l.dir, "apply.log")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, append(b, []byte("xx\n")...), 0o600)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l := newLife(t, "")
			l.offer(1, "admin-a", "admin-b")
			l.start("", nil, nil)
			l.waitAllowed()
			l.stop()
			older, err := os.ReadFile(l.policyFile())
			if err != nil {
				t.Fatal(err)
			}
			l2 := &life{t: t, dir: l.dir, cp: newCP(t), up: l.up}
			l2.offer(2, "admin-a", "admin-b")
			l2.start("", nil, nil)
			l2.waitAllowed()
			l2.stop()
			c.do(t, l2, older)

			dead := httptest.NewServer(http.NotFoundHandler())
			deadURL := dead.URL
			dead.Close()
			before := l.up.count()
			l3 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
			l3.start(deadURL, nil, nil)
			for _, tool := range []string{"crm.read_contact", "crm.update_deal", "admin.shutdown", "help.faq"} {
				for _, k := range []string{keySales, keyIntrn} {
					if r := l3.p.call(k, callBody(tool, `{}`)); allowed(r) {
						t.Errorf("tampered proxy allowed %s: %+v (I3)", tool, r)
					}
				}
			}
			list := l3.p.call(keySales, listBody)
			if strings.Contains(list.body, "crm.read_contact") || strings.Contains(list.body, "admin.shutdown") {
				t.Errorf("tampered proxy still lists tools: %s", list.body)
			}
			if l.up.count() != before {
				t.Errorf("the upstream saw %d requests from a tampered proxy", l.up.count()-before)
			}
			if !strings.Contains(l3.p.out.String(), "tamper") {
				t.Errorf("no tamper message on the operator log: %s", clip(l3.p.out.String()))
			}
			// a decision written while tampered carries the state
			if lines := l3.decisions(); len(lines) > 0 {
				rc, err := declog.Decode([]byte(lines[len(lines)-1]))
				if err != nil || rc.State != wire.StateTampered && rc.State != wire.StateDenyAll {
					t.Errorf("last decision %+v %v", rc, err)
				}
				if rc.Allowed {
					t.Errorf("tampered decision recorded as allowed")
				}
			}
		})
	}
}

// The control plane of a tampered proxy can only recover it with a version above everything ever applied.
func TestTamperedProxyReportsAndRecoversOnlyWithNewerVersion(t *testing.T) {
	l := newLife(t, "")
	l.offer(4, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	l.stop()
	os.WriteFile(l.policyFile(), []byte("garbage"), 0o600)

	l2 := &life{t: t, dir: l.dir, cp: newCP(t), up: l.up}
	l2.offer(4, "admin-a", "admin-b") // same version again
	l2.start("", nil, nil)
	waitFor(t, "poll and status", 10*time.Second, func() bool { return len(l2.cp.statuses()) >= 1 })
	time.Sleep(1500 * time.Millisecond)
	if allowed(l2.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Fatalf("re-offering the version already applied revived a tampered proxy (I2)")
	}
	for _, s := range l2.cp.statuses() {
		if s.State != wire.StateTampered {
			t.Errorf("status while tampered says state %s (S6 needs a tamper report)", s.State)
		}
	}
	for _, q := range l2.cp.all() {
		if q.Path == wire.PathPoll && q.Query.Get(wire.QueryHave) != "4" {
			t.Errorf("tampered proxy polls with have=%s, want 4", q.Query.Get(wire.QueryHave))
			break
		}
	}
	l2.offer(5, "admin-a", "admin-b")
	l2.waitAllowed()
}

// S7: policy expiry at run time and at boot; read_only (default) keeps R tools only; deny_all keeps nothing.
func TestExpiryAndSafeMode(t *testing.T) {
	for _, mode := range []string{"read_only", "deny_all"} {
		t.Run(mode, func(t *testing.T) {
			l := newLife(t, "")
			short := func(version uint64) {
				env := envelopeOf(policyDoc(tenant, version, time.Now().Add(-time.Hour), time.Now().Add(3*time.Second)), key(t, "admin-a"), key(t, "admin-b"))
				l.cp.mu.Lock()
				l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) { return env, have < version }
				l.cp.mu.Unlock()
			}
			short(1)
			l.start("", func(c pcfg) pcfg { return c.with("skew", "1s").with("safe_mode", mode) }, nil)
			l.waitAllowed()
			// stop offering; wait past expires_at + skew
			l.cp.mu.Lock()
			l.cp.offer = nil
			l.cp.mu.Unlock()
			waitFor(t, "safe mode", 15*time.Second, func() bool {
				return !allowed(l.p.call(keySales, callBody("crm.update_deal", `{}`)))
			})
			read := allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`)))
			if mode == "read_only" && !read {
				t.Errorf("read_only safe mode denies an R tool")
			}
			if mode == "deny_all" && read {
				t.Errorf("deny_all safe mode allowed a read")
			}
			if allowed(l.p.call(keySales, callBody("crm.update_deal", `{}`))) || allowed(l.p.call(keySales, callBody("admin.shutdown", `{}`))) {
				t.Errorf("safe mode allowed a W or unlisted tool")
			}
			waitFor(t, "safe_mode status", 15*time.Second, func() bool {
				for _, s := range l.cp.statuses() {
					if s.State == wire.StateSafeMode {
						return true
					}
				}
				return false
			})
			// decisions made in safe mode carry that state (I5)
			ls := l.decisions()
			rc, err := declog.Decode([]byte(ls[len(ls)-1]))
			if err != nil || rc.State != wire.StateSafeMode || rc.Version != 1 {
				t.Errorf("last decision %+v %v, want safe_mode at version 1", rc, err)
			}
			l.stop()

			// boot after expiry: still safe mode with the control plane down, same rule
			dead := httptest.NewServer(http.NotFoundHandler())
			du := dead.URL
			dead.Close()
			l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
			l2.start(du, func(c pcfg) pcfg { return c.with("skew", "1s").with("safe_mode", mode) }, nil)
			if allowed(l2.p.call(keySales, callBody("crm.update_deal", `{}`))) {
				t.Errorf("an expired policy allowed a write after a restart")
			}
			if r := allowed(l2.p.call(keySales, callBody("crm.read_contact", `{}`))); r != (mode == "read_only") {
				t.Errorf("after restart the read decision is %v in %s", r, mode)
			}
		})
	}
}

// S7 / THREATS #12: the wall clock set back. The persisted high-water mark keeps an expired policy expired.
func TestClockSetBackAcrossRestart(t *testing.T) {
	l := newLife(t, "")
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	l.stop()
	hwPath := filepath.Join(l.dir, "highwater")
	b, err := os.ReadFile(hwPath)
	if err != nil || len(bytes.TrimSpace(b)) == 0 {
		t.Fatalf("no high-water mark persisted by a clean shutdown: %v", err)
	}
	layout := time.RFC3339Nano
	cur, err := time.Parse(layout, strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("high-water file is not an RFC 3339 time: %q", b)
	}
	future := cur.Add(72 * time.Hour) // the clock "ran" 3 days ahead before it was set back
	if err := os.WriteFile(hwPath, []byte(future.UTC().Format(layout)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dead := httptest.NewServer(http.NotFoundHandler())
	du := dead.URL
	dead.Close()
	l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
	l2.start(du, nil, nil)
	if allowed(l2.p.call(keySales, callBody("crm.update_deal", `{}`))) {
		t.Errorf("a write is allowed although the high-water mark says the policy expired (clock set back)")
	}
	if !allowed(l2.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Errorf("safe mode (read_only) should still allow R tools")
	}
	l2.stop()
	b2, _ := os.ReadFile(hwPath)
	if got, err := time.Parse(layout, strings.TrimSpace(string(b2))); err != nil || got.Before(future) {
		t.Errorf("high-water mark went backwards: %q (was %v)", b2, future)
	}
	// a garbage mark must not take enforcement away from a good policy (it is repaired, M-D30)
	l3 := newLife(t, "")
	l3.offer(1, "admin-a", "admin-b")
	l3.start("", nil, nil)
	l3.waitAllowed()
	l3.stop()
	os.WriteFile(filepath.Join(l3.dir, "highwater"), []byte("garbage"), 0o600)
	l4 := &life{t: t, dir: l3.dir, cp: l3.cp, up: l3.up}
	l4.start(du, nil, nil)
	if !allowed(l4.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Errorf("a corrupt high-water file denied a good policy: %s", l4.p.out.String())
	}
}

// S5 at binary level: bad offers never change what is enforced and are visible in the status.
func TestBadOffersAreRejectedAndReported(t *testing.T) {
	l := newLife(t, "")
	l.offer(5, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	good := l.envelope
	var mu sync.Mutex
	bad := []wire.Envelope{
		envelopeOf(validPolicy(6)),
		envelopeOf(validPolicy(6), key(t, "admin-a")),
		envelopeOf(validPolicy(6), key(t, "admin-a"), key(t, "outsider")),
		envelopeOf(policyDoc("bank-b", 6, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), key(t, "admin-a"), key(t, "admin-b")),
		envelopeOf(policyDoc(tenant, 4, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)), key(t, "admin-a"), key(t, "admin-b")),
		envelopeOf(policyDoc(tenant, 7, time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour)), key(t, "admin-a"), key(t, "admin-b")),
		envelopeOf([]byte(`{"tenant":"bank-a"}`), key(t, "admin-a"), key(t, "admin-b")),
	}
	idx := 0
	l.cp.mu.Lock()
	l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) {
		mu.Lock()
		defer mu.Unlock()
		e := bad[idx%len(bad)]
		idx++
		return e, true
	}
	l.cp.mu.Unlock()
	waitFor(t, "all bad offers seen", 40*time.Second, func() bool { mu.Lock(); defer mu.Unlock(); return idx >= len(bad)+1 })
	if !allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Fatalf("v5 no longer enforced after bad offers")
	}
	ls := l.decisions()
	rc, _ := declog.Decode([]byte(ls[len(ls)-1]))
	if rc.Version != 5 || rc.Hash != hashOf(good.Payload) {
		t.Errorf("decision after bad offers stamped %+v, want version 5", rc)
	}
	waitFor(t, "last_error in a report", 15*time.Second, func() bool {
		for _, s := range l.cp.statuses() {
			if s.LastError != nil {
				return true
			}
		}
		return false
	})
	for _, s := range l.cp.statuses() {
		if s.AppliedVersion != 0 && s.AppliedVersion != 5 {
			t.Errorf("a report says applied version %d", s.AppliedVersion)
		}
		if s.LastError != nil && !s.LastError.Code.Valid() {
			t.Errorf("invalid error code %q in report", s.LastError.Code)
		}
	}
}

// M-D37: a trusted TEST-ONLY fixture key is a loud warning; a real-looking key is not.
func TestTestOnlyKeyWarning(t *testing.T) {
	l := newLife(t, "")
	l.start("", nil, nil)
	if !strings.Contains(l.p.out.String(), "TEST-ONLY") {
		t.Errorf("trusting fixture keys produced no TEST-ONLY warning: %s", clip(l.p.out.String()))
	}
	l2 := newLife(t, "")
	var pubs []string
	for i := 0; i < 2; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		pubs = append(pubs, hex.EncodeToString(pub))
	}
	l2.start("", func(c pcfg) pcfg { return c.with("trusted_keys", pubs) }, nil)
	if strings.Contains(l2.p.out.String(), "TEST-ONLY") {
		t.Errorf("a warning about fixture keys although none is trusted: %s", clip(l2.p.out.String()))
	}
}

// A signal ends the process cleanly while a long poll is held; the exit code is 0 and no goroutine is left.
func TestShutdownWhilePollHeld(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			l := newLife(t, "")
			hold := make(chan struct{})
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == wire.PathPoll {
					select {
					case <-hold:
					case <-r.Context().Done():
					case <-time.After(30 * time.Second):
					}
					w.WriteHeader(304)
					return
				}
				w.WriteHeader(204)
			}))
			defer srv.Close()
			defer close(hold)
			l.start(srv.URL, nil, nil)
			time.Sleep(500 * time.Millisecond)
			l.p.signal(sig)
			code, ok := l.p.waitExit(8 * time.Second)
			if !ok {
				t.Fatalf("still running 8 s after %s with a poll held", sig)
			}
			if code != 0 {
				t.Errorf("exit %d: %s", code, clip(l.p.out.String()))
			}
			if _, err := os.Stat(filepath.Join(l.dir, "highwater")); err != nil {
				t.Errorf("no high-water file after shutdown: %v", err)
			}
		})
	}
}

// Startup failures are exit 1 and never serve.
func TestStartupFailures(t *testing.T) {
	t.Run("MCP port in use", func(t *testing.T) {
		hold := httptest.NewServer(http.NotFoundHandler())
		defer hold.Close()
		addr := strings.TrimPrefix(hold.URL, "http://")
		c := baseCfg(t, filepath.Join(t.TempDir(), "d"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", addr)
		code, out := runOnce(t, c.bytes(), nil)
		if code != 1 {
			t.Fatalf("exit %d, want 1: %s", code, clip(out))
		}
	})
	t.Run("decisions.log is a directory", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "d")
		os.MkdirAll(filepath.Join(d, "decisions.log"), 0o700)
		c := baseCfg(t, d, "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t))
		code, out := runOnce(t, c.bytes(), nil)
		if code != 1 {
			t.Fatalf("exit %d, want 1 (the decision log cannot open): %s", code, clip(out))
		}
	})
	t.Run("decisions.log is a symlink", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "d")
		os.MkdirAll(d, 0o700)
		victim := filepath.Join(t.TempDir(), "victim")
		os.WriteFile(victim, []byte("keep\n"), 0o600)
		os.Symlink(victim, filepath.Join(d, "decisions.log"))
		c := baseCfg(t, d, "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t))
		code, _ := runOnce(t, c.bytes(), nil)
		if b, _ := os.ReadFile(victim); string(b) != "keep\n" {
			t.Errorf("the symlink target was written: %q", b)
		}
		if code == 0 || code == -1 {
			t.Errorf("exit %d: a symlinked decision log must stop the proxy", code)
		}
	})
	t.Run("data_dir is a regular file", func(t *testing.T) {
		f := filepath.Join(t.TempDir(), "afile")
		os.WriteFile(f, []byte("x"), 0o600)
		c := baseCfg(t, f, "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t))
		code, out := runOnce(t, c.bytes(), nil)
		if code != 1 && code != 2 {
			t.Fatalf("exit %d: %s", code, clip(out))
		}
	})
	t.Run("data_dir cannot be created", func(t *testing.T) {
		d := t.TempDir()
		os.Chmod(d, 0o500)
		defer os.Chmod(d, 0o700)
		if os.Geteuid() == 0 {
			t.Fatal("running as root: cannot test permission denial")
		}
		c := baseCfg(t, filepath.Join(d, "sub", "data"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t))
		code, out := runOnce(t, c.bytes(), nil)
		if code != 1 {
			t.Fatalf("exit %d, want 1: %s", code, clip(out))
		}
	})
	t.Run("apply log that does not verify boots tampered, not dead and not open", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "d")
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, "apply.log"), []byte("garbage\n"), 0o600)
		up := newUpstream(t)
		l := &life{t: t, dir: d, cp: newCP(t), up: up}
		l.start("", nil, nil)
		if allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
			t.Errorf("allowed with a broken apply log")
		}
		if b, _ := os.ReadFile(filepath.Join(d, "apply.log")); string(b) != "garbage\n" {
			t.Errorf("the broken apply log was modified: %q", b)
		}
	})
}

// PRD J2 / S9: the control plane is reached through HTTP_PROXY, nothing else leaves the machine.
func TestForwardProxyEnvironment(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	var auth []string
	fwd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.String())
		auth = append(auth, r.Header.Get("Authorization"))
		mu.Unlock()
		switch r.URL.Path {
		case wire.PathPoll:
			w.WriteHeader(304)
		case wire.PathStatus:
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	defer fwd.Close()
	l := newLife(t, "")
	l.start("http://cp.example.test:8080", nil, []string{"HTTP_PROXY=" + fwd.URL, "NO_PROXY=direct.example.test"})
	waitFor(t, "poll and status through the forward proxy", 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		p, s := false, false
		for _, x := range seen {
			p = p || strings.Contains(x, wire.PathPoll)
			s = s || strings.Contains(x, wire.PathStatus)
		}
		return p && s
	})
	mu.Lock()
	defer mu.Unlock()
	for i, x := range seen {
		if !strings.Contains(x, "cp.example.test:8080") {
			t.Errorf("request %q does not target the configured control plane", x)
		}
		if auth[i] != "Bearer "+token {
			t.Errorf("request %q carried %q", x, auth[i])
		}
	}
	if len(l.cp.all()) != 0 {
		t.Errorf("the proxy talked to the direct control plane")
	}
}
