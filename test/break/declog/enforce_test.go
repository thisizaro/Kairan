package declogbreak

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

// I5 through enforce: every decision is recorded with the exact policy version and hash that made it, using
// the real file-backed log.

const (
	keySales  = "key-sales-0123456789"
	keyIntern = "key-intern-0123456789"
)

func polDoc(version uint64) []byte {
	return []byte(fmt.Sprintf(`{"tenant":"bank-a","version":%d,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-12T11:00:00Z","default":"deny","roles":{`+
		`"sales":{"crm.read_*":"R","crm.update_deal":"W"},"intern":{"help.*":"R"}}}`, version))
}

func activeFor(t testing.TB, version uint64, st wire.ProxyState) *enforce.Active {
	t.Helper()
	p, err := policy.Parse(polDoc(version))
	if err != nil {
		t.Fatal(err)
	}
	return &enforce.Active{Policy: p, Hash: hashN(int(version) * 1000), State: st}
}

type rig struct {
	hold *enforce.Holder
	srv  *httptest.Server
	hits atomic.Int64
	logp string
	log  *declog.Log
}

func newRig(t testing.TB, dl func(*declog.Log) enforce.DecisionLog, a *enforce.Active) *rig {
	t.Helper()
	r := &rig{hold: &enforce.Holder{}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.hits.Add(1)
		body, _ := io.ReadAll(q.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte("tools/list")) {
			io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"crm.read_contact"},{"name":"crm.update_deal"},{"name":"help.faq"},{"name":"admin.shutdown"}]}}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ran"}]}}`)
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	r.logp = filepath.Join(t.TempDir(), "decisions.log")
	l, err := declog.Open(r.logp, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	r.log = l
	t.Cleanup(func() { _ = l.Close() })
	r.hold.Store(a)
	var d enforce.DecisionLog = l
	if dl != nil {
		d = dl(l)
	}
	h := enforce.New(enforce.Config{Upstream: u, APIKeys: map[string]string{keySales: "sales", keyIntern: "intern"}}, r.hold, d, clock.NewReal(), nil)
	r.srv = httptest.NewServer(h)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rig) call(key, body string) (int, string) {
	req, _ := http.NewRequest("POST", r.srv.URL, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return -1, err.Error()
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

func callBody(tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
}

func (r *rig) records(t testing.TB) []enforce.Record {
	t.Helper()
	var out []enforce.Record
	for _, ln := range readLines(t, r.logp) {
		rc, err := declog.Decode([]byte(ln))
		if err != nil {
			t.Fatalf("log line does not decode: %v: %q", err, ln)
		}
		out = append(out, rc)
	}
	return out
}

// I5: allow, deny, list and unreadable calls each leave exactly one line stamped with the Active's version,
// hash and state; role and tool are right; and nothing from the arguments is in the file (I4).
func TestEnforceStampsEveryDecision(t *testing.T) {
	a := activeFor(t, 8, wire.StateEnforcing)
	r := newRig(t, nil, a)
	steps := []struct {
		name, key, body string
		want            enforce.Record
	}{
		{"allow read", keySales, callBody("crm.read_contact", `{"q":"`+canary+`"}`), enforce.Record{Role: "sales", Tool: "crm.read_contact", Allowed: true, Class: policy.ClassR}},
		{"allow write", keySales, callBody("crm.update_deal", `{"note":"`+canary+`"}`), enforce.Record{Role: "sales", Tool: "crm.update_deal", Allowed: true, Class: policy.ClassW}},
		{"deny not granted", keyIntern, callBody("crm.read_contact", `{"q":"`+canary+`"}`), enforce.Record{Role: "intern", Tool: "crm.read_contact", Allowed: false}},
		{"deny default", keySales, callBody("admin.shutdown", `{"why":"`+canary+`"}`), enforce.Record{Role: "sales", Tool: "admin.shutdown", Allowed: false}},
		{"list", keySales, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, enforce.Record{Role: "sales", Tool: "tools/list", Allowed: true}},
		{"hostile tool name logged empty", keySales, callBody("crm.read_contact\n"+canary, `{}`), enforce.Record{Role: "sales", Tool: "", Allowed: false}},
	}
	for _, s := range steps {
		before := len(r.records(t))
		code, _ := r.call(s.key, s.body)
		if code == -1 {
			t.Fatalf("%s: transport error", s.name)
		}
		recs := r.records(t)
		if len(recs) != before+1 {
			t.Errorf("%s: %d records before, %d after (HTTP %d); want exactly one new line per decision", s.name, before, len(recs), code)
			continue
		}
		got := recs[len(recs)-1]
		if got.Role != s.want.Role || got.Tool != s.want.Tool || got.Allowed != s.want.Allowed {
			t.Errorf("%s: logged role=%q tool=%q allowed=%v, want %q %q %v", s.name, got.Role, got.Tool, got.Allowed, s.want.Role, s.want.Tool, s.want.Allowed)
		}
		if s.want.Class != 0 && got.Class != s.want.Class {
			t.Errorf("%s: class %c, want %c", s.name, got.Class, s.want.Class)
		}
		if got.Version != 8 || got.Hash != a.Hash || got.State != wire.StateEnforcing {
			t.Errorf("%s: stamped version=%d hash=%s state=%s, want 8 %s enforcing (I5)", s.name, got.Version, got.Hash, got.State, a.Hash)
		}
		if got.Time.IsZero() {
			t.Errorf("%s: zero time", s.name)
		}
	}
	b, _ := os.ReadFile(r.logp)
	if bytes.Contains(b, []byte(canary)) {
		t.Fatalf("argument canary reached the decision log (I4):\n%s", b)
	}
}

// I5 per Active state: a Holder in each non-enforcing state stamps that state.
func TestEnforceStampsStateAndVersionOfSafeMode(t *testing.T) {
	for _, st := range []wire.ProxyState{wire.StateSafeMode, wire.StateDenyAll, wire.StateTampered} {
		t.Run(string(st), func(t *testing.T) {
			a := activeFor(t, 3, st)
			r := newRig(t, nil, a)
			_, _ = r.call(keySales, callBody("crm.read_contact", `{}`))
			_, _ = r.call(keySales, callBody("crm.update_deal", `{}`))
			recs := r.records(t)
			if len(recs) != 2 {
				t.Fatalf("%d records for 2 calls", len(recs))
			}
			for _, rc := range recs {
				if rc.State != st || rc.Version != 3 || rc.Hash != a.Hash {
					t.Errorf("stamp %+v, want state %s version 3 hash %s", rc, st, a.Hash)
				}
			}
			if st != wire.StateSafeMode && (recs[0].Allowed || recs[1].Allowed) {
				t.Errorf("state %s allowed a call (I3)", st)
			}
			if st == wire.StateSafeMode && recs[1].Allowed {
				t.Errorf("safe mode read_only allowed a write")
			}
		})
	}
}

// Fail closed (M-D33 item 3): when the log cannot store, the call is denied and NOT forwarded.
func TestEnforceFailsClosedWhenLogClosed(t *testing.T) {
	r := newRig(t, nil, activeFor(t, 8, wire.StateEnforcing))
	_ = r.log.Close()
	code, body := r.call(keySales, callBody("crm.read_contact", `{"q":"x"}`))
	if r.hits.Load() != 0 {
		t.Fatalf("call reached the upstream although the decision could not be recorded (HTTP %d %s)", code, body)
	}
	if code == 200 && !strings.Contains(body, "error") && !strings.Contains(body, "blocked") {
		t.Errorf("allowed-looking answer %d %s", code, body)
	}
	// tools/list too: an unrecorded decision must not hand out the tool list
	_, lb := r.call(keySales, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if strings.Contains(lb, "crm.read_contact") {
		t.Errorf("tools/list answered with tools although the decision log is failing: %s", lb)
	}
}

// Fail closed with a log whose Record starts failing in the middle of a run, then recovers.
type flaky struct {
	l    *declog.Log
	fail atomic.Bool
}

func (f *flaky) Record(r enforce.Record) error {
	if f.fail.Load() {
		return fmt.Errorf("disk full")
	}
	return f.l.Record(r)
}

func TestEnforceFailClosedThenRecovers(t *testing.T) {
	var fl *flaky
	r := newRig(t, func(l *declog.Log) enforce.DecisionLog { fl = &flaky{l: l}; return fl }, activeFor(t, 8, wire.StateEnforcing))
	if code, _ := r.call(keySales, callBody("crm.read_contact", `{}`)); code != 200 {
		t.Fatalf("baseline call: %d", code)
	}
	fl.fail.Store(true)
	h0 := r.hits.Load()
	_, _ = r.call(keySales, callBody("crm.read_contact", `{}`))
	if r.hits.Load() != h0 {
		t.Fatal("a call whose decision could not be stored was forwarded")
	}
	fl.fail.Store(false)
	if code, _ := r.call(keySales, callBody("crm.read_contact", `{}`)); code != 200 {
		t.Errorf("proxy did not recover after the log came back: %d", code)
	}
	if n := len(r.records(t)); n != 2 {
		t.Errorf("%d lines, want 2 (the failed call left none, the others one each)", n)
	}
}

// I5 under policy swaps: while Active changes, every line carries a (version, hash, state) triple that was
// one real Active, never a mix (the Active is read once per request).
func TestEnforceNeverMixesVersionAndHash(t *testing.T) {
	r := newRig(t, nil, activeFor(t, 1, wire.StateEnforcing))
	actives := map[uint64]*enforce.Active{}
	for v := uint64(1); v <= 5; v++ {
		actives[v] = activeFor(t, v, wire.StateEnforcing)
	}
	stop := make(chan struct{})
	var swap sync.WaitGroup
	swap.Add(1)
	go func() {
		defer swap.Done()
		v := uint64(1)
		for {
			select {
			case <-stop:
				return
			default:
			}
			v = v%5 + 1
			r.hold.Store(actives[v])
		}
	}()
	var wg sync.WaitGroup
	const workers, per = 8, 40
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r.call(keySales, callBody("crm.read_contact", `{}`))
			}
		}()
	}
	wg.Wait()
	close(stop)
	swap.Wait()
	recs := r.records(t)
	if len(recs) != workers*per {
		t.Fatalf("%d records for %d calls", len(recs), workers*per)
	}
	for _, rc := range recs {
		a, ok := actives[rc.Version]
		if !ok || rc.Hash != a.Hash {
			t.Fatalf("record stamped version %d with hash %s: not any Active that was stored (I5 mix)", rc.Version, rc.Hash)
		}
	}
}

// 401 has no role: no record (doc). Unknown key must not write a line, and must not forward.
func TestEnforceUnauthenticatedWritesNoLine(t *testing.T) {
	r := newRig(t, nil, activeFor(t, 8, wire.StateEnforcing))
	code, _ := r.call("wrong-key", callBody("crm.read_contact", `{}`))
	if code != 401 {
		t.Errorf("bad key: %d, want 401", code)
	}
	if n := len(r.records(t)); n != 0 {
		t.Errorf("%d lines written for an unauthenticated request, doc says none", n)
	}
	if r.hits.Load() != 0 {
		t.Error("unauthenticated request reached the upstream")
	}
}

// With rotation on the real log under load, every decision stays whole and decodes.
func TestEnforceWithRotationKeepsLinesWhole(t *testing.T) {
	a := activeFor(t, 8, wire.StateEnforcing)
	dir := t.TempDir()
	p := filepath.Join(dir, "decisions.log")
	l, err := declog.Open(p, declog.Options{MaxBytes: 2048, Keep: 200})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	hold := &enforce.Holder{}
	hold.Store(a)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		io.Copy(io.Discard, q.Body)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{}}`)
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	srv := httptest.NewServer(enforce.New(enforce.Config{Upstream: u, APIKeys: map[string]string{keySales: "sales"}}, hold, l, clock.NewReal(), nil))
	defer srv.Close()
	var wg sync.WaitGroup
	const workers, per = 8, 50
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < per; i++ {
				req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(callBody("crm.read_contact", `{}`)))
				req.Header.Set("Authorization", "Bearer "+keySales)
				req.Header.Set("Content-Type", "application/json")
				if res, err := http.DefaultClient.Do(req); err == nil {
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
	total := 0
	files, _ := filepath.Glob(p + "*")
	for _, f := range files {
		for _, ln := range readLines(t, f) {
			if _, err := declog.Decode([]byte(ln)); err != nil {
				t.Fatalf("%s: %v: %q", f, err, ln)
			}
			total++
		}
	}
	if total != workers*per {
		t.Errorf("%d decisions on disk across %d files, want %d", total, len(files), workers*per)
	}
}

// Latency sanity: 100 sequential allowed calls through the real log finish in a few seconds (no hidden sleep).
func TestEnforceSequentialLatency(t *testing.T) {
	r := newRig(t, nil, activeFor(t, 8, wire.StateEnforcing))
	start := time.Now()
	for i := 0; i < 100; i++ {
		if code, _ := r.call(keySales, callBody("crm.read_contact", `{}`)); code != 200 {
			t.Fatalf("call %d: %d", i, code)
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("100 sequential calls took %v", d)
	}
}
