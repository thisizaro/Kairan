package enforce

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

// ---- test doubles ---------------------------------------------------------

var (
	hashA = wire.Hash(strings.Repeat("a", 64))
	hashB = wire.Hash(strings.Repeat("b", 64))
)

// policyJSON builds a valid policy payload. Roles:
//
//	reader: notes.read (R), crm.read_* (R)
//	writer: reader + notes.write (W), crm.update_deal (W)
//	boss:   crm.export (X), notes.* (W)
func policyJSON(version int) string {
	return fmt.Sprintf(`{"tenant":"bank-a","version":%d,"issued_at":"2026-11-05T09:00:00Z","expires_at":"2026-11-08T09:00:00Z","default":"deny","roles":{`+
		`"reader":{"notes.read":"R","crm.read_*":"R"},`+
		`"writer":{"notes.read":"R","crm.read_*":"R","notes.write":"W","crm.update_deal":"W"},`+
		`"boss":{"crm.export":"X","notes.*":"W"}}}`, version)
}

func mustPolicy(t testing.TB, version int) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(policyJSON(version)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func enforcing(t testing.TB, version int, hash wire.Hash) *Active {
	return &Active{Policy: mustPolicy(t, version), Hash: hash, State: wire.StateEnforcing}
}

type memLog struct {
	mu   sync.Mutex
	recs []Record
	fail atomic.Bool
}

func (l *memLog) Record(r Record) error {
	if l.fail.Load() {
		return errors.New("disk full")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.recs = append(l.recs, r)
	return nil
}

func (l *memLog) all() []Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Record(nil), l.recs...)
}

type counters struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counters) Inc(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[name]++
}

func (c *counters) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[name]
}

type seenReq struct {
	Method string
	Header http.Header
	Body   []byte
}

// upstream is a fake MCP server. By default it answers like fakemcp: five
// tools, canned call results, as JSON or (sse=true) as an event stream.
type upstream struct {
	srv  *httptest.Server
	sse  bool
	over func(w http.ResponseWriter, r *http.Request, body []byte) bool // optional override; true = handled
	mu   sync.Mutex
	seen []seenReq
}

func newUpstream(t testing.TB) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, seenReq{r.Method, r.Header.Clone(), body})
		u.mu.Unlock()
		if u.over != nil && u.over(w, r, body) {
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		var result string
		switch req.Method {
		case "tools/list":
			result = `{"tools":` + fiveTools + `}`
		case "tools/call":
			result = `{"content":[{"type":"text","text":"upstream ran it"}],"isError":false}`
		default:
			result = `{}`
		}
		msg := `{"jsonrpc":"2.0","id":` + string(req.ID) + `,"result":` + result + `}`
		if len(req.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Mcp-Session-Id", "sess-1")
		if u.sse {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, msg)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) requests() []seenReq {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]seenReq(nil), u.seen...)
}

type rig struct {
	t     *testing.T
	up    *upstream
	h     *Holder
	log   *memLog
	m     *counters
	srv   *httptest.Server
	clk   *clock.Fake
	cfg   Config
	proxy http.Handler
}

func newRig(t *testing.T, mutate func(*Config)) *rig {
	t.Helper()
	r := &rig{t: t, up: newUpstream(t), h: &Holder{}, log: &memLog{}, m: &counters{}, clk: clock.NewFake(time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC))}
	u, _ := url.Parse(r.up.srv.URL)
	r.cfg = Config{
		Upstream: u,
		APIKeys:  map[string]string{"key-reader": "reader", "key-writer": "writer", "key-boss": "boss", "key-unknown-role": "ghost"},
	}
	if mutate != nil {
		mutate(&r.cfg)
	}
	r.proxy = New(r.cfg, r.h, r.log, r.clk, r.m)
	r.srv = httptest.NewServer(r.proxy)
	t.Cleanup(r.srv.Close)
	return r
}

type reply struct {
	Status int
	Header http.Header
	Body   string
}

func (r *rig) do(method, key string, hdr map[string]string, body string) reply {
	r.t.Helper()
	req, err := http.NewRequest(method, r.srv.URL+"/mcp", strings.NewReader(body))
	if err != nil {
		r.t.Fatal(err)
	}
	if body == "" {
		req.Body = nil
		req.ContentLength = 0
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{resp.StatusCode, resp.Header, string(b)}
}

func (r *rig) post(key, body string) reply { return r.do(http.MethodPost, key, nil, body) }

func callBody(id int, tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

func listBody(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, id)
}

// isBlocked reports whether a body is the MCP tool error "blocked by policy vN".
func isBlocked(t *testing.T, body string, version int) bool {
	t.Helper()
	var m struct {
		Result struct {
			IsError bool `json:"isError"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return false
	}
	return m.Result.IsError && len(m.Result.Content) == 1 && m.Result.Content[0].Text == fmt.Sprintf("blocked by policy v%d", version)
}

func listedTools(t *testing.T, body string) []string {
	t.Helper()
	if strings.HasPrefix(strings.TrimSpace(body), "event:") || strings.HasPrefix(body, "data:") {
		ev := testEvents(body)
		if len(ev) == 0 {
			t.Fatalf("no events: %q", body)
		}
		body = ev[len(ev)-1]
	}
	return toolNames(t, []byte(body))
}

func tools(names ...string) string { return strings.Join(names, ",") }

// ---- tests ------------------------------------------------------------------

func TestAuth(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	body := callBody(1, "notes.read", `{}`)
	tests := []struct {
		name string
		hdr  map[string]string
		want int
	}{
		{"bearer ok", map[string]string{"Authorization": "Bearer key-reader"}, 200},
		{"bearer scheme case-insensitive", map[string]string{"Authorization": "bearer key-reader"}, 200},
		{"x-api-key ok", map[string]string{"Authorization": "", "X-Api-Key": "key-reader"}, 200},
		{"both agree", map[string]string{"X-Api-Key": "key-reader"}, 200},
		{"both disagree", map[string]string{"X-Api-Key": "key-writer"}, 401},
		{"no key", map[string]string{"Authorization": ""}, 401},
		{"wrong key", map[string]string{"Authorization": "Bearer key-nope"}, 401},
		{"prefix of a key", map[string]string{"Authorization": "Bearer key-read"}, 401},
		{"key plus suffix", map[string]string{"Authorization": "Bearer key-readerX"}, 401},
		{"key uppercased", map[string]string{"Authorization": "Bearer KEY-READER"}, 401},
		{"empty bearer", map[string]string{"Authorization": "Bearer "}, 401},
		{"basic scheme", map[string]string{"Authorization": "Basic key-reader"}, 401},
		{"bare token", map[string]string{"Authorization": "key-reader"}, 401},
		{"empty x-api-key", map[string]string{"Authorization": "", "X-Api-Key": ""}, 401},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.up.requests())
			hdr := map[string]string{"Authorization": "Bearer key-reader"}
			for k, v := range tc.hdr {
				hdr[k] = v
			}
			rep := r.do(http.MethodPost, "", hdr, body)
			if rep.Status != tc.want {
				t.Fatalf("status %d, want %d (%s)", rep.Status, tc.want, rep.Body)
			}
			if tc.want == 401 {
				if len(r.up.requests()) != before {
					t.Fatal("unauthenticated request reached the upstream")
				}
				if strings.Contains(rep.Body, "reader") || strings.Contains(rep.Body, "role") || strings.Contains(rep.Body, "key-") {
					t.Fatalf("401 body leaks: %s", rep.Body)
				}
			}
		})
	}
	// An unauthenticated request leaves no decision record: there is no role to put in it.
	n := len(r.log.all())
	r.do(http.MethodPost, "", map[string]string{"Authorization": ""}, body)
	if len(r.log.all()) != n {
		t.Fatal("401 wrote a decision record")
	}
	if r.m.get("enforce_auth_failed") == 0 {
		t.Fatal("auth failures not counted")
	}
	// Auth comes before any body read: a 401 for an unreadable body.
	rep := r.do(http.MethodPost, "", map[string]string{"Authorization": "Bearer nope", "Content-Type": "text/plain"}, "garbage")
	if rep.Status != 401 {
		t.Fatalf("garbage + bad key: %d", rep.Status)
	}
	// Other methods need a key too.
	for _, m := range []string{http.MethodGet, http.MethodDelete, http.MethodPut} {
		if rep := r.do(m, "", map[string]string{"Authorization": ""}, ""); rep.Status != 401 {
			t.Fatalf("%s without key: %d", m, rep.Status)
		}
	}
}

func TestAuthEmptyConfigKeys(t *testing.T) {
	r := newRig(t, func(c *Config) { c.APIKeys = map[string]string{"": "reader", "k": ""} })
	r.h.Store(enforcing(t, 8, hashA))
	for _, key := range []string{"", "k"} {
		hdr := map[string]string{"Authorization": "Bearer " + key}
		if rep := r.do(http.MethodPost, "", hdr, callBody(1, "notes.read", `{}`)); rep.Status != 401 {
			t.Fatalf("key %q accepted: %d", key, rep.Status)
		}
	}
}

func TestCallAllowedAndDenied(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	tests := []struct {
		key, tool string
		allowed   bool
		class     policy.Class
		role      string
	}{
		{"key-reader", "notes.read", true, policy.ClassR, "reader"},
		{"key-reader", "crm.read_contact", true, policy.ClassR, "reader"},
		{"key-reader", "notes.write", false, 0, "reader"},
		{"key-reader", "crm.export", false, 0, "reader"},
		{"key-writer", "notes.write", true, policy.ClassW, "writer"},
		{"key-writer", "crm.update_deal", true, policy.ClassW, "writer"},
		{"key-writer", "crm.export", false, 0, "writer"},
		{"key-boss", "crm.export", true, policy.ClassX, "boss"},
		{"key-boss", "notes.read", true, policy.ClassW, "boss"},
		{"key-boss", "crm.read_contact", false, 0, "boss"},
		{"key-unknown-role", "notes.read", false, 0, "ghost"},
		{"key-reader", "Notes.Read", false, 0, "reader"}, // case-sensitive
		{"key-reader", "notes.read ", false, 0, "reader"},
		{"key-reader", "../notes.read", false, 0, "reader"},
		{"key-reader", "nope", false, 0, "reader"},
	}
	for i, tc := range tests {
		before, nlog := len(r.up.requests()), len(r.log.all())
		body := callBody(100+i, tc.tool, `{"q":"v"}`)
		rep := r.post(tc.key, body)
		if rep.Status != 200 {
			t.Fatalf("%s %s: status %d", tc.key, tc.tool, rep.Status)
		}
		recs := r.log.all()
		if len(recs) != nlog+1 {
			t.Fatalf("%s %s: %d records, want 1 new", tc.key, tc.tool, len(recs)-nlog)
		}
		rec := recs[len(recs)-1]
		if rec.Allowed != tc.allowed || rec.Role != tc.role || rec.Version != 8 || rec.Hash != hashA || rec.State != wire.StateEnforcing || rec.Class != tc.class {
			t.Fatalf("%s %s: record %+v", tc.key, tc.tool, rec)
		}
		if !rec.Time.Equal(r.clk.Now()) {
			t.Fatalf("record time %v, clock %v", rec.Time, r.clk.Now())
		}
		reqs := r.up.requests()
		if tc.allowed {
			if len(reqs) != before+1 {
				t.Fatalf("%s %s: allowed call did not reach the upstream", tc.key, tc.tool)
			}
			if !bytes.Equal(reqs[len(reqs)-1].Body, []byte(body)) {
				t.Fatalf("forwarded bytes differ:\n got %q\nwant %q", reqs[len(reqs)-1].Body, body)
			}
			if !strings.Contains(rep.Body, "upstream ran it") || isBlocked(t, rep.Body, 8) {
				t.Fatalf("allowed call answer: %s", rep.Body)
			}
			if rec.Tool != tc.tool {
				t.Fatalf("record tool %q", rec.Tool)
			}
		} else {
			if len(reqs) != before {
				t.Fatalf("%s %s: denied call reached the upstream", tc.key, tc.tool)
			}
			if !isBlocked(t, rep.Body, 8) {
				t.Fatalf("%s %s: not a blocked tool error: %s", tc.key, tc.tool, rep.Body)
			}
			var m struct {
				ID json.RawMessage `json:"id"`
			}
			_ = json.Unmarshal([]byte(rep.Body), &m)
			if string(m.ID) != fmt.Sprint(100+i) {
				t.Fatalf("deny id %s", m.ID)
			}
		}
	}
}

func TestCallForwardsExactBytes(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	// Odd but legal bodies: whitespace, escapes, mixed-case argument keys, unicode, big numbers.
	bodies := []string{
		" \n{ \"jsonrpc\" : \"2.0\",\t\"id\":\"x-1\", \"method\":\"tools\\/call\", \"params\":{\"arguments\":{\"A\":1e400,\"Method\":\"tools/list\",\"t\":\"\\u65e5\\u672c\"},\"name\":\"notes\\u002eread\"}}\r\n",
		`{"id":1,"method":"tools/call","params":{"name":"notes.read","arguments":{"big":123456789012345678901234567890}}}`,
	}
	for _, b := range bodies {
		rep := r.post("key-reader", b)
		if rep.Status != 200 || isBlocked(t, rep.Body, 8) {
			t.Fatalf("body rejected: %d %s", rep.Status, rep.Body)
		}
		reqs := r.up.requests()
		if got := reqs[len(reqs)-1].Body; !bytes.Equal(got, []byte(b)) {
			t.Fatalf("forwarded bytes differ:\n got %q\nwant %q", got, b)
		}
	}
}

func TestDenyResponseUsesPolicyVersionOfThisCall(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 9, hashB))
	rep := r.post("key-reader", callBody(1, "crm.export", `{}`))
	if !isBlocked(t, rep.Body, 9) {
		t.Fatal(rep.Body)
	}
	recs := r.log.all()
	if recs[0].Version != 9 || recs[0].Hash != hashB {
		t.Fatalf("%+v", recs[0])
	}
}

func TestToolsListFiltered(t *testing.T) {
	for _, sse := range []bool{false, true} {
		t.Run(fmt.Sprintf("sse=%v", sse), func(t *testing.T) {
			r := newRig(t, nil)
			r.up.sse = sse
			r.h.Store(enforcing(t, 8, hashA))
			tests := []struct {
				key  string
				want string
			}{
				{"key-reader", tools("notes.read", "crm.read_contact")},
				{"key-writer", tools("notes.read", "crm.read_contact", "notes.write", "crm.update_deal")},
				{"key-boss", tools("notes.read", "notes.write", "crm.export")},
				{"key-unknown-role", ""},
			}
			for i, tc := range tests {
				rep := r.post(tc.key, listBody(i+1))
				if rep.Status != 200 {
					t.Fatalf("status %d: %s", rep.Status, rep.Body)
				}
				got := tools(listedTools(t, rep.Body)...)
				if got != tc.want {
					t.Fatalf("%s: tools %q, want %q", tc.key, got, tc.want)
				}
				wantCT := "application/json"
				if sse {
					wantCT = "text/event-stream"
				}
				if ct := rep.Header.Get("Content-Type"); ct != wantCT {
					t.Fatalf("content type %q", ct)
				}
				if rep.Header.Get("Mcp-Session-Id") != "sess-1" {
					t.Fatalf("session header lost: %v", rep.Header)
				}
			}
			// A tool is listed if and only if a call to it is allowed.
			for _, key := range []string{"key-reader", "key-writer", "key-boss", "key-unknown-role"} {
				listed := map[string]bool{}
				for _, n := range listedTools(t, r.post(key, listBody(50)).Body) {
					listed[n] = true
				}
				for _, n := range []string{"notes.read", "crm.read_contact", "notes.write", "crm.update_deal", "crm.export"} {
					rep := r.post(key, callBody(60, n, `{}`))
					allowed := !isBlocked(t, rep.Body, 8)
					if allowed != listed[n] {
						t.Fatalf("%s %s: listed=%v allowed=%v", key, n, listed[n], allowed)
					}
				}
			}
		})
	}
}

func TestToolsListAnswersAreRecorded(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	r.post("key-reader", listBody(1))
	recs := r.log.all()
	if len(recs) != 1 || recs[0].Tool != "tools/list" || !recs[0].Allowed || recs[0].Version != 8 || recs[0].Hash != hashA || recs[0].Role != "reader" {
		t.Fatalf("%+v", recs)
	}
}

func TestToolsListUpstreamTroubleFailsClosed(t *testing.T) {
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write([]byte(s))
		_ = w.Close()
		return b.Bytes()
	}
	cases := []struct {
		name string
		over func(w http.ResponseWriter, r *http.Request, body []byte) bool
		want string // "empty" | "status:NNN"
	}{
		{"html", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.Header().Set("Content-Type", "text/html")
			_, _ = io.WriteString(w, jsonResp("1", fiveTools))
			return true
		}, "empty"},
		{"no content type", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.Header()["Content-Type"] = nil
			_, _ = io.WriteString(w, jsonResp("1", fiveTools))
			return true
		}, "empty"},
		{"gzip", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(gz(jsonResp("1", fiveTools)))
			return true
		}, "empty"},
		{"truncated json", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, jsonResp("1", fiveTools)[:40])
			return true
		}, "empty"},
		{"oversized", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"notes.read"}],"pad":"`+strings.Repeat("x", maxListBody)+`"}}`)
			return true
		}, "empty"},
		{"500", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, jsonResp("1", fiveTools))
			return true
		}, "status:502"},
		{"202 no body", func(w http.ResponseWriter, r *http.Request, b []byte) bool { w.WriteHeader(202); return true }, "status:502"},
		{"redirect not followed", func(w http.ResponseWriter, r *http.Request, b []byte) bool {
			http.Redirect(w, r, "http://127.0.0.1:1/elsewhere", http.StatusTemporaryRedirect)
			return true
		}, "status:502"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, nil)
			r.up.over = tc.over
			r.h.Store(enforcing(t, 8, hashA))
			rep := r.post("key-boss", listBody(1))
			if strings.HasPrefix(tc.want, "status:") {
				if fmt.Sprint(rep.Status) != strings.TrimPrefix(tc.want, "status:") {
					t.Fatalf("status %d: %s", rep.Status, rep.Body)
				}
			} else if rep.Status != 200 || len(listedTools(t, rep.Body)) != 0 {
				t.Fatalf("not an empty list: %d %s", rep.Status, rep.Body)
			}
			if strings.Contains(rep.Body, "crm.export") || strings.Contains(rep.Body, "crm.update_deal") {
				t.Fatalf("hidden tool in %s", rep.Body)
			}
		})
	}
}

func TestToolsListHostileUpstreamSSE(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	r.up.over = func(w http.ResponseWriter, req *http.Request, body []byte) bool {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, event(jsonResp("1", `[{"name":"crm.export"}]`))) // injected before the real answer (id 1 is the first request)
		fmt.Fprint(w, event(jsonResp("1", fiveTools)))
		fmt.Fprint(w, event(jsonResp("77", `[{"name":"crm.update_deal"}]`)))
		fmt.Fprint(w, "event: message\ndata: [{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[{\"name\":\"crm.export\"}]}}]\n\n")
		return true
	}
	rep := r.post("key-reader", listBody(1))
	if strings.Contains(rep.Body, "crm.export") || strings.Contains(rep.Body, "crm.update_deal") || strings.Contains(rep.Body, "notes.write") {
		t.Fatalf("injected tool reached the agent: %s", rep.Body)
	}
	if got := tools(listedTools(t, rep.Body)...); got != tools("notes.read", "crm.read_contact") && got != "" {
		t.Fatalf("tools %q", got)
	}
}

func TestPassThrough(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(&Active{State: wire.StateDenyAll}) // pass-through needs no policy
	for _, body := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"c"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":3,"method":"resources/list"}`,
	} {
		rep := r.post("key-reader", body)
		if rep.Status != 200 || !strings.Contains(rep.Body, `"result":{}`) {
			t.Fatalf("%s -> %d %s", body, rep.Status, rep.Body)
		}
		reqs := r.up.requests()
		if !bytes.Equal(reqs[len(reqs)-1].Body, []byte(body)) {
			t.Fatalf("body altered: %q", reqs[len(reqs)-1].Body)
		}
	}
	// A notification: the upstream answers 202 with no body.
	rep := r.post("key-reader", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rep.Status != 202 {
		t.Fatalf("notification: %d", rep.Status)
	}
	if rep.Header.Get("Mcp-Session-Id") != "" {
		t.Fatalf("unexpected header on 202: %v", rep.Header)
	}
	// GET and DELETE go through with no body.
	r.up.over = func(w http.ResponseWriter, req *http.Request, body []byte) bool {
		w.Header().Set("X-Seen-Method", req.Method)
		w.WriteHeader(200)
		return true
	}
	for _, m := range []string{http.MethodGet, http.MethodDelete} {
		rep := r.do(m, "key-reader", nil, "")
		if rep.Status != 200 || rep.Header.Get("X-Seen-Method") != m {
			t.Fatalf("%s: %d %v", m, rep.Status, rep.Header)
		}
	}
	// Anything else is refused.
	if rep := r.do(http.MethodPut, "key-reader", nil, "x"); rep.Status != 405 {
		t.Fatalf("PUT: %d", rep.Status)
	}
	// Pass-through is not a decision.
	if n := len(r.log.all()); n != 0 {
		t.Fatalf("%d records for pass-through", n)
	}
}

func TestUpstreamSeesNoAgentCredentials(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	rep := r.do(http.MethodPost, "", map[string]string{
		"Authorization": "Bearer key-reader", "X-Api-Key": "key-reader", "Mcp-Session-Id": "abc", "Accept": "application/json, text/event-stream",
		"Connection": "X-Hop", "X-Hop": "1",
	}, callBody(1, "notes.read", `{}`))
	if rep.Status != 200 {
		t.Fatal(rep.Body)
	}
	h := r.up.requests()[0].Header
	if h.Get("Authorization") != "" || h.Get("X-Api-Key") != "" || h.Get("X-Hop") != "" {
		t.Fatalf("credentials or hop header forwarded: %v", h)
	}
	if h.Get("Mcp-Session-Id") != "abc" || h.Get("Accept") != "application/json, text/event-stream" {
		t.Fatalf("end-to-end headers lost: %v", h)
	}
}

func TestStates(t *testing.T) {
	pol := mustPolicy(t, 8)
	tests := []struct {
		name     string
		active   *Active
		mode     state.SafeMode
		wantList string // reader
		wantCall map[string]bool
	}{
		{"nil active", nil, "", "", map[string]bool{"notes.read": false, "notes.write": false}},
		{"booting", &Active{Policy: pol, Hash: hashA, State: wire.StateBooting}, "", "", map[string]bool{"notes.read": false}},
		{"deny_all state", &Active{State: wire.StateDenyAll}, "", "", map[string]bool{"notes.read": false}},
		{"deny_all state even with a policy", &Active{Policy: pol, Hash: hashA, State: wire.StateDenyAll}, "", "", map[string]bool{"notes.read": false}},
		{"tampered", &Active{Policy: pol, Hash: hashA, State: wire.StateTampered}, "", "", map[string]bool{"notes.read": false}},
		{"unknown state", &Active{Policy: pol, Hash: hashA, State: "wide_open"}, "", "", map[string]bool{"notes.read": false}},
		{"empty state", &Active{Policy: pol, Hash: hashA}, "", "", map[string]bool{"notes.read": false}},
		{"enforcing", &Active{Policy: pol, Hash: hashA, State: wire.StateEnforcing}, "", tools("notes.read", "crm.read_contact"), map[string]bool{"notes.read": true, "notes.write": false}},
		{"safe read_only default", &Active{Policy: pol, Hash: hashA, State: wire.StateSafeMode}, "", tools("notes.read", "crm.read_contact"), map[string]bool{"notes.read": true, "notes.write": false}},
		{"safe read_only", &Active{Policy: pol, Hash: hashA, State: wire.StateSafeMode}, state.ReadOnly, tools("notes.read", "crm.read_contact"), map[string]bool{"notes.read": true}},
		{"safe deny_all", &Active{Policy: pol, Hash: hashA, State: wire.StateSafeMode}, state.DenyAll, "", map[string]bool{"notes.read": false}},
		{"safe unknown mode", &Active{Policy: pol, Hash: hashA, State: wire.StateSafeMode}, "wide_open", "", map[string]bool{"notes.read": false}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(c *Config) { c.SafeMode = tc.mode })
			if tc.active != nil {
				r.h.Store(tc.active)
			}
			before := len(r.up.requests())
			if got := tools(listedTools(t, r.post("key-reader", listBody(1)).Body)...); got != tc.wantList {
				t.Fatalf("list %q, want %q", got, tc.wantList)
			}
			if tc.wantList == "" && len(r.up.requests()) != before {
				t.Fatal("a refused list still contacted the upstream")
			}
			for tool, want := range tc.wantCall {
				rep := r.post("key-reader", callBody(2, tool, `{}`))
				if got := !strings.Contains(rep.Body, "blocked by policy"); got != want {
					t.Fatalf("call %s: allowed=%v want %v (%s)", tool, got, want, rep.Body)
				}
			}
		})
	}
	// Safe mode read_only: a W tool the role may use is denied, with the class in the record.
	r := newRig(t, nil)
	r.h.Store(&Active{Policy: pol, Hash: hashA, State: wire.StateSafeMode})
	rep := r.post("key-writer", callBody(1, "notes.write", `{}`))
	if !isBlocked(t, rep.Body, 8) {
		t.Fatal(rep.Body)
	}
	rec := r.log.all()[0]
	if rec.Allowed || rec.Class != policy.ClassW || rec.State != wire.StateSafeMode {
		t.Fatalf("%+v", rec)
	}
}

func TestDecisionLogFailureDenies(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	r.log.fail.Store(true)
	before := len(r.up.requests())
	rep := r.post("key-reader", callBody(1, "notes.read", `{}`))
	if !isBlocked(t, rep.Body, 8) {
		t.Fatalf("call allowed without a decision record: %s", rep.Body)
	}
	if len(r.up.requests()) != before {
		t.Fatal("upstream reached")
	}
	if got := tools(listedTools(t, r.post("key-reader", listBody(2)).Body)...); got != "" {
		t.Fatalf("list served without a decision record: %q", got)
	}
	if r.m.get("enforce_decision_log_errors") < 2 {
		t.Fatalf("not counted: %v", r.m.m)
	}
	r.log.fail.Store(false)
	if rep := r.post("key-reader", callBody(3, "notes.read", `{}`)); isBlocked(t, rep.Body, 8) {
		t.Fatal("did not recover")
	}
}

func TestNilDecisionLogDenies(t *testing.T) {
	up := newUpstream(t)
	u, _ := url.Parse(up.srv.URL)
	h := &Holder{}
	h.Store(enforcing(t, 8, hashA))
	srv := httptest.NewServer(New(Config{Upstream: u, APIKeys: map[string]string{"k": "reader"}}, h, nil, clock.NewFake(time.Unix(0, 0)), nil))
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(callBody(1, "notes.read", `{}`)))
	req.Header.Set("Authorization", "Bearer k")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !isBlocked(t, string(b), 8) || len(up.requests()) != 0 {
		t.Fatalf("%s", b)
	}
}

// ---- attacks on the request reader (M-D33, THREATS #13) ------------------------

func TestAttackBodiesNeverReachUpstream(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	bodies := map[string]string{
		"duplicate method":             `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"crm.export"}}`,
		"capital Method":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","Method":"tools/list","params":{"name":"crm.export"}}`,
		"method only capital":          `{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"crm.export"}}`,
		"escaped key":                  `{"jsonrpc":"2.0","id":1,"\u006dethod":"tools/call","params":{"name":"crm.export"}}`,
		"escaped params key":           `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"n\u0061me":"crm.export"}}`,
		"duplicate name":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","name":"crm.export"}}`,
		"capital Name":                 `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","Name":"crm.export"}}`,
		"capital Params":               `{"jsonrpc":"2.0","id":1,"method":"tools/call","Params":{"name":"crm.export"},"params":{"name":"notes.read"}}`,
		"long-s params":                "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"paramſ\":{\"name\":\"crm.export\"},\"params\":{\"name\":\"notes.read\"}}",
		"batch":                        `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.export"}}]`,
		"batch with allowed first":     `[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read"}},{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"crm.export"}}]`,
		"trailing second object":       `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read"}}{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"crm.export"}}`,
		"BOM":                          "\xef\xbb\xbf" + `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.export"}}`,
		"method with case change":      `{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"crm.export"}}`,
		"method padded":                `{"jsonrpc":"2.0","id":1,"method":"tools/call ","params":{"name":"crm.export"}}`,
		"truncated":                    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.export"`,
		"invalid utf8":                 "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"crm.export\xff\"}}",
		"call without params":          `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
		"name not string":              `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["crm.export"]}}`,
		"non-object":                   `"tools/call"`,
		"empty":                        ``,
		"call as notification":         `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"crm.export"}}`,
		"object id":                    `{"jsonrpc":"2.0","id":{"a":1},"method":"tools/call","params":{"name":"crm.export"}}`,
		"deeply nested arguments":      callBody(1, "crm.export", strings.Repeat("[", 500)+strings.Repeat("]", 500)),
		"tools/list duplicate params":  `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"cursor":"a","cursor":"b"}}`,
		"tools/list with Capital Meth": `{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"crm.export"}}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			before, nlog := len(r.up.requests()), len(r.log.all())
			rep := r.post("key-reader", body)
			if rep.Status != 400 {
				t.Fatalf("status %d: %s", rep.Status, rep.Body)
			}
			if len(r.up.requests()) != before {
				t.Fatal("attack body reached the upstream")
			}
			recs := r.log.all()
			if len(recs) != nlog+1 {
				t.Fatalf("expected one logged deny, got %d new records", len(recs)-nlog)
			}
			rec := recs[len(recs)-1]
			if rec.Allowed || rec.Role != "reader" || rec.Version != 8 || rec.Hash != hashA || rec.Tool != "" {
				t.Fatalf("record %+v", rec)
			}
			var e struct {
				ID    json.RawMessage `json:"id"`
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal([]byte(rep.Body), &e); err != nil || e.Error.Code != -32600 || string(e.ID) != "null" {
				t.Fatalf("reply %s (%v)", rep.Body, err)
			}
			if strings.Contains(rep.Body, "crm.export") {
				t.Fatalf("reply repeats the payload: %s", rep.Body)
			}
		})
	}
}

func TestAttackTransport(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	good := callBody(1, "notes.read", `{}`)
	bad := callBody(1, "crm.export", `{}`)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(good))
	_ = zw.Close()

	tests := []struct {
		name string
		hdr  map[string]string
		body string
		want int
	}{
		{"text/plain", map[string]string{"Content-Type": "text/plain"}, good, 415},
		{"form", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, good, 415},
		{"no content type", map[string]string{"Content-Type": ""}, good, 415},
		{"json look-alike", map[string]string{"Content-Type": "application/jsonp"}, good, 415},
		{"json+suffix", map[string]string{"Content-Type": "application/vnd.api+json"}, good, 415},
		{"multipart", map[string]string{"Content-Type": "multipart/form-data; boundary=x"}, good, 415},
		{"garbage type", map[string]string{"Content-Type": "application/json;;;"}, good, 415},
		{"json with other charset", map[string]string{"Content-Type": "application/json; charset=utf-16"}, good, 415},
		{"json with unknown param", map[string]string{"Content-Type": "application/json; profile=x"}, good, 415},
		{"json charset utf-8 ok", map[string]string{"Content-Type": "application/json; charset=UTF-8"}, good, 200},
		{"JSON upper-case type ok", map[string]string{"Content-Type": "Application/JSON"}, good, 200},
		{"gzip body", map[string]string{"Content-Encoding": "gzip"}, gz.String(), 415},
		{"deflate", map[string]string{"Content-Encoding": "deflate"}, good, 415},
		{"br", map[string]string{"Content-Encoding": "br"}, good, 415},
		{"identity encoding ok", map[string]string{"Content-Encoding": "identity"}, good, 200},
		{"gzip header over plain bad body", map[string]string{"Content-Encoding": "gzip"}, bad, 415},
		{"too large", nil, `{"id":1,"method":"ping","pad":"` + strings.Repeat("x", MaxBodyBytes) + `"}`, 413},
		{"exactly at the cap but invalid", nil, strings.Repeat(" ", MaxBodyBytes), 400},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := len(r.up.requests())
			rep := r.do(http.MethodPost, "key-reader", tc.hdr, tc.body)
			if rep.Status != tc.want {
				t.Fatalf("status %d, want %d", rep.Status, tc.want)
			}
			reached := len(r.up.requests()) != before
			if tc.want != 200 && reached {
				t.Fatal("rejected request reached the upstream")
			}
			if tc.want == 200 && !reached {
				t.Fatal("good request did not reach the upstream")
			}
		})
	}
	// Two Content-Type headers: refuse.
	req, _ := http.NewRequest("POST", r.srv.URL, strings.NewReader(good))
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Type", "text/plain")
	req.Header.Set("Authorization", "Bearer key-reader")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 415 {
		t.Fatalf("two content types: %d", resp.StatusCode)
	}
}

// A chunked body is read whole, and the upstream gets exactly those bytes
// with a fixed length, never chunked framing the proxy did not inspect.
func TestChunkedBodyForwardedAsInspected(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	pr, pw := io.Pipe()
	req, _ := http.NewRequest("POST", r.srv.URL, pr)
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer key-reader")
	body := callBody(1, "notes.read", `{"a":1}`)
	go func() {
		for i := 0; i < len(body); i += 7 {
			end := min(i+7, len(body))
			_, _ = pw.Write([]byte(body[i:end]))
		}
		_ = pw.Close()
	}()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), "upstream ran it") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	got := r.up.requests()[0]
	if string(got.Body) != body {
		t.Fatalf("forwarded %q", got.Body)
	}
	if te := got.Header.Get("Transfer-Encoding"); te != "" {
		t.Fatalf("Transfer-Encoding forwarded: %q", te)
	}
}

// A chunked request that smuggles a second request after the first (HTTP-level
// pipelining attempt) never reaches the upstream as a second call.
func TestCannotSmuggleSecondCallInBody(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	two := callBody(1, "notes.read", `{}`) + "\r\n" + callBody(2, "crm.export", `{}`)
	rep := r.post("key-reader", two)
	if rep.Status != 400 {
		t.Fatalf("status %d", rep.Status)
	}
	for _, q := range r.up.requests() {
		if strings.Contains(string(q.Body), "crm.export") {
			t.Fatal("hidden call reached the upstream")
		}
	}
}

func TestToolErrorForAllowedCallPassesThrough(t *testing.T) {
	// The allowed call's answer is the upstream's, byte for byte, JSON or SSE, status included.
	for _, sse := range []bool{false, true} {
		r := newRig(t, nil)
		r.up.sse = sse
		r.h.Store(enforcing(t, 8, hashA))
		rep := r.post("key-reader", callBody(5, "notes.read", `{}`))
		want := `{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"upstream ran it"}],"isError":false}}`
		if sse {
			want = "event: message\ndata: " + want + "\n\n"
		}
		if rep.Body != want {
			t.Fatalf("sse=%v got %q", sse, rep.Body)
		}
	}
}

func TestUpstreamErrors(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	r.up.srv.Close() // connection refused
	rep := r.post("key-reader", callBody(4, "notes.read", `{}`))
	if rep.Status != 502 || !strings.Contains(rep.Body, `"id":4`) || !strings.Contains(rep.Body, "upstream unavailable") {
		t.Fatalf("%d %s", rep.Status, rep.Body)
	}
	if r.m.get("enforce_upstream_errors") != 1 {
		t.Fatalf("%v", r.m.m)
	}
	// The allow was recorded before the call: the log says what was decided.
	if recs := r.log.all(); len(recs) != 1 || !recs[0].Allowed {
		t.Fatalf("%+v", recs)
	}
}

func TestUpstreamTimeout(t *testing.T) {
	r := newRig(t, func(c *Config) { c.UpstreamTimeout = 150 * time.Millisecond })
	r.h.Store(enforcing(t, 8, hashA))
	done := make(chan struct{})
	defer close(done)
	r.up.over = func(w http.ResponseWriter, req *http.Request, body []byte) bool {
		select {
		case <-done:
		case <-req.Context().Done():
		case <-time.After(5 * time.Second):
		}
		return true
	}
	start := time.Now()
	rep := r.post("key-reader", callBody(4, "notes.read", `{}`))
	if rep.Status != 504 || !strings.Contains(rep.Body, "upstream timeout") {
		t.Fatalf("%d %s", rep.Status, rep.Body)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("timeout took %v", d)
	}
	// Same for a list.
	rep = r.post("key-reader", listBody(5))
	if rep.Status != 504 {
		t.Fatalf("list: %d %s", rep.Status, rep.Body)
	}
}

func TestDefaultUpstreamTimeout(t *testing.T) {
	r := New(Config{}, &Holder{}, &memLog{}, clock.NewFake(time.Unix(0, 0)), nil).(*proxy)
	if r.timeout != 60*time.Second {
		t.Fatalf("default timeout %v", r.timeout)
	}
}

func TestConfigValidate(t *testing.T) {
	u, _ := url.Parse("http://127.0.0.1:9090/mcp")
	ok := Config{Upstream: u, APIKeys: map[string]string{"k": "r"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := map[string]Config{
		"no upstream":   {APIKeys: ok.APIKeys},
		"ftp upstream":  {Upstream: &url.URL{Scheme: "ftp", Host: "x"}, APIKeys: ok.APIKeys},
		"no host":       {Upstream: &url.URL{Scheme: "http"}, APIKeys: ok.APIKeys},
		"no keys":       {Upstream: u},
		"empty key":     {Upstream: u, APIKeys: map[string]string{"": "r"}},
		"empty role":    {Upstream: u, APIKeys: map[string]string{"k": ""}},
		"bad safe mode": {Upstream: u, APIKeys: ok.APIKeys, SafeMode: "wide_open"},
		"neg timeout":   {Upstream: u, APIKeys: ok.APIKeys, UpstreamTimeout: -1},
	}
	for name, c := range bad {
		if c.Validate() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An unusable config never panics and never allows.
	srv := httptest.NewServer(New(Config{}, &Holder{}, &memLog{}, clock.NewFake(time.Unix(0, 0)), nil))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", strings.NewReader(callBody(1, "notes.read", `{}`)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("empty config served: %d", resp.StatusCode)
	}
}

func TestListenerLimits(t *testing.T) {
	s := NewServer("127.0.0.1:0", http.NotFoundHandler())
	if s.ReadHeaderTimeout != 5*time.Second || s.IdleTimeout != 60*time.Second || s.MaxHeaderBytes != 8<<10 || s.WriteTimeout != 0 {
		t.Fatalf("limits: %+v", s)
	}
}

// Oversize headers are refused by the listener before the handler runs.
func TestHeaderCap(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	srv := httptest.NewUnstartedServer(nil)
	srv.Config = NewServer("", r.proxy)
	srv.Start()
	defer srv.Close()
	req, _ := http.NewRequest("POST", srv.URL, strings.NewReader(callBody(1, "notes.read", `{}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer key-reader")
	req.Header.Set("X-Pad", strings.Repeat("x", 20<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // connection closed is also a refusal
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

// ---- I4 and the swap ---------------------------------------------------------

func TestRecordsCarryNoArgumentsOrResults(t *testing.T) {
	r := newRig(t, nil)
	r.h.Store(enforcing(t, 8, hashA))
	canary := "CANARY-SECRET-7f3a"
	r.post("key-reader", callBody(1, "notes.read", `{"secret":"`+canary+`"}`))
	r.post("key-reader", callBody(2, "crm.export", `{"secret":"`+canary+`"}`))
	r.post("key-reader", `{"id":3,"method":"tools/call","Method":"x","params":{"name":"`+canary+`"}}`)
	r.post("key-reader", callBody(4, "x/"+canary, `{}`)) // junk tool name
	recs := r.log.all()
	b, _ := json.Marshal(recs)
	if strings.Contains(string(b), canary) {
		t.Fatalf("canary in records: %s", b)
	}
	if len(recs) != 4 {
		t.Fatalf("%d records", len(recs))
	}
	if recs[3].Tool != "" {
		t.Fatalf("junk tool name logged as %q", recs[3].Tool)
	}
}

// A policy swap while calls are in flight never produces a record or an
// answer that mixes two policies. Version 1 allows notes.read and has hash A;
// version 2 denies it and has hash B.
func TestSwapNeverMixesPolicies(t *testing.T) {
	pAllow, err := policy.Parse([]byte(strings.Replace(policyJSON(1), `"reader":{"notes.read":"R","crm.read_*":"R"}`, `"reader":{"notes.read":"R"}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	pDeny, err := policy.Parse([]byte(strings.Replace(policyJSON(2), `"reader":{"notes.read":"R","crm.read_*":"R"}`, `"reader":{"crm.read_*":"R"}`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	a1 := &Active{Policy: pAllow, Hash: hashA, State: wire.StateEnforcing}
	a2 := &Active{Policy: pDeny, Hash: hashB, State: wire.StateEnforcing}

	r := newRig(t, nil)
	r.h.Store(a1)
	stop := make(chan struct{})
	var swaps sync.WaitGroup
	swaps.Add(1)
	go func() {
		defer swaps.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				r.h.Store(a2)
			} else {
				r.h.Store(a1)
			}
		}
	}()

	const workers, perWorker = 8, 60
	var wg sync.WaitGroup
	var bad atomic.Int64
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				id := w*1000 + i
				resp, err := http.DefaultClient.Do(mustReq(r, callBody(id, "notes.read", `{}`)))
				if err != nil {
					bad.Add(1)
					continue
				}
				b, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				blocked := strings.Contains(string(b), "blocked by policy")
				// The answer must agree with the policy named in it.
				switch {
				case blocked && !strings.Contains(string(b), "blocked by policy v2"):
					bad.Add(1)
				case !blocked && !strings.Contains(string(b), "upstream ran it"):
					bad.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	swaps.Wait()
	if bad.Load() != 0 {
		t.Fatalf("%d inconsistent answers", bad.Load())
	}
	sawAllow, sawDeny := false, false
	for _, rec := range r.log.all() {
		switch {
		case rec.Version == 1 && rec.Hash == hashA && rec.Allowed:
			sawAllow = true
		case rec.Version == 2 && rec.Hash == hashB && !rec.Allowed:
			sawDeny = true
		default:
			t.Fatalf("record mixes two policies: %+v", rec)
		}
	}
	if !sawAllow || !sawDeny {
		t.Logf("only one side seen (allow=%v deny=%v); swap timing", sawAllow, sawDeny)
	}
}

func mustReq(r *rig, body string) *http.Request {
	req, _ := http.NewRequestWithContext(context.Background(), "POST", r.srv.URL, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer key-reader")
	return req
}

// An in-flight call finishes under the policy it started with: the answer
// to a call that was allowed is not turned into a deny by a swap to a policy
// that forbids it, and the record says what was decided.
func TestInFlightCallKeepsItsPolicy(t *testing.T) {
	r := newRig(t, nil)
	a1 := enforcing(t, 8, hashA)
	r.h.Store(a1)
	started, release := make(chan struct{}), make(chan struct{})
	r.up.over = func(w http.ResponseWriter, req *http.Request, body []byte) bool {
		close(started)
		<-release
		return false
	}
	done := make(chan reply)
	go func() { done <- r.post("key-reader", callBody(1, "notes.read", `{}`)) }()
	<-started
	r.h.Store(&Active{Policy: mustPolicy(t, 9), Hash: hashB, State: wire.StateDenyAll})
	close(release)
	rep := <-done
	if !strings.Contains(rep.Body, "upstream ran it") {
		t.Fatalf("in-flight call changed: %s", rep.Body)
	}
	if rec := r.log.all()[0]; rec.Version != 8 || rec.Hash != hashA || !rec.Allowed {
		t.Fatalf("%+v", rec)
	}
}
