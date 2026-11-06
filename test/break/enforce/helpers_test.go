// Package enforcebreak holds black-box attack tests for the MCP-facing handler of kairan-proxy
// (task P-02). Sources: ARCHITECTURE sections 3, 4, 10 proxy/enforce (M-D31, M-D33, R-D2), invariants
// I3, I4, I5, THREATS #7 and #13, the go doc of enforce, policy, state and wire. The upstream MCP server
// is an in-test httptest server that records every byte it receives.
package enforcebreak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

const canary = "CANARY-9f3b27-SECRET"

const (
	keySales  = "key-sales-0123456789"
	keyEng    = "key-engineer-0123456789"
	keyIntern = "key-intern-0123456789"
	keyGhost  = "key-ghost-0123456789"
)

func policyDoc(version uint64) []byte {
	return []byte(fmt.Sprintf(`{"tenant":"bank-a","version":%d,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-12T11:00:00Z","default":"deny","roles":{`+
		`"sales":{"crm.read_*":"R","crm.update_deal":"W","crm.run_report":"X"},`+
		`"engineer":{"github.*":"R","github.create_issue":"W","ci.rerun":"X"},`+
		`"intern":{"help.*":"R","crm.read_contact":"R"}}}`, version))
}

func mustPolicy(t testing.TB, version uint64) *policy.Policy {
	t.Helper()
	p, err := policy.Parse(policyDoc(version))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func hashN(n int) wire.Hash { return wire.Hash(fmt.Sprintf("%064x", n)) }

// catalog is what the fake upstream lists (in this order).
var catalog = []string{
	"crm.read_contact", "crm.read_deal", "crm.update_deal", "crm.run_report", "crm.delete_all",
	"github.list_repos", "github.create_issue", "github.delete_repo", "ci.rerun", "help.faq", "admin.shutdown",
}

type upReq struct {
	Method string
	URI    string
	Header http.Header
	Body   []byte
}

type upstream struct {
	t   testing.TB
	srv *httptest.Server
	mu  sync.Mutex
	got []upReq
	// respond overrides the default MCP behaviour when set.
	respond func(w http.ResponseWriter, r *http.Request, body []byte)
	sse     bool
	before  func() // called when a request arrives, before it is answered
}

func newUpstream(t testing.TB) *upstream {
	u := &upstream{t: t}
	u.srv = httptest.NewServer(http.HandlerFunc(u.serve))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) url() *url.URL {
	p, _ := url.Parse(u.srv.URL + "/mcp-endpoint?fixed=1")
	return p
}

func (u *upstream) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	u.mu.Lock()
	u.got = append(u.got, upReq{r.Method, r.URL.RequestURI(), r.Header.Clone(), body})
	respond := u.respond
	before := u.before
	u.mu.Unlock()
	if before != nil {
		before()
	}
	if respond != nil {
		respond(w, r, body)
		return
	}
	u.defaultMCP(w, r, body)
}

func toolsJSON(names []string) string {
	var parts []string
	for _, n := range names {
		parts = append(parts, fmt.Sprintf(`{"name":%q,"description":"desc of %s","inputSchema":{"type":"object"}}`, n, n))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func (u *upstream) defaultMCP(w http.ResponseWriter, r *http.Request, body []byte) {
	var req struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.Unmarshal(body, &req)
	id := string(req.ID)
	if id == "" {
		id = "null"
	}
	var out string
	switch req.Method {
	case "tools/list":
		out = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}`, id, toolsJSON(catalog))
	case "tools/call":
		out = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"upstream-ran"}]}}`, id)
	case "":
		w.WriteHeader(http.StatusAccepted)
		return
	default:
		out = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"echo":%q}}`, id, req.Method)
	}
	if u.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", out)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	io.WriteString(w, out)
}

func (u *upstream) requests() []upReq {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upReq(nil), u.got...)
}

func (u *upstream) count() int { return len(u.requests()) }

// ---- decision log and metrics ----

type decisionLog struct {
	mu   sync.Mutex
	recs []enforce.Record
	err  error
	// failIf, when set, makes Record fail for records it returns true for.
	failIf func(enforce.Record) bool
	onRec  func(enforce.Record)
}

func (d *decisionLog) Record(r enforce.Record) error {
	d.mu.Lock()
	if d.onRec != nil {
		d.onRec(r)
	}
	if d.err != nil || (d.failIf != nil && d.failIf(r)) {
		err := d.err
		if err == nil {
			err = errors.New("disk full")
		}
		d.mu.Unlock()
		return err
	}
	d.recs = append(d.recs, r)
	d.mu.Unlock()
	return nil
}

func (d *decisionLog) all() []enforce.Record {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]enforce.Record(nil), d.recs...)
}

type metrics struct {
	mu sync.Mutex
	m  map[string]int
}

func (m *metrics) Inc(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.m == nil {
		m.m = map[string]int{}
	}
	m.m[name]++
}

func (m *metrics) get(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[name]
}

func (m *metrics) names() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k := range m.m {
		out = append(out, k)
	}
	return out
}

// ---- the proxy under test ----

type rig struct {
	t      testing.TB
	up     *upstream
	hold   *enforce.Holder
	dl     *decisionLog
	met    *metrics
	h      http.Handler
	srv    *httptest.Server
	ver    uint64
	cfg    enforce.Config
	active *enforce.Active
	nilLog bool
}

func newRig(t testing.TB, mod ...func(*rig)) *rig {
	t.Helper()
	r := &rig{t: t, up: newUpstream(t), hold: &enforce.Holder{}, dl: &decisionLog{}, met: &metrics{}, ver: 8}
	r.cfg = enforce.Config{
		Upstream: r.up.url(),
		APIKeys:  map[string]string{keySales: "sales", keyEng: "engineer", keyIntern: "intern", keyGhost: "ghost"},
	}
	r.active = &enforce.Active{Policy: mustPolicy(t, r.ver), Hash: hashN(int(r.ver)), State: wire.StateEnforcing}
	for _, m := range mod {
		m(r)
	}
	r.hold.Store(r.active)
	var dl enforce.DecisionLog = r.dl
	if r.nilLog {
		dl = nil
	}
	r.h = enforce.New(r.cfg, r.hold, dl, clock.NewReal(), r.met)
	r.srv = httptest.NewServer(r.h)
	t.Cleanup(r.srv.Close)
	return r
}

type reply struct {
	code int
	hdr  http.Header
	body []byte
}

func (r *rig) post(key string, body string, hdr ...string) reply {
	return r.send("POST", "/", key, []byte(body), hdr...)
}

func (r *rig) send(method, path, key string, body []byte, hdr ...string) reply {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, r.srv.URL+path, rd)
	if err != nil {
		r.t.Fatal(err)
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		if hdr[i+1] == "\x00DEL" {
			req.Header.Del(hdr[i])
			continue
		}
		req.Header.Set(hdr[i], hdr[i+1])
	}
	cl := &http.Client{Timeout: 20 * time.Second}
	res, err := cl.Do(req)
	if err != nil {
		return reply{code: -1, body: []byte(err.Error())}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header, b}
}

func callBody(id int, tool string, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, id, tool, args)
}

func listBody(id int) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/list"}`, id)
}

// blocked says whether the reply is the documented MCP tool error "blocked by policy vN".
func blocked(rep reply, ver uint64) bool {
	return rep.code == 200 && strings.Contains(string(rep.body), fmt.Sprintf("blocked by policy v%d", ver))
}

// allowedBy says what the policy says, independent of the proxy: the oracle.
func allowedBy(p *policy.Policy, role, tool string, safe bool) bool {
	return p.Decide(role, tool, safe).Allowed
}

// toolNames reads tool names out of a tools/list answer, JSON or SSE, or fails.
func toolNames(t testing.TB, rep reply) []string {
	t.Helper()
	var docs [][]byte
	ct := rep.hdr.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		for _, ln := range strings.Split(string(rep.body), "\n") {
			ln = strings.TrimRight(ln, "\r")
			if strings.HasPrefix(ln, "data:") {
				docs = append(docs, []byte(strings.TrimSpace(strings.TrimPrefix(ln, "data:"))))
			}
		}
	} else {
		docs = [][]byte{rep.body}
	}
	var names []string
	for _, d := range docs {
		var m struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}
		if err := json.Unmarshal(d, &m); err != nil {
			t.Fatalf("answer is not JSON-RPC: %v: %.200q", err, d)
		}
		for _, x := range m.Result.Tools {
			names = append(names, x.Name)
		}
	}
	return names
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func states() []wire.ProxyState {
	return []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode}
}

var _ = state.ReadOnly
