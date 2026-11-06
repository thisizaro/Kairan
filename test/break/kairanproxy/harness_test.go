// Package kairanproxybreak holds black-box attack tests for the kairan-proxy binary (task P-07) and the
// agent's boot-from-disk behaviour as an operator sees it. It runs the program named by PROXY_BIN.
// Sources: ARCHITECTURE kairan-proxy LLD, section 4 boot rule (M-D33), M-D30, M-D31, M-D37, P-D7, invariants
// I1-I6, PRD J2, S3, S6, S7.
package kairanproxybreak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

const (
	tenant   = "bank-a"
	proxyID  = "p1"
	token    = "tok-p1-0123456789abcdef-CANARY-TOKEN"
	keySales = "key-sales-0123456789-CANARY-KEY"
	keyIntrn = "key-intern-0123456789"
	canary   = "CANARY-9f3b27-SECRET"
)

func bin(t testing.TB) string {
	t.Helper()
	b := os.Getenv("PROXY_BIN")
	if b == "" {
		t.Skip("PROXY_BIN is not set: no binary to attack")
	}
	if _, err := os.Stat(b); err != nil {
		t.Fatalf("PROXY_BIN is set but unusable: %v", err)
	}
	return b
}

func fx(t testing.TB, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

type keyPair struct {
	pub  string
	priv ed25519.PrivateKey
}

func key(t testing.TB, who string) keyPair {
	t.Helper()
	seed, err := hex.DecodeString(fx(t, "TEST-ONLY-"+who+".seed"))
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pub: fx(t, "TEST-ONLY-"+who+".pub"), priv: ed25519.NewKeyFromSeed(seed)}
}

func policyDoc(tn string, version uint64, issued, expires time.Time) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"},"intern":{"help.*":"R"}}}`,
		tn, version, issued.UTC().Format(time.RFC3339), expires.UTC().Format(time.RFC3339)))
}

func validPolicy(version uint64) []byte {
	return policyDoc(tenant, version, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
}

func envelopeOf(payload []byte, signers ...keyPair) wire.Envelope {
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, k := range signers {
		trust.Sign(&e, k.priv)
	}
	return e
}

func hashOf(b []byte) wire.Hash { s := sha256.Sum256(b); return wire.Hash(hex.EncodeToString(s[:])) }

// ---- fake control plane ----

type cpReq struct {
	Path   string
	Query  url.Values
	Header http.Header
	Body   []byte
}

type fakeCP struct {
	srv   *httptest.Server
	mu    sync.Mutex
	reqs  []cpReq
	offer func(n int, have uint64) (wire.Envelope, bool) // nil = 304
	n     int
}

func newCP(t testing.TB) *fakeCP {
	c := &fakeCP{}
	c.srv = httptest.NewServer(http.HandlerFunc(c.serve))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	c.mu.Lock()
	c.reqs = append(c.reqs, cpReq{r.URL.Path, r.URL.Query(), r.Header.Clone(), body})
	offer := c.offer
	if r.URL.Path == wire.PathPoll {
		c.n++
	}
	n := c.n
	c.mu.Unlock()
	switch r.URL.Path {
	case wire.PathPoll:
		if offer != nil {
			have, _ := parseUint(r.URL.Query().Get(wire.QueryHave))
			if env, ok := offer(n, have); ok {
				b, _ := json.Marshal(wire.PollResponse{Version: 0, Envelope: env})
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(b)
				return
			}
		}
		// a held poll that ends quickly keeps the test fast
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusNotModified)
	case wire.PathStatus:
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(404)
	}
}

func parseUint(s string) (uint64, error) {
	var v uint64
	_, err := fmt.Sscanf(s, "%d", &v)
	return v, err
}

func (c *fakeCP) url() string { return c.srv.URL }

func (c *fakeCP) all() []cpReq {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]cpReq(nil), c.reqs...)
}

func (c *fakeCP) statuses() []wire.StatusReport {
	var out []wire.StatusReport
	for _, q := range c.all() {
		if q.Path == wire.PathStatus {
			var s wire.StatusReport
			if json.Unmarshal(q.Body, &s) == nil {
				out = append(out, s)
			}
		}
	}
	return out
}

// ---- fake MCP upstream ----

type upstream struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []string
	body [][]byte
}

func newUpstream(t testing.TB) *upstream {
	u := &upstream{}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.hits = append(u.hits, r.Method+" "+r.URL.Path)
		u.body = append(u.body, b)
		u.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(b, []byte(`"tools/list"`)) {
			io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"crm.read_contact","description":"desc of crm.read_contact","inputSchema":{"type":"object"}},{"name":"crm.update_deal","description":"desc of crm.update_deal","inputSchema":{"type":"object"}},{"name":"help.faq","description":"desc of help.faq","inputSchema":{"type":"object"}},{"name":"admin.shutdown","description":"desc of admin.shutdown","inputSchema":{"type":"object"}}]}}`)
			return
		}
		io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"ran"}]}}`)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

func (u *upstream) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.hits) }

// ---- proxy process ----

type pcfg map[string]any

func freePort(t testing.TB) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func baseCfg(t testing.TB, dir, cpURL, up string, listen string) pcfg {
	return pcfg{
		"tenant": tenant, "proxy_id": proxyID, "cp_url": cpURL, "token": token,
		"trusted_keys": []string{key(t, "admin-a").pub, key(t, "admin-b").pub, key(t, "admin-c").pub},
		"threshold":    2, "listen": listen, "upstream": up,
		"api_keys": map[string]string{keySales: "sales", keyIntrn: "intern"},
		"data_dir": dir, "allow_plaintext": true,
	}
}

func (c pcfg) clone() pcfg {
	b, _ := json.Marshal(c)
	var o pcfg
	_ = json.Unmarshal(b, &o)
	return o
}

func (c pcfg) with(k string, v any) pcfg {
	o := c.clone()
	if v == nil {
		delete(o, k)
	} else {
		o[k] = v
	}
	return o
}

func (c pcfg) bytes() []byte { b, _ := json.Marshal(c); return b }

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type proc struct {
	t      testing.TB
	cmd    *exec.Cmd
	out    *lockedBuf
	done   chan struct{}
	code   int
	listen string
	dir    string
}

func writeCfg(t testing.TB, raw []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func startProc(t testing.TB, raw []byte, env []string, args ...string) *proc {
	t.Helper()
	b := bin(t)
	cfgPath := writeCfg(t, raw)
	cmd := exec.Command(b, append([]string{"-config", cfgPath}, args...)...)
	cmd.Dir = t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + cmd.Dir, "LANG=C"}, env...)
	p := &proc{t: t, cmd: cmd, out: &lockedBuf{}, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = cmd.Wait()
		p.code = cmd.ProcessState.ExitCode()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

func (p *proc) exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *proc) waitExit(d time.Duration) (int, bool) {
	select {
	case <-p.done:
		return p.code, true
	case <-time.After(d):
		return 0, false
	}
}

func (p *proc) signal(s syscall.Signal) { _ = p.cmd.Process.Signal(s) }

// runOnce runs the binary until it exits (config errors) within 20 s.
func runOnce(t testing.TB, raw []byte, env []string, args ...string) (int, string) {
	t.Helper()
	p := startProc(t, raw, env, args...)
	code, ok := p.waitExit(20 * time.Second)
	if !ok {
		_ = p.cmd.Process.Kill()
		<-p.done
		return -1, p.out.String()
	}
	return code, p.out.String()
}

// startServing starts the proxy and waits until it listens and has booted.
func startServing(t *testing.T, c pcfg, env []string) *proc {
	t.Helper()
	p := startProc(t, c.bytes(), env)
	p.listen, _ = c["listen"].(string)
	p.dir, _ = c["data_dir"].(string)
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if p.exited() {
			t.Fatalf("proxy exited (%d) before listening: %s", p.code, p.out.String())
		}
		if conn, err := net.DialTimeout("tcp", p.listen, 100*time.Millisecond); err == nil {
			conn.Close()
			return p
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf("proxy not listening in 10 s: %s", p.out.String())
	return nil
}

type reply struct {
	code int
	body string
}

func (p *proc) call(key, body string) reply {
	req, _ := http.NewRequest("POST", "http://"+p.listen+"/", strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return reply{-1, err.Error()}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, string(b)}
}

func callBody(tool, args string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":%s}}`, tool, args)
}

const listBody = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`

func waitFor(t testing.TB, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// allowed reports whether a tool call returned the upstream result.
func allowed(r reply) bool {
	return r.code == 200 && strings.Contains(r.body, "ran") && !strings.Contains(r.body, "blocked")
}

// startRaw runs the binary with exactly args.
func startRaw(t testing.TB, b string, args []string) *proc {
	t.Helper()
	c := exec.Command(b, args...)
	c.Dir = t.TempDir()
	c.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + c.Dir, "LANG=C"}
	p := &proc{t: t, cmd: c, out: &lockedBuf{}, done: make(chan struct{})}
	c.Stdout, c.Stderr = p.out, p.out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = c.Wait()
		p.code = c.ProcessState.ExitCode()
		close(p.done)
	}()
	t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			_ = c.Process.Kill()
			<-p.done
		}
	})
	return p
}

func clip(s string) string {
	if len(s) > 500 {
		return s[:500] + "..."
	}
	return s
}
