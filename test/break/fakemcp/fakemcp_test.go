// Package fakemcpbreak is a light black-box pass over the fake MCP server
// (task P-08, test tooling only). Sources: ARCHITECTURE fakemcp LLD (tools
// notes.read R, notes.write W, crm.read_contact R, crm.export X; "echoes nothing
// secret"; test and demo only), M-D31 (1 MiB request cap) and P-D3 (flags
// -addr -sse -echo). The server is run as a process; its source is not read.
//
// The black-box guard forbids naming the command's source path from a test, so
// the test takes a prebuilt binary from the environment variable FAKEMCP_BIN and
// skips (loudly) without it. Build it with the Makefile's build step or:
//
//	go build -o /tmp/fakemcp <fakemcp package>   # the Overseer runs this
//	FAKEMCP_BIN=/tmp/fakemcp go test -race -count=1 ./test/break/fakemcp/...
package fakemcpbreak

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

const canary = "CANARY-9f3b27-SECRET"

func binary(t *testing.T) string {
	t.Helper()
	p := os.Getenv("FAKEMCP_BIN")
	if p == "" {
		t.Skip("SKIPPED: FAKEMCP_BIN is not set. Build the fake MCP server and point FAKEMCP_BIN at it to run this pass (the guard forbids building it from inside a Q test).")
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("FAKEMCP_BIN=%s: %v", p, err)
	}
	return p
}

type server struct {
	base string
	cmd  *exec.Cmd
	out  *bytes.Buffer
	mu   sync.Mutex
}

func freeAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	a := l.Addr().String()
	l.Close()
	return a
}

func start(t *testing.T, args ...string) *server {
	t.Helper()
	bin := binary(t)
	addr := freeAddr(t)
	cmd := exec.Command(bin, append([]string{"-addr", addr}, args...)...)
	s := &server{base: "http://" + addr, cmd: cmd, out: &bytes.Buffer{}}
	cmd.Stdout = &lockedWriter{s}
	cmd.Stderr = &lockedWriter{s}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
			return s
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("fakemcp did not listen on %s; output: %s", addr, s.output())
	return nil
}

type lockedWriter struct{ s *server }

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	defer w.s.mu.Unlock()
	return w.s.out.Write(p)
}

func (s *server) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

var client = &http.Client{Timeout: 10 * time.Second}

// path finds the MCP endpoint: the first candidate that does not answer 404 or 405.
func (s *server) path(t *testing.T) string {
	t.Helper()
	for _, p := range []string{"/mcp", "/", "/rpc", "/message"} {
		r, err := post(s.base+p, "application/json", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
		if err != nil {
			continue
		}
		if r.code != 404 && r.code != 405 {
			return p
		}
	}
	t.Fatal("no candidate MCP endpoint path answered tools/list (the test found one before; fakemcp regressed)")
	return ""
}

type reply struct {
	code int
	ct   string
	body string
}

func post(url, ct, body string) (reply, error) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := client.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	return reply{resp.StatusCode, resp.Header.Get("Content-Type"), string(b)}, nil
}

func rpc(method string, params any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	return string(b)
}

// unwrap returns the JSON-RPC object from a plain JSON or an SSE body.
func unwrap(t *testing.T, r reply) map[string]any {
	t.Helper()
	body := r.body
	if strings.HasPrefix(r.ct, "text/event-stream") {
		var data []string
		sc := bufio.NewScanner(strings.NewReader(body))
		for sc.Scan() {
			if v, ok := strings.CutPrefix(sc.Text(), "data:"); ok {
				data = append(data, strings.TrimPrefix(v, " "))
			}
		}
		if len(data) == 0 {
			t.Fatalf("SSE body has no data line: %q", body)
		}
		body = strings.Join(data, "\n")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("response is not JSON-RPC: %v: %.300s", err, body)
	}
	return m
}

func toolNames(m map[string]any) []string {
	res, _ := m["result"].(map[string]any)
	tools, _ := res["tools"].([]any)
	var out []string
	for _, x := range tools {
		if tm, ok := x.(map[string]any); ok {
			out = append(out, fmt.Sprint(tm["name"]))
		}
	}
	return out
}

func TestToolsListHasTheDocumentedTools(t *testing.T) {
	s := start(t)
	p := s.path(t)
	r, err := post(s.base+p, "application/json", rpc("tools/list", map[string]any{}))
	if err != nil || r.code != 200 {
		t.Fatalf("tools/list: %v %+v", err, r)
	}
	names := toolNames(unwrap(t, r))
	have := map[string]bool{}
	for _, n := range names {
		have[n] = true
	}
	for _, want := range []string{"notes.read", "notes.write", "crm.read_contact", "crm.export"} {
		if !have[want] {
			t.Errorf("tool %q missing from tools/list (%v)", want, names)
		}
	}
}

// "Echoes nothing secret": with echo off, nothing the caller sent comes back.
func TestEchoOffNeverEchoesArgumentsOrNames(t *testing.T) {
	for _, mode := range [][]string{{}, {"-echo=false"}} {
		t.Run(strings.Join(mode, " "), func(t *testing.T) {
			s := start(t, mode...)
			p := s.path(t)
			tools := []string{"notes.read", "notes.write", "crm.read_contact", "crm.export", "crm.update_deal", "nope." + canary, canary}
			argShapes := []any{
				map[string]any{"q": canary, "text": canary, "id": canary, "nested": map[string]any{"deep": []any{canary}}},
				[]any{canary},
				canary,
				nil,
			}
			for _, tool := range tools {
				for i, args := range argShapes {
					body := rpc("tools/call", map[string]any{"name": tool, "arguments": args})
					r, err := post(s.base+p, "application/json", body)
					if err != nil {
						t.Fatalf("%s #%d: %v", tool, i, err)
					}
					if strings.Contains(r.body, canary) {
						t.Errorf("%s with argument shape %d: the response echoes caller data: %.300s", tool, i, r.body)
					}
				}
			}
			if strings.Contains(s.output(), canary) {
				t.Errorf("the server logged caller data: %.300s", s.output())
			}
			for _, m := range []string{"initialize", "ping", "tools/list", "resources/list", canary} {
				r, _ := post(s.base+p, "application/json", rpc(m, map[string]any{"clientInfo": map[string]any{"name": canary}, "x": canary}))
				if strings.Contains(r.body, canary) {
					t.Errorf("method %q echoes caller data: %.300s", m, r.body)
				}
			}
		})
	}
}

func TestSSEFraming(t *testing.T) {
	s := start(t, "-sse")
	p := s.path(t)
	for _, method := range []string{"tools/list", "tools/call"} {
		params := any(map[string]any{})
		if method == "tools/call" {
			params = map[string]any{"name": "notes.read", "arguments": map[string]any{}}
		}
		r, err := post(s.base+p, "application/json", rpc(method, params))
		if err != nil || r.code != 200 {
			t.Fatalf("%s: %v %+v", method, err, r)
		}
		if !strings.HasPrefix(r.ct, "text/event-stream") {
			t.Fatalf("%s: with -sse the Content-Type is %q", method, r.ct)
		}
		norm := strings.ReplaceAll(r.body, "\r\n", "\n")
		if !strings.HasSuffix(norm, "\n\n") {
			t.Errorf("%s: SSE event is not terminated by a blank line: %q", method, r.body)
		}
		for _, ev := range strings.Split(strings.TrimSpace(norm), "\n\n") {
			sawData := false
			for _, ln := range strings.Split(ev, "\n") {
				switch {
				case strings.HasPrefix(ln, "data:"):
					sawData = true
					payload := strings.TrimPrefix(strings.TrimPrefix(ln, "data:"), " ")
					var m map[string]any
					if err := json.Unmarshal([]byte(payload), &m); err != nil {
						t.Errorf("%s: data line is not one JSON object: %q", method, ln)
					}
				case strings.HasPrefix(ln, "event:"), strings.HasPrefix(ln, "id:"), strings.HasPrefix(ln, "retry:"), strings.HasPrefix(ln, ":"), ln == "":
				default:
					t.Errorf("%s: line %q is not valid SSE", method, ln)
				}
			}
			if !sawData {
				t.Errorf("%s: event without data: %q", method, ev)
			}
		}
		if m := unwrap(t, r); m["jsonrpc"] != "2.0" {
			t.Errorf("%s: jsonrpc field %v", method, m["jsonrpc"])
		}
	}
	s2 := start(t)
	p2 := s2.path(t)
	r, _ := post(s2.base+p2, "application/json", rpc("tools/list", map[string]any{}))
	if !strings.HasPrefix(r.ct, "application/json") {
		t.Errorf("default Content-Type %q, want application/json", r.ct)
	}
}

func TestBodyCapIsOneMiB(t *testing.T) {
	s := start(t)
	p := s.path(t)
	mk := func(total int) string {
		base := rpc("tools/call", map[string]any{"name": "notes.read", "arguments": map[string]any{"pad": ""}})
		pad := total - len(base)
		if pad < 0 {
			pad = 0
		}
		return strings.Replace(base, `"pad":""`, `"pad":"`+strings.Repeat("a", pad)+`"`, 1)
	}
	const mib = 1 << 20
	for _, c := range []struct {
		name  string
		size  int
		allow bool
	}{{"small", 1000, true}, {"just under 1 MiB", mib - 10, true}, {"exactly 1 MiB", mib, true}, {"1 MiB + 1", mib + 1, false}, {"2 MiB", 2 * mib, false}, {"16 MiB", 16 * mib, false}} {
		body := mk(c.size)
		r, err := post(s.base+p, "application/json", body)
		if err != nil {
			if c.allow {
				t.Errorf("%s: %v", c.name, err)
			}
			continue // the server may drop an oversized upload
		}
		if c.allow && r.code != 200 {
			t.Errorf("%s: status %d, want 200: %.200s", c.name, r.code, r.body)
		}
		if !c.allow && r.code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: status %d, want 413", c.name, r.code)
		}
	}
	r, err := post(s.base+p, "application/json", rpc("tools/list", map[string]any{}))
	if err != nil || r.code != 200 {
		t.Fatalf("server unhealthy after oversized bodies: %v %+v", err, r)
	}
}

func TestMalformedRequestsDoNotCrashTheServer(t *testing.T) {
	s := start(t)
	p := s.path(t)
	bodies := map[string]string{
		"empty":            "",
		"not-json":         "hello",
		"truncated":        `{"jsonrpc":"2.0","id":1,"method":"tools/li`,
		"array-batch":      `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`,
		"null":             "null",
		"number":           "42",
		"deep":             strings.Repeat("[", 100000),
		"no-method":        `{"jsonrpc":"2.0","id":1}`,
		"method-number":    `{"jsonrpc":"2.0","id":1,"method":5}`,
		"unknown-method":   rpc("does/not/exist", nil),
		"params-string":    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"x"}`,
		"name-number":      `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":5}}`,
		"id-object":        `{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}`,
		"notification":     `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		"duplicate-keys":   `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list","method":"tools/call"}`,
		"nul-bytes":        "\x00\x00\x00",
		"huge-number":      `{"jsonrpc":"2.0","id":1e999999,"method":"tools/list"}`,
		"trailing-garbage": rpc("tools/list", nil) + "garbage",
	}
	for name, b := range bodies {
		for _, ct := range []string{"application/json", "text/plain", ""} {
			r, err := post(s.base+p, ct, b)
			if err != nil {
				t.Errorf("%s (%q): transport error %v", name, ct, err)
				continue
			}
			if r.code >= 500 {
				t.Errorf("%s (%q): server error %d: %.200s", name, ct, r.code, r.body)
			}
		}
	}
	for _, m := range []string{"PUT", "DELETE", "PATCH", "OPTIONS"} {
		req, _ := http.NewRequest(m, s.base+p, strings.NewReader("{}"))
		resp, err := client.Do(req)
		if err != nil {
			t.Errorf("%s: %v", m, err)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode >= 500 {
			t.Errorf("%s: status %d", m, resp.StatusCode)
		}
	}
	r, err := post(s.base+p, "application/json", rpc("tools/list", map[string]any{}))
	if err != nil || r.code != 200 {
		t.Fatalf("server dead after hostile input: %v %+v\n%s", err, r, s.output())
	}
}

func TestConcurrentCallsAreSafe(t *testing.T) {
	s := start(t, "-sse")
	p := s.path(t)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tool := []string{"notes.read", "notes.write", "crm.read_contact", "crm.export"}[(i+j)%4]
				r, err := post(s.base+p, "application/json", rpc("tools/call", map[string]any{"name": tool, "arguments": map[string]any{"i": i}}))
				if err != nil || r.code != 200 {
					t.Errorf("worker %d: %v %+v", i, err, r)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
