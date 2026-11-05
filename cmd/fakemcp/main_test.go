package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) rpcResp {
	t.Helper()
	var r rpcResp
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
		t.Fatalf("response is not JSON: %v: %q", err, rec.Body.String())
	}
	return r
}

func TestToolsList(t *testing.T) {
	h := newHandler(options{})
	rec := post(t, h, `{"jsonrpc":"2.0","id":7,"method":"tools/list"}`)
	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content type %q", ct)
	}
	r := decode(t, rec)
	if string(r.ID) != "7" || r.JSONRPC != "2.0" {
		t.Fatalf("bad envelope: %+v", r)
	}
	var res struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, tl := range res.Tools {
		got[tl.Name] = true
		if tl.Description == "" {
			t.Errorf("%s has no description", tl.Name)
		}
	}
	for _, want := range []string{"notes.read", "notes.write", "crm.read_contact", "crm.export", "crm.update_deal"} {
		if !got[want] {
			t.Errorf("missing tool %s", want)
		}
	}
}

func TestToolsCall(t *testing.T) {
	tests := []struct {
		name    string
		opts    options
		body    string
		wantErr int // JSON-RPC error code, 0 for success
		want    []string
		notWant []string
	}{
		{
			name: "read tool canned",
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"id":"c-1"}}}`,
			want: []string{"fakemcp", "crm.read_contact"},
		},
		{
			name: "write tool canned",
			body: `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"notes.write","arguments":{"text":"x"}}}`,
			want: []string{"notes.write"},
		},
		{
			name:    "arguments not echoed by default",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.write","arguments":{"text":"CANARY-123"}}}`,
			notWant: []string{"CANARY-123"},
		},
		{
			name: "arguments echoed on flag",
			opts: options{echo: true},
			body: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.write","arguments":{"text":"CANARY-123"}}}`,
			want: []string{"CANARY-123"},
		},
		{
			name:    "unknown tool",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"nope.nothing"}}`,
			wantErr: -32602,
		},
		{
			name:    "params missing",
			body:    `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
			wantErr: -32602,
		},
		{
			name:    "unknown method",
			body:    `{"jsonrpc":"2.0","id":1,"method":"resources/list"}`,
			wantErr: -32601,
		},
		{
			name:    "parse error",
			body:    `{not json`,
			wantErr: -32700,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := post(t, newHandler(tc.opts), tc.body)
			r := decode(t, rec)
			if tc.wantErr != 0 {
				if r.Error == nil || r.Error.Code != tc.wantErr {
					t.Fatalf("want error %d, got %+v", tc.wantErr, r.Error)
				}
				return
			}
			if r.Error != nil {
				t.Fatalf("unexpected error %+v", r.Error)
			}
			out := string(r.Result)
			for _, s := range tc.want {
				if !strings.Contains(out, s) {
					t.Errorf("result %s lacks %q", out, s)
				}
			}
			for _, s := range tc.notWant {
				if strings.Contains(rec.Body.String(), s) {
					t.Errorf("response leaks %q: %s", s, rec.Body.String())
				}
			}
		})
	}
}

func TestSSEMode(t *testing.T) {
	h := newHandler(options{sse: true})
	rec := post(t, h, `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type %q", ct)
	}
	body := rec.Body.String()
	if !strings.HasPrefix(body, "event: message\ndata: ") || !strings.HasSuffix(body, "\n\n") {
		t.Fatalf("not an SSE event: %q", body)
	}
	data := strings.TrimSuffix(strings.TrimPrefix(body, "event: message\ndata: "), "\n\n")
	if strings.Contains(data, "\n") {
		t.Fatalf("data spans lines: %q", data)
	}
	var r rpcResp
	if err := json.Unmarshal([]byte(data), &r); err != nil || string(r.ID) != "3" || r.Result == nil {
		t.Fatalf("bad event payload %q: %v", data, err)
	}
}

func TestNotificationAndInitialize(t *testing.T) {
	h := newHandler(options{})
	rec := post(t, h, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("notification: %d %q", rec.Code, rec.Body.String())
	}
	rec = post(t, h, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	r := decode(t, rec)
	if r.Error != nil || !strings.Contains(string(r.Result), "serverInfo") {
		t.Fatalf("initialize: %s", rec.Body.String())
	}
}

func TestHTTPShape(t *testing.T) {
	h := newHandler(options{})
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "POST" {
		t.Fatalf("GET: %d allow=%q", rec.Code, rec.Header().Get("Allow"))
	}

	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.write","arguments":{"t":"` +
		strings.Repeat("a", maxBody) + `"}}}`
	rec = post(t, h, big)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize body: %d", rec.Code)
	}
}

func TestServerTimeouts(t *testing.T) {
	s := newServer(":0", options{})
	if s.ReadHeaderTimeout != 5*time.Second || s.IdleTimeout != 60*time.Second || s.MaxHeaderBytes != 8<<10 {
		t.Fatalf("timeouts: %v %v %d", s.ReadHeaderTimeout, s.IdleTimeout, s.MaxHeaderBytes)
	}
}

func TestEndToEndOverHTTP(t *testing.T) {
	srv := httptest.NewServer(newHandler(options{}))
	defer srv.Close()
	resp, err := http.Post(srv.URL, "application/json", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "crm.export") {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
}

func TestParseFlags(t *testing.T) {
	addr, o, err := parseFlags([]string{"-addr", "127.0.0.1:9", "-sse", "-echo"})
	if err != nil || addr != "127.0.0.1:9" || !o.sse || !o.echo {
		t.Fatalf("%q %+v %v", addr, o, err)
	}
	if _, _, err := parseFlags([]string{"-bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}

func FuzzHandler(f *testing.F) {
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	f.Add(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	f.Add(`[]`)
	f.Add(``)
	h := newHandler(options{echo: true})
	f.Fuzz(func(t *testing.T, body string) {
		rec := post(t, h, body)
		if rec.Code >= 500 {
			t.Fatalf("server error %d for %q", rec.Code, body)
		}
	})
}
