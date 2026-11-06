// Command fakemcp is a tiny fake MCP server for tests and the demo. It is
// NOT a real MCP implementation and must never front real data.
//
// It speaks JSON-RPC 2.0 over HTTP POST and understands initialize, ping,
// tools/list and tools/call. Every tool is harmless and returns a canned
// result that contains nothing secret.
//
// Tools (ARCHITECTURE section 10, cmd/fakemcp):
//
//	notes.read        read-like
//	crm.read_contact  read-like
//	notes.write       write-like
//	crm.update_deal   write-like
//	crm.export        exec/export-like
//
// Flags:
//
//	-addr  listen address (default 127.0.0.1:9090)
//	-sse   answer with a text/event-stream body instead of application/json,
//	       so enforce's tools/list filtering is exercised on both forms
//	-echo  copy the call's arguments into the result text, so the leak check
//	       (S10) can plant canary secrets and see where they end up
//
// By default arguments are never echoed. Server timeouts follow M-D31:
// ReadHeaderTimeout 5s, IdleTimeout 60s, MaxHeaderBytes 8 KiB, body cap 1 MiB.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const maxBody = 1 << 20

type options struct {
	sse  bool // respond as text/event-stream
	echo bool // echo call arguments into the result
}

type tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var anyObject = json.RawMessage(`{"type":"object"}`)

// tools is the fixed tool set, in list order.
var tools = []tool{
	{"notes.read", "Read a note (read-like, harmless).", anyObject},
	{"crm.read_contact", "Read a CRM contact (read-like, harmless).", anyObject},
	{"notes.write", "Write a note (write-like, harmless, stores nothing).", anyObject},
	{"crm.update_deal", "Update a CRM deal (write-like, harmless, stores nothing).", anyObject},
	{"crm.export", "Export CRM data (exec-like, harmless, exports nothing).", anyObject},
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type handler struct{ opts options }

func newHandler(o options) http.Handler { return handler{opts: o} }

func newServer(addr string, o options) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           newHandler(o),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func (h handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req request
	if err := json.Unmarshal(body, &req); err != nil {
		h.reply(w, response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{-32700, "parse error"}})
		return
	}
	if len(req.ID) == 0 { // notification: no answer
		w.WriteHeader(http.StatusAccepted)
		return
	}
	resp := response{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": "2025-03-26",
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fakemcp", "version": "0"},
		}
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": tools}
	case "tools/call":
		resp.Result, resp.Error = h.call(req.Params)
	default:
		resp.Error = &rpcError{-32601, "method not found"}
	}
	h.reply(w, resp)
}

func (h handler) call(params json.RawMessage) (any, *rpcError) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if len(params) == 0 || json.Unmarshal(params, &p) != nil {
		return nil, &rpcError{-32602, "invalid params"}
	}
	known := false
	for _, t := range tools {
		if t.Name == p.Name {
			known = true
			break
		}
	}
	if !known {
		return nil, &rpcError{-32602, "unknown tool"}
	}
	text := "fakemcp: " + p.Name + " ok (canned)"
	if h.opts.echo && len(p.Arguments) > 0 {
		text += " args=" + string(p.Arguments)
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": false,
	}, nil
}

// reply writes resp as application/json, or as a single SSE event in -sse
// mode. json.Marshal never emits a raw newline, so data is one line.
func (h handler) reply(w http.ResponseWriter, resp response) {
	b, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if h.opts.sse {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func parseFlags(args []string) (string, options, error) {
	fs := flag.NewFlagSet("fakemcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", "127.0.0.1:9090", "listen address")
	sse := fs.Bool("sse", false, "respond with text/event-stream")
	echo := fs.Bool("echo", false, "echo call arguments into results (leak-check canaries)")
	if err := fs.Parse(args); err != nil {
		return "", options{}, err
	}
	return *addr, options{sse: *sse, echo: *echo}, nil
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	addr, opts, err := parseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "fakemcp:", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := newServer(addr, opts)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("fakemcp listening (test and demo only)", "addr", addr, "sse", opts.sse, "echo", opts.echo)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", "err", err)
		os.Exit(1)
	}
}
