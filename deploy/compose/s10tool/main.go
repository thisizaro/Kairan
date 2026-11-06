// Command s10tool is the test tooling for the S10 leak-check chaos scenario (Q-04). It is a test tool only:
// no authentication, never part of the product image, stdlib only. Two modes:
//
//	s10tool capture  -listen 0.0.0.0:8080 -to http://cp:8080 -out /cap/capture.raw
//	    a logging reverse proxy that sits between the proxies and the control plane. It writes every request
//	    and every response (headers and body, raw bytes) to -out and answers GET /_s10/stats with counters.
//	s10tool upstream -listen 0.0.0.0:9000 -result CANARY -header CANARY -seen CANARY
//	    a tiny MCP-style JSON-RPC server (same four tools as fakemcp) whose results, tool descriptions and
//	    response headers carry canary strings, and which counts the calls whose body contained -seen (proof
//	    that the planted canaries really reached the upstream). GET /_s10/stats returns the counters.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: s10tool capture|upstream [flags]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "capture":
		runCapture(os.Args[2:])
	case "upstream":
		runUpstream(os.Args[2:])
	default:
		fmt.Fprintln(os.Stderr, "usage: s10tool capture|upstream [flags]")
		os.Exit(2)
	}
}

// ---- capture ----

type capture struct {
	to     string
	client *http.Client
	mu     sync.Mutex
	f      *os.File
	n      atomic.Int64
	bytes  atomic.Int64
}

func runCapture(args []string) {
	fs := flag.NewFlagSet("capture", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:8080", "listen address")
	to := fs.String("to", "", "upstream base URL (the real control plane)")
	out := fs.String("out", "/cap/capture.raw", "raw capture file")
	_ = fs.Parse(args)
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		log.Fatal(err)
	}
	c := &capture{to: strings.TrimRight(*to, "/"), f: f, client: &http.Client{Timeout: 70 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	log.Printf("s10tool capture: %s -> %s, raw capture in %s (S10 test tool)", *listen, c.to, *out)
	srv := &http.Server{Addr: *listen, Handler: c, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

var hop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Connection": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true}

func (c *capture) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/_s10/stats" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]int64{"requests": c.n.Load(), "bytes": c.bytes.Load()})
		return
	}
	reqBody, _ := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	req, err := http.NewRequestWithContext(r.Context(), r.Method, c.to+r.URL.RequestURI(), bytes.NewReader(reqBody))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for k, vs := range r.Header {
		if hop[k] {
			continue
		}
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := c.client.Do(req)
	var respBody []byte
	status := http.StatusBadGateway
	var respHdr http.Header
	if err == nil {
		defer resp.Body.Close()
		respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		status, respHdr = resp.StatusCode, resp.Header
	}
	id := c.n.Add(1)
	var rec bytes.Buffer
	fmt.Fprintf(&rec, "=== REQ %d from %s\r\n%s %s HTTP/1.1\r\nHost: %s\r\n", id, r.RemoteAddr, r.Method, r.URL.RequestURI(), r.Host)
	_ = r.Header.Write(&rec)
	rec.WriteString("\r\n")
	rec.Write(reqBody)
	fmt.Fprintf(&rec, "\r\n=== RESP %d status %d\r\n", id, status)
	if respHdr != nil {
		_ = respHdr.Write(&rec)
	}
	rec.WriteString("\r\n")
	rec.Write(respBody)
	rec.WriteString("\r\n")
	c.mu.Lock()
	_, _ = c.f.Write(rec.Bytes())
	c.mu.Unlock()
	c.bytes.Add(int64(rec.Len()))
	if err != nil {
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	for k, vs := range respHdr {
		if hop[k] || k == "Content-Length" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(status)
	_, _ = w.Write(respBody)
}

// ---- upstream ----

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func runUpstream(args []string) {
	fs := flag.NewFlagSet("upstream", flag.ExitOnError)
	listen := fs.String("listen", "0.0.0.0:9000", "listen address")
	result := fs.String("result", "", "canary placed in every tool result and tool description")
	header := fs.String("header", "", "canary placed in a response header")
	seen := fs.String("seen", "", "count calls whose body contains this string")
	_ = fs.Parse(args)
	var calls, seenCalls atomic.Int64
	tools := []string{"notes.read", "notes.write", "crm.read_contact", "crm.export"}
	mux := http.NewServeMux()
	mux.HandleFunc("/_s10/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int64{"calls": calls.Load(), "calls_with_seen": seenCalls.Load()})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4<<20))
		calls.Add(1)
		if *seen != "" && bytes.Contains(body, []byte(*seen)) {
			seenCalls.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Upstream-Note", *header)
		var q rpcReq
		if err := json.Unmarshal(body, &q); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error ` + *result + `"}}`))
			return
		}
		id := q.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		var res any
		switch q.Method {
		case "tools/list":
			var ts []map[string]any
			for _, n := range tools {
				ts = append(ts, map[string]any{"name": n, "description": "tool " + n + " " + *result,
					"inputSchema": map[string]any{"type": "object"}})
			}
			res = map[string]any{"tools": ts}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(q.Params, &p)
			res = map[string]any{"isError": false, "content": []map[string]any{
				{"type": "text", "text": "result for " + p.Name + ": " + *result + " echo=" + string(p.Arguments)}}}
		default:
			res = map[string]any{"note": "upstream result " + *result}
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "result": res})
		_, _ = w.Write(out)
	})
	log.Printf("s10tool upstream: %s (S10 test tool: results carry canary strings)", *listen)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
