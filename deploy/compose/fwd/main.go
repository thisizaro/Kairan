// Command fwd is a tiny corporate-style forward proxy for the S9 chaos scenario (Q-03): it answers HTTP
// CONNECT and nothing else, splices the two sockets, and logs one line per tunnel to stdout. Test tool only:
// no authentication, no access control, never part of the product image.
//
//	fwd -addr 0.0.0.0:3128
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:3128", "listen address")
	flag.Parse()
	srv := &http.Server{
		Addr:              *addr,
		Handler:           http.HandlerFunc(connect),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("fwd: tunnel-only forward proxy listening on %s (S9 test tool)", *addr)
	log.Fatal(srv.ListenAndServe())
}

func connect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		// plain HTTP through the proxy is refused on purpose: the scenario is about HTTPS_PROXY tunnels
		log.Printf("REFUSED %s %s from %s", r.Method, r.RequestURI, r.RemoteAddr)
		http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	dst, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		log.Printf("CONNECT %s from %s FAILED: %v", r.Host, r.RemoteAddr, err)
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		dst.Close()
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	src, _, err := hj.Hijack()
	if err != nil {
		dst.Close()
		return
	}
	log.Printf("CONNECT %s from %s", r.Host, r.RemoteAddr)
	if _, err := fmt.Fprint(src, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		src.Close()
		dst.Close()
		return
	}
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(to, from net.Conn) {
		defer wg.Done()
		_, _ = io.Copy(to, from)
		if tc, ok := to.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}
	go pipe(dst, src)
	go pipe(src, dst)
	wg.Wait()
	src.Close()
	dst.Close()
}
