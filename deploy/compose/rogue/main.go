// Command rogue is a scripted, hostile control plane for the S12 chaos scenario (Q-09). It speaks just enough
// of the proxy-facing protocol (GET /v1/poll, POST /v1/status) to feed a real kairan-proxy whatever bytes the
// test puts in a directory. Test tool only: no authentication (it accepts every token on purpose), stdlib
// only, never part of the product image.
//
//	rogue -listen 0.0.0.0:8080 -dir /rogue
//
// Files in -dir (the test writes them on the host; the container user must be able to write there):
//
//	offer.json    raw bytes served as the body of every poll; absent or empty = nothing to offer (the poll is
//	              held for 2 s and answered 304)
//	offer.status  optional HTTP status for offer.json (default 200)
//	poll.log      one line per poll: "<unix ms> served=<0|1> <raw query>"
//	status.log    one line per status report body (raw JSON, newlines removed)
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {
	listen := flag.String("listen", "0.0.0.0:8080", "listen address")
	dir := flag.String("dir", "/rogue", "directory with offer.json and the logs")
	flag.Parse()
	var mu sync.Mutex
	appendLine := func(name, line string) {
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(filepath.Join(*dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			log.Printf("rogue: %v", err)
			return
		}
		defer f.Close()
		_, _ = f.WriteString(line + "\n")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/poll", func(w http.ResponseWriter, r *http.Request) {
		offer, _ := os.ReadFile(filepath.Join(*dir, "offer.json"))
		if len(offer) == 0 {
			appendLine("poll.log", fmt.Sprintf("%d served=0 %s", time.Now().UnixMilli(), r.URL.RawQuery))
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		status := http.StatusOK
		if b, err := os.ReadFile(filepath.Join(*dir, "offer.status")); err == nil {
			if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				status = n
			}
		}
		appendLine("poll.log", fmt.Sprintf("%d served=1 %s", time.Now().UnixMilli(), r.URL.RawQuery))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(offer)
	})
	mux.HandleFunc("/v1/status", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		b = bytes.ReplaceAll(bytes.ReplaceAll(b, []byte("\n"), nil), []byte("\r"), nil)
		appendLine("status.log", string(b))
		w.WriteHeader(http.StatusNoContent)
	})
	log.Printf("rogue: hostile test control plane on %s, serving files from %s (S12 test tool)", *listen, *dir)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
