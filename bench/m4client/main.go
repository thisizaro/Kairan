// Command m4client measures tools/call latency with and without the proxy (PRD M4). It runs inside the same
// network namespace as the proxy and fakemcp, so every hop is loopback.
//
// It alternates one direct call to the upstream (fakemcp) and one call through the proxy, for -n pairs after a
// warm-up, each over its own keep-alive connection, and prints the raw latencies in microseconds as JSON.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type out struct {
	Direct []int64 `json:"direct_us"`
	Proxy  []int64 `json:"proxy_us"`
	Errors int     `json:"errors"`
}

func main() {
	direct := flag.String("direct", "http://127.0.0.1:9000/", "upstream URL (no proxy)")
	proxy := flag.String("proxy", "http://127.0.0.1:8080/", "proxy URL")
	key := flag.String("key", "", "API key for the proxy")
	n := flag.Int("n", 3000, "measured pairs")
	warm := flag.Int("warm", 500, "warm-up pairs (not measured)")
	flag.Parse()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","arguments":{}}}`
	mk := func() *http.Client {
		return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{MaxIdleConnsPerHost: 1}}
	}
	cd, cp := mk(), mk()
	call := func(c *http.Client, url, bearer string) (time.Duration, bool) {
		req, _ := http.NewRequest("POST", url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		t := time.Now()
		res, err := c.Do(req)
		if err != nil {
			return 0, false
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		d := time.Since(t)
		// the call must succeed: 200 and no "blocked by policy" / error result
		return d, res.StatusCode == 200 && !strings.Contains(string(b), "blocked by policy") && !strings.Contains(string(b), `"isError":true`)
	}
	var o out
	for i := 0; i < *warm+*n; i++ {
		dd, ok1 := call(cd, *direct, "")
		dp, ok2 := call(cp, *proxy, *key)
		if !ok1 || !ok2 {
			o.Errors++
			continue
		}
		if i >= *warm {
			o.Direct = append(o.Direct, dd.Microseconds())
			o.Proxy = append(o.Proxy, dp.Microseconds())
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(o); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
