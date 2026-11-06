package enforcebreak

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

// Doc: "the proxy forwards ... with the agent's own credentials removed. Requests always go to the
// configured upstream URL; the path and query of the agent's request are not used."
func TestForwardingStripsCredentialsAndIgnoresAgentPath(t *testing.T) {
	r := newRig(t)
	body := callBody(1, "crm.read_contact", `{}`)
	rep := r.send("POST", "/evil/path?api_key="+keySales+"&x="+canary, "", []byte(body),
		"Authorization", "Bearer "+keySales, "X-Api-Key", keySales, "Cookie", "s=1", "X-Canary", canary)
	if rep.code != 200 {
		t.Fatalf("%d %.100s", rep.code, rep.body)
	}
	got := r.up.requests()
	if len(got) != 1 {
		t.Fatalf("upstream saw %d", len(got))
	}
	u := got[0]
	if u.URI != "/mcp-endpoint?fixed=1" {
		t.Errorf("upstream request target %q, want the configured /mcp-endpoint?fixed=1", u.URI)
	}
	for _, h := range []string{"Authorization", "X-Api-Key"} {
		if v := u.Header.Get(h); v != "" {
			t.Errorf("agent credential %s forwarded to the upstream: %q", h, v)
		}
	}
	for k, vs := range u.Header {
		for _, v := range vs {
			if strings.Contains(v, keySales) {
				t.Errorf("the API key leaked in header %s to the upstream", k)
			}
		}
	}
	if u.Method != "POST" {
		t.Errorf("method %s", u.Method)
	}
}

// GET and DELETE pass through (stream and session teardown) with credentials removed, and still need a key.
func TestGetAndDeletePassThroughButNeedAKey(t *testing.T) {
	for _, m := range []string{"GET", "DELETE"} {
		r := newRig(t)
		if rep := r.send(m, "/", "", nil); rep.code != 401 || r.up.count() != 0 {
			t.Errorf("%s without a key: %d, upstream %d", m, rep.code, r.up.count())
		}
		rep := r.send(m, "/", keySales, nil, "Mcp-Session-Id", "abc")
		if rep.code/100 == 5 && rep.code != 502 && rep.code != 504 {
			t.Errorf("%s with key: %d", m, rep.code)
		}
		got := r.up.requests()
		if len(got) != 1 || got[0].Method != m {
			t.Errorf("%s: upstream saw %v", m, got)
			continue
		}
		if got[0].Header.Get("Authorization") != "" || got[0].Header.Get("X-Api-Key") != "" {
			t.Errorf("%s forwarded the agent's credentials", m)
		}
		if got[0].Header.Get("Mcp-Session-Id") != "abc" {
			t.Errorf("%s dropped the session header", m)
		}
		for _, rec := range r.dl.all() {
			if rec.Tool != "" && rec.Tool != "tools/list" {
				t.Errorf("%s produced a decision %+v", m, rec)
			}
		}
	}
}

// A GET carrying a body or a tools/call-looking query must not become a way around the policy: the proxy
// judges POST bodies only, and forwards the GET exactly as a GET (a body on GET is dropped or refused).
func TestGetWithToolsCallBodyIsNotAnEscapeHatch(t *testing.T) {
	r := newRig(t)
	body := callBody(1, "crm.delete_all", `{}`)
	rep := r.send("GET", "/", keySales, []byte(body))
	_ = rep
	for _, u := range r.up.requests() {
		if strings.Contains(string(u.Body), "crm.delete_all") {
			t.Fatalf("a denied tools/call was forwarded inside a GET body: %s %q", u.Method, u.Body)
		}
	}
	for _, m := range []string{"PUT", "PATCH", "OPTIONS", "TRACE", "CONNECT", "PROPFIND"} {
		r2 := newRig(t)
		rep := r2.send(m, "/", keySales, []byte(body))
		for _, u := range r2.up.requests() {
			if strings.Contains(string(u.Body), "crm.delete_all") {
				t.Fatalf("a denied tools/call was forwarded with method %s (answer %d)", m, rep.code)
			}
		}
	}
}

// I5: "in-flight calls finish under the policy they started with", and every decision carries the policy
// version and hash it was judged under. Swap the policy while a call is in the upstream.
func TestInFlightCallFinishesUnderItsPolicy(t *testing.T) {
	r := newRig(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
		close(entered)
		<-release
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream-ran"}]}}`)
	}
	done := make(chan reply, 1)
	go func() { done <- r.post(keySales, callBody(1, "crm.read_contact", `{}`)) }()
	<-entered
	// Swap to a policy that denies everything, version 9.
	r.hold.Store(&enforce.Active{Policy: nil, Hash: hashN(9), State: wire.StateDenyAll})
	rep2 := r.post(keySales, callBody(2, "crm.read_contact", `{}`))
	if !blocked(rep2, 0) && !strings.Contains(string(rep2.body), "blocked by policy") {
		t.Fatalf("a call started after the swap was not denied: %d %.150s", rep2.code, rep2.body)
	}
	close(release)
	rep1 := <-done
	if rep1.code != 200 || !strings.Contains(string(rep1.body), "upstream-ran") {
		t.Fatalf("the in-flight call did not finish under its policy: %d %.150s", rep1.code, rep1.body)
	}
	recs := r.dl.all()
	if len(recs) != 2 {
		t.Fatalf("records %+v", recs)
	}
	var first, second *enforce.Record
	for i := range recs {
		if recs[i].Version == 8 {
			first = &recs[i]
		} else {
			second = &recs[i]
		}
	}
	if first == nil || !first.Allowed || first.Hash != hashN(8) || first.State != wire.StateEnforcing {
		t.Fatalf("the in-flight call's record: %+v", first)
	}
	if second == nil || second.Allowed || second.Hash != hashN(9) || second.State != wire.StateDenyAll {
		t.Fatalf("the later call's record: %+v", second)
	}
}

// I5/I3 under -race: while the policy flips between A (v1, allows crm.read_contact) and B (v2, denies it),
// every record is internally consistent (version, hash, verdict from the same policy), and a denial's
// text names the version of its own record.
func TestSwapRaceKeepsEveryDecisionConsistent(t *testing.T) {
	r := newRig(t)
	pa := mustPolicy(t, 1)
	pb := mustPolicy(t, 2)
	// B is the same policy text with another version; make B deny by using a state that denies.
	a := &enforce.Active{Policy: pa, Hash: hashN(1), State: wire.StateEnforcing}
	b := &enforce.Active{Policy: pb, Hash: hashN(2), State: wire.StateTampered}
	r.hold.Store(a)
	stop := make(chan struct{})
	var swaps atomic.Int64
	go func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				r.hold.Store(b)
			} else {
				r.hold.Store(a)
			}
			swaps.Add(1)
		}
	}()
	var wg sync.WaitGroup
	for g := 0; g < 12; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 40; i++ {
				rep := r.post(keySales, callBody(g*100+i, "crm.read_contact", `{}`))
				if rep.code != 200 {
					t.Errorf("%d %.100s", rep.code, rep.body)
					return
				}
				if strings.Contains(string(rep.body), "blocked by policy") {
					if !strings.Contains(string(rep.body), "blocked by policy v2") {
						t.Errorf("a denial from state tampered names the wrong version: %.150s", rep.body)
					}
				}
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	ups := r.up.count()
	allowed := 0
	for _, rec := range r.dl.all() {
		switch rec.Version {
		case 1:
			if rec.Hash != hashN(1) || rec.State != wire.StateEnforcing || !rec.Allowed {
				t.Errorf("v1 record inconsistent: %+v", rec)
			}
			allowed++
		case 2:
			if rec.Hash != hashN(2) || rec.State != wire.StateTampered || rec.Allowed {
				t.Errorf("v2 record inconsistent (tampered must deny): %+v", rec)
			}
		default:
			t.Errorf("record with an unknown version: %+v", rec)
		}
	}
	if allowed != ups {
		t.Errorf("%d allow records but the upstream ran %d calls", allowed, ups)
	}
	if swaps.Load() < 10 {
		t.Logf("only %d swaps happened", swaps.Load())
	}
}

// ---- upstream faults ----

func TestUpstreamHangsEndsAtTheCallTimeout(t *testing.T) {
	r := newRig(t, func(r *rig) { r.cfg.UpstreamTimeout = 400 * time.Millisecond })
	release := make(chan struct{})
	defer close(release)
	r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}
	start := time.Now()
	rep := r.post(keySales, callBody(1, "crm.read_contact", `{}`))
	el := time.Since(start)
	if el > 3*time.Second {
		t.Fatalf("the call took %v with a 400ms upstream timeout", el)
	}
	if rep.code == 200 && strings.Contains(string(rep.body), "upstream-ran") {
		t.Fatal("impossible success")
	}
	if rep.code/100 == 2 && !strings.Contains(string(rep.body), "error") {
		t.Errorf("a timed-out call answered %d %.100s", rep.code, rep.body)
	}
	if r.met.get("enforce_upstream_errors") == 0 {
		t.Errorf("enforce_upstream_errors not counted: %v", r.met.names())
	}
	if recs := r.dl.all(); len(recs) != 1 {
		t.Errorf("records %+v", recs)
	}
	// The same for tools/list: the agent must not see a stale or partial list.
	r2 := newRig(t, func(r *rig) { r.cfg.UpstreamTimeout = 300 * time.Millisecond })
	r2.up.respond = r.up.respond
	start = time.Now()
	lrep := r2.post(keySales, listBody(1))
	if time.Since(start) > 3*time.Second {
		t.Fatalf("tools/list against a hanging upstream took %v", time.Since(start))
	}
	if lrep.code == 200 {
		if names := toolNames(t, lrep); len(names) != 0 {
			t.Fatalf("hanging upstream, list = %v", names)
		}
	}
}

func TestUpstreamUnreachableOrBrokenNeverWidens(t *testing.T) {
	for name, mod := range map[string]func(*upstream){
		"closed-connection": func(u *upstream) {
			u.respond = func(w http.ResponseWriter, r *http.Request, b []byte) {
				c, _, _ := w.(http.Hijacker).Hijack()
				c.Close()
			}
		},
		"half-body": func(u *upstream) {
			u.respond = func(w http.ResponseWriter, r *http.Request, b []byte) {
				w.Header().Set("Content-Length", "1000")
				io.WriteString(w, `{"jsonrpc":"2.0","id":1,"res`)
			}
		},
		"500": func(u *upstream) {
			u.respond = func(w http.ResponseWriter, r *http.Request, b []byte) { http.Error(w, "boom "+canary, 500) }
		},
		"redirect-to-evil": func(u *upstream) {
			u.respond = func(w http.ResponseWriter, r *http.Request, b []byte) {
				http.Redirect(w, r, "http://127.0.0.1:1/steal", http.StatusTemporaryRedirect)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(r *rig) { r.cfg.UpstreamTimeout = 2 * time.Second })
			mod(r.up)
			for _, body := range []string{callBody(1, "crm.read_contact", `{}`), listBody(2)} {
				rep := r.post(keySales, body)
				if rep.code == -1 {
					continue // the proxy dropped the connection: nothing widened
				}
				if strings.Contains(string(rep.body), "upstream-ran") {
					t.Fatal("impossible success")
				}
			}
			recs := r.dl.all()
			for _, rec := range recs {
				if rec.Tool == "crm.delete_all" {
					t.Fatalf("%+v", rec)
				}
			}
		})
	}
}

// Redirects from the upstream are not followed: a 307 must not send the agent's body (or the request)
// to a host nobody configured.
func TestUpstreamRedirectsAreNotFollowed(t *testing.T) {
	evilHits := atomic.Int32{}
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { evilHits.Add(1) }))
	defer evil.Close()
	r := newRig(t)
	r.up.respond = func(w http.ResponseWriter, req *http.Request, b []byte) {
		http.Redirect(w, req, evil.URL+"/steal", http.StatusTemporaryRedirect)
	}
	r.post(keySales, callBody(1, "crm.read_contact", `{"q":"`+canary+`"}`))
	r.post(keySales, listBody(2))
	if evilHits.Load() != 0 {
		t.Fatalf("the proxy followed an upstream redirect to another host (%d hits)", evilHits.Load())
	}
}

// ---- listener limits (M-D31) ----

func TestNewServerLimits(t *testing.T) {
	r := newRig(t)
	s := enforce.NewServer("127.0.0.1:0", r.h)
	if s.ReadHeaderTimeout != 5*time.Second {
		t.Errorf("ReadHeaderTimeout %v", s.ReadHeaderTimeout)
	}
	if s.IdleTimeout != 60*time.Second {
		t.Errorf("IdleTimeout %v", s.IdleTimeout)
	}
	if s.MaxHeaderBytes != 8<<10 {
		t.Errorf("MaxHeaderBytes %d", s.MaxHeaderBytes)
	}
	if s.WriteTimeout != 0 {
		t.Errorf("WriteTimeout %v: a response may stream, the per-call upstream timeout bounds it", s.WriteTimeout)
	}
	if enforce.MaxBodyBytes != 1<<20 || enforce.DefaultUpstreamTimeout != 60*time.Second {
		t.Errorf("constants %d %v", enforce.MaxBodyBytes, enforce.DefaultUpstreamTimeout)
	}
	if s.Handler == nil || s.Addr != "127.0.0.1:0" {
		t.Errorf("handler/addr: %v %q", s.Handler, s.Addr)
	}
}

func (r *rig) serveReal() string {
	r.t.Helper()
	s := enforce.NewServer("127.0.0.1:0", r.h)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		r.t.Fatal(err)
	}
	go s.Serve(l)
	r.t.Cleanup(func() { s.Close() })
	return l.Addr().String()
}

func TestSlowHeaderClientIsCutOff(t *testing.T) {
	t.Parallel()
	r := newRig(t)
	addr := r.serveReal()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.Write([]byte("POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + keySales + "\r\nX-Slow: "))
	_ = c.SetReadDeadline(time.Now().Add(12 * time.Second))
	_, _ = bufio.NewReader(c).ReadString('\n')
	el := time.Since(start)
	if el < 4*time.Second || el > 9*time.Second {
		t.Fatalf("a slow-header client was cut off after %v, want about 5s", el)
	}
}

func TestOversizeHeadersAreRefused(t *testing.T) {
	r := newRig(t)
	addr := r.serveReal()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := callBody(1, "crm.read_contact", `{}`)
	fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Pad: %s\r\n\r\n%s",
		keySales, len(body), strings.Repeat("a", 16<<10), body)
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, _ := bufio.NewReader(c).ReadString('\n')
	if strings.Contains(line, " 200 ") {
		t.Fatalf("16 KiB of headers was served: %q", line)
	}
	if r.up.count() != 0 {
		t.Fatalf("a request with oversize headers reached the upstream")
	}
}

// A client that disconnects mid-call must not leave the handler stuck or crash the proxy.
func TestClientDisconnectMidCall(t *testing.T) {
	r := newRig(t)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	r.up.respond = func(w http.ResponseWriter, req *http.Request, b []byte) {
		select {
		case entered <- struct{}{}:
		default:
		}
		select {
		case <-release:
		case <-req.Context().Done():
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "POST", r.srv.URL, strings.NewReader(callBody(1, "crm.read_contact", `{}`)))
	req.Header.Set("Authorization", "Bearer "+keySales)
	req.Header.Set("Content-Type", "application/json")
	go http.DefaultClient.Do(req)
	<-entered
	cancel()
	close(release)
	time.Sleep(100 * time.Millisecond)
	if rep := r.post(keySales, callBody(2, "crm.read_contact", `{}`)); rep.code == -1 {
		t.Fatalf("proxy unusable after a client disconnect: %s", rep.body)
	}
}
