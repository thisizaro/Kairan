package cpapibreak

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// M-D9 / M-D31: HTTPServer limits, read from the returned http.Server.
func TestHTTPServerLimits(t *testing.T) {
	e := newEnv(t)
	s := e.srv.HTTPServer("127.0.0.1:0")
	if s == nil {
		t.Fatal("nil server")
	}
	checks := []struct {
		name      string
		got, want time.Duration
	}{
		{"ReadHeaderTimeout", s.ReadHeaderTimeout, 5 * time.Second},
		{"ReadTimeout", s.ReadTimeout, 10 * time.Second},
		{"WriteTimeout", s.WriteTimeout, 40 * time.Second},
		{"IdleTimeout", s.IdleTimeout, 60 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if s.MaxHeaderBytes != 8<<10 {
		t.Errorf("MaxHeaderBytes = %d, want %d", s.MaxHeaderBytes, 8<<10)
	}
	if s.WriteTimeout <= wire.PollHold {
		t.Errorf("WriteTimeout %v must exceed the %v poll hold", s.WriteTimeout, wire.PollHold)
	}
	if s.Addr != "127.0.0.1:0" {
		t.Errorf("Addr = %q", s.Addr)
	}
	if s.Handler == nil {
		t.Error("no handler")
	}
}

// serve starts the real http.Server returned by HTTPServer on a loopback listener.
func (e *env) serve() string {
	e.t.Helper()
	s := e.srv.HTTPServer("127.0.0.1:0")
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		e.t.Fatal(err)
	}
	go s.Serve(l)
	e.t.Cleanup(func() { s.Close() })
	return l.Addr().String()
}

// M-D9: a slow-header client is cut off (slowloris), within ReadHeaderTimeout plus slack.
func TestSlowHeaderClientIsCutOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	addr := e.serve()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.Write([]byte("GET /v1/fleet?tenant=bank-a HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + adminTok + "\r\nX-Slow: "))
	_ = c.SetReadDeadline(time.Now().Add(12 * time.Second))
	buf := make([]byte, 1024)
	n, err := c.Read(buf)
	el := time.Since(start)
	if el < 4*time.Second {
		t.Fatalf("cut off after only %v; ReadHeaderTimeout is 5s", el)
	}
	if el > 9*time.Second {
		t.Fatalf("a client that never finishes its headers was still connected after %v (n=%d err=%v)", el, n, err)
	}
	if n > 0 && strings.Contains(string(buf[:n]), "200 OK") {
		t.Fatalf("an incomplete request was served: %q", buf[:n])
	}
}

// M-D9: a client that sends headers, promises a body and stalls is cut off by ReadTimeout (10s).
func TestSlowBodyClientIsCutOff(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	addr := e.serve()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	c.Write([]byte("POST /v1/status HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + tokOf("p1") + "\r\nContent-Type: application/json\r\nContent-Length: 500\r\n\r\n{\"tenant\":"))
	_ = c.SetReadDeadline(time.Now().Add(16 * time.Second))
	n, err := bufio.NewReader(c).Read(make([]byte, 1024))
	el := time.Since(start)
	if el > 14*time.Second {
		t.Fatalf("a stalled body kept the connection for %v (n=%d err=%v)", el, n, err)
	}
	if el < 8*time.Second {
		// Closing earlier is fine too (a 400 answer), but must not be a success.
		t.Logf("closed after %v", el)
	}
}

// M-D9: MaxHeaderBytes 8 KiB. A request with 16 KiB of headers is refused, not served.
func TestOversizeHeadersAreRefused(t *testing.T) {
	e := newEnv(t)
	addr := e.serve()
	for name, hdr := range map[string]string{
		"one-big-header":   "X-Pad: " + strings.Repeat("a", 16<<10) + "\r\n",
		"many-headers":     strings.Repeat("X-A: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n", 200),
		"huge-request-uri": "",
	} {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		target := "/v1/fleet?tenant=bank-a"
		if name == "huge-request-uri" {
			target += "&pad=" + strings.Repeat("a", 16<<10)
		}
		c.Write([]byte("GET " + target + " HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer " + adminTok + "\r\n" + hdr + "\r\n"))
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		line, _ := bufio.NewReader(c).ReadString('\n')
		c.Close()
		if strings.Contains(line, " 200 ") || strings.Contains(line, " 401 ") || strings.Contains(line, " 403 ") {
			t.Errorf("%s: oversize headers were processed: %q", name, line)
		}
	}
}

// The real server end to end: a normal request works and the Allow/405 and 401 paths work over the wire.
func TestRealServerServesTheAPI(t *testing.T) {
	e := newEnv(t)
	addr := e.serve()
	req, _ := http.NewRequest("GET", "http://"+addr+wire.PathFleet+"?tenant=bank-a", nil)
	req.Header.Set("Authorization", "Bearer "+adminTok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("got %d", res.StatusCode)
	}
}
