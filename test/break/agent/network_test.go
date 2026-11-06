package agentbreak

import (
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

// Go reads the proxy environment once per process, so the forward proxy is set up before any test runs.
var (
	fwdMu   sync.Mutex
	fwdSeen []fwdReq
	fwd     *httptest.Server
)

type fwdReq struct {
	Method, Host, URL string
	Header            http.Header
}

func fwdTake() []fwdReq {
	fwdMu.Lock()
	defer fwdMu.Unlock()
	out := fwdSeen
	fwdSeen = nil
	return out
}

func TestMain(m *testing.M) {
	fwd = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fwdMu.Lock()
		fwdSeen = append(fwdSeen, fwdReq{r.Method, r.Host, r.URL.String(), r.Header.Clone()})
		fwdMu.Unlock()
		if r.Method == http.MethodConnect {
			w.WriteHeader(http.StatusForbidden) // a forward proxy that refuses the tunnel
			return
		}
		switch r.URL.Path {
		case wire.PathPoll:
			w.WriteHeader(http.StatusNotModified)
		case wire.PathStatus:
			w.WriteHeader(http.StatusNoContent)
		default:
			io.WriteString(w, "via-proxy")
		}
	}))
	os.Setenv("HTTP_PROXY", fwd.URL)
	os.Setenv("HTTPS_PROXY", fwd.URL)
	os.Setenv("NO_PROXY", "direct.example.test")
	code := m.Run()
	fwd.Close()
	os.Exit(code)
}

// HTTP_PROXY / HTTPS_PROXY are honoured (PRD J2): a non-loopback control plane is reached through the forward
// proxy, with CONNECT for https.
func TestHonoursForwardProxyEnvironment(t *testing.T) {
	hc, err := agent.NewHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	fwdTake()
	res, err := hc.Get("http://cp.example.test:8080/anything")
	if err != nil {
		t.Fatalf("GET through the proxy: %v", err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if string(b) != "via-proxy" {
		t.Errorf("did not go through the forward proxy: %q", b)
	}
	seen := fwdTake()
	if len(seen) != 1 || seen[0].Method != "GET" || !strings.Contains(seen[0].URL, "cp.example.test:8080") {
		t.Errorf("proxy saw %+v", seen)
	}

	// https: a CONNECT to cp.example.test:443, without the bearer token
	req, _ := http.NewRequest("GET", "https://cp.example.test/v1/poll", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if res, err := hc.Do(req); err == nil {
		res.Body.Close()
		t.Errorf("a tunnel the proxy refused was treated as success")
	}
	seen = fwdTake()
	if len(seen) == 0 || seen[0].Method != "CONNECT" || !strings.HasPrefix(seen[0].Host, "cp.example.test:443") {
		t.Fatalf("expected a CONNECT to cp.example.test:443, proxy saw %+v", seen)
	}
	if a := seen[0].Header.Get("Authorization"); a != "" {
		t.Errorf("the bearer token was sent to the forward proxy in the CONNECT: %q", a)
	}
	if v := seen[0].Header.Get("Proxy-Authorization"); v != "" {
		t.Errorf("unexpected Proxy-Authorization %q", v)
	}
}

func TestNoProxyIsHonoured(t *testing.T) {
	hc, _ := agent.NewHTTPClient("")
	fwdTake()
	res, err := hc.Get("http://direct.example.test:8080/x")
	if err == nil {
		res.Body.Close()
	}
	if seen := fwdTake(); len(seen) != 0 {
		t.Errorf("NO_PROXY host went through the proxy: %+v", seen)
	}
}

// The agent itself polls and reports through the forward proxy and sends no other kind of traffic (all outbound).
func TestAgentRunsThroughForwardProxy(t *testing.T) {
	fwdTake()
	r := newRig(t, "", nil, nil, func(c *agent.Config) { c.CP = mustURL("http://cp.example.test:8080") })
	r.boot()
	r.run()
	waitFor(t, "poll and status through the proxy", func() bool {
		fwdMu.Lock()
		defer fwdMu.Unlock()
		p, s := false, false
		for _, x := range fwdSeen {
			p = p || strings.Contains(x.URL, wire.PathPoll)
			s = s || strings.Contains(x.URL, wire.PathStatus)
		}
		return p && s
	})
	for _, x := range fwdTake() {
		if x.Method == http.MethodConnect {
			continue
		}
		if x.Header.Get("Authorization") != "Bearer "+token {
			t.Errorf("request %s to the control plane lacks the bearer token", x.URL)
		}
	}
	if r.cp.pollCount() != 0 || r.cp.statusCount() != 0 {
		t.Errorf("traffic went straight to the (unused) fake control plane")
	}
}

// TLS (M-D31): TLS 1.2 minimum, system roots plus ca_file, never InsecureSkipVerify, redirects not followed.
func TestTLSVerificationAndCAFile(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()

	plain, _ := agent.NewHTTPClient("")
	if res, err := plain.Get(srv.URL); err == nil {
		res.Body.Close()
		t.Fatal("a self-signed certificate was accepted with no ca_file (InsecureSkipVerify?)")
	}

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := srv.Certificate()
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	withCA, err := agent.NewHTTPClient(caPath)
	if err != nil {
		t.Fatalf("ca_file refused: %v", err)
	}
	res, err := withCA.Get(srv.URL)
	if err != nil {
		t.Fatalf("a server signed by the configured CA failed: %v", err)
	}
	res.Body.Close()
	if withCA.Timeout != 0 {
		t.Errorf("client has an overall Timeout %v; the agent sets per-request deadlines (a poll is held for 30 s)", withCA.Timeout)
	}

	for name, content := range map[string][]byte{
		"empty":   nil,
		"garbage": []byte("not pem"),
		"private": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2, 3}}),
	} {
		p := filepath.Join(t.TempDir(), "bad.pem")
		_ = os.WriteFile(p, content, 0o600)
		if hc, err := agent.NewHTTPClient(p); err == nil {
			// accepting a CA file with no certificate would silently leave the system roots only; that
			// is harmless for security but hides the operator's mistake. Fail only if it trusts the server.
			if res, err := hc.Get(srv.URL); err == nil {
				res.Body.Close()
				t.Errorf("%s ca_file: server trusted", name)
			}
		}
	}
	if hc, err := agent.NewHTTPClient(filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		_ = hc
		t.Errorf("a missing ca_file was accepted")
	}
}

func TestTLSMinimumVersion(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	srv.StartTLS()
	defer srv.Close()
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	hc, err := agent.NewHTTPClient(caPath)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := hc.Get(srv.URL); err == nil {
		res.Body.Close()
		t.Errorf("a TLS 1.1 handshake succeeded; minimum is TLS 1.2")
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	var hits atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer src.Close()
	hc, _ := agent.NewHTTPClient("")
	req, _ := http.NewRequest("GET", src.URL, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := hc.Do(req)
	if err == nil {
		res.Body.Close()
		if res.StatusCode != http.StatusFound {
			t.Errorf("status %d, want the 302 handed back", res.StatusCode)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if hits.Load() != 0 {
		t.Errorf("redirect target was contacted")
	}
}
