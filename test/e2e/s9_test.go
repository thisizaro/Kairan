package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// S9 corporate forward proxy (optional): a proxy that can reach the control plane only through HTTPS_PROXY.
//
// Topology (all built by this test with plain docker commands, next to the demo stack, nothing simulated):
//
//	s9-edge network: kairan-s9-px (proxy, HTTPS_PROXY=http://s9-fwd:3128), kairan-s9-fakemcp, kairan-s9-fwd
//	s9-core network: kairan-s9-fwd, kairan-s9-cp (TLS, self-signed certificate generated here)
//
// The proxy shares no network with the control plane, and its cp_url names a host (cp-s9) that only the
// forward proxy can resolve. fwd (deploy/compose/fwd, stdlib Go, built on the host and mounted into a
// kairan:demo container) is CONNECT-only and logs every tunnel.
// Pass: enrolment, long-poll, policy apply and status reports work through the tunnel; fwd's log shows only
// CONNECT cp-s9:8443; with fwd stopped the proxy fails static (nothing reaches it, no direct route exists)
// and it catches up when fwd returns. J2.
const (
	s9Edge   = "kairan-s9-edge"
	s9Core   = "kairan-s9-core"
	s9Tenant = "corp-s9"
	s9Proxy  = "corp-s9-px"
	s9CPPort = 18443
	s9PxMCP  = 18190
	s9PxMet  = 19190
)

var s9Containers = []string{"kairan-s9-px", "kairan-s9-fakemcp", "kairan-s9-fwd", "kairan-s9-cp"}

func s9Cleanup() {
	for _, c := range s9Containers {
		_, _ = docker("rm", "-f", "-v", c)
	}
	for _, v := range []string{"kairan-s9-cp-data", "kairan-s9-px-data"} {
		_, _ = docker("volume", "rm", "-f", v)
	}
	for _, n := range []string{s9Edge, s9Core} {
		_, _ = docker("network", "rm", n)
	}
}

func s9Cert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "cp-s9 (kairan S9 test, not for production)"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"cp-s9"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

type s9World struct {
	w     *world
	hc    *http.Client
	token string
	ver   uint64
}

func (s *s9World) admin(method, path string, body, out any) (int, wire.ErrorCode, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, fmt.Sprintf("https://127.0.0.1:%d%s", s9CPPort, path), rd)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+s.token)
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	res, err := s.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode/100 != 2 {
		var er wire.ErrorResponse
		_ = json.Unmarshal(data, &er)
		return res.StatusCode, er.Code, nil
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return res.StatusCode, "", err
		}
	}
	return res.StatusCode, "", nil
}

func (s *s9World) release(t *testing.T) uint64 {
	t.Helper()
	s.ver++
	env := s.w.envelope(goodPayload(s9Tenant, s.ver), "admin-a", "admin-b")
	if code, ec, err := s.admin("POST", wire.PathPolicies, env, nil); err != nil || code/100 != 2 {
		t.Fatalf("s9 publish v%d: HTTP %d %s (%v)", s.ver, code, ec, err)
	}
	if code, ec, err := s.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: s9Tenant, Version: s.ver, CanaryDwellSeconds: 1}, nil); err != nil || code/100 != 2 {
		t.Fatalf("s9 rollout v%d: HTTP %d %s (%v)", s.ver, code, ec, err)
	}
	return s.ver
}

func (s *s9World) row() (wire.ProxyView, error) {
	var fv wire.FleetView
	code, ec, err := s.admin("GET", wire.PathFleet+"?tenant="+s9Tenant, nil, &fv)
	if err != nil || code != 200 {
		return wire.ProxyView{}, fmt.Errorf("fleet: HTTP %d %s %v", code, ec, err)
	}
	for _, r := range fv.Proxies {
		if string(r.ProxyID) == s9Proxy {
			return r, nil
		}
	}
	return wire.ProxyView{}, fmt.Errorf("%s not enrolled/seen yet", s9Proxy)
}

func (s *s9World) selfView() (self, error) {
	var sv self
	res, err := s.w.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/v1/self", s9PxMet))
	if err != nil {
		return sv, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return sv, json.Unmarshal(b, &sv)
}

func TestS9ForwardProxy(t *testing.T) {
	w := need(t)
	w.baseline(t)
	s9Cleanup()
	t.Cleanup(s9Cleanup)

	dir := filepath.Join(w.run, "s9")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// the forward proxy: stdlib Go, static, built on the host, run inside a kairan:demo container
	root := filepath.Join(w.compose, "..", "..")
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "fwd"), "./deploy/compose/fwd")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fwd: %v\n%s", err, out)
	}

	certPEM, keyPEM := s9Cert(t)
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cp-cert.pem", certPEM)
	write("cp-key.pem", keyPEM) // generated for this run only, in the gitignored .run directory
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(certPEM)

	var pubs []string
	pb, err := os.ReadFile(filepath.Join(w.run, "trusted-keys.json"))
	if err != nil || json.Unmarshal(pb, &pubs) != nil {
		t.Fatalf("trusted-keys.json: %v", err)
	}
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	adminTok := hex.EncodeToString(rb)
	_, _ = rand.Read(rb)
	pxTok := "tok-s9-" + hex.EncodeToString(rb)
	sum := sha256.Sum256([]byte(pxTok))

	cpCfg, _ := json.Marshal(map[string]any{
		"listen": "0.0.0.0:8443", "metrics_listen": "0.0.0.0:9100", "data_dir": "/data",
		"tls_cert_file": "/etc/kairan/cp-cert.pem", "tls_key_file": "/etc/kairan/cp-key.pem",
		"log_level": "info", "canary_dwell_seconds": 5,
		"tenants":     map[string]any{s9Tenant: map[string]any{"threshold": 2, "admin_keys": pubs}},
		"enrollments": []any{map[string]any{"proxy_id": s9Proxy, "tenant": s9Tenant, "group": "canary", "token_sha256": hex.EncodeToString(sum[:])}},
	})
	write("cp.json", cpCfg)
	pxCfg, _ := json.Marshal(map[string]any{
		"tenant": s9Tenant, "proxy_id": s9Proxy, "cp_url": "https://cp-s9:8443", "token": pxTok,
		"ca_file": "/etc/kairan/cp-cert.pem", "trusted_keys": pubs, "threshold": 2,
		"listen": "0.0.0.0:8080", "metrics_listen": "0.0.0.0:9090", "upstream": "http://fakemcp-s9:9000",
		"api_keys": map[string]string{w.salesKey: "sales", w.internKey: "intern"}, "data_dir": "/data",
	})
	write("proxy.json", pxCfg)

	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	run := func(args ...string) {
		t.Helper()
		mustDocker(t, append([]string{"run", "-d"}, args...)...)
	}
	mustDocker(t, "network", "create", s9Edge)
	mustDocker(t, "network", "create", s9Core)
	mustDocker(t, "volume", "create", "kairan-s9-cp-data")
	mustDocker(t, "volume", "create", "kairan-s9-px-data")

	// control plane: core network only
	run(append(hard, "--name", "kairan-s9-cp", "--network", s9Core, "--network-alias", "cp-s9",
		"-e", "KCP_ADMIN_TOKEN="+adminTok, "-v", "kairan-s9-cp-data:/data",
		"-v", filepath.Join(dir, "cp.json")+":/etc/kairan/cp.json:ro",
		"-v", filepath.Join(dir, "cp-cert.pem")+":/etc/kairan/cp-cert.pem:ro",
		"-v", filepath.Join(dir, "cp-key.pem")+":/etc/kairan/cp-key.pem:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8443", s9CPPort),
		image, "kairan-cp", "-config", "/etc/kairan/cp.json")...)
	// forward proxy: edge network, then also core
	run(append(hard, "--name", "kairan-s9-fwd", "--network", s9Edge, "--network-alias", "s9-fwd",
		"-v", filepath.Join(dir, "fwd")+":/usr/local/bin/s9fwd:ro",
		image, "s9fwd", "-addr", "0.0.0.0:3128")...)
	mustDocker(t, "network", "connect", s9Core, "kairan-s9-fwd")
	run(append(hard, "--name", "kairan-s9-fakemcp", "--network", s9Edge, "--network-alias", "fakemcp-s9",
		image, "fakemcp", "-addr", "0.0.0.0:9000")...)

	s9 := &s9World{w: w, token: adminTok, hc: &http.Client{Timeout: 10 * time.Second,
		Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12}}}}
	eventually(t, 60*time.Second, time.Second, "the s9 control plane to answer over TLS", func() (bool, string) {
		code, _, err := s9.admin("GET", wire.PathFleet+"?tenant="+s9Tenant, nil, nil)
		return err == nil && code == 200, fmt.Sprintf("HTTP %d %v", code, err)
	})

	// a policy is waiting before the proxy even starts
	v1 := s9.release(t)

	// the proxy: edge network only, and the only way out is the forward proxy
	run(append(hard, "--name", "kairan-s9-px", "--network", s9Edge, "--network-alias", "s9-px",
		"-e", "HTTPS_PROXY=http://s9-fwd:3128", "-e", "NO_PROXY=",
		"-v", "kairan-s9-px-data:/data",
		"-v", filepath.Join(dir, "proxy.json")+":/etc/kairan/proxy.json:ro",
		"-v", filepath.Join(dir, "cp-cert.pem")+":/etc/kairan/cp-cert.pem:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", s9PxMCP), "-p", fmt.Sprintf("127.0.0.1:%d:9090", s9PxMet),
		image, "kairan-proxy", "-config", "/etc/kairan/proxy.json")...)

	took := eventually(t, 90*time.Second, 500*time.Millisecond, "the proxy behind the forward proxy to apply v"+itoa(v1), func() (bool, string) {
		r, err := s9.row()
		if err != nil {
			return false, err.Error()
		}
		return r.AppliedVersion >= v1 && r.State == wire.StateEnforcing && r.Health == wire.HealthHealthy, fmt.Sprintf("applied v%d %s %s", r.AppliedVersion, r.State, r.Health)
	})
	t.Logf("S9: proxy behind HTTPS_PROXY enrolled, long-polled and acked v%d in %.1fs", v1, took.Seconds())

	tunnels := func() []string {
		out, _ := docker("logs", "kairan-s9-fwd")
		var lines []string
		for _, ln := range strings.Split(out, "\n") {
			if strings.Contains(ln, "CONNECT") || strings.Contains(ln, "REFUSED") {
				lines = append(lines, ln)
			}
		}
		return lines
	}
	lines := tunnels()
	connects := 0
	for _, ln := range lines {
		switch {
		case strings.Contains(ln, "CONNECT cp-s9:8443") && !strings.Contains(ln, "FAILED"):
			connects++
		default:
			t.Errorf("forward proxy log line that is not a good tunnel to the control plane: %q", ln)
		}
	}
	if connects < 1 {
		t.Fatalf("the forward proxy saw no CONNECT cp-s9:8443; log: %v", lines)
	}
	t.Logf("S9: forward proxy log shows %d tunnel(s), all to cp-s9:8443", connects)

	// enforcement works too (calls reach the fake MCP server directly on the edge network)
	pxs := px{ID: s9Proxy, Tenant: s9Tenant, MCP: s9PxMCP, Metrics: s9PxMet}
	for _, cm := range callMix {
		if r := w.call(pxs, w.keyFor(cm.role), cm.tool); r.Err != nil || r.Allowed != wantAllowed(cm.role, cm.tool, v1) {
			t.Errorf("s9 proxy %s/%s allowed=%v err=%v under v%d", cm.role, cm.tool, r.Allowed, r.Err, v1)
		}
	}

	// no direct route: the name does not resolve from the proxy's network and the CP's address is not reachable
	if out, err := docker("exec", "kairan-s9-px", "wget", "-q", "-T", "3", "-O", "/dev/null", "https://cp-s9:8443/"); err == nil {
		t.Errorf("the proxy container reached cp-s9 directly: %s", out)
	}
	if ip, err := docker("inspect", "-f", "{{(index .NetworkSettings.Networks \""+s9Core+"\").IPAddress}}", "kairan-s9-cp"); err != nil || ip == "" {
		t.Errorf("cannot find the control plane's address: %q %v", ip, err)
	} else if out, err := docker("exec", "kairan-s9-px", "wget", "-q", "-T", "3", "-O", "/dev/null", "--no-check-certificate", "https://"+ip+":8443/"); err == nil {
		t.Errorf("the proxy container reached the control plane's address %s directly: %s", ip, out)
	}

	// cut the forward proxy: fail-static, and since there is no other route nothing arrives
	mustDocker(t, "stop", "-t", "2", "kairan-s9-fwd")
	cutAt := time.Now()
	v2 := s9.release(t)
	time.Sleep(15 * time.Second)
	sv, err := s9.selfView()
	if err != nil || sv.AppliedVersion != v1 || sv.State != string(wire.StateEnforcing) {
		t.Errorf("with the forward proxy down the proxy should stay on v%d enforcing: %+v (%v)", v1, sv, err)
	}
	if r := w.call(pxs, w.salesKey, "notes.write"); r.Allowed != wantAllowed("sales", "notes.write", v1) {
		t.Errorf("fail-static call answer changed while cut off: %+v", r)
	}
	if row, err := s9.row(); err != nil || row.AppliedVersion != v1 {
		t.Errorf("control plane's view while fwd is down: %+v (%v)", row, err)
	}

	// bring it back: the proxy reconnects through the tunnel and catches up
	mustDocker(t, "start", "kairan-s9-fwd")
	back := eventually(t, 90*time.Second, 500*time.Millisecond, "the proxy to catch up to v"+itoa(v2)+" through the restarted forward proxy", func() (bool, string) {
		r, err := s9.row()
		if err != nil {
			return false, err.Error()
		}
		return r.AppliedVersion >= v2 && r.Health == wire.HealthHealthy, fmt.Sprintf("applied v%d %s", r.AppliedVersion, r.Health)
	})
	t.Logf("S9: forward proxy down %.0fs; after it returned the proxy reached v%d in %.1fs", time.Since(cutAt).Seconds()-back.Seconds(), v2, back.Seconds())
	for _, ln := range tunnels() {
		if !strings.Contains(ln, "CONNECT cp-s9:8443") || strings.Contains(ln, "FAILED") {
			t.Errorf("forward proxy log line that is not a good tunnel to the control plane: %q", ln)
		}
	}
	if r := w.call(pxs, w.salesKey, "notes.write"); !r.Allowed {
		t.Errorf("after catching up to v%d notes.write should be allowed: %+v", v2, r)
	}
}
