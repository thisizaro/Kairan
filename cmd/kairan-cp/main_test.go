package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kairan/internal/wire"
)

var binPath string

// TestMain builds the real binary once; the process tests below run it.
//
// The binary lives in a fixed per-user cache directory, named by this
// process's pid, never in a fresh random temp directory: a run that is killed
// or crashes (test timeout, panic in a goroutine, SIGKILL) cannot clean up
// after itself, and random directories then pile up (M-D68 G1 triage). A
// fixed directory bounds the leak to one binary per dead run, and the next run
// sweeps those away. Normal exit, panic in TestMain and SIGINT/SIGTERM remove
// the binary at once.
func TestMain(m *testing.M) {
	os.Exit(runMain(m))
}

func runMain(m *testing.M) int {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	dir := filepath.Join(cache, "kairan-test", "kairan-cp-bin")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	sweepStaleBinaries(dir)

	binPath = filepath.Join(dir, fmt.Sprintf("kairan-cp.%d", os.Getpid()))
	cleanup := func() { os.Remove(binPath) }
	defer cleanup() // also runs when m.Run panics in this goroutine

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		if _, ok := <-sig; ok {
			cleanup()
			os.Exit(1)
		}
	}()

	if out, err := exec.Command("go", "build", "-o", binPath, ".").CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build failed: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// sweepStaleBinaries removes kairan-cp.<pid> files left by runs that died
// without cleaning up. A file whose pid is still alive is left alone.
func sweepStaleBinaries(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		rest, ok := strings.CutPrefix(e.Name(), "kairan-cp.")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(rest)
		if err != nil || pid <= 0 {
			continue
		}
		if err := syscall.Kill(pid, 0); err == nil || err == syscall.EPERM {
			continue // owner still running
		}
		os.Remove(filepath.Join(dir, e.Name()))
	}
}

const (
	fixtures  = "../../test/fixtures"
	testAdmin = "admin-token-for-the-tests-0001"
)

func fixturePub(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, "TEST-ONLY-"+name+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}

// harness is one temp directory with a config, an admin token file and a
// data dir.
type harness struct {
	t     *testing.T
	dir   string
	cfg   map[string]any
	token string // admin token file
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	h := &harness{t: t, dir: dir, token: filepath.Join(dir, "admin.token")}
	if err := os.WriteFile(h.token, []byte(testAdmin+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.cfg = map[string]any{
		"listen":          "127.0.0.1:0",
		"metrics_listen":  "127.0.0.1:0",
		"data_dir":        filepath.Join(dir, "data"),
		"log_level":       "debug",
		"allow_plaintext": true,
		"tenants": map[string]any{
			"bank-a": map[string]any{"threshold": 2, "admin_keys": []any{fixturePub(t, "admin-a"), fixturePub(t, "admin-b"), fixturePub(t, "admin-c")}},
		},
		"enrollments": []any{
			map[string]any{"proxy_id": "px-canary", "tenant": "bank-a", "group": "canary", "token_sha256": digestOf("proxy-token-canary-000001")},
			map[string]any{"proxy_id": "px-main", "tenant": "bank-a", "group": "main", "token_sha256": digestOf("proxy-token-main-0000001")},
		},
	}
	return h
}

func (h *harness) write() string {
	h.t.Helper()
	p := filepath.Join(h.dir, "cp.json")
	if err := os.WriteFile(p, marshal(h.t, h.cfg), 0o644); err != nil {
		h.t.Fatal(err)
	}
	return p
}

// lockedBuf collects a process's stderr and hands out complete lines.
type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type proc struct {
	t       *testing.T
	cmd     *exec.Cmd
	stderr  *lockedBuf
	done    chan error
	addr    string
	metrics string
}

// start runs the binary and waits for its "listening" log line.
func (h *harness) start(args ...string) *proc {
	h.t.Helper()
	p := h.launch(args...)
	deadline := time.After(15 * time.Second)
	for {
		select {
		case err := <-p.done:
			h.t.Fatalf("kairan-cp exited early: %v\n%s", err, p.stderr.String())
		case <-deadline:
			p.cmd.Process.Kill()
			h.t.Fatalf("no listening line:\n%s", p.stderr.String())
		case <-time.After(20 * time.Millisecond):
		}
		sc := bufio.NewScanner(strings.NewReader(p.stderr.String()))
		for sc.Scan() {
			var rec map[string]any
			if json.Unmarshal(sc.Bytes(), &rec) != nil || rec["msg"] != "listening" {
				continue
			}
			p.addr, _ = rec["addr"].(string)
			p.metrics, _ = rec["metrics_addr"].(string)
			return p
		}
	}
}

func (h *harness) launch(args ...string) *proc {
	h.t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), envTokenFile + "=" + h.token}
	p := &proc{t: h.t, cmd: cmd, stderr: &lockedBuf{}, done: make(chan error, 1)}
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	go func() { p.done <- cmd.Wait() }()
	h.t.Cleanup(func() {
		select {
		case <-p.done:
		default:
			cmd.Process.Kill()
			<-p.done
		}
	})
	return p
}

// stop sends SIGTERM and returns the exit error (nil = exit code 0).
func (p *proc) stop() error {
	p.t.Helper()
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		p.t.Fatal(err)
	}
	select {
	case err := <-p.done:
		p.done <- err // keep Cleanup happy
		return err
	case <-time.After(10 * time.Second):
		p.cmd.Process.Kill()
		p.t.Fatalf("no exit within 10s of SIGTERM:\n%s", p.stderr.String())
	}
	return nil
}

var client = &http.Client{Timeout: 10 * time.Second}

func call(t *testing.T, c *http.Client, method, url, bearer string, body []byte) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestRunsForReal(t *testing.T) {
	h := newHarness(t)
	p := h.start("-config", h.write())
	base := "http://" + p.addr
	canary, mainTok := "proxy-token-canary-000001", "proxy-token-main-0000001"

	// publish the golden fixture envelope with plain HTTP calls
	env, err := os.ReadFile(filepath.Join(fixtures, "envelopes", "valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code, _ := call(t, client, "POST", base+wire.PathPolicies, "wrong-admin-token-0000000", env); code != 401 {
		t.Fatalf("wrong admin token: %d", code)
	}
	if code, _ := call(t, client, "POST", base+wire.PathPolicies, canary, env); code != 403 {
		t.Fatalf("proxy token on an admin path: %d", code)
	}
	code, body := call(t, client, "POST", base+wire.PathPolicies, testAdmin, env)
	var pub wire.PublishResponse
	if code != 200 || json.Unmarshal(body, &pub) != nil || pub.Tenant != "bank-a" || pub.Version != 2 || !pub.PolicyHash.Valid() {
		t.Fatalf("publish: %d %s", code, body)
	}
	if code, _ := call(t, client, "POST", base+wire.PathPolicies, testAdmin, env); code != 409 {
		t.Fatalf("second publish of the same version: %d", code)
	}

	// before a rollout nothing is offered: a poll with have=2 is held then 304,
	// so use the rollout to make it immediate
	rb, _ := json.Marshal(wire.RolloutRequest{Tenant: "bank-a", Version: 2, CanaryDwellSeconds: 3600})
	if code, body := call(t, client, "POST", base+wire.PathRollouts, testAdmin, rb); code != 200 {
		t.Fatalf("rollout: %d %s", code, body)
	}
	pollURL := func(id wire.ID, have uint64) string {
		return base + wire.PathPoll + "?" + wire.PollRequest{Tenant: "bank-a", ProxyID: id, Have: have}.Query().Encode()
	}
	code, body = call(t, client, "GET", pollURL("px-canary", 0), canary, nil)
	var pr wire.PollResponse
	if code != 200 || json.Unmarshal(body, &pr) != nil || pr.Version != 2 || !bytes.Contains(body, []byte(`"payloadType"`)) {
		t.Fatalf("canary poll: %d %s", code, body)
	}
	if code, _ := call(t, client, "GET", pollURL("px-canary", 0), mainTok, nil); code != 403 {
		t.Fatalf("another proxy's token: %d", code)
	}

	// status round trip
	rep := wire.StatusReport{Tenant: "bank-a", ProxyID: "px-canary", Seq: 1, State: wire.StateEnforcing, AppliedVersion: 2,
		PolicyHash: pub.PolicyHash, LogSeq: 1, LogHead: pub.PolicyHash}
	rj, _ := json.Marshal(rep)
	if code, body := call(t, client, "POST", base+wire.PathStatus, canary, rj); code != 204 {
		t.Fatalf("status: %d %s", code, body)
	}
	code, body = call(t, client, "GET", base+wire.PathFleet+"?tenant=bank-a", testAdmin, nil)
	var fv wire.FleetView
	if code != 200 || json.Unmarshal(body, &fv) != nil || len(fv.Proxies) != 2 {
		t.Fatalf("fleet: %d %s", code, body)
	}
	got := map[wire.ID]wire.ProxyView{}
	for _, pv := range fv.Proxies {
		got[pv.ProxyID] = pv
	}
	if got["px-canary"].AppliedVersion != 2 || got["px-canary"].Health != wire.HealthHealthy {
		t.Errorf("canary row: %+v", got["px-canary"])
	}
	if got["px-main"].Health != wire.HealthLost { // enrolled, never reported
		t.Errorf("never-seen proxy must be lost: %+v", got["px-main"])
	}

	// the fleet page is at the root of the admin listener, behind the admin token (M-D43)
	req, _ := http.NewRequest("GET", base+"/?tenant=bank-a&lang=en", nil)
	if resp, err := client.Do(req); err != nil || resp.StatusCode != 401 {
		t.Fatalf("page without credentials: %v %v", resp, err)
	}
	req.SetBasicAuth("anyone", testAdmin)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(page, []byte("px-canary")) {
		t.Fatalf("page: %d %.200s", resp.StatusCode, page)
	}

	// /metrics is on its own listener and not on the admin one
	code, body = call(t, client, "GET", "http://"+p.metrics+"/metrics", "", nil)
	if code != 200 {
		t.Fatalf("metrics: %d", code)
	}
	for _, want := range []string{
		`kairan_cp_status_total{result="ok"} 1`,
		`kairan_cp_polls_total{result="update"} 1`,
		`kairan_cp_auth_failures_total{code="unauthorized"} 2`, // wrong admin token, page without credentials
		`kairan_cp_auth_failures_total{code="forbidden"} 2`,    // proxy token on an admin path, another proxy's token
		`kairan_cp_enrolled_proxies{tenant="bank-a"} 2`,
		`kairan_cp_active_polls 0`,
	} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if code, body := call(t, client, "GET", base+"/metrics", testAdmin, nil); bytes.Contains(body, []byte("kairan_cp_")) {
		t.Errorf("admin listener serves metrics: %d", code)
	}
	if code, _ := call(t, client, "GET", "http://"+p.metrics+"/", "", nil); code != 404 {
		t.Errorf("metrics listener serves something besides /metrics: %d", code)
	}
	if code, _ := call(t, client, "GET", "http://"+p.metrics+wire.PathFleet+"?tenant=bank-a", testAdmin, nil); code != 404 {
		t.Errorf("metrics listener serves the API: %d", code)
	}

	// no secret reaches the logs (I4 and key hygiene)
	logs := p.stderr.String()
	for _, secret := range []string{testAdmin, canary, mainTok, string(env[:60])} {
		if strings.Contains(logs, secret) {
			t.Errorf("log holds a secret or payload: %q", secret)
		}
	}
	if !strings.Contains(logs, "plaintext HTTP") {
		t.Error("no loud plaintext warning in the log")
	}

	// SIGTERM: clean exit 0
	if err := p.stop(); err != nil {
		t.Fatalf("exit after SIGTERM: %v\n%s", err, p.stderr.String())
	}
	if l := p.stderr.String(); !strings.Contains(l, `"msg":"shutting down"`) || !strings.Contains(l, `"msg":"stopped"`) {
		t.Errorf("shutdown not logged:\n%s", l)
	}

	// state survives a restart
	p2 := h.start("-config", h.write())
	code, body = call(t, client, "GET", "http://"+p2.addr+wire.PathRollouts+"?tenant=bank-a", testAdmin, nil)
	var rv wire.RolloutView
	if code != 200 || json.Unmarshal(body, &rv) != nil || rv.Version != 2 || rv.Phase != wire.PhaseCanary {
		t.Fatalf("rollout after restart: %d %s", code, body)
	}
	if err := p2.stop(); err != nil {
		t.Fatal(err)
	}
}

// SIGTERM must not wait for a held long-poll (poll hold is 30s).
func TestShutdownReleasesHeldPoll(t *testing.T) {
	h := newHarness(t)
	p := h.start("-config", h.write())
	url := "http://" + p.addr + wire.PathPoll + "?" + wire.PollRequest{Tenant: "bank-a", ProxyID: "px-canary", Have: 0}.Query().Encode()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+"proxy-token-canary-000001")
	answered := make(chan struct{})
	go func() {
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
		close(answered)
	}()
	// wait until the poll is held
	for i := 0; ; i++ {
		_, body := call(t, client, "GET", "http://"+p.metrics+"/metrics", "", nil)
		if bytes.Contains(body, []byte("kairan_cp_active_polls 1")) {
			break
		}
		if i > 200 {
			t.Fatal("poll never became active")
		}
		time.Sleep(25 * time.Millisecond)
	}
	start := time.Now()
	if err := p.stop(); err != nil {
		t.Fatalf("exit: %v\n%s", err, p.stderr.String())
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("shutdown took %v with a held poll", d)
	}
	<-answered
}

func TestSIGINTAlsoStops(t *testing.T) {
	h := newHarness(t)
	delete(h.cfg, "metrics_listen")
	p := h.start("-config", h.write())
	if p.metrics != "" {
		t.Errorf("metrics listener without metrics_listen: %s", p.metrics)
	}
	p.cmd.Process.Signal(syscall.SIGINT)
	select {
	case err := <-p.done:
		p.done <- err // keep Cleanup happy
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no exit")
	}
}

func TestTLSMinimumVersion(t *testing.T) {
	h := newHarness(t)
	certPEM, keyPEM := selfSigned(t)
	cp, kp := filepath.Join(h.dir, "c.pem"), filepath.Join(h.dir, "k.pem")
	os.WriteFile(cp, certPEM, 0o644)
	os.WriteFile(kp, keyPEM, 0o600)
	h.cfg["allow_plaintext"] = false
	h.cfg["tls_cert_file"], h.cfg["tls_key_file"] = cp, kp
	p := h.start("-config", h.write())
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)
	good := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	if code, _ := call(t, good, "GET", "https://"+p.addr+wire.PathFleet+"?tenant=bank-a", testAdmin, nil); code != 200 {
		t.Fatalf("https fleet: %d", code)
	}
	// TLS 1.2 works, 1.1 does not
	conn, err := tls.Dial("tcp", p.addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("TLS 1.2: %v", err)
	}
	conn.Close()
	if conn, err := tls.Dial("tcp", p.addr, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}); err == nil {
		conn.Close()
		t.Fatal("server accepted TLS 1.1")
	}
	// plain HTTP to the TLS port gets no API answer
	if resp, err := client.Get("http://" + p.addr + wire.PathFleet + "?tenant=bank-a"); err == nil {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == 200 || bytes.Contains(b, []byte("proxies")) {
			t.Fatalf("plaintext answered on the TLS port: %d", resp.StatusCode)
		}
	}
	if strings.Contains(p.stderr.String(), "plaintext HTTP") {
		t.Error("plaintext warning with TLS on")
	}
	if err := p.stop(); err != nil {
		t.Fatal(err)
	}
}

func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kairan-cp test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd})
}

// ---- command line behaviour ----

func runBin(t *testing.T, h *harness, env []string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(binPath, args...)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH")}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
	case <-ctx.Done():
		cmd.Process.Kill()
		t.Fatalf("did not exit: %v", args)
	}
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return code, so.String(), se.String()
}

func TestCheckFlag(t *testing.T) {
	h := newHarness(t)
	cfg := h.write()
	tokenEnv := []string{envTokenFile + "=" + h.token}
	code, out, errOut := runBin(t, h, tokenEnv, "-config", cfg, "-check")
	if code != 0 || !strings.Contains(out, "config ok: 1 tenant(s), 2 proxy enrollment(s)") || !strings.Contains(out, "設定は正常です") || errOut != "" {
		t.Fatalf("check: %d %q %q", code, out, errOut)
	}
	if _, err := os.Stat(filepath.Join(h.dir, "data")); err == nil {
		t.Error("-check created the data directory")
	}
	// -check validates the token too
	code, _, errOut = runBin(t, h, nil, "-config", cfg, "-check")
	if code != 2 || !strings.Contains(errOut, "no admin token") || !strings.Contains(errOut, "管理トークンがありません") {
		t.Fatalf("no token: %d %q", code, errOut)
	}
	// the token flag works as well
	if code, _, errOut := runBin(t, h, nil, "-config", cfg, "-admin-token-file", h.token, "-check"); code != 0 {
		t.Fatalf("flag token: %d %q", code, errOut)
	}
}

func TestBadConfigExitsNonZeroInBothLanguages(t *testing.T) {
	h := newHarness(t)
	tokenEnv := []string{envTokenFile + "=" + h.token}
	h.cfg["tenants"].(map[string]any)["bank-a"].(map[string]any)["threshold"] = 1
	for _, args := range [][]string{{"-config", h.write()}, {"-config", h.write(), "-check"}} {
		code, out, errOut := runBin(t, h, tokenEnv, args...)
		if code != 2 || out != "" {
			t.Fatalf("%v: code %d stdout %q", args, code, out)
		}
		if !strings.Contains(errOut, "kairan-cp: error: ") || !strings.Contains(errOut, "threshold must be at least 2") ||
			!strings.Contains(errOut, "kairan-cp: エラー: ") || !strings.Contains(errOut, "threshold は 2 以上") {
			t.Fatalf("message: %q", errOut)
		}
	}
	for name, args := range map[string][]string{
		"no -config":        {},
		"missing file":      {"-config", filepath.Join(h.dir, "none.json")},
		"extra argument":    {"-config", h.write(), "extra"},
		"unknown flag":      {"-config", h.write(), "-bogus"},
		"bad -check usage":  {"-config"},
		"token as a flag":   {"-config", h.write(), "-admin-token", testAdmin},
		"directory config":  {"-config", h.dir},
		"empty config path": {"-config", ""},
	} {
		code, out, errOut := runBin(t, h, tokenEnv, args...)
		if code != 2 || out != "" || errOut == "" {
			t.Errorf("%s: code %d stdout %q stderr %q", name, code, out, errOut)
		}
		if strings.Contains(errOut, testAdmin) {
			t.Errorf("%s: stderr echoes the token", name)
		}
	}
}

func TestAdminTokenMustDifferFromProxyTokens(t *testing.T) {
	h := newHarness(t)
	h.cfg["enrollments"].([]any)[0].(map[string]any)["token_sha256"] = digestOf(testAdmin)
	code, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write(), "-check")
	if code != 2 || !strings.Contains(errOut, "also a proxy token") || !strings.Contains(errOut, "プロキシのトークンと同じ") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestLoosePermissionsOnTokenFileRefused(t *testing.T) {
	h := newHarness(t)
	if err := os.Chmod(h.token, 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write())
	if code != 2 || !strings.Contains(errOut, "chmod 600") || !strings.Contains(errOut, "権限が緩すぎます") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestCorruptStateDirRefusesToStart(t *testing.T) {
	h := newHarness(t)
	d := filepath.Join(h.dir, "data", "envelopes", "bank-a")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "00000000000000000001.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write())
	if code != 1 || !strings.Contains(errOut, "damaged state file") || !strings.Contains(errOut, "壊れています") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestAddressInUseExitsNonZero(t *testing.T) {
	h := newHarness(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	h.cfg["listen"] = ln.Addr().String()
	code, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write())
	if code != 1 || !strings.Contains(errOut, "cannot listen for listen") || !strings.Contains(errOut, "待ち受けを開始できません") {
		t.Fatalf("%d %q", code, errOut)
	}
	// and the metrics address
	h.cfg["listen"] = "127.0.0.1:0"
	h.cfg["metrics_listen"] = ln.Addr().String()
	code, _, errOut = runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write())
	if code != 1 || !strings.Contains(errOut, "cannot listen for metrics_listen") {
		t.Fatalf("%d %q", code, errOut)
	}
}

func TestMetricsOnPublicInterfaceWarns(t *testing.T) {
	h := newHarness(t)
	h.cfg["metrics_listen"] = "0.0.0.0:0"
	p := h.start("-config", h.write())
	if !strings.Contains(p.stderr.String(), "metrics listener is not on loopback") {
		t.Errorf("no warning:\n%s", p.stderr.String())
	}
	p.stop()
}
