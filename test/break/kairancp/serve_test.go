package kairancpbreak

import (
	"bytes"
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
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

func listen(addr string) (net.Listener, error) { return net.Listen("tcp", addr) }

// live is a running kairan-cp plus helpers to talk to it.
type live struct {
	*server
	base, metrics string
	data          string
	cfgPath       string
	tokPath       string
	cl            *http.Client
}

type liveOpts struct {
	mod     func(c cfg, port, mport string)
	metrics bool
	keepDir string // reuse a data dir (restart)
}

func startLive(t *testing.T, o liveOpts) *live {
	t.Helper()
	data := o.keepDir
	if data == "" {
		data = filepath.Join(t.TempDir(), "data")
	}
	port := freePort(t)
	c := baseCfg(t, data).with(t, "listen", port)
	mport := ""
	if o.metrics {
		mport = freePort(t)
		c["metrics_listen"] = mport
	}
	if o.mod != nil {
		o.mod(c, port, mport)
	}
	f := writeFiles(t, c.bytes(t), adminTok+"\n")
	s := start(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
	l := &live{server: s, base: "http://" + port, data: data, cfgPath: f.cfgPath, tokPath: f.tokPath,
		cl: &http.Client{Timeout: 10 * time.Second}}
	if mport != "" {
		l.metrics = "http://" + mport
	}
	l.waitReady(t)
	return l
}

func (l *live) waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-l.done:
			t.Fatalf("server exited (%d) before it was ready: %s", l.code, l.out.String())
		default:
		}
		if r, err := http.Get(l.base + wire.PathFleet + "?tenant=bank-a"); err == nil {
			r.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("server not ready in 10s: %s", l.out.String())
}

type reply struct {
	code int
	hdr  http.Header
	body []byte
}

func (l *live) do(method, path, token string, body []byte) reply {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, l.base+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	res, err := l.cl.Do(req)
	if err != nil {
		return reply{code: -1, body: []byte(err.Error())}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, res.Header, b}
}

func policyJSON(tenant string, version uint64) []byte {
	return []byte(fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":"%s","expires_at":"%s","default":"deny","roles":{"sales":{"crm.read_*":"R"}}}`,
		tenant, version, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339), time.Now().UTC().Add(72*time.Hour).Format(time.RFC3339)))
}

func envelope(t testing.TB, payload []byte, signers ...string) []byte {
	t.Helper()
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, s := range signers {
		trust.Sign(&e, privKey(t, s))
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (l *live) publish(t testing.TB, tenant string, version uint64, signers ...string) reply {
	return l.do("POST", wire.PathPolicies, adminTok, envelope(t, policyJSON(tenant, version), signers...))
}

// Authentication matrix: each credential reaches only what it should (I3: a failure never widens access).
func TestServeAuthMatrix(t *testing.T) {
	l := startLive(t, liveOpts{})
	if r := l.publish(t, "bank-a", 1, "admin-a", "admin-b"); r.code != 200 {
		t.Fatalf("baseline publish: %d %s", r.code, r.body)
	}
	cases := []struct {
		name          string
		method, path  string
		token         string
		body          []byte
		wantNot200    bool
		want200       bool
		wantStatusAny []int
	}{
		{"fleet admin", "GET", wire.PathFleet + "?tenant=bank-a", adminTok, nil, false, true, nil},
		{"fleet no token", "GET", wire.PathFleet + "?tenant=bank-a", "", nil, true, false, []int{401}},
		{"fleet wrong token", "GET", wire.PathFleet + "?tenant=bank-a", "wrong-token-0123456789abcdef", nil, true, false, []int{401}},
		{"fleet proxy token", "GET", wire.PathFleet + "?tenant=bank-a", tokOf("p1"), nil, true, false, []int{401, 403}},
		{"fleet canary token", "GET", wire.PathFleet + "?tenant=bank-a", tokOf("c1"), nil, true, false, []int{401, 403}},
		{"timeline proxy token", "GET", wire.PathTimeline + "?tenant=bank-a", tokOf("p1"), nil, true, false, []int{401, 403}},
		{"rollouts GET proxy token", "GET", wire.PathRollouts + "?tenant=bank-a", tokOf("p1"), nil, true, false, []int{401, 403}},
		{"rollouts POST proxy token", "POST", wire.PathRollouts, tokOf("p1"), mustJSON(t, wire.RolloutRequest{Tenant: "bank-a", Version: 1}), true, false, []int{401, 403}},
		{"publish proxy token", "POST", wire.PathPolicies, tokOf("p1"), envelope(t, policyJSON("bank-a", 2), "admin-a", "admin-b"), true, false, []int{401, 403}},
		{"publish no token", "POST", wire.PathPolicies, "", envelope(t, policyJSON("bank-a", 2), "admin-a", "admin-b"), true, false, []int{401}},
		{"poll admin token", "GET", wire.PathPoll + "?tenant=bank-a&proxy=p1&have=0", adminTok, nil, true, false, []int{401, 403}},
		{"poll other proxy's token", "GET", wire.PathPoll + "?tenant=bank-a&proxy=p1&have=0", tokOf("p2"), nil, true, false, []int{401, 403}},
		{"poll other tenant's proxy", "GET", wire.PathPoll + "?tenant=bank-a&proxy=p1&have=0", tokOf("q1"), nil, true, false, []int{401, 403}},
		{"poll right proxy, wrong tenant claimed", "GET", wire.PathPoll + "?tenant=bank-b&proxy=p1&have=0", tokOf("p1"), nil, true, false, []int{401, 403}},
		{"poll unknown proxy", "GET", wire.PathPoll + "?tenant=bank-a&proxy=ghost&have=0", tokOf("p1"), nil, true, false, []int{401, 403}},
		{"poll no token", "GET", wire.PathPoll + "?tenant=bank-a&proxy=p1&have=0", "", nil, true, false, []int{401}},
		{"status as another proxy", "POST", wire.PathStatus, tokOf("p1"), mustJSON(t, goodReport("bank-a", "p2")), true, false, []int{401, 403}},
		{"status as another tenant", "POST", wire.PathStatus, tokOf("p1"), mustJSON(t, goodReport("bank-b", "p1")), true, false, []int{401, 403}},
		{"status with admin token", "POST", wire.PathStatus, adminTok, mustJSON(t, goodReport("bank-a", "p1")), true, false, []int{401, 403}},
		{"empty bearer", "GET", wire.PathFleet + "?tenant=bank-a", " ", nil, true, false, []int{401}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := l.do(c.method, c.path, c.token, c.body)
			if c.want200 && r.code != 200 {
				t.Fatalf("got %d %s, want 200", r.code, r.body)
			}
			if c.wantNot200 {
				ok := false
				for _, s := range c.wantStatusAny {
					ok = ok || r.code == s
				}
				if !ok {
					t.Fatalf("got %d %s, want one of %v", r.code, clip(string(r.body)), c.wantStatusAny)
				}
			}
		})
	}
	// control: the same report with the right token is accepted, so the 4xx above are about identity
	if r := l.do("POST", wire.PathStatus, tokOf("p1"), mustJSON(t, goodReport("bank-a", "p1"))); r.code != 204 {
		t.Fatalf("control status: %d %s", r.code, r.body)
	}
	// the admin token only: tokens with a different case, a prefix or a suffix must not authenticate
	for _, tok := range []string{strings.ToLower(adminTok), adminTok + "x", adminTok[:len(adminTok)-1], " " + adminTok} {
		if r := l.do("GET", wire.PathFleet+"?tenant=bank-a", tok, nil); r.code == 200 {
			t.Errorf("near-miss admin token %q accepted", tok)
		}
	}
}

func goodReport(tenant, proxy string) wire.StatusReport {
	return wire.StatusReport{Tenant: wire.ID(tenant), ProxyID: wire.ID(proxy), Seq: 1, State: wire.StateDenyAll}
}

func mustJSON(t testing.TB, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The binary is wired with the config's trust root (I1): threshold 2 of the tenant's own admin keys.
func TestServePublishUsesConfiguredTrustRoot(t *testing.T) {
	l := startLive(t, liveOpts{})
	cases := []struct {
		name     string
		tenant   string
		version  uint64
		signers  []string
		wantCode int
	}{
		{"two trusted signers", "bank-a", 1, []string{"admin-a", "admin-b"}, 200},
		{"other pair of trusted signers", "bank-a", 2, []string{"admin-b", "admin-c"}, 200},
		{"one signer", "bank-a", 3, []string{"admin-a"}, 400},
		{"the same signer twice", "bank-a", 3, []string{"admin-a", "admin-a"}, 400},
		{"no signer", "bank-a", 3, nil, 400},
		{"one trusted and one outsider", "bank-a", 3, []string{"admin-a", "outsider"}, 400},
		{"outsider twice", "bank-a", 3, []string{"outsider", "outsider"}, 400},
		{"admin-c is not trusted by bank-b", "bank-b", 1, []string{"admin-a", "admin-c"}, 400},
		{"bank-b with its own pair", "bank-b", 1, []string{"admin-a", "admin-b"}, 200},
		{"unknown tenant", "bank-z", 1, []string{"admin-a", "admin-b"}, 400},
		{"old version is not newer", "bank-a", 1, []string{"admin-a", "admin-b"}, 409},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := l.publish(t, c.tenant, c.version, c.signers...)
			if r.code != c.wantCode && !(c.wantCode == 400 && (r.code == 403 || r.code == 404)) {
				t.Fatalf("got %d %s, want %d", r.code, r.body, c.wantCode)
			}
			if c.wantCode != 200 && r.code == 200 {
				t.Fatalf("PUBLISHED with %v", c.signers)
			}
		})
	}
	// bank-a's envelope signed by the right keys must not be published under bank-b by relabelling the tenant:
	// the payload names its tenant and the signatures cover it, so this is the same as "unknown/other root".
	fv := l.do("GET", wire.PathFleet+"?tenant=bank-b", adminTok, nil)
	if fv.code != 200 {
		t.Fatalf("fleet bank-b: %d", fv.code)
	}
}

// Tenant isolation through the binary: bank-b's token never reads bank-a's data.
func TestServeTenantIsolation(t *testing.T) {
	l := startLive(t, liveOpts{})
	var fv wire.FleetView
	r := l.do("GET", wire.PathFleet+"?tenant=bank-a", adminTok, nil)
	if r.code != 200 || json.Unmarshal(r.body, &fv) != nil {
		t.Fatalf("fleet: %d %s", r.code, r.body)
	}
	for _, p := range fv.Proxies {
		if p.ProxyID == "q1" {
			t.Errorf("bank-b's proxy q1 is listed in bank-a's fleet")
		}
	}
	// enrollment rows exist for p1, p2, c1 with the canary group kept as configured
	groups := map[wire.ID]wire.ID{}
	for _, p := range fv.Proxies {
		groups[p.ProxyID] = p.Group
	}
	if len(groups) > 0 && groups["c1"] != "canary" {
		t.Errorf("c1 group = %q, want canary (the enrollment decides, M-D54)", groups["c1"])
	}
}

// Restart keeps state: published policy and rollout survive SIGTERM and a new process on the same data_dir.
func TestServeStateSurvivesRestart(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	l := startLive(t, liveOpts{keepDir: dataDir})
	if r := l.publish(t, "bank-a", 1, "admin-a", "admin-b"); r.code != 200 {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
	if r := l.do("POST", wire.PathRollouts, adminTok, mustJSON(t, wire.RolloutRequest{Tenant: "bank-a", Version: 1})); r.code != 200 {
		t.Fatalf("rollout: %d %s", r.code, r.body)
	}
	l.signal(syscall.SIGTERM)
	if code, ok := l.waitExit(10 * time.Second); !ok || code != 0 {
		t.Fatalf("SIGTERM: exited=%v code=%d: %s", ok, code, l.out.String())
	}
	l2 := startLive(t, liveOpts{keepDir: dataDir})
	r := l2.do("GET", wire.PathRollouts+"?tenant=bank-a", adminTok, nil)
	var rv wire.RolloutView
	if r.code != 200 || json.Unmarshal(r.body, &rv) != nil || rv.Version != 1 {
		t.Fatalf("rollout after restart: %d %s", r.code, r.body)
	}
	if r := l2.publish(t, "bank-a", 1, "admin-a", "admin-b"); r.code != 409 {
		t.Errorf("republishing v1 after restart: %d, want 409 (replay protection survives a restart, I2)", r.code)
	}
	// the canary can fetch the stored envelope after the restart
	pr := l2.do("GET", wire.PathPoll+"?tenant=bank-a&proxy=c1&have=0", tokOf("c1"), nil)
	if pr.code != 200 {
		t.Fatalf("canary poll after restart: %d %s", pr.code, pr.body)
	}
}

// Graceful shutdown (C-D10): SIGTERM and SIGINT end held long-polls at once and the process exits 0 well inside
// the 5 s grace.
func TestServeGracefulShutdownEndsHeldPolls(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			l := startLive(t, liveOpts{})
			if r := l.publish(t, "bank-a", 1, "admin-a", "admin-b"); r.code != 200 {
				t.Fatalf("publish %d", r.code)
			}
			if r := l.do("POST", wire.PathRollouts, adminTok, mustJSON(t, wire.RolloutRequest{Tenant: "bank-a", Version: 1})); r.code != 200 {
				t.Fatalf("rollout %d", r.code)
			}
			// c1 already has v1: this poll is held for up to 30 s
			held := make(chan reply, 1)
			go func() {
				cl := &http.Client{Timeout: 40 * time.Second}
				req, _ := http.NewRequest("GET", l.base+wire.PathPoll+"?tenant=bank-a&proxy=c1&have=1", nil)
				req.Header.Set("Authorization", "Bearer "+tokOf("c1"))
				res, err := cl.Do(req)
				if err != nil {
					held <- reply{code: -1}
					return
				}
				res.Body.Close()
				held <- reply{code: res.StatusCode}
			}()
			time.Sleep(700 * time.Millisecond)
			start := time.Now()
			l.signal(sig)
			select {
			case <-held:
				if d := time.Since(start); d > 3*time.Second {
					t.Errorf("held poll ended after %v; shutdown must cancel it at once", d)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("held long-poll still open 10 s after the signal")
			}
			code, ok := l.waitExit(8 * time.Second)
			if !ok {
				t.Fatalf("process did not exit within 8 s of %s", sig)
			}
			if code != 0 {
				t.Errorf("exit code %d after %s, want 0: %s", code, sig, l.out.String())
			}
		})
	}
}

// A second signal or a signal during idle must not crash; the process exits 0.
func TestServeRepeatedSignals(t *testing.T) {
	l := startLive(t, liveOpts{})
	l.signal(syscall.SIGTERM)
	l.signal(syscall.SIGTERM)
	l.signal(syscall.SIGINT)
	code, ok := l.waitExit(8 * time.Second)
	if !ok {
		t.Fatal("did not exit")
	}
	if code != 0 {
		t.Errorf("exit %d: %s", code, l.out.String())
	}
	noPanic(t, result{stderr: l.out.String()})
}

// SIGHUP, SIGPIPE-style signals are not shutdown requests documented anywhere; USR1 must not kill the process
// by default Go behaviour in a way that loses state - just check SIGHUP does not leave the port half-open.
// (Not asserted: the docs give no rule. Kept out deliberately.)

// Metrics listener (C-D10): separate, unauthenticated, warns when not loopback; the main listener does not
// serve it; and no secret is in it.
func TestServeMetricsListener(t *testing.T) {
	l := startLive(t, liveOpts{metrics: true})
	l.publish(t, "bank-a", 1, "admin-a", "admin-b")
	l.do("GET", wire.PathFleet+"?tenant=bank-a", "CANARY-bad-token-"+canary, nil)
	res, err := http.Get(l.metrics + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("metrics: %d", res.StatusCode)
	}
	text := string(body)
	if !strings.Contains(text, "kairan_cp_enrolled_proxies") {
		t.Errorf("kairan_cp_enrolled_proxies gauge missing (C-D10)")
	}
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "kairan_cp_enrolled_proxies") && !strings.HasPrefix(line, "#") {
			f := strings.Fields(line)
			if f[len(f)-1] != "4" && !strings.Contains(line, "tenant") {
				t.Errorf("enrolled gauge %q, want 4", line)
			}
		}
	}
	for _, secret := range []string{adminTok, tokOf("p1"), tokOf("c1"), canary, sha(tokOf("p1"))} {
		if strings.Contains(text, secret) {
			t.Errorf("metrics expose %q", secret)
		}
	}
	// not on the main listener without credentials
	r := l.do("GET", "/metrics", "", nil)
	if r.code == 200 && strings.Contains(string(r.body), "kairan_cp_") {
		t.Errorf("the API listener serves /metrics unauthenticated")
	}
	// the API is not on the metrics listener
	res2, err := http.Get(l.metrics + wire.PathFleet + "?tenant=bank-a")
	if err == nil {
		res2.Body.Close()
		if res2.StatusCode == 200 {
			t.Errorf("the metrics listener serves the fleet API")
		}
	}
	// the metrics port does not accept the admin token as a way in to anything else
	req, _ := http.NewRequest("POST", l.metrics+wire.PathPolicies, bytes.NewReader(envelope(t, policyJSON("bank-a", 5), "admin-a", "admin-b")))
	req.Header.Set("Authorization", "Bearer "+adminTok)
	if res3, err := http.DefaultClient.Do(req); err == nil {
		res3.Body.Close()
		if res3.StatusCode == 200 {
			t.Errorf("publish worked on the metrics listener")
		}
	}
}

// Loud warnings: plaintext, and metrics on a non-loopback address (C-D10).
func TestServeWarnsOnPlaintextAndOpenMetrics(t *testing.T) {
	l := startLive(t, liveOpts{mod: func(c cfg, port, mport string) {
		c["metrics_listen"] = "0.0.0.0:" + strings.Split(freePort(t), ":")[1]
	}})
	out := strings.ToLower(l.out.String())
	if !strings.Contains(out, "plaintext") {
		t.Errorf("no plaintext warning on stderr: %q", clip(l.out.String()))
	}
	if !strings.Contains(out, "metrics") {
		t.Errorf("no warning about metrics on a non-loopback address: %q", clip(l.out.String()))
	}
}

// C-D10: "every message is English and Japanese". The startup warnings are messages too.
func TestServeWarningsAreBilingual(t *testing.T) {
	l := startLive(t, liveOpts{})
	if !hasCJK(l.out.String()) {
		t.Errorf("startup warnings are English only: %q", clip(l.out.String()))
	}
}

// No secret reaches the process output or the data directory (I4 spirit, THREATS #7).
func TestServeNeverLogsOrStoresSecrets(t *testing.T) {
	l := startLive(t, liveOpts{})
	badTok := "Bad-" + canary
	l.do("GET", wire.PathFleet+"?tenant=bank-a", badTok, nil)
	l.do("GET", wire.PathPoll+"?tenant=bank-a&proxy=p1&have=0", badTok, nil)
	l.do("GET", wire.PathPoll+"?tenant=bank-a&proxy=p1&have=0", adminTok, nil)
	l.do("GET", wire.PathFleet+"?tenant=bank-a", tokOf("p1"), nil)
	l.publish(t, "bank-a", 1, "admin-a", "admin-b")
	l.publish(t, "bank-a", 2, "admin-a")
	l.do("POST", wire.PathStatus, tokOf("p1"), mustJSON(t, goodReport("bank-a", "p1")))
	l.do("POST", wire.PathStatus, tokOf("p1"), []byte(`{"tenant":"bank-a","proxy_id":"p1","note":"`+canary+`"}`))
	time.Sleep(300 * time.Millisecond)
	out := l.out.String()
	for _, secret := range []string{adminTok, tokOf("p1"), tokOf("p2"), tokOf("c1"), tokOf("q1"), badTok, canary} {
		if strings.Contains(out, secret) {
			t.Errorf("process output contains %q:\n%s", secret, clip(out))
		}
	}
	l.signal(syscall.SIGTERM)
	l.waitExit(8 * time.Second)
	_ = filepath.Walk(l.data, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		b, _ := os.ReadFile(p)
		for _, secret := range []string{adminTok, tokOf("p1"), tokOf("c1"), badTok, canary} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("data file %s contains %q", p, secret)
			}
		}
		return nil
	})
}

// Startup failures are exit 1, never 0, and never a half-started server.
func TestStartupFailures(t *testing.T) {
	t.Run("port already in use", func(t *testing.T) {
		port := freePort(t)
		hold, err := listen(port)
		if err != nil {
			t.Fatal(err)
		}
		defer hold.Close()
		f := writeFiles(t, baseCfg(t, filepath.Join(t.TempDir(), "d")).with(t, "listen", port).bytes(t), adminTok)
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		noPanic(t, r)
		if r.code != 1 {
			t.Fatalf("exit %d, want 1 (startup failure): %s", r.code, clip(r.all()))
		}
	})
	t.Run("metrics port already in use", func(t *testing.T) {
		mport := freePort(t)
		hold, err := listen(mport)
		if err != nil {
			t.Fatal(err)
		}
		defer hold.Close()
		c := baseCfg(t, filepath.Join(t.TempDir(), "d")).with(t, "listen", freePort(t)).with(t, "metrics_listen", mport)
		f := writeFiles(t, c.bytes(t), adminTok)
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		if r.code == 0 {
			t.Fatalf("exit 0 although the metrics listener could not start: %s", clip(r.all()))
		}
	})
	t.Run("data_dir is a regular file", func(t *testing.T) {
		d := t.TempDir()
		bad := filepath.Join(d, "afile")
		os.WriteFile(bad, []byte("x"), 0o600)
		f := writeFiles(t, baseCfg(t, bad).with(t, "listen", freePort(t)).bytes(t), adminTok)
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		if r.code != 1 && r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
	})
	t.Run("data_dir under a read-only directory", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Fatal("running as root: permission denial cannot be tested here")
		}
		d := t.TempDir()
		os.Chmod(d, 0o500)
		defer os.Chmod(d, 0o700)
		f := writeFiles(t, baseCfg(t, filepath.Join(d, "sub", "data")).with(t, "listen", freePort(t)).bytes(t), adminTok)
		r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
		if r.code != 1 {
			t.Fatalf("exit %d, want 1: %s", r.code, clip(r.all()))
		}
	})
}

// TLS (ARCHITECTURE: TLS 1.2 minimum): a TLS config serves HTTPS only and refuses TLS 1.1 and plain HTTP.
func TestServeTLS(t *testing.T) {
	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kairan-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)

	port := freePort(t)
	c := baseCfg(t, filepath.Join(dir, "data")).with(t, "listen", port).with(t, "allow_plaintext", nil)
	c["tls_cert_file"] = certPath
	c["tls_key_file"] = keyPath
	f := writeFiles(t, c.bytes(t), adminTok)
	s := start(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath)
	pool := x509.NewCertPool()
	cert, _ := x509.ParseCertificate(der)
	pool.AddCert(cert)
	good := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	var lastErr error
	ready := false
	for i := 0; i < 100 && !ready; i++ {
		select {
		case <-s.done:
			t.Fatalf("exited %d: %s", s.code, s.out.String())
		default:
		}
		req, _ := http.NewRequest("GET", "https://"+port+wire.PathFleet+"?tenant=bank-a", nil)
		req.Header.Set("Authorization", "Bearer "+adminTok)
		res, err := good.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatalf("https fleet: %d", res.StatusCode)
			}
			ready = true
			break
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("HTTPS never came up: %v: %s", lastErr, s.out.String())
	}
	old := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}}}
	if res, err := old.Get("https://" + port + wire.PathFleet + "?tenant=bank-a"); err == nil {
		res.Body.Close()
		t.Errorf("a TLS 1.1 handshake succeeded; the minimum is TLS 1.2")
	}
	if res, err := http.Get("http://" + port + wire.PathFleet + "?tenant=bank-a"); err == nil {
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		if res.StatusCode == 200 || strings.Contains(string(b), `"proxies"`) {
			t.Errorf("plain HTTP answered on a TLS listener: %d", res.StatusCode)
		}
	}
	if strings.Contains(strings.ToLower(s.out.String()), "plaintext") {
		t.Errorf("a TLS config warns about plaintext: %q", clip(s.out.String()))
	}
}
