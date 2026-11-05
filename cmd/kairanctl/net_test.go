package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

const testToken = "s3cret-admin-token-xyz"

// recorded is one request the fake control plane saw.
type recorded struct {
	Method, Path, Query, Auth string
	Body                      []byte
}

// fakeCP speaks the admin API of wire with strict decoding. Each handler
// field can be replaced by a test; the defaults answer correctly.
type fakeCP struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex
	got []recorded

	publish  func(w http.ResponseWriter, env wire.Envelope, raw []byte)
	rollout  func(w http.ResponseWriter, req wire.RolloutRequest)
	status   func(w http.ResponseWriter, tenant string)
	fleet    func(w http.ResponseWriter, tenant string)
	timeline func(w http.ResponseWriter, tenant string)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", wire.ContentTypeJSON)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeCode(w http.ResponseWriter, status int, code wire.ErrorCode) {
	writeJSON(w, status, wire.ErrorResponse{Code: code})
}

func newFakeCP(t *testing.T, tls bool) *fakeCP {
	t.Helper()
	f := &fakeCP{t: t}
	f.publish = func(w http.ResponseWriter, env wire.Envelope, raw []byte) {
		p, err := policy.Parse(env.Payload)
		if err != nil {
			writeCode(w, 400, wire.ErrMalformed)
			return
		}
		sum := sha256.Sum256(env.Payload)
		writeJSON(w, 200, wire.PublishResponse{Tenant: p.Tenant, Version: p.Version, PolicyHash: wire.Hash(hex.EncodeToString(sum[:]))})
	}
	f.rollout = func(w http.ResponseWriter, req wire.RolloutRequest) {
		writeJSON(w, 200, wire.RolloutView{Tenant: req.Tenant, Version: req.Version, Phase: wire.PhaseCanary})
	}
	f.status = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, wire.RolloutView{Tenant: wire.ID(tenant), Version: 9, Phase: wire.PhaseHalted, Reason: wire.ErrCanaryLost})
	}
	f.fleet = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, wire.FleetView{Tenant: wire.ID(tenant), Proxies: fleetFixture()})
	}
	f.timeline = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, wire.TimelineView{Tenant: wire.ID(tenant), Entries: timelineFixture()})
	}
	h := http.HandlerFunc(f.serve)
	if tls {
		f.srv = httptest.NewTLSServer(h)
	} else {
		f.srv = httptest.NewServer(h)
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCP) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, wire.MaxEnvelopeBytes+1))
	f.mu.Lock()
	f.got = append(f.got, recorded{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get(wire.HeaderAuthorization), body})
	f.mu.Unlock()
	if r.Header.Get(wire.HeaderAuthorization) != wire.BearerPrefix+testToken {
		writeCode(w, 401, wire.ErrUnauthorized)
		return
	}
	method := func(want string) bool {
		if r.Method != want {
			w.Header().Set("Allow", want)
			writeCode(w, 405, wire.ErrMethodNotAllowed)
			return false
		}
		return true
	}
	tenant := r.URL.Query().Get("tenant")
	switch r.URL.Path {
	case wire.PathPolicies:
		if !method("POST") {
			return
		}
		var env wire.Envelope
		if wire.Decode(bytes.NewReader(body), wire.MaxEnvelopeBytes, &env) != nil || env.ValidateShape() != nil {
			writeCode(w, 400, wire.ErrBadRequest)
			return
		}
		f.publish(w, env, body)
	case wire.PathRollouts:
		if r.Method == "POST" {
			var req wire.RolloutRequest
			if wire.Decode(bytes.NewReader(body), wire.MaxSmallRequestBytes, &req) != nil || req.Validate() != nil {
				writeCode(w, 400, wire.ErrBadRequest)
				return
			}
			f.rollout(w, req)
			return
		}
		if method("GET") {
			f.status(w, tenant)
		}
	case wire.PathFleet:
		if method("GET") {
			f.fleet(w, tenant)
		}
	case wire.PathTimeline:
		if method("GET") {
			f.timeline(w, tenant)
		}
	default:
		writeCode(w, 404, wire.ErrNotFound)
	}
}

func (f *fakeCP) requests() []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recorded(nil), f.got...)
}

// 2026-11-05T09:00:00Z
const t0 = int64(1793869200000)

func fleetFixture() []wire.ProxyView {
	h := wire.Hash(strings.Repeat("ab", 32))
	return []wire.ProxyView{
		{ProxyID: "bank-a-p1", Group: "canary", Health: wire.HealthHealthy, State: wire.StateEnforcing,
			DesiredVersion: 9, AppliedVersion: 9, PolicyHash: h, LastSeenUnixMs: t0},
		{ProxyID: "bank-a-p2", Group: "main", Health: wire.HealthStale, State: wire.StateEnforcing,
			DesiredVersion: 9, AppliedVersion: 8, PolicyHash: h, Drift: 1, LastSeenUnixMs: t0 + 60_000,
			LastError: &wire.ApplyError{Code: wire.ErrNotNewer, Version: 8}},
	}
}

func timelineFixture() []wire.TimelineEntry {
	h8 := wire.Hash(strings.Repeat("11", 32))
	h9 := wire.Hash(strings.Repeat("22", 32))
	return []wire.TimelineEntry{
		{ProxyID: "bank-a-p2", Version: 9, PolicyHash: h9, FirstSeenUnixMs: t0 + 3_600_000, LastSeenUnixMs: t0 + 7_200_000},
		{ProxyID: "bank-a-p1", Version: 8, PolicyHash: h8, FirstSeenUnixMs: t0, LastSeenUnixMs: t0 + 1_800_000},
		{ProxyID: "bank-a-p1", Version: 9, PolicyHash: h9, FirstSeenUnixMs: t0 + 1_800_000, LastSeenUnixMs: t0 + 7_200_000},
	}
}

// ctlEnv is ctl with an environment.
func ctlEnv(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, streams{
		in: strings.NewReader(""), out: &out, err: &errb,
		now:    func() time.Time { return testNow },
		getenv: func(k string) string { return env[k] },
	})
	return code, out.String(), errb.String()
}

// admin runs a networked command against f with the right token.
func (f *fakeCP) admin(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	return ctlEnv(t, map[string]string{"KCTL_ADMIN_TOKEN": testToken}, withConn(f.srv.URL, args)...)
}

// withConn inserts -url and -allow-plaintext after the command words.
func withConn(url string, args []string) []string {
	n := 1
	if (args[0] == "rollout" || args[0] == "evidence") && len(args) > 1 {
		n = 2
	}
	out := append([]string{}, args[:n]...)
	out = append(out, "-url", url, "-allow-plaintext")
	return append(out, args[n:]...)
}

func noSecret(t *testing.T, outs ...string) {
	t.Helper()
	for _, o := range outs {
		if strings.Contains(o, testToken) {
			t.Errorf("admin token appears in output: %q", o)
		}
	}
}

func twoSigned(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	p, _ := signedBy(t, dir, rawPayload, "admin-a", "admin-b")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, b
}

func TestPublish(t *testing.T) {
	cp := newFakeCP(t, false)
	dir := t.TempDir()
	envPath, raw := twoSigned(t, dir)
	code, out, errb := cp.admin(t, "publish", "-in", envPath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	reqs := cp.requests()
	if len(reqs) != 1 || reqs[0].Method != "POST" || reqs[0].Path != wire.PathPolicies {
		t.Fatalf("requests: %+v", reqs)
	}
	if !bytes.Equal(reqs[0].Body, raw) {
		t.Error("the envelope was not sent byte for byte")
	}
	if reqs[0].Auth != "Bearer "+testToken {
		t.Errorf("auth header %q", reqs[0].Auth)
	}
	sum := sha256.Sum256([]byte(rawPayload))
	for _, want := range []string{"bank-a", "8", hex.EncodeToString(sum[:]), "rollout start"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "not") {
		t.Errorf("output should say publish does not roll out:\n%s", out)
	}
	noSecret(t, out, errb)
}

func TestTokenSources(t *testing.T) {
	cp := newFakeCP(t, false)
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	args := []string{"publish", "-url", cp.srv.URL, "-allow-plaintext", "-in", envPath}

	// Token file.
	tf := filepath.Join(dir, "token")
	if err := os.WriteFile(tf, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, e := ctlEnv(t, nil, append(args, "-token-file", tf)...); code != 0 {
		t.Fatalf("token file: exit %d %s", code, e)
	}
	// Token file from the environment.
	if code, _, e := ctlEnv(t, map[string]string{"KCTL_ADMIN_TOKEN_FILE": tf}, args...); code != 0 {
		t.Fatalf("token file env: exit %d %s", code, e)
	}
	// URL from the environment.
	if code, _, e := ctlEnv(t, map[string]string{"KCTL_ADMIN_TOKEN": testToken, "KCTL_CP_URL": cp.srv.URL},
		"publish", "-allow-plaintext", "-in", envPath); code != 0 {
		t.Fatalf("url env: exit %d %s", code, e)
	}

	before := len(cp.requests())
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(testToken), 0o644); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctrl := filepath.Join(dir, "ctrl")
	if err := os.WriteFile(ctrl, []byte("ab\x1bcd"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
	}{
		"no token":           {nil, args},
		"loose token file":   {nil, append(args, "-token-file", loose)},
		"empty token file":   {nil, append(args, "-token-file", empty)},
		"control characters": {nil, append(args, "-token-file", ctrl)},
		"missing file":       {nil, append(args, "-token-file", filepath.Join(dir, "nope"))},
		"env with newline":   {map[string]string{"KCTL_ADMIN_TOKEN": "a\nb"}, args},
	} {
		code, out, errb := ctlEnv(t, tc.env, tc.args...)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("%s: exit %d stderr %q", name, code, errb)
		}
		noSecret(t, out, errb)
	}
	// A token can never be a flag: it would show in ps.
	if code, _, _ := ctlEnv(t, nil, append(args, "-token", testToken)...); code != 2 {
		t.Errorf("-token flag exit %d, want 2", code)
	}
	if n := len(cp.requests()); n != before {
		t.Errorf("%d requests were sent although the token was bad", n-before)
	}
}

func TestPublishRefusesBeforeSending(t *testing.T) {
	cp := newFakeCP(t, false)
	dir := t.TempDir()
	one, _ := signedBy(t, dir, rawPayload, "admin-a")
	bad := t.TempDir()
	two, _ := signedBy(t, bad, rawPayload, "admin-a", "admin-b")
	env := readEnvelope(t, two)
	// Several entries but only one admin (Q-D4): the same signature twice,
	// the same key ID with another signature, and the same key three times.
	withSigs := func(name string, sigs ...wire.Signature) string {
		e := env
		e.Signatures = sigs
		b, _ := json.Marshal(e)
		p := filepath.Join(bad, name)
		writeFile(t, p, string(b))
		return p
	}
	s0, s1 := env.Signatures[0], env.Signatures[1]
	sameSig := withSigs("samesig.json", s0, s0)
	sameID := withSigs("sameid.json", s0, wire.Signature{KeyID: s0.KeyID, Sig: s1.Sig})
	three := withSigs("three.json", s0, s0, s0)
	env.Payload = []byte(`{"tenant":"bank-a"}`)
	b, _ := json.Marshal(env)
	badPayload := filepath.Join(bad, "badpayload.json")
	writeFile(t, badPayload, string(b))
	notJSON := filepath.Join(bad, "x.json")
	writeFile(t, notJSON, "hello")
	huge := filepath.Join(bad, "huge.json")
	writeFile(t, huge, strings.Repeat("a", wire.MaxEnvelopeBytes+1))

	for name, in := range map[string]string{
		"one signature":        one,
		"same signature twice": sameSig,
		"same key ID twice":    sameID,
		"same key ID 3 times":  three,
		"invalid payload":      badPayload,
		"not an envelope":      notJSON,
		"too big":              huge,
		"missing":              filepath.Join(bad, "nope.json"),
	} {
		code, _, errb := cp.admin(t, "publish", "-in", in)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("%s: exit %d stderr %q", name, code, errb)
		}
	}
	if code, _, _ := cp.admin(t, "publish"); code != 2 {
		t.Errorf("missing -in: exit %d, want 2", code)
	}
	if n := len(cp.requests()); n != 0 {
		t.Errorf("%d requests sent for refused input", n)
	}
}

func TestPublishServerAnswers(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	good := func(f *fakeCP) wire.PublishResponse {
		sum := sha256.Sum256([]byte(rawPayload))
		return wire.PublishResponse{Tenant: "bank-a", Version: 8, PolicyHash: wire.Hash(hex.EncodeToString(sum[:]))}
	}
	for name, tc := range map[string]func(f *fakeCP){
		"401": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { writeCode(w, 401, wire.ErrUnauthorized) }
		},
		"403": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { writeCode(w, 403, wire.ErrForbidden) }
		},
		"409 conflict": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { writeCode(w, 409, wire.ErrConflict) }
		},
		"threshold": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { writeCode(w, 400, wire.ErrThreshold) }
		},
		"413": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { writeCode(w, 413, wire.ErrTooLarge) }
		},
		"503 retry-after": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				w.Header().Set("Retry-After", "7")
				writeCode(w, 503, wire.ErrUnavailable)
			}
		},
		"500 html": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				w.WriteHeader(500)
				_, _ = w.Write([]byte("<html>oops \x1b[31m</html>"))
			}
		},
		"unknown error code": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"code":"\u001b[2Jevil"}`))
			}
		},
		"200 empty": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) { w.WriteHeader(200) }
		},
		"200 unknown field": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				_, _ = w.Write([]byte(`{"tenant":"bank-a","version":8,"policy_hash":"` + string(good(nil).PolicyHash) + `","extra":1}`))
			}
		},
		"200 trailing data": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				b, _ := json.Marshal(good(nil))
				_, _ = w.Write(append(b, []byte(` {}`)...))
			}
		},
		"200 other hash": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				r := good(nil)
				r.PolicyHash = wire.Hash(strings.Repeat("0", 64))
				writeJSON(w, 200, r)
			}
		},
		"200 other version": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				r := good(nil)
				r.Version = 99
				writeJSON(w, 200, r)
			}
		},
		"200 other tenant": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				r := good(nil)
				r.Tenant = "bank-b"
				writeJSON(w, 200, r)
			}
		},
		"redirect": func(f *fakeCP) {
			f.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
				http.Redirect(w, &http.Request{}, "http://127.0.0.1:1/evil", 307)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, false)
			tc(cp)
			code, out, errb := cp.admin(t, "publish", "-in", envPath)
			if code != 1 || !hasBoth(errb) {
				t.Errorf("exit %d stdout %q stderr %q", code, out, errb)
			}
			if strings.Contains(out, "published") {
				t.Errorf("claimed success: %q", out)
			}
			if strings.ContainsRune(errb+out, 0x1b) {
				t.Errorf("control character from the server reached the terminal: %q", errb)
			}
			noSecret(t, out, errb)
		})
	}

	t.Run("503 shows retry-after", func(t *testing.T) {
		cp := newFakeCP(t, false)
		cp.publish = func(w http.ResponseWriter, _ wire.Envelope, _ []byte) {
			w.Header().Set("Retry-After", "7")
			writeCode(w, 503, wire.ErrUnavailable)
		}
		_, _, errb := cp.admin(t, "publish", "-in", envPath)
		if !strings.Contains(errb, "7") {
			t.Errorf("Retry-After not shown: %q", errb)
		}
	})
}

func TestTimeout(t *testing.T) {
	old := httpTimeout
	httpTimeout = 150 * time.Millisecond
	defer func() { httpTimeout = old }()
	cp := newFakeCP(t, false)
	cp.fleet = func(w http.ResponseWriter, _ string) { time.Sleep(600 * time.Millisecond) }
	code, _, errb := cp.admin(t, "fleet", "-tenant", "bank-a")
	if code != 1 || !hasBoth(errb) || !strings.Contains(errb, "time") {
		t.Errorf("exit %d stderr %q", code, errb)
	}
	if old != 30*time.Second {
		t.Errorf("default timeout %v, want 30s (M-D31)", old)
	}
}

func TestConnectionRules(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	env := map[string]string{"KCTL_ADMIN_TOKEN": testToken}

	plain := newFakeCP(t, false)
	// Plaintext only with the explicit flag.
	code, _, errb := ctlEnv(t, env, "publish", "-url", plain.srv.URL, "-in", envPath)
	if code != 1 || !hasBoth(errb) {
		t.Errorf("plaintext without flag: exit %d stderr %q", code, errb)
	}
	for name, u := range map[string]string{
		"ftp":          "ftp://example.com",
		"userinfo":     "https://user:pass@example.com",
		"no host":      "https://",
		"query":        "https://example.com/?a=b",
		"fragment":     "https://example.com/#x",
		"path":         "https://example.com/admin",
		"not a url":    "::::",
		"empty scheme": "example.com",
	} {
		code, _, errb := ctlEnv(t, env, "publish", "-url", u, "-in", envPath)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("%s: exit %d stderr %q", name, code, errb)
		}
	}
	if n := len(plain.requests()); n != 0 {
		t.Errorf("%d requests sent over a refused connection", n)
	}
	if code, _, _ := ctlEnv(t, env, "publish", "-in", envPath); code != 2 {
		t.Errorf("missing -url: exit %d, want 2", code)
	}

	// TLS: an unknown CA is refused; -ca-file makes it work.
	tls := newFakeCP(t, true)
	code, _, errb = ctlEnv(t, env, "publish", "-url", tls.srv.URL, "-in", envPath)
	if code != 1 || !hasBoth(errb) || !strings.Contains(errb, "-ca-file") {
		t.Errorf("unknown CA: exit %d stderr %q", code, errb)
	}
	ca := filepath.Join(dir, "ca.pem")
	writeFile(t, ca, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.srv.Certificate().Raw})))
	code, _, errb = ctlEnv(t, env, "publish", "-url", tls.srv.URL, "-ca-file", ca, "-in", envPath)
	if code != 0 {
		t.Errorf("with -ca-file: exit %d stderr %q", code, errb)
	}
	junk := filepath.Join(dir, "junk.pem")
	writeFile(t, junk, "not pem")
	for name, p := range map[string]string{"junk": junk, "missing": filepath.Join(dir, "nope.pem")} {
		code, _, errb = ctlEnv(t, env, "publish", "-url", tls.srv.URL, "-ca-file", p, "-in", envPath)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("ca-file %s: exit %d stderr %q", name, code, errb)
		}
	}

	// Nothing is listening.
	code, _, errb = ctlEnv(t, env, "publish", "-url", "http://127.0.0.1:1", "-allow-plaintext", "-in", envPath)
	if code != 1 || !hasBoth(errb) {
		t.Errorf("connection refused: exit %d stderr %q", code, errb)
	}
}

func TestRolloutStart(t *testing.T) {
	cp := newFakeCP(t, false)
	code, out, errb := cp.admin(t, "rollout", "start", "-tenant", "bank-a", "-version", "9", "-canary-dwell", "10m")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	reqs := cp.requests()
	if len(reqs) != 1 || reqs[0].Method != "POST" || reqs[0].Path != wire.PathRollouts {
		t.Fatalf("requests %+v", reqs)
	}
	var got wire.RolloutRequest
	if err := wire.Decode(bytes.NewReader(reqs[0].Body), wire.MaxSmallRequestBytes, &got); err != nil {
		t.Fatal(err)
	}
	if got.Tenant != "bank-a" || got.Version != 9 || got.CanaryDwellSeconds != 600 {
		t.Errorf("sent %+v", got)
	}
	for _, want := range []string{"bank-a", "9", "canary"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
	noSecret(t, out, errb)

	// Default dwell is left to the control plane.
	if code, _, e := cp.admin(t, "rollout", "start", "-tenant", "bank-a", "-version", "9"); code != 0 {
		t.Fatal(e)
	}
	reqs = cp.requests()
	if strings.Contains(string(reqs[len(reqs)-1].Body), "canary_dwell_seconds") {
		t.Errorf("dwell sent although not given: %s", reqs[len(reqs)-1].Body)
	}
}

func TestRolloutStartRefusals(t *testing.T) {
	cp := newFakeCP(t, false)
	before := len(cp.requests())
	for name, args := range map[string][]string{
		"no tenant":      {"rollout", "start", "-version", "9"},
		"bad tenant":     {"rollout", "start", "-tenant", "Bank_A", "-version", "9"},
		"no version":     {"rollout", "start", "-tenant", "bank-a"},
		"version zero":   {"rollout", "start", "-tenant", "bank-a", "-version", "0"},
		"fractional":     {"rollout", "start", "-tenant", "bank-a", "-version", "9", "-canary-dwell", "1500ms"},
		"negative dwell": {"rollout", "start", "-tenant", "bank-a", "-version", "9", "-canary-dwell", "-5s"},
		"huge dwell":     {"rollout", "start", "-tenant", "bank-a", "-version", "9", "-canary-dwell", "100000h"},
	} {
		code, _, errb := cp.admin(t, args...)
		if code == 0 || !hasBoth(errb) {
			t.Errorf("%s: exit %d stderr %q", name, code, errb)
		}
	}
	if n := len(cp.requests()) - before; n != 0 {
		t.Errorf("%d requests sent for refused input", n)
	}
	if code, _, _ := cp.admin(t, "rollout"); code != 2 {
		t.Errorf("rollout alone: exit %d", code)
	}
	if code, _, _ := cp.admin(t, "rollout", "frobnicate"); code != 2 {
		t.Errorf("unknown rollout command: exit %d", code)
	}
}

func TestRolloutServerAnswers(t *testing.T) {
	for name, view := range map[string]wire.RolloutView{
		"other tenant":  {Tenant: "bank-b", Version: 9, Phase: wire.PhaseCanary},
		"other version": {Tenant: "bank-a", Version: 3, Phase: wire.PhaseCanary},
		"bad phase":     {Tenant: "bank-a", Version: 9, Phase: "\x1b[2J"},
		"bad reason":    {Tenant: "bank-a", Version: 9, Phase: wire.PhaseHalted, Reason: "\x1b[2J"},
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, false)
			cp.rollout = func(w http.ResponseWriter, _ wire.RolloutRequest) { writeJSON(w, 200, view) }
			code, out, errb := cp.admin(t, "rollout", "start", "-tenant", "bank-a", "-version", "9")
			if code != 1 || !hasBoth(errb) || strings.ContainsRune(out+errb, 0x1b) {
				t.Errorf("exit %d out %q err %q", code, out, errb)
			}
		})
	}
	t.Run("conflict", func(t *testing.T) {
		cp := newFakeCP(t, false)
		cp.rollout = func(w http.ResponseWriter, _ wire.RolloutRequest) { writeCode(w, 409, wire.ErrConflict) }
		code, _, errb := cp.admin(t, "rollout", "start", "-tenant", "bank-a", "-version", "9")
		if code != 1 || !hasBoth(errb) {
			t.Errorf("exit %d err %q", code, errb)
		}
	})
}

func TestRolloutStatus(t *testing.T) {
	cp := newFakeCP(t, false)
	code, out, errb := cp.admin(t, "rollout", "status", "-tenant", "bank-a")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	reqs := cp.requests()
	if reqs[0].Method != "GET" || reqs[0].Path != wire.PathRollouts || reqs[0].Query != "tenant=bank-a" {
		t.Errorf("request %+v", reqs[0])
	}
	for _, want := range []string{"bank-a", "9", "halted", "canary_lost"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}

	cp.status = func(w http.ResponseWriter, _ string) { writeCode(w, 404, wire.ErrNotFound) }
	code, out, errb = cp.admin(t, "rollout", "status", "-tenant", "bank-a")
	if code != 0 || !strings.Contains(out, "no rollout") {
		t.Errorf("404: exit %d out %q err %q", code, out, errb)
	}

	cp.status = func(w http.ResponseWriter, _ string) {
		writeJSON(w, 200, wire.RolloutView{Tenant: "bank-b", Version: 1, Phase: wire.PhaseComplete})
	}
	if code, _, errb = cp.admin(t, "rollout", "status", "-tenant", "bank-a"); code != 1 || !hasBoth(errb) {
		t.Errorf("wrong tenant answer: exit %d err %q", code, errb)
	}
	if code, _, _ = cp.admin(t, "rollout", "status"); code == 0 {
		t.Error("status without -tenant succeeded")
	}
}

func TestFleet(t *testing.T) {
	cp := newFakeCP(t, false)
	code, out, errb := cp.admin(t, "fleet", "-tenant", "bank-a")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	reqs := cp.requests()
	if reqs[0].Path != wire.PathFleet || reqs[0].Query != "tenant=bank-a" {
		t.Errorf("request %+v", reqs[0])
	}
	for _, want := range []string{"bank-a-p1", "bank-a-p2", "canary", "healthy", "stale", "enforcing",
		"not_newer", "version_not_newer", "2026-11-05 18:00:00 JST", "2026-11-05 09:00:00 UTC", strings.Repeat("ab", 6)} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	noSecret(t, out, errb)
}

func TestFleetRejectsBadAnswers(t *testing.T) {
	mut := func(edit func(*wire.FleetView)) func(w http.ResponseWriter, tenant string) {
		return func(w http.ResponseWriter, tenant string) {
			v := wire.FleetView{Tenant: wire.ID(tenant), Proxies: fleetFixture()}
			edit(&v)
			writeJSON(w, 200, v)
		}
	}
	for name, fn := range map[string]func(w http.ResponseWriter, tenant string){
		"other tenant": mut(func(v *wire.FleetView) { v.Tenant = "bank-b" }),
		"escape in id": mut(func(v *wire.FleetView) { v.Proxies[0].ProxyID = "p\x1b[2J" }),
		"bad group":    mut(func(v *wire.FleetView) { v.Proxies[0].Group = "G R" }),
		"bad health":   mut(func(v *wire.FleetView) { v.Proxies[0].Health = "\x1b[31m" }),
		"bad state":    mut(func(v *wire.FleetView) { v.Proxies[0].State = "\x1b]0;x" }),
		"bad hash":     mut(func(v *wire.FleetView) { v.Proxies[0].PolicyHash = "\x1b" }),
		"bad err code": mut(func(v *wire.FleetView) { v.Proxies[1].LastError.Code = "\x1b[2J" }),
		"unknown field": func(w http.ResponseWriter, _ string) {
			_, _ = w.Write([]byte(`{"tenant":"bank-a","proxies":[],"x":1}`))
		},
		"not json": func(w http.ResponseWriter, _ string) { _, _ = w.Write([]byte("<html>")) },
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, false)
			cp.fleet = fn
			code, out, errb := cp.admin(t, "fleet", "-tenant", "bank-a")
			if code != 1 || !hasBoth(errb) || strings.ContainsRune(out+errb, 0x1b) {
				t.Errorf("exit %d out %q err %q", code, out, errb)
			}
		})
	}
	t.Run("empty fleet", func(t *testing.T) {
		cp := newFakeCP(t, false)
		cp.fleet = func(w http.ResponseWriter, tenant string) { writeJSON(w, 200, wire.FleetView{Tenant: wire.ID(tenant)}) }
		code, out, _ := cp.admin(t, "fleet", "-tenant", "bank-a")
		if code != 0 || !strings.Contains(out, "no proxies") {
			t.Errorf("exit %d out %q", code, out)
		}
	})
	t.Run("no tenant", func(t *testing.T) {
		cp := newFakeCP(t, false)
		if code, _, _ := cp.admin(t, "fleet"); code == 0 {
			t.Error("fleet without -tenant succeeded")
		}
	})
}

func TestEvidenceExport(t *testing.T) {
	cp := newFakeCP(t, false)
	code, out, errb := cp.admin(t, "evidence", "export", "-tenant", "bank-a")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	reqs := cp.requests()
	if reqs[0].Path != wire.PathTimeline || reqs[0].Query != "tenant=bank-a" {
		t.Errorf("request %+v", reqs[0])
	}
	h8 := strings.Repeat("11", 32)
	line := "proxy bank-a-p1 enforced version 8 (hash " + h8 + ") from 2026-11-05 18:00:00 JST (2026-11-05 09:00:00 UTC) to 2026-11-05 18:30:00 JST (2026-11-05 09:30:00 UTC)"
	if !strings.Contains(out, line) {
		t.Errorf("missing J5 line\nwant %s\n%s", line, out)
	}
	// Ordered by proxy, then first seen.
	i1 := strings.Index(out, "bank-a-p1 enforced version 8")
	i2 := strings.Index(out, "bank-a-p1 enforced version 9")
	i3 := strings.Index(out, "bank-a-p2 enforced version 9")
	if !(i1 >= 0 && i1 < i2 && i2 < i3) {
		t.Errorf("entries out of order: %d %d %d\n%s", i1, i2, i3, out)
	}
	if !strings.Contains(out, "control plane") {
		t.Errorf("output should say these are the control plane's observations:\n%s", out)
	}

	// -proxy filters.
	code, out, _ = cp.admin(t, "evidence", "export", "-tenant", "bank-a", "-proxy", "bank-a-p2")
	if code != 0 || strings.Contains(out, "bank-a-p1 enforced") || !strings.Contains(out, "bank-a-p2 enforced") {
		t.Errorf("filter: exit %d\n%s", code, out)
	}

	// -out writes a new file and never overwrites.
	dir := t.TempDir()
	file := filepath.Join(dir, "evidence.txt")
	if code, _, e := cp.admin(t, "evidence", "export", "-tenant", "bank-a", "-out", file); code != 0 {
		t.Fatal(e)
	}
	if !strings.Contains(readFile(t, file), line) {
		t.Error("file lacks the evidence line")
	}
	if code, _, errb := cp.admin(t, "evidence", "export", "-tenant", "bank-a", "-out", file); code != 1 || !hasBoth(errb) {
		t.Errorf("overwrite: exit %d err %q", code, errb)
	}
	noSecret(t, out, errb)
}

func TestEvidenceRejectsBadAnswers(t *testing.T) {
	mut := func(edit func(*wire.TimelineView)) func(w http.ResponseWriter, tenant string) {
		return func(w http.ResponseWriter, tenant string) {
			v := wire.TimelineView{Tenant: wire.ID(tenant), Entries: timelineFixture()}
			edit(&v)
			writeJSON(w, 200, v)
		}
	}
	for name, fn := range map[string]func(w http.ResponseWriter, tenant string){
		"other tenant":  mut(func(v *wire.TimelineView) { v.Tenant = "bank-b" }),
		"escape in id":  mut(func(v *wire.TimelineView) { v.Entries[0].ProxyID = "p\x1b[2J" }),
		"bad hash":      mut(func(v *wire.TimelineView) { v.Entries[0].PolicyHash = "zz" }),
		"zero version":  mut(func(v *wire.TimelineView) { v.Entries[0].Version = 0 }),
		"time reversed": mut(func(v *wire.TimelineView) { v.Entries[0].LastSeenUnixMs = v.Entries[0].FirstSeenUnixMs - 1 }),
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, false)
			cp.timeline = fn
			code, out, errb := cp.admin(t, "evidence", "export", "-tenant", "bank-a")
			if code != 1 || !hasBoth(errb) || strings.ContainsRune(out+errb, 0x1b) {
				t.Errorf("exit %d out %q err %q", code, out, errb)
			}
		})
	}
	cp := newFakeCP(t, false)
	for name, args := range map[string][]string{
		"bad proxy filter": {"evidence", "export", "-tenant", "bank-a", "-proxy", "P R"},
		"no tenant":        {"evidence", "export"},
		"no subcommand":    {"evidence"},
		"bad subcommand":   {"evidence", "frobnicate"},
	} {
		if code, _, _ := cp.admin(t, args...); code == 0 {
			t.Errorf("%s succeeded", name)
		}
	}
}

func TestEvidenceEmpty(t *testing.T) {
	cp := newFakeCP(t, false)
	cp.timeline = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, wire.TimelineView{Tenant: wire.ID(tenant)})
	}
	code, out, _ := cp.admin(t, "evidence", "export", "-tenant", "bank-a")
	if code != 0 || !strings.Contains(out, "no entries") {
		t.Errorf("exit %d out %q", code, out)
	}
}

// Rollback: old content, new version, fresh validity, no signatures unless
// both keys are given.
func TestRolloutRollback(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	out := filepath.Join(dir, "v12.json")
	code, stdout, errb := ctl(t, "", "rollout", "rollback", "-from", envPath, "-version", "12", "-validity", "24h", "-out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	newPol, err := policy.Parse([]byte(readFile(t, out)))
	if err != nil {
		t.Fatalf("output does not parse: %v", err)
	}
	oldPol, _ := policy.Parse([]byte(rawPayload))
	if newPol.Version != 12 || newPol.Tenant != "bank-a" {
		t.Errorf("tenant/version: %s %d", newPol.Tenant, newPol.Version)
	}
	if !newPol.IssuedAt.Equal(testNow.UTC().Truncate(time.Second)) || !newPol.ExpiresAt.Equal(newPol.IssuedAt.Add(24*time.Hour)) {
		t.Errorf("validity: %v .. %v", newPol.IssuedAt, newPol.ExpiresAt)
	}
	body := func(p *policy.Policy) string { return strings.SplitN(p.Render(), "\n", 5)[4] }
	if body(newPol) != body(oldPol) || body(newPol) == "" {
		t.Errorf("rules changed:\nold %s\nnew %s", body(oldPol), body(newPol))
	}
	for _, want := range []string{"sign", "approve", "publish", "rollout start", "12"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("next steps lack %q:\n%s", want, stdout)
		}
	}

	// A raw payload file works as input too.
	raw := filepath.Join(dir, "old-payload.json")
	writeFile(t, raw, rawPayload)
	out2 := filepath.Join(dir, "v13.json")
	if code, _, e := ctl(t, "", "rollout", "rollback", "-from", raw, "-version", "13", "-out", out2); code != 0 {
		t.Fatal(e)
	}
	p2, _ := policy.Parse([]byte(readFile(t, out2)))
	if p2.Version != 13 || p2.ExpiresAt.Sub(p2.IssuedAt) != 72*time.Hour {
		t.Errorf("defaults: %+v", p2)
	}
}

func TestRolloutRollbackRefusals(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	existing := filepath.Join(dir, "exists.json")
	writeFile(t, existing, "x")
	bad := filepath.Join(dir, "bad.json")
	writeFile(t, bad, `{"tenant":"bank-a"}`)
	for name, args := range map[string][]string{
		"same version":     {"-from", envPath, "-version", "8", "-out", filepath.Join(dir, "a")},
		"older version":    {"-from", envPath, "-version", "3", "-out", filepath.Join(dir, "b")},
		"version zero":     {"-from", envPath, "-version", "0", "-out", filepath.Join(dir, "c")},
		"no version":       {"-from", envPath, "-out", filepath.Join(dir, "d")},
		"no out":           {"-from", envPath, "-version", "9"},
		"no from":          {"-version", "9", "-out", filepath.Join(dir, "e")},
		"overwrite":        {"-from", envPath, "-version", "9", "-out", existing},
		"invalid source":   {"-from", bad, "-version", "9", "-out", filepath.Join(dir, "f")},
		"missing source":   {"-from", filepath.Join(dir, "nope"), "-version", "9", "-out", filepath.Join(dir, "g")},
		"bad validity":     {"-from", envPath, "-version", "9", "-validity", "500ms", "-out", filepath.Join(dir, "h")},
		"one key only":     {"-from", envPath, "-version", "9", "-out", filepath.Join(dir, "i"), "-key", "x.key", "-env-out", filepath.Join(dir, "j")},
		"keys without out": {"-from", envPath, "-version", "9", "-out", filepath.Join(dir, "k"), "-key", "x.key", "-key2", "y.key"},
	} {
		code, _, errb := ctl(t, "", append([]string{"rollout", "rollback"}, args...)...)
		if code == 0 || !hasBoth(errb) && code != 2 {
			t.Errorf("%s: exit %d stderr %q", name, code, errb)
		}
	}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "k"} {
		if _, err := os.Stat(filepath.Join(dir, n)); err == nil {
			t.Errorf("refused rollback left file %s", n)
		}
	}
	if readFile(t, existing) != "x" {
		t.Error("existing file overwritten")
	}
}

func TestRolloutRollbackSignsOnlyWithBothKeys(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := twoSigned(t, dir)
	keyA, pubA := fixtureKey(t, dir, "admin-a", "ka")
	keyB, pubB := fixtureKey(t, dir, "admin-b", "kb")
	payload := filepath.Join(dir, "v12.json")
	envOut := filepath.Join(dir, "v12.env.json")
	code, _, errb := ctl(t, "", "rollout", "rollback", "-from", envPath, "-version", "12", "-out", payload,
		"-key", keyA, "-key2", keyB, "-env-out", envOut)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	env := readEnvelope(t, envOut)
	if string(env.Payload) != readFile(t, payload) {
		t.Error("envelope payload differs from the payload file")
	}
	if len(env.Signatures) != 2 || !verifies(env, 0, pubA) || !verifies(env, 1, pubB) {
		t.Errorf("signatures: %d", len(env.Signatures))
	}
	// The same key twice is refused.
	code, _, errb = ctl(t, "", "rollout", "rollback", "-from", envPath, "-version", "13", "-out", filepath.Join(dir, "v13.json"),
		"-key", keyA, "-key2", keyA, "-env-out", filepath.Join(dir, "v13.env.json"))
	if code != 1 || !hasBoth(errb) {
		t.Errorf("same key twice: exit %d err %q", code, errb)
	}
	if _, err := os.Stat(filepath.Join(dir, "v13.json")); err == nil {
		t.Error("a refused rollback left its payload behind")
	}
}

func TestNetworkCommandsInUsage(t *testing.T) {
	code, out, _ := ctl(t, "", "help")
	if code != 0 {
		t.Fatal(code)
	}
	for _, w := range []string{"publish", "rollout start", "rollout status", "rollout rollback", "fleet", "evidence export", "KCTL_ADMIN_TOKEN"} {
		if !strings.Contains(out, w) {
			t.Errorf("help lacks %q", w)
		}
	}
}
