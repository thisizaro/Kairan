package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
	"kairan/internal/trust"
	"kairan/internal/wire"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

type world struct {
	t        *testing.T
	dir      string
	keys     []ed25519.PrivateKey
	upstream *httptest.Server
	upHits   atomic.Int64
	cp       *httptest.Server
	cpEnv    atomic.Pointer[wire.Envelope]
	mu       sync.Mutex
	statuses []wire.StatusReport
	cfg      map[string]any
}

func seed(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("kairan proxy main test " + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, dir: t.TempDir(), keys: []ed25519.PrivateKey{seed("a"), seed("b"), seed("c")}}
	w.upstream = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.upHits.Add(1)
		io.Copy(io.Discard, r.Body)
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream-ran"}]}}`))
	}))
	t.Cleanup(w.upstream.Close)
	mux := http.NewServeMux()
	mux.HandleFunc(wire.PathPoll, func(rw http.ResponseWriter, r *http.Request) {
		have := r.URL.Query().Get(wire.QueryHave)
		if env := w.cpEnv.Load(); env != nil && have == "0" {
			rw.Header().Set("Content-Type", wire.ContentTypeJSON)
			json.NewEncoder(rw).Encode(wire.PollResponse{Version: 3, Envelope: *env})
			return
		}
		select { // a short real hold
		case <-r.Context().Done():
		case <-time.After(300 * time.Millisecond):
		}
		rw.WriteHeader(http.StatusNotModified)
	})
	mux.HandleFunc(wire.PathStatus, func(rw http.ResponseWriter, r *http.Request) {
		var rep wire.StatusReport
		if wire.Decode(r.Body, wire.MaxStatusBytes, &rep) == nil {
			w.mu.Lock()
			w.statuses = append(w.statuses, rep)
			w.mu.Unlock()
		}
		rw.WriteHeader(http.StatusNoContent)
	})
	w.cp = httptest.NewServer(mux)
	t.Cleanup(w.cp.Close)

	var pubs []string
	for _, k := range w.keys {
		pubs = append(pubs, hex.EncodeToString(k.Public().(ed25519.PublicKey)))
	}
	w.cfg = map[string]any{
		"tenant": "bank-a", "proxy_id": "proxy-1", "cp_url": w.cp.URL, "token": "enroll-token-xyz",
		"trusted_keys": pubs, "threshold": 2, "listen": "127.0.0.1:0", "upstream": w.upstream.URL,
		"api_keys": map[string]string{"key-sales-123": "sales"}, "data_dir": filepath.Join(w.dir, "data"),
		"allow_plaintext": true,
	}
	return w
}

func (w *world) envelope(version uint64, ttl time.Duration) wire.Envelope {
	now := time.Now().UTC()
	p := fmt.Sprintf(`{"tenant":"bank-a","version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}}`,
		version, now.Add(-time.Hour).Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(p)}
	trust.Sign(&env, w.keys[0])
	trust.Sign(&env, w.keys[1])
	return env
}

func (w *world) writeConfig() string {
	b, err := json.Marshal(w.cfg)
	if err != nil {
		w.t.Fatal(err)
	}
	p := filepath.Join(w.dir, "proxy.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

type running struct {
	addr    string
	metrics string // local listener address, "" if not configured

	cancel context.CancelFunc
	done   chan error
	stderr *syncBuf
}

func (w *world) start() *running {
	w.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	r := &running{cancel: cancel, done: make(chan error, 1), stderr: &syncBuf{}}
	ready := make(chan string, 1)
	go func() {
		r.done <- runLocal(ctx, []string{"-config", w.writeConfig()}, r.stderr, func(a string) { ready <- a }, func(a string) { r.metrics = a })
	}()
	select {
	case r.addr = <-ready:
	case err := <-r.done:
		cancel()
		w.t.Fatalf("run ended before ready: %v\n%s", err, r.stderr.String())
	case <-time.After(10 * time.Second):
		cancel()
		w.t.Fatal("proxy not ready")
	}
	w.t.Cleanup(func() { cancel(); <-r.done })
	return r
}

func (r *running) stop(t *testing.T) error {
	t.Helper()
	r.cancel()
	select {
	case err := <-r.done:
		r.done <- err
		return err
	case <-time.After(15 * time.Second):
		t.Fatal("proxy did not stop")
		return nil
	}
}

// call sends one tools/call and reports whether it reached the upstream.
func (w *world) call(r *running, key, tool string) (reached bool, body string) {
	w.t.Helper()
	before := w.upHits.Load()
	req, _ := http.NewRequest(http.MethodPost, "http://"+r.addr+"/", strings.NewReader(
		fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, tool)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return w.upHits.Load() > before, string(b)
}

func (w *world) await(what string, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			w.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (w *world) lastStatus() (wire.StatusReport, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.statuses) == 0 {
		return wire.StatusReport{}, false
	}
	return w.statuses[len(w.statuses)-1], true
}

func TestRunEnforcesDeliveredPolicy(t *testing.T) {
	w := newWorld(t)
	r := w.start()

	// Before any policy: deny-all. Nothing reaches the upstream.
	if reached, body := w.call(r, "key-sales-123", "crm.read_contact"); reached || !strings.Contains(body, "blocked by policy") {
		t.Fatalf("deny-all failed: reached=%v body=%s", reached, body)
	}
	// Wrong API key: rejected before any decision.
	if reached, _ := w.call(r, "wrong", "crm.read_contact"); reached {
		t.Fatal("unknown key reached the upstream")
	}

	env := w.envelope(3, time.Hour)
	w.cpEnv.Store(&env)
	w.await("policy applied", func() bool {
		s, ok := w.lastStatus()
		return ok && s.State == wire.StateEnforcing && s.AppliedVersion == 3
	})
	if reached, body := w.call(r, "key-sales-123", "crm.read_contact"); !reached || !strings.Contains(body, "upstream-ran") {
		t.Fatalf("read tool not allowed: reached=%v body=%s", reached, body)
	}
	if reached, body := w.call(r, "key-sales-123", "crm.update_deal"); !reached {
		t.Fatalf("write tool the policy grants was blocked: %s", body)
	}
	if reached, body := w.call(r, "key-sales-123", "crm.export"); reached || !strings.Contains(body, "blocked by policy v3") {
		t.Fatalf("ungranted tool: reached=%v body=%s", reached, body)
	}

	s, _ := w.lastStatus()
	if s.LogSeq != 1 || !s.LogHead.Valid() || !s.PolicyHash.Valid() || s.Tenant != "bank-a" || s.ProxyID != "proxy-1" {
		t.Fatalf("status = %+v", s)
	}

	if err := r.stop(t); err != nil {
		t.Fatalf("run = %v\n%s", err, r.stderr.String())
	}
	data := filepath.Join(w.dir, "data")
	for _, f := range []string{"policy.json", "apply.log", "decisions.log", "highwater"} {
		if fi, err := os.Stat(filepath.Join(data, f)); err != nil || fi.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	// I5: every decision carries the policy version and hash.
	log, _ := os.ReadFile(filepath.Join(data, "decisions.log"))
	if !strings.Contains(string(log), `"version":3`) || !strings.Contains(string(log), string(s.PolicyHash)) {
		t.Fatalf("decision log lacks version/hash:\n%s", log)
	}
	// Nothing secret in the logs or the status stream (I4).
	for _, leak := range []string{"enroll-token-xyz", "key-sales-123"} {
		if strings.Contains(r.stderr.String(), leak) {
			t.Fatalf("stderr leaks %q", leak)
		}
		if strings.Contains(string(log), leak) {
			t.Fatalf("decision log leaks %q", leak)
		}
	}
}

// With the control plane unreachable, a restart enforces the stored policy
// (J2/S3): boot is local, and the policy was re-verified from disk.
func TestRestartEnforcesFromDiskWithCPDown(t *testing.T) {
	w := newWorld(t)
	r := w.start()
	env := w.envelope(3, time.Hour)
	w.cpEnv.Store(&env)
	w.await("policy applied", func() bool { s, ok := w.lastStatus(); return ok && s.AppliedVersion == 3 })
	if err := r.stop(t); err != nil {
		t.Fatal(err)
	}
	w.cp.Close()

	r2 := w.start()
	if reached, body := w.call(r2, "key-sales-123", "crm.read_contact"); !reached {
		t.Fatalf("restart did not enforce the stored policy: %s", body)
	}
	if reached, _ := w.call(r2, "key-sales-123", "crm.export"); reached {
		t.Fatal("restart allowed an ungranted tool")
	}
	if !strings.Contains(r2.stderr.String(), `"state":"enforcing"`) {
		t.Fatalf("boot log: %s", r2.stderr.String())
	}
}

func TestTamperedPolicyFileDeniesEverything(t *testing.T) {
	w := newWorld(t)
	r := w.start()
	env := w.envelope(3, time.Hour)
	w.cpEnv.Store(&env)
	w.await("policy applied", func() bool { s, ok := w.lastStatus(); return ok && s.AppliedVersion == 3 })
	r.stop(t)
	w.cp.Close()

	// Widen the stored policy without re-signing it.
	p := filepath.Join(w.dir, "data", "policy.json")
	b, _ := os.ReadFile(p)
	var stored wire.Envelope
	if err := json.Unmarshal(b, &stored); err != nil {
		t.Fatal(err)
	}
	stored.Payload = bytes.Replace(stored.Payload, []byte("crm.read_*"), []byte("crm.*"), 1)
	nb, _ := json.Marshal(stored)
	if err := os.WriteFile(p, nb, 0o600); err != nil {
		t.Fatal(err)
	}

	r2 := w.start()
	for _, tool := range []string{"crm.read_contact", "crm.update_deal", "crm.export"} {
		if reached, _ := w.call(r2, "key-sales-123", tool); reached {
			t.Fatalf("tampered proxy let %s through", tool)
		}
	}
	if !strings.Contains(r2.stderr.String(), `"state":"tampered"`) {
		t.Fatalf("boot log: %s", r2.stderr.String())
	}
}

func TestBrokenApplyLogStartsTampered(t *testing.T) {
	w := newWorld(t)
	data := filepath.Join(w.dir, "data")
	os.MkdirAll(data, 0o700)
	garbage := "garbage that is not a log\n"
	os.WriteFile(filepath.Join(data, "apply.log"), []byte(garbage), 0o600)
	// Nothing newer on offer: Tampered, nothing enforced, log untouched.
	r := w.start()
	if reached, _ := w.call(r, "key-sales-123", "crm.read_contact"); reached {
		t.Fatal("proxy with a broken apply log let a call through")
	}
	w.await("tampered status", func() bool { s, ok := w.lastStatus(); return ok && s.State == wire.StateTampered })
	time.Sleep(400 * time.Millisecond)
	if s, _ := w.lastStatus(); s.State != wire.StateTampered || s.AppliedVersion != 0 {
		t.Fatalf("status = %+v", s)
	}
	if b, _ := os.ReadFile(filepath.Join(data, "apply.log")); string(b) != garbage {
		t.Fatal("the broken apply log was modified")
	}
	if _, err := os.Stat(filepath.Join(data, "apply.log.broken-1")); err == nil {
		t.Fatal("reset without a policy to apply")
	}
	r.stop(t)
}

// A newer valid policy from the control plane lifts Tampered: the broken log
// is kept, a new chain starts, and the reset is in the status report (P-13,
// M-D64, Q-D30).
func TestBrokenApplyLogRecoversOnNewerPolicy(t *testing.T) {
	w := newWorld(t)
	data := filepath.Join(w.dir, "data")
	os.MkdirAll(data, 0o700)
	garbage := "garbage that is not a log\n"
	os.WriteFile(filepath.Join(data, "apply.log"), []byte(garbage), 0o600)
	env := w.envelope(3, time.Hour)
	w.cpEnv.Store(&env)
	r := w.start()
	w.await("enforcing again", func() bool { s, ok := w.lastStatus(); return ok && s.State == wire.StateEnforcing })
	s, _ := w.lastStatus()
	if s.AppliedVersion != 3 || s.LogSeq != 2 || s.LastError == nil || s.LastError.Code != wire.ErrTampered {
		t.Fatalf("status = %+v last_error %+v", s, s.LastError)
	}
	if reached, body := w.call(r, "key-sales-123", "crm.read_contact"); !reached {
		t.Fatalf("read tool denied after recovery: %s", body)
	}
	if b, _ := os.ReadFile(filepath.Join(data, "apply.log.broken-1")); string(b) != garbage {
		t.Fatal("the broken log was not kept byte for byte")
	}
	if !strings.Contains(r.stderr.String(), "apply log reset") || !japanese.MatchString(r.stderr.String()) {
		t.Fatalf("no bilingual reset line:\n%s", r.stderr.String())
	}
	r.stop(t)
}

func TestTestOnlyKeyWarning(t *testing.T) {
	w := newWorld(t)
	var pubs []string
	for _, n := range []string{"admin-a", "admin-b"} {
		b, err := os.ReadFile("../../test/fixtures/TEST-ONLY-" + n + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, strings.TrimSpace(string(b)))
	}
	w.cfg["trusted_keys"] = pubs
	r := w.start()
	out := r.stderr.String()
	if !strings.Contains(out, "TEST-ONLY KEY TRUSTED") || !strings.Contains(out, `"level":"WARN"`) {
		t.Fatalf("no loud warning:\n%s", out)
	}
}

func TestNoteTestOnlyKeysCounts(t *testing.T) {
	w := newWorld(t)
	var pubs []string
	for _, n := range []string{"admin-a", "admin-b", "outsider"} {
		b, _ := os.ReadFile("../../test/fixtures/TEST-ONLY-" + n + ".pub")
		pubs = append(pubs, strings.TrimSpace(string(b)))
	}
	pubs = append(pubs, w.cfg["trusted_keys"].([]string)[0])
	w.cfg["trusted_keys"] = pubs
	cfg, err := LoadConfig(w.writeConfig())
	if err != nil {
		t.Fatal(err)
	}
	var out syncBuf
	stats := &agent.Stats{}
	noteTestOnlyKeys(cfg, stats, slog.New(slog.NewJSONHandler(&out, nil)))
	if got := stats.Count(metricTestOnlyKey); got != 3 {
		t.Fatalf("metric = %d, want 3", got)
	}
	if !strings.Contains(out.String(), "TEST-ONLY KEY TRUSTED") {
		t.Fatal("no warning")
	}

	// Fresh keys: silent and zero.
	w2 := newWorld(t)
	cfg2, _ := LoadConfig(w2.writeConfig())
	out.mu.Lock()
	out.b.Reset()
	out.mu.Unlock()
	stats2 := &agent.Stats{}
	noteTestOnlyKeys(cfg2, stats2, slog.New(slog.NewJSONHandler(&out, nil)))
	if stats2.Count(metricTestOnlyKey) != 0 || out.String() != "" {
		t.Fatal("fresh keys flagged")
	}
}

func TestConfigErrorsStopBeforeListening(t *testing.T) {
	tests := []struct {
		name string
		mod  func(c map[string]any)
	}{
		{"threshold one", func(c map[string]any) { c["threshold"] = 1 }},
		{"skew over 5m", func(c map[string]any) { c["skew"] = "6m" }},
		{"safe mode outside enum", func(c map[string]any) { c["safe_mode"] = "allow_all" }},
		{"unknown field", func(c map[string]any) { c["surprise"] = true }},
		{"http cp without allow_plaintext", func(c map[string]any) { c["allow_plaintext"] = false }},
		{"missing upstream", func(c map[string]any) { delete(c, "upstream") }},
		{"ca_file missing", func(c map[string]any) { c["ca_file"] = "/nonexistent/ca.pem" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			tc.mod(w.cfg)
			var out syncBuf
			called := false
			err := run(t.Context(), []string{"-config", w.writeConfig()}, &out, func(string) { called = true })
			if err == nil || !errors.Is(err, errUsage) || called {
				t.Fatalf("err = %v, ready called = %v", err, called)
			}
			for _, secret := range []string{"enroll-token-xyz", "key-sales-123"} {
				if strings.Contains(err.Error()+out.String(), secret) {
					t.Fatalf("error leaks %q", secret)
				}
			}
			if _, statErr := os.Stat(filepath.Join(w.dir, "data", "policy.json")); statErr == nil {
				t.Fatal("proxy touched its data directory")
			}
		})
	}
}

func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{nil, {"-config"}, {"-config", "/nonexistent.json"}, {"-nope"}, {"-config", "x", "extra"}} {
		var out syncBuf
		err := run(t.Context(), args, &out, func(string) { t.Fatal("started") })
		if err == nil || !errors.Is(err, errUsage) {
			t.Fatalf("args %v: err = %v", args, err)
		}
	}
}

func TestListenFailureIsAnError(t *testing.T) {
	w := newWorld(t)
	r := w.start()
	w.cfg["listen"] = r.addr // already taken
	var out syncBuf
	err := run(t.Context(), []string{"-config", w.writeConfig()}, &out, func(string) { t.Fatal("ready") })
	if err == nil || errors.Is(err, errUsage) {
		t.Fatalf("err = %v", err)
	}
}
