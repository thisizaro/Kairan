// Package e2e holds the chaos scenarios S1-S6 (Q-02, ARCHITECTURE section 11) as automated tests against
// the compose stack in deploy/compose. They are black-box: they talk to kairan-cp and the proxies over HTTP
// with the frozen wire types, and inject faults with real tools (docker kill, stop, start, restart,
// network disconnect, editing files in a stopped proxy's volume).
//
// Guard: nothing here runs unless E2E=1 (plain `go test ./...` needs no Docker). With E2E=1 TestMain brings a
// fresh stack up with deploy/compose/demo.sh (which publishes v1 to both tenants and waits for 10 acks) and
// tears it down at the end. E2E_REUSE=1 reuses a running stack and never tears it down; E2E_KEEP=1 leaves a stack it started running.
// DEMO_SRC points demo.sh at a checkout that has the program sources (needed only in lane Q's sparse worktree).
//
// The scenarios share one stack and run in file order (s1 ... s6). Each starts with baseline(), which heals
// containers and networks left broken by a failed earlier scenario.
package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

const (
	cloudNet = "kairan-demo_cloud"
	cpURL    = "http://127.0.0.1:18080"
	image    = "kairan:demo"
)

type px struct {
	ID, Tenant, Group, Container string
	MCP, Metrics                 int
}

var proxies = func() []px {
	spec := []struct{ t, g string }{
		{"bank-a", "canary"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"},
		{"city-b", "canary"}, {"city-b", "main"}, {"city-b", "main"}, {"city-b", "main"},
	}
	var out []px
	n, mains := 0, 0
	for _, s := range spec {
		n++
		id := s.t + "-" + s.g
		if s.g == "main" {
			mains++
			id += fmt.Sprintf("-%d", mains)
		} else {
			mains = 0
		}
		out = append(out, px{ID: id, Tenant: s.t, Group: s.g, Container: "kairan-" + id, MCP: 18100 + n, Metrics: 19100 + n})
	}
	return out
}()

func proxyByID(id string) px {
	for _, p := range proxies {
		if p.ID == id {
			return p
		}
	}
	panic("unknown proxy " + id)
}

func tenantProxies(tenant string) []px {
	var out []px
	for _, p := range proxies {
		if p.Tenant == tenant {
			out = append(out, p)
		}
	}
	return out
}

var tenants = []string{"bank-a", "city-b"}

type world struct {
	dir        string // test/e2e
	compose    string // deploy/compose
	run        string // deploy/compose/.run (generated, gitignored)
	adminToken string
	salesKey   string
	internKey  string
	keys       map[string]ed25519.PrivateKey
	hc         *http.Client
	mu         sync.Mutex
	ver        map[string]uint64
}

var W *world

func enabled() bool { return os.Getenv("E2E") == "1" }

func TestMain(m *testing.M) {
	if !enabled() {
		os.Exit(m.Run())
	}
	wd, _ := os.Getwd()
	comp, _ := filepath.Abs(filepath.Join(wd, "..", "..", "deploy", "compose"))
	W = &world{dir: wd, compose: comp, run: filepath.Join(comp, ".run"), ver: map[string]uint64{},
		hc: &http.Client{Timeout: 10 * time.Second}}
	if os.Getenv("E2E_REUSE") != "1" {
		cmd := exec.Command("bash", filepath.Join(comp, "demo.sh"), "demo")
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "e2e: demo.sh failed:", err)
			os.Exit(1)
		}
	}
	if err := W.load(); err != nil {
		fmt.Fprintln(os.Stderr, "e2e: load generated secrets:", err)
		os.Exit(1)
	}
	code := m.Run()
	if os.Getenv("E2E_KEEP") != "1" && os.Getenv("E2E_REUSE") != "1" {
		_ = exec.Command("bash", filepath.Join(comp, "demo.sh"), "down").Run()
	}
	os.Exit(code)
}

func readTrim(p string) (string, error) {
	b, err := os.ReadFile(p)
	return strings.TrimSpace(string(b)), err
}

func (w *world) load() error {
	var err error
	if w.adminToken, err = readTrim(filepath.Join(w.run, "admin.token")); err != nil {
		return err
	}
	if w.salesKey, err = readTrim(filepath.Join(w.run, "agent-key-sales")); err != nil {
		return err
	}
	if w.internKey, err = readTrim(filepath.Join(w.run, "agent-key-intern")); err != nil {
		return err
	}
	w.keys = map[string]ed25519.PrivateKey{}
	for _, n := range []string{"admin-a", "admin-b", "admin-c"} {
		hx, err := readTrim(filepath.Join(w.run, "keys", n+".key"))
		if err != nil {
			return err
		}
		seed, err := hex.DecodeString(hx)
		if err != nil || len(seed) != ed25519.SeedSize {
			return fmt.Errorf("key %s: not a hex ed25519 seed", n)
		}
		w.keys[n] = ed25519.NewKeyFromSeed(seed)
	}
	// Version counters continue from what the control plane already has (demo.sh published v1).
	for _, t := range tenants {
		var rv wire.RolloutView
		if code, _, _ := w.admin("GET", wire.PathRollouts+"?tenant="+t, nil, &rv); code == 200 {
			w.ver[t] = rv.Version
		}
	}
	return nil
}

// need skips unless E2E=1 and returns the world.
func need(t *testing.T) *world {
	t.Helper()
	if !enabled() {
		t.Skip("E2E is not 1: chaos scenarios need Docker and the compose stack (make chaos)")
	}
	return W
}

// ---- control plane client ----

// admin calls the control plane as the admin. It returns the HTTP status and, for a non-2xx answer, the
// error code. A transport error returns status 0.
func (w *world) admin(method, path string, body, out any) (int, wire.ErrorCode, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, cpURL+path, rd)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+w.adminToken)
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	res, err := w.hc.Do(req)
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
			return res.StatusCode, "", fmt.Errorf("decode %s: %w", path, err)
		}
	}
	return res.StatusCode, "", nil
}

func (w *world) fleet(tenant string) (wire.FleetView, error) {
	var fv wire.FleetView
	code, ec, err := w.admin("GET", wire.PathFleet+"?tenant="+tenant, nil, &fv)
	if err == nil && code != 200 {
		err = fmt.Errorf("fleet %s: HTTP %d %s", tenant, code, ec)
	}
	return fv, err
}

func (w *world) fleetRow(id string) (wire.ProxyView, error) {
	p := proxyByID(id)
	fv, err := w.fleet(p.Tenant)
	if err != nil {
		return wire.ProxyView{}, err
	}
	for _, r := range fv.Proxies {
		if string(r.ProxyID) == id {
			return r, nil
		}
	}
	return wire.ProxyView{}, fmt.Errorf("proxy %s not in fleet view", id)
}

func (w *world) timeline(tenant string) (wire.TimelineView, error) {
	var tv wire.TimelineView
	code, ec, err := w.admin("GET", wire.PathTimeline+"?tenant="+tenant, nil, &tv)
	if err == nil && code != 200 {
		err = fmt.Errorf("timeline %s: HTTP %d %s", tenant, code, ec)
	}
	return tv, err
}

func (w *world) rolloutView(tenant string) (wire.RolloutView, error) {
	var rv wire.RolloutView
	code, ec, err := w.admin("GET", wire.PathRollouts+"?tenant="+tenant, nil, &rv)
	if err == nil && code != 200 {
		err = fmt.Errorf("rollout %s: HTTP %d %s", tenant, code, ec)
	}
	return rv, err
}

// ---- policies ----

// payload builds the policy bytes (ARCHITECTURE 10.0). v1 = sales read-only; v2 and later add notes.write
// for sales (same as demo.sh). Extra rules let a scenario widen it.
func payload(tenant string, version uint64, issued, expires time.Time, extraSales map[string]string) []byte {
	sales := map[string]string{"notes.read": "R", "crm.read_*": "R"}
	if version >= 2 {
		sales["notes.write"] = "W"
	}
	for k, v := range extraSales {
		sales[k] = v
	}
	doc := map[string]any{
		"tenant": tenant, "version": version,
		"issued_at":  issued.UTC().Format(time.RFC3339),
		"expires_at": expires.UTC().Format(time.RFC3339),
		"default":    "deny",
		"roles":      map[string]any{"sales": sales, "intern": map[string]string{"notes.read": "R"}},
	}
	b, _ := json.Marshal(doc)
	return b
}

func goodPayload(tenant string, version uint64) []byte {
	return payload(tenant, version, time.Now().Add(-time.Minute), time.Now().Add(72*time.Hour), nil)
}

func (w *world) envelope(p []byte, signers ...string) wire.Envelope {
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: p, Signatures: []wire.Signature{}}
	for _, s := range signers {
		trust.Sign(&env, w.keys[s])
	}
	return env
}

func (w *world) nextVersion(tenant string) uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ver[tenant]++
	return w.ver[tenant]
}

// publish sends an envelope to the control plane and returns the HTTP status and error code.
func (w *world) publish(env wire.Envelope) (int, wire.ErrorCode, wire.PublishResponse, error) {
	var pr wire.PublishResponse
	code, ec, err := w.admin("POST", wire.PathPolicies, env, &pr)
	return code, ec, pr, err
}

// release publishes a good 2-signature policy for the tenant at the next version and starts a rollout.
// It returns the version, the policy hash and the host time just before the publish.
func (w *world) release(t *testing.T, tenant string, dwell uint64) (uint64, wire.Hash, time.Time) {
	t.Helper()
	v := w.nextVersion(tenant)
	t0 := time.Now()
	code, ec, pr, err := w.publish(w.envelope(goodPayload(tenant, v), "admin-a", "admin-b"))
	if err != nil || code/100 != 2 {
		t.Fatalf("publish %s v%d: HTTP %d %s err=%v", tenant, v, code, ec, err)
	}
	var rv wire.RolloutView
	code, ec, err = w.admin("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: wire.ID(tenant), Version: v, CanaryDwellSeconds: dwell}, &rv)
	if err != nil || code/100 != 2 {
		t.Fatalf("rollout start %s v%d: HTTP %d %s err=%v", tenant, v, code, ec, err)
	}
	return v, pr.PolicyHash, t0
}

// ---- proxies ----

type self struct {
	Tenant         string `json:"tenant"`
	ProxyID        string `json:"proxy_id"`
	State          string `json:"state"`
	AppliedVersion uint64 `json:"applied_version"`
	PolicyHash     string `json:"policy_hash"`
	LogSeq         uint64 `json:"log_seq"`
	LogHead        string `json:"log_head"`
	ClockUntrusted bool   `json:"clock_untrusted"`
}

func (w *world) self(p px) (self, error) {
	var s self
	res, err := w.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/v1/self", p.Metrics))
	if err != nil {
		return s, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != 200 {
		return s, fmt.Errorf("self %s: HTTP %d", p.ID, res.StatusCode)
	}
	return s, json.Unmarshal(b, &s)
}

// metric returns the value of the first series whose line starts with prefix (name or name{labels}).
func (w *world) metric(p px, prefix string) (float64, error) {
	res, err := w.hc.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", p.Metrics))
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, prefix) {
			var v float64
			f := strings.Fields(ln)
			if _, err := fmt.Sscanf(f[len(f)-1], "%g", &v); err == nil {
				return v, nil
			}
		}
	}
	return 0, fmt.Errorf("metric %q not found on %s", prefix, p.ID)
}

type callResult struct {
	HTTP    int
	Allowed bool
	Blocked bool
	Text    string
	Err     error
}

// call sends tools/call through proxy p as the given API key.
func (w *world) call(p px, key, tool string) callResult { return w.callWith(w.hc, p, key, tool) }

func (w *world) callWith(hc *http.Client, p px, key, tool string) callResult {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, tool)
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/", p.MCP), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+key)
	res, err := hc.Do(req)
	if err != nil {
		return callResult{Err: err}
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	r := callResult{HTTP: res.StatusCode, Text: string(b)}
	var doc struct {
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	_ = json.Unmarshal(b, &doc)
	r.Blocked = strings.Contains(r.Text, "blocked by policy")
	r.Allowed = res.StatusCode == 200 && doc.Result != nil && !doc.Result.IsError && !r.Blocked
	return r
}

// listTools returns the tool names the proxy shows to the key's role.
func (w *world) listTools(p px, key string) ([]string, error) {
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d/", p.MCP),
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+key)
	res, err := w.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	var doc struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("tools/list: %w (%s)", err, b)
	}
	var out []string
	for _, x := range doc.Result.Tools {
		out = append(out, x.Name)
	}
	return out, nil
}

// wantAllowed is the oracle for fakemcp's four tools under the demo policy at the given version.
// Unknown tools and every other role are denied (default deny).
func wantAllowed(role, tool string, version uint64) bool {
	switch role {
	case "sales":
		switch tool {
		case "notes.read", "crm.read_contact":
			return true
		case "notes.write":
			return version >= 2
		}
	case "intern":
		return tool == "notes.read"
	}
	return false
}

var callMix = []struct{ role, tool string }{
	{"sales", "notes.read"}, {"sales", "crm.read_contact"}, {"sales", "notes.write"}, {"sales", "crm.export"},
	{"sales", "admin.shutdown"}, {"intern", "notes.read"}, {"intern", "notes.write"}, {"intern", "crm.export"},
}

func (w *world) keyFor(role string) string {
	if role == "sales" {
		return w.salesKey
	}
	return w.internKey
}

// ---- docker ----

func docker(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func mustDocker(t *testing.T, args ...string) string {
	t.Helper()
	out, err := docker(args...)
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func containerRunning(name string) bool {
	out, err := docker("inspect", "-f", "{{.State.Running}}", name)
	return err == nil && out == "true"
}

// volumeShell runs a shell snippet against a proxy's data volume with the proxy stopped.
func volumeShell(t *testing.T, p px, script string, stdin string) string {
	t.Helper()
	args := []string{"run", "--rm", "-i", "-v", "kairan-demo_" + p.ID + "-data:/data", "--entrypoint", "sh", image, "-c", script}
	cmd := exec.Command("docker", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("volume shell on %s: %v\n%s", p.ID, err, out)
	}
	return string(out)
}

// ---- waiting ----

// eventually polls f every `every` until it returns true or the time is up, then fails the test with the
// last detail f reported.
func eventually(t *testing.T, limit, every time.Duration, what string, f func() (bool, string)) time.Duration {
	t.Helper()
	start := time.Now()
	last := ""
	for {
		ok, detail := f()
		if ok {
			return time.Since(start)
		}
		last = detail
		if time.Since(start) > limit {
			t.Fatalf("timed out after %v waiting for %s; last state: %s", limit, what, last)
		}
		time.Sleep(every)
	}
}

// ackTimes polls the fleet views of the given tenants (tenant -> version) until every proxy of those tenants,
// or only the listed ones, reports applied >= its tenant's version, and returns the host time at which each
// was first seen doing so. All tenants are watched in one loop so the times are comparable.
func (w *world) ackTimes(t *testing.T, versions map[string]uint64, limit time.Duration, only ...string) map[string]time.Time {
	t.Helper()
	got := map[string]time.Time{}
	include := func(id string) bool {
		if len(only) == 0 {
			return true
		}
		for _, o := range only {
			if o == id {
				return true
			}
		}
		return false
	}
	want := 0
	for tn := range versions {
		for _, p := range tenantProxies(tn) {
			if include(p.ID) {
				want++
			}
		}
	}
	eventually(t, limit, 100*time.Millisecond, fmt.Sprintf("proxies to ack %v", versions), func() (bool, string) {
		var behind []string
		for tn, version := range versions {
			fv, err := w.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			now := time.Now()
			for _, r := range fv.Proxies {
				id := string(r.ProxyID)
				if !include(id) {
					continue
				}
				if r.AppliedVersion >= version {
					if _, seen := got[id]; !seen {
						got[id] = now
					}
				} else {
					behind = append(behind, fmt.Sprintf("%s@%d", id, r.AppliedVersion))
				}
			}
		}
		return len(got) == want, "behind: " + strings.Join(behind, ",")
	})
	return got
}

// baseline heals infrastructure left broken by an earlier scenario: stopped containers are started, proxies
// are reattached to the cloud network, and every proxy must report to the control plane again.
func (w *world) baseline(t *testing.T) {
	t.Helper()
	for _, name := range []string{"kairan-cp", "kairan-fakemcp-bank-a", "kairan-fakemcp-city-b"} {
		if !containerRunning(name) {
			mustDocker(t, "start", name)
		}
	}
	for _, p := range proxies {
		if !containerRunning(p.Container) {
			mustDocker(t, "start", p.Container)
		}
		_, _ = docker("network", "connect", cloudNet, p.Container) // "already exists" is fine
	}
	eventually(t, 90*time.Second, time.Second, "baseline: all proxies healthy at their desired version", func() (bool, string) {
		var bad []string
		for _, tn := range tenants {
			fv, err := w.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			if len(fv.Proxies) != len(tenantProxies(tn)) {
				return false, fmt.Sprintf("%s: %d proxies in fleet view", tn, len(fv.Proxies))
			}
			for _, r := range fv.Proxies {
				if r.Health != wire.HealthHealthy || r.Drift != 0 || r.State != wire.StateEnforcing {
					bad = append(bad, fmt.Sprintf("%s(%s,%s,drift %d)", r.ProxyID, r.Health, r.State, r.Drift))
				}
			}
		}
		return len(bad) == 0, strings.Join(bad, " ")
	})
}

func percentile(ds []time.Duration, p float64) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if s[j] < s[i] {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	idx := int(float64(len(s)-1)*p + 0.5)
	return s[idx]
}
