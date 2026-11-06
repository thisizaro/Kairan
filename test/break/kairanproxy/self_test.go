package kairanproxybreak

// Break pass for P-09: the proxy's local self view (/v1/self) and metrics (/metrics) on metrics_listen.
// Sources: the kairan-proxy command doc (Local self view and metrics), ARCHITECTURE section 10
// (proxy metrics, M-D29, M-D30, M-D37, I4), P-D9 (state label spelling), M-D51 (inbound inside the customer network).

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

func waitDial(t *testing.T, addr string) {
	t.Helper()
	waitFor(t, "listener "+addr, 10*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			c.Close()
		}
		return err == nil
	})
}

// selfLife starts a proxy with a metrics listener.
func selfLife(t *testing.T, version uint64, mod func(c pcfg) pcfg) (*life, string) {
	t.Helper()
	l := newLife(t, "")
	if version > 0 {
		l.offer(version, "admin-a", "admin-b")
	}
	maddr := freePort(t)
	l.start("", func(c pcfg) pcfg {
		c = c.with("metrics_listen", maddr)
		if mod != nil {
			c = mod(c)
		}
		return c
	}, nil)
	waitDial(t, maddr)
	return l, maddr
}

func httpDo(method, url, body string, hdr map[string]string) (int, http.Header, string, error) {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, nil, "", err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := (&http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b), nil
}

type selfView struct {
	Tenant         string `json:"tenant"`
	ProxyID        string `json:"proxy_id"`
	State          string `json:"state"`
	AppliedVersion uint64 `json:"applied_version"`
	PolicyHash     string `json:"policy_hash"`
	LogSeq         uint64 `json:"log_seq"`
	LogHead        string `json:"log_head"`
	ClockUntrusted bool   `json:"clock_untrusted"`
}

func getSelf(t testing.TB, maddr string) (selfView, string) {
	t.Helper()
	code, _, body, err := httpDo("GET", "http://"+maddr+"/v1/self", "", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /v1/self: %d %v %s", code, err, body)
	}
	var v selfView
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("self view is not JSON: %v: %s", err, body)
	}
	return v, body
}

func getMetrics(t testing.TB, maddr string) string {
	t.Helper()
	code, _, body, err := httpDo("GET", "http://"+maddr+"/metrics", "", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /metrics: %d %v %s", code, err, body)
	}
	return body
}

type sample struct {
	name   string
	labels map[string]string
	value  float64
}

var sampleRe = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{(.*)\})?[ \t]+(\S+)([ \t]+-?[0-9]+)?$`)
var labelRe = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"$`)

// parseProm is a strict reader of the text format 0.0.4: any line that is not a comment, blank, or a sample is an error.
func parseProm(t testing.TB, body string) (samples []sample, types map[string]string) {
	t.Helper()
	types = map[string]string{}
	if body != "" && !strings.HasSuffix(body, "\n") {
		t.Errorf("exposition does not end with a newline (format 0.0.4)")
	}
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		ln := sc.Text()
		if strings.TrimSpace(ln) == "" {
			continue
		}
		if strings.HasPrefix(ln, "# TYPE ") {
			f := strings.Fields(ln)
			if len(f) != 4 {
				t.Errorf("bad TYPE line %q", ln)
				continue
			}
			types[f[2]] = f[3]
			continue
		}
		if strings.HasPrefix(ln, "#") {
			continue
		}
		m := sampleRe.FindStringSubmatch(ln)
		if m == nil {
			t.Errorf("line is not a sample in text format 0.0.4: %q", ln)
			continue
		}
		v, err := strconv.ParseFloat(m[4], 64)
		if err != nil {
			t.Errorf("bad value in %q", ln)
			continue
		}
		s := sample{name: m[1], labels: map[string]string{}, value: v}
		if m[3] != "" {
			for _, p := range strings.Split(m[3], ",") {
				lm := labelRe.FindStringSubmatch(strings.TrimSpace(p))
				if lm == nil {
					t.Errorf("bad label %q in %q", p, ln)
					continue
				}
				s.labels[lm[1]] = lm[2]
			}
		}
		samples = append(samples, s)
	}
	return
}

func metricVal(t testing.TB, ss []sample, name string) float64 {
	t.Helper()
	var found []float64
	for _, s := range ss {
		if s.name == name && len(s.labels) == 0 {
			found = append(found, s.value)
		}
	}
	if len(found) != 1 {
		t.Fatalf("metric %s: %d unlabelled series, want 1", name, len(found))
	}
	return found[0]
}

func stateSeries(t testing.TB, ss []sample) (current string, all map[string]float64) {
	t.Helper()
	all = map[string]float64{}
	for _, s := range ss {
		if s.name != "kairan_proxy_state" {
			continue
		}
		if len(s.labels) != 1 {
			t.Errorf("kairan_proxy_state carries labels %v, want only state", s.labels)
		}
		if _, dup := all[s.labels["state"]]; dup {
			t.Errorf("duplicate state series %q", s.labels["state"])
		}
		all[s.labels["state"]] = s.value
		if s.value == 1 {
			if current != "" {
				t.Errorf("two states are 1: %q and %q", current, s.labels["state"])
			}
			current = s.labels["state"]
		} else if s.value != 0 {
			t.Errorf("state %q has value %v, want 0 or 1", s.labels["state"], s.value)
		}
	}
	return
}

var hyphenStates = []string{"booting", "deny-all", "tampered", "enforcing", "safe-mode"}

var documentedMetrics = []string{
	"kairan_proxy_state", "kairan_proxy_applied_version", "kairan_proxy_log_seq", "kairan_proxy_clock_untrusted",
	"kairan_proxy_test_only_trusted_keys",
	"kairan_proxy_calls_allowed_total", "kairan_proxy_calls_denied_total", "kairan_proxy_requests_rejected_total",
	"kairan_proxy_auth_failures_total", "kairan_proxy_upstream_errors_total", "kairan_proxy_policies_applied_total",
	"kairan_proxy_policies_rejected_total", "kairan_proxy_poll_errors_total", "kairan_proxy_status_errors_total",
	"kairan_proxy_policy_expired_total", "kairan_proxy_boot_tampered_total", "kairan_proxy_clock_untrusted_total",
	"kairan_proxy_decision_log_denied_total", "kairan_proxy_decision_log_write_errors_total",
	"kairan_proxy_decision_log_rotate_errors_total",
}

var hex64 = regexp.MustCompile(`[0-9a-f]{64}`)

// The self view is exactly the eight documented fields, with the documented types; after an apply it matches the
// apply log head, the status report and the policy hash.
func TestSelfViewShapeAndAnchor(t *testing.T) {
	l, maddr := selfLife(t, 7, nil)
	l.waitAllowed()
	h := hashOf(l.envelope.Payload)

	code, hdr, body, err := httpDo("GET", "http://"+maddr+"/v1/self", "", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /v1/self: %d %v", code, err)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type %q, want application/json", ct)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &raw); err != nil {
		t.Fatalf("not a JSON object: %v: %s", err, body)
	}
	want := []string{"tenant", "proxy_id", "state", "applied_version", "policy_hash", "log_seq", "log_head", "clock_untrusted"}
	if len(raw) != len(want) {
		t.Errorf("self view has %d fields %v, want exactly %v", len(raw), keysOf(raw), want)
	}
	for _, k := range want {
		if _, ok := raw[k]; !ok {
			t.Errorf("self view lacks %q", k)
		}
	}
	for _, k := range []string{"tenant", "proxy_id", "state", "policy_hash", "log_head"} {
		var s string
		if err := json.Unmarshal(raw[k], &s); err != nil {
			t.Errorf("%s is not a string: %s", k, raw[k])
		}
	}
	for _, k := range []string{"applied_version", "log_seq"} {
		var n uint64
		if err := json.Unmarshal(raw[k], &n); err != nil {
			t.Errorf("%s is not an unsigned integer: %s", k, raw[k])
		}
	}
	var b bool
	if err := json.Unmarshal(raw["clock_untrusted"], &b); err != nil || b {
		t.Errorf("clock_untrusted %s on a sane clock", raw["clock_untrusted"])
	}

	var v selfView
	_ = json.Unmarshal([]byte(body), &v)
	if v.Tenant != tenant || v.ProxyID != proxyID {
		t.Errorf("identity %q/%q, want %q/%q", v.Tenant, v.ProxyID, tenant, proxyID)
	}
	if v.State != string(wire.StateEnforcing) {
		t.Errorf("state %q, want the wire state %q", v.State, wire.StateEnforcing)
	}
	if v.AppliedVersion != 7 || v.PolicyHash != string(h) {
		t.Errorf("version/hash %d/%s, want 7/%s", v.AppliedVersion, v.PolicyHash, h)
	}

	// the apply log is the evidence: the self view carries its anchor
	f, err := os.Open(filepath.Join(l.dir, "apply.log"))
	if err != nil {
		t.Fatal(err)
	}
	last, n, err := applylog.Verify(f)
	f.Close()
	if err != nil || n < 1 {
		t.Fatalf("apply log: %v n=%d", err, n)
	}
	if v.LogSeq != last.Seq || v.LogHead != string(last.Self) {
		t.Errorf("self view anchor (%d,%s) differs from the apply log head (%d,%s)", v.LogSeq, v.LogHead, last.Seq, last.Self)
	}

	// and the status report sent to the control plane says the same
	waitFor(t, "status with the policy", 15*time.Second, func() bool {
		for _, s := range l.cp.statuses() {
			if s.AppliedVersion == 7 {
				return true
			}
		}
		return false
	})
	var rep wire.StatusReport
	for _, s := range l.cp.statuses() {
		if s.AppliedVersion == 7 {
			rep = s
		}
	}
	if string(rep.State) != v.State || rep.AppliedVersion != v.AppliedVersion || string(rep.PolicyHash) != v.PolicyHash ||
		rep.LogSeq != v.LogSeq || string(rep.LogHead) != v.LogHead {
		t.Errorf("status report %+v differs from the self view %+v (THREATS #2 compares them)", rep, v)
	}

	// no secret in it (I4)
	for _, s := range []string{token, keySales, keyIntrn, canary, "sales", "crm."} {
		if strings.Contains(body, s) {
			t.Errorf("self view contains %q", s)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var o []string
	for k := range m {
		o = append(o, k)
	}
	return o
}

// A proxy that has no policy: deny_all, version 0, empty hash, and the metric agrees.
func TestSelfViewWithoutPolicy(t *testing.T) {
	_, maddr := selfLife(t, 0, nil)
	v, body := getSelf(t, maddr)
	if v.State != "deny_all" || v.AppliedVersion != 0 || v.PolicyHash != "" {
		t.Errorf("no policy: %s, want deny_all, 0, empty hash", body)
	}
	if !regexp.MustCompile(`"policy_hash"\s*:\s*""`).MatchString(body) {
		t.Errorf("policy_hash must be the empty string (not null, not absent): %s", body)
	}
	ss, _ := parseProm(t, getMetrics(t, maddr))
	cur, _ := stateSeries(t, ss)
	if cur != "deny-all" {
		t.Errorf("metrics state %q, want deny-all (hyphen, P-D9)", cur)
	}
	if metricVal(t, ss, "kairan_proxy_applied_version") != 0 {
		t.Errorf("applied_version metric is not 0")
	}
}

// /metrics: valid text format 0.0.4, every documented metric, one state series per state with hyphens, one current.
func TestMetricsFormatAndNames(t *testing.T) {
	l, maddr := selfLife(t, 3, nil)
	l.waitAllowed()
	code, hdr, body, err := httpDo("GET", "http://"+maddr+"/metrics", "", nil)
	if err != nil || code != 200 {
		t.Fatalf("GET /metrics: %d %v", code, err)
	}
	if ct := hdr.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") || !strings.Contains(ct, "version=0.0.4") {
		t.Errorf("Content-Type %q, want text/plain; version=0.0.4", ct)
	}
	ss, types := parseProm(t, body)
	have := map[string]bool{}
	for _, s := range ss {
		have[s.name] = true
		if !strings.HasPrefix(s.name, "kairan_proxy_") {
			t.Errorf("metric %q outside the kairan_proxy_ namespace", s.name)
		}
		if s.value < 0 || s.value != s.value {
			t.Errorf("metric %s has value %v", s.name, s.value)
		}
	}
	for _, m := range documentedMetrics {
		if !have[m] {
			t.Errorf("documented metric %s is missing", m)
		}
		want := "counter"
		if !strings.HasSuffix(m, "_total") {
			want = "gauge"
		}
		if got := types[m]; got != "" && got != want {
			t.Errorf("%s TYPE %q, want %s", m, got, want)
		}
	}
	cur, all := stateSeries(t, ss)
	if len(all) != 5 {
		t.Errorf("%d state series %v, want one per state (5)", len(all), all)
	}
	for _, st := range hyphenStates {
		if _, ok := all[st]; !ok {
			t.Errorf("no state series %q (P-D9: hyphens)", st)
		}
	}
	for st := range all {
		if strings.Contains(st, "_") {
			t.Errorf("state label %q uses an underscore", st)
		}
	}
	if cur != "enforcing" {
		t.Errorf("current state %q, want enforcing", cur)
	}
	if got := metricVal(t, ss, "kairan_proxy_applied_version"); got != 3 {
		t.Errorf("applied_version %v, want 3", got)
	}
	// labels: only state, on exactly one metric (I4)
	for _, s := range ss {
		if s.name != "kairan_proxy_state" && len(s.labels) != 0 {
			t.Errorf("metric %s has labels %v; only kairan_proxy_state may (I4)", s.name, s.labels)
		}
	}
	v, _ := getSelf(t, maddr)
	if got := metricVal(t, ss, "kairan_proxy_log_seq"); got != float64(v.LogSeq) {
		t.Errorf("log_seq metric %v differs from the self view %d", got, v.LogSeq)
	}
	if got := metricVal(t, ss, "kairan_proxy_policies_applied_total"); got != 1 {
		t.Errorf("policies_applied_total %v after one apply", got)
	}
	if got := metricVal(t, ss, "kairan_proxy_boot_tampered_total"); got != 0 {
		t.Errorf("boot_tampered_total %v on a clean boot", got)
	}
	if got := metricVal(t, ss, "kairan_proxy_clock_untrusted"); got != 0 {
		t.Errorf("clock_untrusted gauge %v on a sane clock", got)
	}
}

// I4: nothing from a call (arguments, tool, key, role, token, hash) reaches either output, with hostile values.
func TestSelfAndMetricsLeakNothing(t *testing.T) {
	l, maddr := selfLife(t, 2, nil)
	l.waitAllowed()
	hostile := []string{
		canary, `"}` + "\n" + `kairan_proxy_evil 1`, "tool\"name\nx", strings.Repeat("A", 4000),
	}
	for _, h := range hostile {
		l.p.call(keySales, callBody("crm.update_deal", fmt.Sprintf(`{"note":%q}`, h)))
		l.p.call(keySales, callBody(fmt.Sprintf("evil.%.20s", h), `{}`))
		l.p.call("bad-key-"+canary, callBody("crm.read_contact", `{}`))
		l.p.call(keySales, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"`+canary+`"`)
	}
	m := getMetrics(t, maddr)
	_, selfBody := getSelf(t, maddr)
	h := hashOf(l.envelope.Payload)
	for _, c := range []struct{ what, body string }{{"metrics", m}, {"self", selfBody}} {
		for _, s := range []string{canary, token, keySales, keyIntrn, "crm.", "admin.shutdown", "sales", "intern", "evil", "tool\\\"name"} {
			if strings.Contains(c.body, s) {
				t.Errorf("%s output contains %q (I4)", c.what, s)
			}
		}
	}
	if strings.Contains(m, string(h)) {
		t.Errorf("metrics contain the policy hash (never a metric label)")
	}
	if hex64.MatchString(m) {
		t.Errorf("metrics contain a 64-hex value (a hash): %s", hex64.FindString(m))
	}
	ss, _ := parseProm(t, m)
	for _, s := range ss {
		if s.name == "kairan_proxy_evil" {
			t.Errorf("injected metric line from a request body")
		}
	}
	if got := metricVal(t, ss, "kairan_proxy_auth_failures_total"); got < float64(len(hostile)) {
		t.Errorf("auth_failures_total %v after %d bad keys", got, len(hostile))
	}
}

// Counters move by exactly the events: one allowed call, one denied call, one auth failure.
func TestMetricsCountersMove(t *testing.T) {
	l, maddr := selfLife(t, 4, nil)
	l.waitAllowed()
	read := func() map[string]float64 {
		ss, _ := parseProm(t, getMetrics(t, maddr))
		o := map[string]float64{}
		for _, s := range ss {
			if len(s.labels) == 0 {
				o[s.name] = s.value
			}
		}
		return o
	}
	b := read()
	l.p.call(keySales, callBody("crm.read_contact", `{}`))
	a1 := read()
	if d := a1["kairan_proxy_calls_allowed_total"] - b["kairan_proxy_calls_allowed_total"]; d != 1 {
		t.Errorf("one allowed call moved calls_allowed_total by %v", d)
	}
	if d := a1["kairan_proxy_calls_denied_total"] - b["kairan_proxy_calls_denied_total"]; d != 0 {
		t.Errorf("one allowed call moved calls_denied_total by %v", d)
	}
	l.p.call(keySales, callBody("admin.shutdown", `{}`))
	a2 := read()
	if d := a2["kairan_proxy_calls_denied_total"] - a1["kairan_proxy_calls_denied_total"]; d != 1 {
		t.Errorf("one denied call moved calls_denied_total by %v", d)
	}
	if d := a2["kairan_proxy_calls_allowed_total"] - a1["kairan_proxy_calls_allowed_total"]; d != 0 {
		t.Errorf("one denied call moved calls_allowed_total by %v", d)
	}
	l.p.call("nope", callBody("crm.read_contact", `{}`))
	a3 := read()
	if d := a3["kairan_proxy_auth_failures_total"] - a2["kairan_proxy_auth_failures_total"]; d != 1 {
		t.Errorf("one bad key moved auth_failures_total by %v", d)
	}
	if d := a3["kairan_proxy_calls_allowed_total"] - a2["kairan_proxy_calls_allowed_total"]; d != 0 {
		t.Errorf("a bad key counted as an allowed call")
	}
	for k, v := range a3 {
		if strings.HasSuffix(k, "_total") && v < b[k] {
			t.Errorf("counter %s went down: %v -> %v", k, b[k], v)
		}
	}
	for i := 0; i < 5; i++ {
		getMetrics(t, maddr)
		getSelf(t, maddr)
	}
	a4 := read()
	if a4["kairan_proxy_calls_allowed_total"] != a3["kairan_proxy_calls_allowed_total"] || a4["kairan_proxy_calls_denied_total"] != a3["kairan_proxy_calls_denied_total"] {
		t.Errorf("reading the metrics changed the call counters")
	}
}

// Bad offers move policies_rejected_total and never the applied version or the self view.
func TestMetricsRejectedPolicies(t *testing.T) {
	l, maddr := selfLife(t, 5, nil)
	l.waitAllowed()
	before, _ := getSelf(t, maddr)
	bad := envelopeOf(validPolicy(6), key(t, "admin-a"))
	l.cp.mu.Lock()
	l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) { return bad, true }
	l.cp.mu.Unlock()
	waitFor(t, "a rejected policy", 15*time.Second, func() bool {
		ss, _ := parseProm(t, getMetrics(t, maddr))
		return metricVal(t, ss, "kairan_proxy_policies_rejected_total") >= 1
	})
	after, _ := getSelf(t, maddr)
	// the apply log records the rejection (the anchor moves); what is enforced does not
	if after.State != before.State || after.AppliedVersion != before.AppliedVersion || after.PolicyHash != before.PolicyHash {
		t.Errorf("a rejected offer changed what is enforced: %+v -> %+v", before, after)
	}
	if after.LogSeq < before.LogSeq {
		t.Errorf("log_seq went backwards on a rejection: %d -> %d", before.LogSeq, after.LogSeq)
	}
	if f, err := os.Open(filepath.Join(l.dir, "apply.log")); err == nil {
		last, _, verr := applylog.Verify(f)
		f.Close()
		if verr != nil || (after.LogSeq == last.Seq && after.LogHead != string(last.Self)) {
			t.Errorf("anchor (%d,%s) vs apply log (%d,%s) %v", after.LogSeq, after.LogHead, last.Seq, last.Self, verr)
		}
	}
	ss, _ := parseProm(t, getMetrics(t, maddr))
	if metricVal(t, ss, "kairan_proxy_applied_version") != 5 || metricVal(t, ss, "kairan_proxy_policies_applied_total") != 1 {
		t.Errorf("a rejected offer changed applied metrics")
	}
}

// Method and path handling: GET and HEAD only; 405 on other methods for the two routes; 404 elsewhere; no auth needed.
func TestSelfMethodsAndPaths(t *testing.T) {
	l, maddr := selfLife(t, 1, nil)
	l.waitAllowed()
	base := "http://" + maddr
	for _, path := range []string{"/v1/self", "/metrics"} {
		for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "PROPFIND"} {
			t.Run(m+" "+path, func(t *testing.T) {
				c, _, body, err := httpDo(m, base+path, `{"x":1}`, nil)
				if err != nil {
					t.Fatalf("%v", err)
				}
				if c != 405 {
					t.Errorf("%s %s answered %d, want 405", m, path, c)
				}
				if strings.Contains(body, "kairan_proxy_") || strings.Contains(body, "policy_hash") {
					t.Errorf("%s %s leaked data in the error body", m, path)
				}
			})
		}
		t.Run("HEAD "+path, func(t *testing.T) {
			c, hdr, body, err := httpDo("HEAD", base+path, "", nil)
			if err != nil || c != 200 || body != "" {
				t.Errorf("HEAD %s: %d %v body %q", path, c, err, body)
			}
			if hdr.Get("Content-Type") == "" {
				t.Errorf("HEAD %s has no Content-Type", path)
			}
		})
		t.Run("auth is not needed and not looked at "+path, func(t *testing.T) {
			for _, h := range []map[string]string{nil, {"Authorization": "Bearer garbage"}, {"Authorization": "Bearer " + keySales}, {"Authorization": "Basic eDp5"}} {
				c, _, body, err := httpDo("GET", base+path, "", h)
				if err != nil || c != 200 {
					t.Errorf("GET %s with %v: %d %v", path, h, c, err)
				}
				if strings.Contains(body, keySales) {
					t.Errorf("a credential came back in the body")
				}
			}
		})
		t.Run("request body on GET is ignored "+path, func(t *testing.T) {
			c, _, _, err := httpDo("GET", base+path, strings.Repeat("A", 1<<20), nil)
			if err != nil || c != 200 {
				t.Errorf("GET %s with a 1 MiB body: %d %v", path, c, err)
			}
		})
	}
	for _, path := range []string{"/", "/v1", "/v1/", "/v1/self/", "/v1/SELF", "/Metrics", "/metrics/", "/metrics.json", "/v1/status", "/v1/poll", "/v1/self/x", "/mcp", "/debug/pprof/", "/debug/vars", "/v1/self%00", "/favicon.ico", "/admin", "/healthz"} {
		t.Run("GET "+path, func(t *testing.T) {
			c, _, body, err := httpDo("GET", base+path, "", nil)
			if err != nil {
				return
			}
			if c == 200 {
				t.Errorf("GET %s answered 200: %s", path, clip(body))
			}
			if c >= 500 {
				t.Errorf("GET %s answered %d", path, c)
			}
			if c != 404 && c != 400 && c != 301 && c != 308 {
				t.Errorf("GET %s answered %d, want 404", path, c)
			}
			if strings.Contains(body, "goroutine") || strings.Contains(body, "cmdline") {
				t.Errorf("GET %s exposes debug data: %s", path, clip(body))
			}
		})
	}
	t.Run("query strings do not change the answer", func(t *testing.T) {
		c, _, body, err := httpDo("GET", base+"/v1/self?proxy_id=other&tenant=bank-b", "", nil)
		if err != nil || c != 200 {
			t.Fatalf("%d %v", c, err)
		}
		var v selfView
		_ = json.Unmarshal([]byte(body), &v)
		if v.Tenant != tenant || v.ProxyID != proxyID {
			t.Errorf("a query string changed the identity: %s", body)
		}
	})
	t.Run("the MCP listener does not serve them", func(t *testing.T) {
		for _, p := range []string{"/v1/self", "/metrics"} {
			c, _, body, err := httpDo("GET", "http://"+l.listen+p, "", map[string]string{"Authorization": "Bearer " + keySales})
			if err == nil && c == 200 && (strings.Contains(body, "kairan_proxy_") || strings.Contains(body, "policy_hash")) {
				t.Errorf("GET %s on the MCP listener returned the local view", p)
			}
		}
	})
	t.Run("the metrics listener does not serve MCP", func(t *testing.T) {
		c, _, body, err := httpDo("POST", base+"/", callBody("crm.read_contact", `{}`), map[string]string{"Authorization": "Bearer " + keySales})
		if err == nil && (c == 200 || strings.Contains(body, "ran")) {
			t.Errorf("a tool call was served on the metrics listener: %d %s", c, clip(body))
		}
	})
	t.Run("raw request lines", func(t *testing.T) {
		for _, req := range []string{
			"GET /metrics HTTP/1.0\r\n\r\n",
			"GET /v1/self HTTP/1.1\r\nHost: evil.example\r\nConnection: close\r\n\r\n",
			"GET /metrics HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\nConnection: close\r\n\r\n0\r\n\r\n",
			"GET http://evil.example/metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			"GET /v1/../metrics HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			strings.Repeat("A", 70000) + "\r\n\r\n",
			"GET /" + strings.Repeat("a", 70000) + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
			"\x00\x01\x02\r\n\r\n",
		} {
			c, err := net.DialTimeout("tcp", maddr, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			c.SetDeadline(time.Now().Add(5 * time.Second))
			_, _ = c.Write([]byte(req))
			b, _ := io.ReadAll(c)
			c.Close()
			if bytes.Contains(b, []byte(token)) || bytes.Contains(b, []byte(keySales)) {
				t.Errorf("secret in a raw reply")
			}
			if bytes.HasPrefix(b, []byte("HTTP/1.1 5")) {
				t.Errorf("server error for raw request %q: %s", clip(req[:min(len(req), 60)]), clip(string(b)))
			}
		}
		if c, _, _, err := httpDo("GET", base+"/metrics", "", nil); err != nil || c != 200 {
			t.Errorf("listener not answering after hostile requests: %d %v", c, err)
		}
	})
	t.Run("half-open requests do not block other readers or enforcement", func(t *testing.T) {
		var conns []net.Conn
		for i := 0; i < 50; i++ {
			c, err := net.Dial("tcp", maddr)
			if err != nil {
				break
			}
			_, _ = c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: x\r\nX-A: "))
			conns = append(conns, c)
		}
		defer func() {
			for _, c := range conns {
				c.Close()
			}
		}()
		if c, _, _, err := httpDo("GET", base+"/v1/self", "", nil); err != nil || c != 200 {
			t.Errorf("a reader is blocked by half-open requests: %d %v", c, err)
		}
		if r := l.p.call(keySales, callBody("crm.read_contact", `{}`)); !allowed(r) {
			t.Errorf("half-open requests on the metrics listener hurt enforcement: %+v", r)
		}
	})
}

// Concurrent readers during calls and an apply: no torn view (version 0 iff no hash, enforcing implies a policy),
// no error, monotone anchors.
func TestSelfConcurrentConsistency(t *testing.T) {
	l := newLife(t, "")
	maddr := freePort(t)
	l.start("", func(c pcfg) pcfg { return c.with("metrics_listen", maddr) }, nil)
	waitDial(t, maddr)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	var errs []string
	fail := func(f string, a ...any) { mu.Lock(); errs = append(errs, fmt.Sprintf(f, a...)); mu.Unlock() }
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var lastSeq, lastVer uint64
			for {
				select {
				case <-stop:
					return
				default:
				}
				code, _, body, err := httpDo("GET", "http://"+maddr+"/v1/self", "", nil)
				if err != nil || code != 200 {
					fail("self: %d %v", code, err)
					return
				}
				var v selfView
				if json.Unmarshal([]byte(body), &v) != nil {
					fail("not JSON: %s", body)
					return
				}
				if (v.AppliedVersion == 0) != (v.PolicyHash == "") {
					fail("torn view: version %d with hash %q", v.AppliedVersion, v.PolicyHash)
				}
				if v.State == "enforcing" && v.AppliedVersion == 0 {
					fail("enforcing without a policy: %s", body)
				}
				if v.LogSeq < lastSeq || v.AppliedVersion < lastVer {
					fail("went backwards: seq %d->%d version %d->%d", lastSeq, v.LogSeq, lastVer, v.AppliedVersion)
				}
				lastSeq, lastVer = v.LogSeq, v.AppliedVersion
				if i%2 == 0 {
					code, _, mb, err := httpDo("GET", "http://"+maddr+"/metrics", "", nil)
					if err != nil || code != 200 || !strings.Contains(mb, "kairan_proxy_state") {
						fail("metrics: %d %v", code, err)
						return
					}
				}
			}
		}(i)
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				l.p.call(keySales, callBody("crm.read_contact", `{}`))
				l.p.call(keySales, callBody("admin.shutdown", `{}`))
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	l.offer(9, "admin-a", "admin-b")
	l.waitAllowed()
	time.Sleep(500 * time.Millisecond)
	close(stop)
	wg.Wait()
	for _, e := range errs {
		t.Error(e)
	}
	v, _ := getSelf(t, maddr)
	if v.AppliedVersion != 9 || v.State != "enforcing" {
		t.Errorf("after the apply: %+v", v)
	}
}

// States on the wire: tampered and safe mode, in the self view with underscores and in metrics with hyphens.
func TestSelfStatesTamperedAndSafeMode(t *testing.T) {
	t.Run("tampered", func(t *testing.T) {
		l := newLife(t, "")
		l.offer(4, "admin-a", "admin-b")
		l.start("", nil, nil)
		l.waitAllowed()
		l.stop()
		os.WriteFile(l.policyFile(), []byte("garbage"), 0o600)
		dead := httptest.NewServer(http.NotFoundHandler())
		du := dead.URL
		dead.Close()
		maddr := freePort(t)
		l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
		l2.start(du, func(c pcfg) pcfg { return c.with("metrics_listen", maddr) }, nil)
		waitDial(t, maddr)
		v, body := getSelf(t, maddr)
		if v.State != "tampered" {
			t.Errorf("state %q, want tampered: %s", v.State, body)
		}
		if v.PolicyHash != "" {
			t.Errorf("a tampered proxy shows policy_hash %q; no policy is in force", v.PolicyHash)
		}
		ss, _ := parseProm(t, getMetrics(t, maddr))
		if cur, _ := stateSeries(t, ss); cur != "tampered" {
			t.Errorf("metric state %q, want tampered", cur)
		}
		if metricVal(t, ss, "kairan_proxy_boot_tampered_total") != 1 {
			t.Errorf("boot_tampered_total %v, want 1", metricVal(t, ss, "kairan_proxy_boot_tampered_total"))
		}
		l2.p.call(keySales, callBody("crm.read_contact", `{}`))
		ss, _ = parseProm(t, getMetrics(t, maddr))
		if metricVal(t, ss, "kairan_proxy_calls_allowed_total") != 0 {
			t.Errorf("a tampered proxy counted an allowed call (I3)")
		}
	})
	for _, mode := range []string{"read_only", "deny_all"} {
		t.Run("safe_mode "+mode, func(t *testing.T) {
			l := newLife(t, "")
			env := envelopeOf(policyDoc(tenant, 1, time.Now().Add(-time.Hour), time.Now().Add(3*time.Second)), key(t, "admin-a"), key(t, "admin-b"))
			l.cp.mu.Lock()
			l.cp.offer = func(n int, have uint64) (wire.Envelope, bool) { return env, have < 1 }
			l.cp.mu.Unlock()
			maddr := freePort(t)
			l.start("", func(c pcfg) pcfg {
				return c.with("skew", "1s").with("safe_mode", mode).with("metrics_listen", maddr)
			}, nil)
			l.waitAllowed()
			waitFor(t, "safe mode in the self view", 20*time.Second, func() bool {
				c, _, body, err := httpDo("GET", "http://"+maddr+"/v1/self", "", nil)
				return err == nil && c == 200 && strings.Contains(body, `"safe_mode"`)
			})
			v, _ := getSelf(t, maddr)
			if v.State != "safe_mode" {
				t.Errorf("state %q", v.State)
			}
			if v.AppliedVersion != 1 {
				t.Errorf("safe mode lost the applied version: %d", v.AppliedVersion)
			}
			ss, _ := parseProm(t, getMetrics(t, maddr))
			cur, all := stateSeries(t, ss)
			if cur != "safe-mode" {
				t.Errorf("metric state %q, want safe-mode (hyphen)", cur)
			}
			if _, bad := all["safe_mode"]; bad {
				t.Errorf("a state series with an underscore exists")
			}
			if metricVal(t, ss, "kairan_proxy_policy_expired_total") < 1 {
				t.Errorf("policy_expired_total did not move")
			}
		})
	}
}

// M-D30: a wall clock behind the high-water mark is reported in both outputs.
func TestSelfClockUntrusted(t *testing.T) {
	l := newLife(t, "")
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	l.stop()
	hw := filepath.Join(l.dir, "highwater")
	b, _ := os.ReadFile(hw)
	cur, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("high-water: %q", b)
	}
	os.WriteFile(hw, []byte(cur.Add(2*time.Hour).UTC().Format(time.RFC3339Nano)+"\n"), 0o600)
	dead := httptest.NewServer(http.NotFoundHandler())
	du := dead.URL
	dead.Close()
	maddr := freePort(t)
	l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
	l2.start(du, func(c pcfg) pcfg { return c.with("metrics_listen", maddr) }, nil)
	waitDial(t, maddr)
	v, body := getSelf(t, maddr)
	if !v.ClockUntrusted {
		t.Errorf("wall clock 2h behind the high-water mark but clock_untrusted is false: %s", body)
	}
	ss, _ := parseProm(t, getMetrics(t, maddr))
	if metricVal(t, ss, "kairan_proxy_clock_untrusted") != 1 {
		t.Errorf("clock_untrusted gauge %v, want 1", metricVal(t, ss, "kairan_proxy_clock_untrusted"))
	}
	if metricVal(t, ss, "kairan_proxy_clock_untrusted_total") < 1 {
		t.Errorf("clock_untrusted_total did not count (M-D30)")
	}
}

// M-D37: the TEST-ONLY trusted key gauge is positive with fixture keys and zero with others.
func TestMetricsTestOnlyKeys(t *testing.T) {
	_, maddr := selfLife(t, 0, nil)
	ss, _ := parseProm(t, getMetrics(t, maddr))
	if metricVal(t, ss, "kairan_proxy_test_only_trusted_keys") < 1 {
		t.Errorf("fixture keys are trusted but test_only_trusted_keys is 0")
	}
	pubs := []string{strings.Repeat("ab", 32), strings.Repeat("cd", 32)}
	_, maddr2 := selfLife(t, 0, func(c pcfg) pcfg { return c.with("trusted_keys", pubs) })
	ss, _ = parseProm(t, getMetrics(t, maddr2))
	if got := metricVal(t, ss, "kairan_proxy_test_only_trusted_keys"); got != 0 {
		t.Errorf("no fixture key is trusted but the gauge is %v", got)
	}
}

// Restart: the self view's anchor is the apply log head across a restart.
func TestSelfSurvivesRestart(t *testing.T) {
	l, maddr := selfLife(t, 6, nil)
	l.waitAllowed()
	before, _ := getSelf(t, maddr)
	l.stop()
	dead := httptest.NewServer(http.NotFoundHandler())
	du := dead.URL
	dead.Close()
	m2 := freePort(t)
	l2 := &life{t: t, dir: l.dir, cp: l.cp, up: l.up}
	l2.start(du, func(c pcfg) pcfg { return c.with("metrics_listen", m2) }, nil)
	waitDial(t, m2)
	after, body := getSelf(t, m2)
	if after.AppliedVersion != 6 || after.PolicyHash != before.PolicyHash || after.State != "enforcing" {
		t.Errorf("after restart %s, before %+v", body, before)
	}
	if after.LogSeq < before.LogSeq {
		t.Errorf("log_seq went back across a restart: %d -> %d", before.LogSeq, after.LogSeq)
	}
	f, _ := os.Open(filepath.Join(l.dir, "apply.log"))
	last, _, err := applylog.Verify(f)
	f.Close()
	if err != nil || after.LogSeq != last.Seq || after.LogHead != string(last.Self) {
		t.Errorf("anchor (%d,%s) differs from the apply log (%d,%s) %v", after.LogSeq, after.LogHead, last.Seq, last.Self, err)
	}
}

// Configuration of metrics_listen.
func TestMetricsListenConfig(t *testing.T) {
	t.Run("same as listen is a config error, exit 2", func(t *testing.T) {
		addr := freePort(t)
		c := baseCfg(t, filepath.Join(t.TempDir(), "d"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", addr).with("metrics_listen", addr)
		code, out := runOnce(t, c.bytes(), nil)
		if code != 2 {
			t.Errorf("exit %d, want 2: %s", code, clip(out))
		}
		if strings.Contains(out, token) || strings.Contains(out, keySales) {
			t.Errorf("secret in the error")
		}
	})
	for name, v := range map[string]any{
		"not host:port": "nonsense", "empty": "", "no port": "127.0.0.1", "named port": "127.0.0.1:http-alt", "number": 9090,
		"bool": true, "list": []string{"127.0.0.1:1"}, "port too large": "127.0.0.1:70000", "negative": "127.0.0.1:-1",
	} {
		t.Run("invalid value "+name, func(t *testing.T) {
			c := baseCfg(t, filepath.Join(t.TempDir(), "d"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t)).with("metrics_listen", v)
			code, out := runOnce(t, c.bytes(), nil)
			if code == 0 || code == -1 {
				t.Errorf("exit %d for metrics_listen=%v (must not run): %s", code, v, clip(out))
			}
		})
	}
	t.Run("port in use stops the proxy", func(t *testing.T) {
		hold := httptest.NewServer(http.NotFoundHandler())
		defer hold.Close()
		taken := strings.TrimPrefix(hold.URL, "http://")
		d := filepath.Join(t.TempDir(), "d")
		c := baseCfg(t, d, "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t)).with("metrics_listen", taken)
		code, out := runOnce(t, c.bytes(), nil)
		if code != 1 {
			t.Errorf("exit %d, want 1 (runtime failure at startup): %s", code, clip(out))
		}
	})
	t.Run("duplicate and case-variant key", func(t *testing.T) {
		addr := freePort(t)
		base := string(baseCfg(t, filepath.Join(t.TempDir(), "d"), "http://127.0.0.1:9", "http://127.0.0.1:9/mcp", freePort(t)).bytes())
		for _, extra := range []string{
			fmt.Sprintf(`,"metrics_listen":%q,"metrics_listen":%q`, addr, addr),
			fmt.Sprintf(`,"Metrics_Listen":%q`, addr),
		} {
			raw := strings.TrimSuffix(base, "}") + extra + "}"
			code, out := runOnce(t, []byte(raw), nil)
			if code != 2 {
				t.Errorf("exit %d for %s, want 2: %s", code, extra, clip(out))
			}
		}
	})
	t.Run("unset means no second listener", func(t *testing.T) {
		l := newLife(t, "")
		l.start("", nil, nil)
		for _, p := range []string{"/v1/self", "/metrics"} {
			c, _, body, err := httpDo("GET", "http://"+l.listen+p, "", nil)
			if err == nil && c == 200 && (strings.Contains(body, "kairan_proxy_") || strings.Contains(body, "applied_version")) {
				t.Errorf("without metrics_listen, the MCP listener serves %s", p)
			}
		}
	})
	t.Run("the metrics listener goes with the proxy on SIGTERM", func(t *testing.T) {
		l, maddr := selfLife(t, 0, nil)
		l.stop()
		if c, err := net.DialTimeout("tcp", maddr, 500*time.Millisecond); err == nil {
			c.Close()
			t.Errorf("metrics listener still open after shutdown")
		}
	})
	t.Run("a half-open reader does not block shutdown", func(t *testing.T) {
		l, maddr := selfLife(t, 0, nil)
		c, err := net.Dial("tcp", maddr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, _ = c.Write([]byte("GET /metrics HTTP/1.1\r\nHost: x\r\n"))
		l.p.signal(15)
		if code, ok := l.p.waitExit(10 * time.Second); !ok || code != 0 {
			t.Errorf("shutdown with a half-open metrics request: exited=%v code=%d", ok, code)
		}
	})
}
