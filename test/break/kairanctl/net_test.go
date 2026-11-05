package kairanctlbreak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// --- a recording control-plane stub ---

type seen struct {
	method, path, rawQuery, auth, ctype string
	body                                []byte
	hdr                                 http.Header
}

type cpStub struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []seen
	n    atomic.Int64
}

func (c *cpStub) requests() []seen {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]seen(nil), c.reqs...)
}

func newCP(t *testing.T, tls bool, h func(w http.ResponseWriter, r *http.Request, body []byte)) *cpStub {
	t.Helper()
	c := &cpStub{}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		c.mu.Lock()
		c.reqs = append(c.reqs, seen{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), b, r.Header.Clone()})
		c.mu.Unlock()
		c.n.Add(1)
		h(w, r, b)
	})
	if tls {
		c.srv = httptest.NewTLSServer(wrapped)
	} else {
		c.srv = httptest.NewServer(wrapped)
	}
	t.Cleanup(c.srv.Close)
	return c
}

func jsonReply(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", wire.ContentTypeJSON)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// connEnv sets the token through both spellings of the environment variables
// (M-D45 renames KAIRAN_* to KCTL_*; the test must not depend on which one is current).
func connEnv(token string) []string {
	return []string{"KAIRAN_ADMIN_TOKEN=" + token, "KCTL_ADMIN_TOKEN=" + token}
}

const tok = "TOKEN-s3cr3t-d41d8cd98f00b204"

// twoSigEnvelope writes a valid 2-signature envelope file and returns its parsed form.
func twoSigEnvelope(t *testing.T, dir, name string, version int) wire.Envelope {
	t.Helper()
	pb := payload("bank-a", version, stdRoles)
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: pb}
	for i := 0; i < 2; i++ {
		_, pk, _ := ed25519.GenerateKey(nil)
		trust.Sign(&env, pk)
	}
	bs, _ := json.Marshal(env)
	writeFile(t, filepath.Join(dir, name), bs, 0o644)
	return env
}

// connectors: every network subcommand with the arguments it needs.
type sub struct {
	name string
	args func(dir string) []string
}

func subs() []sub {
	return []sub{
		{"publish", func(d string) []string { return []string{"publish", "-in", filepath.Join(d, "env.json")} }},
		{"rollout-start", func(string) []string { return []string{"rollout", "start", "-tenant", "bank-a", "-version", "2"} }},
		{"rollout-status", func(string) []string { return []string{"rollout", "status", "-tenant", "bank-a"} }},
		{"fleet", func(string) []string { return []string{"fleet", "-tenant", "bank-a"} }},
		{"evidence", func(string) []string { return []string{"evidence", "export", "-tenant", "bank-a"} }},
	}
}

func okReply(w http.ResponseWriter, r *http.Request, body []byte) {
	switch r.URL.Path {
	case wire.PathFleet:
		jsonReply(w, 200, wire.FleetView{Tenant: "bank-a", Proxies: []wire.ProxyView{}})
	case wire.PathTimeline:
		jsonReply(w, 200, wire.TimelineView{Tenant: "bank-a", Entries: []wire.TimelineEntry{}})
	case wire.PathRollouts:
		jsonReply(w, 200, wire.RolloutView{Tenant: "bank-a", Version: 2, Phase: wire.PhaseCanary})
	case wire.PathPolicies:
		var e wire.Envelope
		_ = json.Unmarshal(body, &e)
		jsonReply(w, 200, wire.PublishResponse{Tenant: "bank-a", Version: 2, PolicyHash: wire.Hash(sha(e.Payload))})
	default:
		http.NotFound(w, r)
	}
}

// --- M-D31: transport rules ---

func TestPlaintextNeedsExplicitFlag(t *testing.T) {
	bin := buildCtl(t)
	for _, s := range subs() {
		s := s
		t.Run(s.name, func(t *testing.T) {
			d := t.TempDir()
			twoSigEnvelope(t, d, "env.json", 2)
			cp := newCP(t, false, okReply)
			// 1. -url http:// without the flag; 2. env URL without the flag.
			r := runIn(t, bin, d, connEnv(tok), "", append(s.args(d), "-url", cp.srv.URL)...)
			if r.code == 0 || cp.n.Load() != 0 {
				t.Fatalf("http:// without -allow-plaintext: exit %d, server saw %d requests (M-D31: plaintext needs the flag)", r.code, cp.n.Load())
			}
			r = runIn(t, bin, d, append(connEnv(tok), "KAIRAN_CP_URL="+cp.srv.URL, "KCTL_CP_URL="+cp.srv.URL), "", s.args(d)...)
			if r.code == 0 || cp.n.Load() != 0 {
				t.Fatalf("http:// from env without flag: exit %d, requests %d", r.code, cp.n.Load())
			}
			if strings.Contains(r.stdout+r.stderr, tok) {
				t.Fatal("token printed")
			}
			// 3. with the flag it works and carries the bearer token exactly.
			r = runIn(t, bin, d, connEnv(tok), "", append(s.args(d), "-url", cp.srv.URL, "-allow-plaintext")...)
			if r.code != 0 {
				t.Fatalf("with -allow-plaintext: exit %d: %s%s", r.code, r.stdout, r.stderr)
			}
			rs := cp.requests()
			if len(rs) != 1 {
				t.Fatalf("want exactly 1 request, got %d", len(rs))
			}
			if rs[0].auth != wire.BearerPrefix+tok {
				t.Fatalf("Authorization = %q, want Bearer + token exactly", rs[0].auth)
			}
		})
	}
}

func TestURLShapesRefused(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	host := strings.TrimPrefix(cp.srv.URL, "http://")
	bad := []string{
		"http://user:pw@" + host, "http://user@" + host, "http://" + host + "/v1/evil", "http://" + host + "/?x=1", "http://" + host + "?x=1",
		"http://" + host + "#frag", "ftp://" + host, "file:///etc/passwd", "gopher://" + host, "//" + host, host, "", "http://", "https://", "javascript:alert(1)",
		"http://" + host + "%0d%0aX-Evil:1", "http://[::1", "unix:///var/run/x.sock",
	}
	for _, u := range bad {
		r := runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", u, "-allow-plaintext")
		if r.code == 0 {
			t.Fatalf("url %q accepted (T-D4: no userinfo/path/query, https or opted-in http only)", u)
		}
		if strings.Contains(r.stdout+r.stderr, tok) {
			t.Fatalf("url %q: token printed", u)
		}
	}
	if n := cp.n.Load(); n != 0 {
		t.Fatalf("server received %d requests for invalid URLs", n)
	}
	// Userinfo password must not be echoed in errors.
	r := runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", "https://admin:hunter2pass@cp.example", "-allow-plaintext")
	if strings.Contains(r.stdout+r.stderr, "hunter2pass") {
		t.Fatal("URL password echoed in the error text")
	}
}

func TestTokenNeverFromFlag(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	for _, fl := range [][]string{{"-token", tok}, {"-admin-token", tok}, {"--token=" + tok}, {"-token=" + tok}, {"-t", tok}, {"-bearer", tok}, {"-password", tok}} {
		args := append([]string{"fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext"}, fl...)
		r := runIn(t, bin, d, nil, "", args...)
		if r.code == 0 {
			t.Fatalf("%v: accepted a token on the command line (M-D45, T-D4)", fl)
		}
		if strings.Contains(r.stdout+r.stderr, tok) {
			t.Fatalf("%v: token echoed back", fl)
		}
	}
	if n := cp.n.Load(); n != 0 {
		t.Fatalf("a request was made with a flag token (%d)", n)
	}
	// No token at all: refuse locally; do not ask the control plane anonymously.
	r := runIn(t, bin, d, nil, "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
	if r.code == 0 {
		t.Fatal("fleet without any token succeeded")
	}
	if cp.n.Load() != 0 {
		t.Fatalf("request sent without a token (%d)", cp.n.Load())
	}
}

func TestTokenFileRules(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	conn := []string{"fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext"}

	writeFile(t, filepath.Join(d, "tok0600"), []byte(tok+"\n"), 0o600)
	r := runIn(t, bin, d, nil, "", append(conn, "-token-file", "tok0600")...)
	if r.code != 0 {
		t.Fatalf("0600 token file: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
	if rs := cp.requests(); len(rs) != 1 || rs[0].auth != "Bearer "+tok {
		t.Fatalf("token file: auth header %+v, want trailing newline trimmed", rs)
	}
	// Env var pointing at the file works too.
	cp.mu.Lock()
	cp.reqs = nil
	cp.mu.Unlock()
	r = runIn(t, bin, d, []string{"KAIRAN_ADMIN_TOKEN_FILE=tok0600", "KCTL_ADMIN_TOKEN_FILE=tok0600"}, "", conn...)
	if r.code != 0 {
		t.Fatalf("token file from env: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
	// Group/other-readable token files are refused (T-D4 "a 0600 file").
	cp.n.Store(0)
	for _, m := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666} {
		writeFile(t, filepath.Join(d, "tokloose"), []byte(tok+"\n"), m)
		r := runIn(t, bin, d, nil, "", append(conn, "-token-file", "tokloose")...)
		if r.code == 0 || cp.n.Load() != 0 {
			t.Fatalf("token file with mode %v accepted (exit %d, %d requests)", m, r.code, cp.n.Load())
		}
		if strings.Contains(r.stdout+r.stderr, tok) {
			t.Fatal("token printed while refusing a loose file")
		}
	}
	// Directory / missing / empty token files.
	for _, f := range []string{d, filepath.Join(d, "missing"), "/dev/null"} {
		if r := runIn(t, bin, d, nil, "", append(conn, "-token-file", f)...); r.code == 0 {
			t.Fatalf("token file %s accepted", f)
		}
	}
	writeFile(t, filepath.Join(d, "empty"), nil, 0o600)
	if r := runIn(t, bin, d, nil, "", append(conn, "-token-file", "empty")...); r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("empty token file accepted / request sent")
	}
	writeFile(t, filepath.Join(d, "ws"), []byte(" \n\t\n"), 0o600)
	if r := runIn(t, bin, d, nil, "", append(conn, "-token-file", "ws")...); r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("whitespace-only token accepted / request sent")
	}
}

func TestTokenHeaderInjection(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	bad := tok + "\r\nX-Evil: 1"
	r := runIn(t, bin, d, connEnv(bad), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
	for _, q := range cp.requests() {
		if q.hdr.Get("X-Evil") != "" {
			t.Fatal("CR/LF in the token produced an injected header")
		}
	}
	_ = r
}

func TestTokenNeverEchoedByErrors(t *testing.T) {
	bin := buildCtl(t)
	for _, s := range subs() {
		s := s
		t.Run(s.name, func(t *testing.T) {
			d := t.TempDir()
			twoSigEnvelope(t, d, "env.json", 2)
			for _, st := range []int{400, 401, 403, 404, 409, 413, 500, 503} {
				if s.name == "rollout-status" && st == 404 {
					continue // by design: "no rollout yet for tenant"
				}
				cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, body []byte) {
					// A hostile or sloppy server echoes the Authorization header and request body.
					w.Header().Set("Content-Type", "text/plain")
					w.Header().Set("X-Debug", r.Header.Get("Authorization"))
					w.WriteHeader(st)
					fmt.Fprintf(w, "oops %s %s", r.Header.Get("Authorization"), body)
				})
				r := runIn(t, bin, d, connEnv(tok), "", append(s.args(d), "-url", cp.srv.URL, "-allow-plaintext")...)
				if r.code == 0 {
					t.Fatalf("status %d treated as success", st)
				}
				if strings.Contains(r.stdout+r.stderr, tok) {
					t.Fatalf("status %d: token appears in output: %q", st, r.stdout+r.stderr)
				}
				if s.name == "publish" && strings.Contains(r.stdout+r.stderr, "payloadType") {
					t.Fatalf("status %d: server-echoed request body appears in output", st)
				}
			}
		})
	}
}

func TestRedirectsNeverFollowed(t *testing.T) {
	bin := buildCtl(t)
	for _, s := range subs() {
		s := s
		t.Run(s.name, func(t *testing.T) {
			for _, code := range []int{301, 302, 303, 307, 308} {
				d := t.TempDir()
				twoSigEnvelope(t, d, "env.json", 2)
				evil := newCP(t, false, okReply)
				cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, body []byte) {
					http.Redirect(w, r, evil.srv.URL+r.URL.Path+"?"+r.URL.RawQuery, code)
				})
				r := runIn(t, bin, d, connEnv(tok), "", append(s.args(d), "-url", cp.srv.URL, "-allow-plaintext")...)
				if evil.n.Load() != 0 {
					t.Fatalf("redirect %d followed: the second server got the request (token leak: %+v)", code, evil.requests())
				}
				if r.code == 0 {
					t.Fatalf("redirect %d reported as success", code)
				}
			}
		})
	}
}

// --- publish ---

func TestPublishSignatureCountAndBody(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	conn := []string{"-url", cp.srv.URL, "-allow-plaintext"}

	_, k1, _ := ed25519.GenerateKey(nil)
	_, k2, _ := ed25519.GenerateKey(nil)
	pb := payload("bank-a", 2, stdRoles)
	mk := func(n int, ks ...ed25519.PrivateKey) wire.Envelope {
		e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: pb}
		for _, k := range ks {
			trust.Sign(&e, k)
		}
		return e
	}
	write := func(name string, e wire.Envelope) {
		bs, _ := json.Marshal(e)
		writeFile(t, filepath.Join(d, name), bs, 0o644)
	}

	// Refused locally, zero requests (T-D4: publish refuses fewer than 2 signatures).
	refused := map[string]wire.Envelope{
		"zero-sigs": mk(0),
		"one-sig":   mk(1, k1),
	}
	var nine []ed25519.PrivateKey
	for i := 0; i < 9; i++ {
		_, k, _ := ed25519.GenerateKey(nil)
		nine = append(nine, k)
	}
	refused["nine-sigs"] = mk(9, nine...)
	wt := mk(2, k1, k2)
	wt.PayloadType = "text/plain"
	refused["wrong-payload-type"] = wt
	inv := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(`{"tenant":"bank-a","tenant":"city-b"}`)}
	trust.Sign(&inv, k1)
	trust.Sign(&inv, k2)
	refused["invalid-policy-inside"] = inv
	for n, e := range refused {
		write(n+".json", e)
		r := runIn(t, bin, d, connEnv(tok), "", append([]string{"publish", "-in", n + ".json"}, conn...)...)
		if r.code == 0 || cp.n.Load() != 0 {
			t.Fatalf("%s: exit %d, %d requests (publish must refuse before sending)", n, r.code, cp.n.Load())
		}
	}
	// Garbage files.
	for n, c := range map[string]string{"empty": "", "null": "null", "array": "[]", "trailing": func() string { bs, _ := json.Marshal(mk(2, k1, k2)); return string(bs) + "{}" }()} {
		writeFile(t, filepath.Join(d, "g-"+n), []byte(c), 0o644)
		r := runIn(t, bin, d, connEnv(tok), "", append([]string{"publish", "-in", "g-" + n}, conn...)...)
		if r.code == 0 || cp.n.Load() != 0 {
			t.Fatalf("garbage %s: exit %d, %d requests", n, r.code, cp.n.Load())
		}
	}
	// Oversize file.
	writeFile(t, filepath.Join(d, "huge"), bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes+1), 0o644)
	if r := runIn(t, bin, d, connEnv(tok), "", append([]string{"publish", "-in", "huge"}, conn...)...); r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("oversize envelope sent / accepted (exit %d, %d reqs)", r.code, cp.n.Load())
	}

	// Valid: exactly one POST to PathPolicies carrying the envelope as written.
	good := mk(2, k1, k2)
	write("good.json", good)
	r := runIn(t, bin, d, connEnv(tok), "", append([]string{"publish", "-in", "good.json"}, conn...)...)
	if r.code != 0 {
		t.Fatalf("valid publish: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
	rs := cp.requests()
	if len(rs) != 1 || rs[0].method != "POST" || rs[0].path != wire.PathPolicies {
		t.Fatalf("requests: %+v", rs)
	}
	if !strings.HasPrefix(rs[0].ctype, wire.ContentTypeJSON) {
		t.Fatalf("content type %q", rs[0].ctype)
	}
	sent, err := trust.DecodeEnvelope(rs[0].body)
	if err != nil || !bytes.Equal(sent.Payload, pb) || len(sent.Signatures) != 2 {
		t.Fatalf("body is not the envelope as signed: %v", err)
	}
	if bytes.Contains(rs[0].body, []byte(tok)) {
		t.Fatal("token inside the request body")
	}
}

// Four-eyes: the same signature twice is one person (PRD G1). Not spelled out
// for publish itself; the CP/proxy reject it anyway, so this only checks the
// admin tool does not wave it through silently.
func TestPublishDuplicateSignatureNotWavedThrough(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	_, k1, _ := ed25519.GenerateKey(nil)
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload("bank-a", 2, stdRoles)}
	trust.Sign(&e, k1)
	trust.Sign(&e, k1)
	bs, _ := json.Marshal(e)
	writeFile(t, filepath.Join(d, "dup.json"), bs, 0o644)
	r := runIn(t, bin, d, connEnv(tok), "", "publish", "-in", "dup.json", "-url", cp.srv.URL, "-allow-plaintext")
	if r.code == 0 && cp.n.Load() > 0 {
		t.Skip("doc ambiguity Q-D4: publish sends a two-identical-signature envelope; docs say only 'fewer than 2 signatures' (T-D4), PRD G1 wants 2 different people")
	}
}

func TestPublishChecksTheAnswer(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	env := twoSigEnvelope(t, d, "env.json", 2)
	h := wire.Hash(sha(env.Payload))
	other := wire.Hash(strings.Repeat("ab", 32))
	rows := map[string]string{
		"wrong-hash":       fmt.Sprintf(`{"tenant":"bank-a","version":2,"policy_hash":%q}`, other),
		"wrong-version":    fmt.Sprintf(`{"tenant":"bank-a","version":3,"policy_hash":%q}`, h),
		"version-zero":     fmt.Sprintf(`{"tenant":"bank-a","version":0,"policy_hash":%q}`, h),
		"wrong-tenant":     fmt.Sprintf(`{"tenant":"city-b","version":2,"policy_hash":%q}`, h),
		"uppercase-hash":   fmt.Sprintf(`{"tenant":"bank-a","version":2,"policy_hash":%q}`, strings.ToUpper(string(h))),
		"unknown-field":    fmt.Sprintf(`{"tenant":"bank-a","version":2,"policy_hash":%q,"note":"\u001b[31mhi"}`, h),
		"trailing-data":    fmt.Sprintf(`{"tenant":"bank-a","version":2,"policy_hash":%q} {"x":1}`, h),
		"empty-body":       ``,
		"html":             `<html>\x1b[2Jhacked</html>`,
		"escape-in-tenant": fmt.Sprintf(`{"tenant":"bank-a\u001b[2J","version":2,"policy_hash":%q}`, h),
		"array":            `[]`,
		"null":             `null`,
		"missing-hash":     `{"tenant":"bank-a","version":2}`,
		"huge-version":     fmt.Sprintf(`{"tenant":"bank-a","version":99999999999999999999999,"policy_hash":%q}`, h),
	}
	for n, body := range rows {
		n, body := n, body
		cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			w.Header().Set("Content-Type", wire.ContentTypeJSON)
			io.WriteString(w, body)
		})
		r := runIn(t, bin, d, connEnv(tok), "", "publish", "-in", "env.json", "-url", cp.srv.URL, "-allow-plaintext")
		if r.code == 0 {
			t.Errorf("%s: publish reported success on a mismatching/hostile answer (T-D4: checks tenant, version and hash)\nstdout: %s", n, r.stdout)
		}
		if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
			t.Errorf("%s: terminal escape from the server reached the output", n)
		}
	}
	// And the good answer is a success.
	cp := newCP(t, false, okReply)
	if r := runIn(t, bin, d, connEnv(tok), "", "publish", "-in", "env.json", "-url", cp.srv.URL, "-allow-plaintext"); r.code != 0 {
		t.Fatalf("good answer: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
}

// --- hostile answers for the read commands ---

func TestRogueCPNeverReachesTheTerminal(t *testing.T) {
	bin := buildCtl(t)
	esc := `\u001b[2J\u001b]0;pwned\u0007`
	h := strings.Repeat("ab", 32)
	proxy := func(over string) string {
		base := map[string]string{
			"proxy_id": `"p-1"`, "group": `"canary"`, "health": `"healthy"`, "state": `"enforcing"`,
			"desired_version": `2`, "applied_version": `2`, "policy_hash": `"` + h + `"`, "drift": `0`, "last_seen_unix_ms": `1700000000000`,
		}
		for _, kv := range strings.Split(over, "|") {
			if kv == "" {
				continue
			}
			p := strings.SplitN(kv, "=", 2)
			base[p[0]] = p[1]
		}
		var parts []string
		for k, v := range base {
			parts = append(parts, `"`+k+`":`+v)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	fleet := func(tenant, px string) string {
		return `{"tenant":"` + tenant + `","proxies":[` + px + `]}`
	}
	tl := func(tenant, e string) string { return `{"tenant":"` + tenant + `","entries":[` + e + `]}` }
	entry := func(over string) string {
		base := map[string]string{"proxy_id": `"p-1"`, "version": `2`, "policy_hash": `"` + h + `"`, "first_seen_unix_ms": `1700000000000`, "last_seen_unix_ms": `1700000060000`}
		for _, kv := range strings.Split(over, "|") {
			if kv == "" {
				continue
			}
			p := strings.SplitN(kv, "=", 2)
			base[p[0]] = p[1]
		}
		var parts []string
		for k, v := range base {
			parts = append(parts, `"`+k+`":`+v)
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	type row struct {
		name, sub, body string
	}
	rows := []row{
		// fleet
		{"fleet-esc-proxy-id", "fleet", fleet("bank-a", proxy(`proxy_id="p`+esc+`"`))},
		{"fleet-esc-group", "fleet", fleet("bank-a", proxy(`group="g`+esc+`"`))},
		{"fleet-esc-health", "fleet", fleet("bank-a", proxy(`health="`+esc+`"`))},
		{"fleet-bad-health", "fleet", fleet("bank-a", proxy(`health="on fire"`))},
		{"fleet-esc-state", "fleet", fleet("bank-a", proxy(`state="`+esc+`"`))},
		{"fleet-bad-state", "fleet", fleet("bank-a", proxy(`state="enforcing "`))},
		{"fleet-esc-tenant", "fleet", fleet("bank-a"+esc, proxy(""))},
		{"fleet-wrong-tenant", "fleet", fleet("city-b", proxy(""))},
		{"fleet-bad-hash", "fleet", fleet("bank-a", proxy(`policy_hash="`+esc+`"`))},
		{"fleet-short-hash", "fleet", fleet("bank-a", proxy(`policy_hash="abcd"`))},
		{"fleet-bad-last-error", "fleet", fleet("bank-a", proxy(`last_error={"code":"`+esc+`"}`))},
		{"fleet-unknown-field", "fleet", fleet("bank-a", proxy(`note="`+esc+`"`))},
		{"fleet-trailing", "fleet", fleet("bank-a", proxy("")) + ` ` + esc},
		{"fleet-not-json", "fleet", "\x1b[2J" + "garbage"},
		{"fleet-negative-drift", "fleet", fleet("bank-a", proxy(`drift=-1`))},
		{"fleet-huge-ms", "fleet", fleet("bank-a", proxy(`last_seen_unix_ms=99999999999999999999`))},
		// rollout
		{"rollout-esc-phase", "rollout-status", `{"tenant":"bank-a","version":2,"phase":"` + esc + `"}`},
		{"rollout-bad-phase", "rollout-status", `{"tenant":"bank-a","version":2,"phase":"exploding"}`},
		{"rollout-esc-reason", "rollout-status", `{"tenant":"bank-a","version":2,"phase":"halted","reason":"` + esc + `"}`},
		{"rollout-wrong-tenant", "rollout-status", `{"tenant":"city-b","version":2,"phase":"canary"}`},
		{"rollout-start-wrong-tenant", "rollout-start", `{"tenant":"city-b","version":2,"phase":"canary"}`},
		{"rollout-esc-tenant", "rollout-status", `{"tenant":"bank-a` + esc + `","version":2,"phase":"canary"}`},
		// evidence
		{"evidence-esc-proxy", "evidence", tl("bank-a", entry(`proxy_id="p`+esc+`"`))},
		{"evidence-bad-hash", "evidence", tl("bank-a", entry(`policy_hash="`+esc+`"`))},
		{"evidence-wrong-tenant", "evidence", tl("city-b", entry(""))},
		{"evidence-esc-tenant", "evidence", tl("bank-a"+esc, entry(""))},
		{"evidence-unknown-field", "evidence", tl("bank-a", entry(`extra="`+esc+`"`))},
		{"evidence-first-after-last", "evidence", tl("bank-a", entry(`first_seen_unix_ms=1700000060000|last_seen_unix_ms=1700000000000`))},
		{"evidence-negative-time", "evidence", tl("bank-a", entry(`first_seen_unix_ms=-5`))},
		{"evidence-huge-time", "evidence", tl("bank-a", entry(`last_seen_unix_ms=9223372036854775807`))},
		{"evidence-version-zero", "evidence", tl("bank-a", entry(`version=0`))},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			d := t.TempDir()
			twoSigEnvelope(t, d, "env.json", 2)
			cp := newCP(t, false, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
				w.Header().Set("Content-Type", wire.ContentTypeJSON)
				io.WriteString(w, r.body)
			})
			var args []string
			for _, s := range subs() {
				if s.name == r.sub {
					args = s.args(d)
				}
			}
			res := runIn(t, bin, d, connEnv(tok), "", append(args, "-url", cp.srv.URL, "-allow-plaintext")...)
			all := res.stdout + res.stderr
			if strings.ContainsRune(all, 0x1b) || strings.ContainsRune(all, 7) {
				t.Fatalf("server-supplied terminal control characters reached the output (T-D4):\n%q", all)
			}
			if strings.Contains(all, "pwned") || strings.Contains(all, "[2J") {
				t.Fatalf("server-supplied text echoed: %q", all)
			}
			if res.code == 0 {
				t.Fatalf("hostile/invalid answer accepted (exit 0); stdout: %q", res.stdout)
			}
			if res.stdout != "" {
				t.Fatalf("something was printed before/despite validation failure (T-D4: checked before anything is printed): %q", res.stdout)
			}
		})
	}
}

func TestReadCommandsRenderValidAnswers(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	h := strings.Repeat("ab", 32)
	cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		switch r.URL.Path {
		case wire.PathFleet:
			jsonReply(w, 200, wire.FleetView{Tenant: "bank-a", Proxies: []wire.ProxyView{
				{ProxyID: "p-1", Group: "canary", Health: wire.HealthHealthy, State: wire.StateEnforcing, DesiredVersion: 3, AppliedVersion: 3, PolicyHash: wire.Hash(h), LastSeenUnixMs: 1700000000000},
				{ProxyID: "p-2", Group: "main", Health: wire.HealthLost, State: wire.StateSafeMode, DesiredVersion: 3, AppliedVersion: 2, PolicyHash: wire.Hash(h), Drift: 1, LastSeenUnixMs: 1700000000000, LastError: &wire.ApplyError{Code: wire.ErrExpired, Version: 3}},
			}})
		case wire.PathRollouts:
			jsonReply(w, 200, wire.RolloutView{Tenant: "bank-a", Version: 3, Phase: wire.PhaseHalted, Reason: wire.ErrCanaryLost})
		case wire.PathTimeline:
			jsonReply(w, 200, wire.TimelineView{Tenant: "bank-a", Entries: []wire.TimelineEntry{
				{ProxyID: "p-1", Version: 3, PolicyHash: wire.Hash(h), FirstSeenUnixMs: 1700000000000, LastSeenUnixMs: 1700003600000},
				{ProxyID: "p-2", Version: 2, PolicyHash: wire.Hash(h), FirstSeenUnixMs: 1700000000000, LastSeenUnixMs: 1700003600000},
			}})
		}
	})
	c := []string{"-url", cp.srv.URL, "-allow-plaintext"}
	r := runIn(t, bin, d, connEnv(tok), "", append([]string{"fleet", "-tenant", "bank-a"}, c...)...)
	if r.code != 0 || !strings.Contains(r.stdout, "p-1") || !strings.Contains(r.stdout, "p-2") || !strings.Contains(r.stdout, "lost") {
		t.Fatalf("fleet output: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	r = runIn(t, bin, d, connEnv(tok), "", append([]string{"rollout", "status", "-tenant", "bank-a"}, c...)...)
	if r.code != 0 || !strings.Contains(r.stdout, "halted") || !strings.Contains(r.stdout, "canary_lost") {
		t.Fatalf("rollout status output: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	// evidence export: wording from T-D4/J5, JST and UTC, labelled as the control plane's record.
	r = runIn(t, bin, d, connEnv(tok), "", append([]string{"evidence", "export", "-tenant", "bank-a"}, c...)...)
	if r.code != 0 {
		t.Fatalf("evidence: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	out := r.stdout
	for _, want := range []string{"p-1", "p-2", "enforced version 3", "enforced version 2", h, "UTC", "JST", "22:13:20", "07:13:20", "23:13:20"} {
		if !strings.Contains(out, want) {
			t.Errorf("evidence output lacks %q\n%s", want, out)
		}
	}
	if !strings.Contains(strings.ToLower(out), "control plane") && !strings.Contains(out, "制御") && !strings.Contains(out, "コントロール") {
		t.Errorf("evidence must be labelled as the control plane's record (T-D4)\n%s", out)
	}
	// -proxy restricts the output even if the server ignores the filter.
	r = runIn(t, bin, d, connEnv(tok), "", append([]string{"evidence", "export", "-tenant", "bank-a", "-proxy", "p-2"}, c...)...)
	if r.code != 0 || strings.Contains(r.stdout, "p-1") || !strings.Contains(r.stdout, "p-2") {
		t.Errorf("evidence -proxy p-2 shows other proxies or not p-2 (exit %d):\n%s%s", r.code, r.stdout, r.stderr)
	}
}

func TestRequestShapes(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, okReply)
	c := []string{"-url", cp.srv.URL, "-allow-plaintext"}
	run := func(a ...string) result { return runIn(t, bin, d, connEnv(tok), "", append(a, c...)...) }

	run("rollout", "start", "-tenant", "bank-a", "-version", "2", "-canary-dwell", "90s")
	run("rollout", "status", "-tenant", "bank-a")
	run("fleet", "-tenant", "bank-a")
	run("evidence", "export", "-tenant", "bank-a")
	rs := cp.requests()
	if len(rs) != 4 {
		t.Fatalf("expected 4 requests, got %d", len(rs))
	}
	if rs[0].method != "POST" || rs[0].path != wire.PathRollouts {
		t.Fatalf("rollout start: %+v", rs[0])
	}
	var rr wire.RolloutRequest
	if err := wire.Decode(bytes.NewReader(rs[0].body), wire.MaxSmallRequestBytes, &rr); err != nil || rr.Tenant != "bank-a" || rr.Version != 2 || rr.CanaryDwellSeconds != 90 {
		t.Fatalf("rollout body %q: %v %+v", rs[0].body, err, rr)
	}
	for i, p := range []string{wire.PathRollouts, wire.PathFleet, wire.PathTimeline} {
		q := rs[i+1]
		if q.method != "GET" || q.path != p {
			t.Fatalf("request %d: %+v, want GET %s", i+1, q, p)
		}
		vals, _ := url.ParseQuery(q.rawQuery)
		if vals.Get("tenant") != "bank-a" || len(vals) != 1 {
			t.Fatalf("query %q", q.rawQuery)
		}
	}
	// Argument validation happens before any request.
	cp.n.Store(0)
	for _, a := range [][]string{
		{"rollout", "start", "-tenant", "bank-a", "-version", "0"},
		{"rollout", "start", "-tenant", "Bank-A", "-version", "2"},
		{"rollout", "start", "-tenant", "", "-version", "2"},
		{"rollout", "start", "-tenant", "bank-a&tenant=city-b", "-version", "2"},
		{"rollout", "start", "-tenant", "bank-a", "-version", "2", "-canary-dwell", "-5m"},
		{"fleet", "-tenant", "bank-a&x=1"},
		{"fleet", "-tenant", "../../etc"},
		{"fleet", "-tenant", "bank-a%26tenant=city-b"},
		{"fleet"},
		{"evidence", "export", "-tenant", "bank-a", "-proxy", "p 1"},
		{"evidence", "export", "-tenant", "bank-a", "-proxy", "../x"},
	} {
		r := run(a...)
		if r.code == 0 {
			t.Errorf("%v accepted", a)
		}
	}
	if n := cp.n.Load(); n != 0 {
		t.Errorf("%d requests were sent for invalid arguments", n)
	}
}

// --- TLS rules (M-D31) ---

func TestTLSVerificationIsNeverSkipped(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, true, okReply)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cp.srv.Certificate().Raw})
	writeFile(t, filepath.Join(d, "ca.pem"), caPEM, 0o644)
	// httptest servers all share one built-in certificate, so make a distinct CA.
	_, caKey, _ := ed25519.GenerateKey(nil)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "unrelated test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(d, "otherca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	writeFile(t, filepath.Join(d, "garbage.pem"), []byte("not a pem"), 0o644)
	port := cp.srv.URL[strings.LastIndex(cp.srv.URL, ":"):]

	// Unknown CA: refused, handler never reached.
	r := runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL)
	if r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("self-signed server accepted without -ca-file (exit %d, reqs %d): InsecureSkipVerify?", r.code, cp.n.Load())
	}
	if strings.Contains(r.stdout+r.stderr, tok) {
		t.Fatal("token printed")
	}
	// Wrong CA file.
	r = runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-ca-file", "otherca.pem")
	if r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("server accepted with an unrelated CA file (exit %d)", r.code)
	}
	// Garbage / missing CA file: an error, not a silent fallback to insecure.
	for _, f := range []string{"garbage.pem", "missing.pem"} {
		r = runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-ca-file", f)
		if r.code == 0 || cp.n.Load() != 0 {
			t.Fatalf("-ca-file %s: exit %d, reqs %d", f, r.code, cp.n.Load())
		}
	}
	// Host name mismatch (cert is for 127.0.0.1 / example.com, not localhost).
	r = runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", "https://localhost"+port, "-ca-file", "ca.pem")
	if r.code == 0 || cp.n.Load() != 0 {
		t.Fatalf("certificate accepted for the wrong host name (exit %d, reqs %d)", r.code, cp.n.Load())
	}
	// Correct CA works.
	r = runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-ca-file", "ca.pem")
	if r.code != 0 || cp.n.Load() != 1 {
		t.Fatalf("valid TLS with -ca-file failed (exit %d, reqs %d): %s%s", r.code, cp.n.Load(), r.stdout, r.stderr)
	}
	// Redirect from https to http must not be followed either (downgrade).
	plain := newCP(t, false, okReply)
	dg := newCP(t, true, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		http.Redirect(w, r, plain.srv.URL+r.URL.Path, 302)
	})
	writeFile(t, filepath.Join(d, "dgca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: dg.srv.Certificate().Raw}), 0o644)
	runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", dg.srv.URL, "-ca-file", "dgca.pem")
	if plain.n.Load() != 0 {
		t.Fatalf("https -> http downgrade redirect followed; token sent in clear: %+v", plain.requests())
	}
}

// --- 30 second client timeout (M-D31) ---

func TestClientTimeout30s(t *testing.T) {
	if testing.Short() {
		t.Skip("takes ~30s")
	}
	bin := buildCtl(t)
	for name, h := range map[string]func(w http.ResponseWriter, r *http.Request, b []byte){
		"hang-before-headers": func(w http.ResponseWriter, r *http.Request, b []byte) {
			select {
			case <-r.Context().Done():
			case <-time.After(60 * time.Second):
			}
		},
		"slow-drip-body": func(w http.ResponseWriter, r *http.Request, b []byte) {
			w.Header().Set("Content-Type", wire.ContentTypeJSON)
			w.WriteHeader(200)
			fl, _ := w.(http.Flusher)
			for i := 0; i < 120; i++ {
				if _, err := io.WriteString(w, " "); err != nil {
					return
				}
				if fl != nil {
					fl.Flush()
				}
				select {
				case <-r.Context().Done():
					return
				case <-time.After(time.Second):
				}
			}
		},
	} {
		name, h := name, h
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := t.TempDir()
			cp := newCP(t, false, h)
			start := time.Now()
			r := runTimeout(t, bin, d, connEnv(tok), "", 50*time.Second, "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
			el := time.Since(start)
			if r.code == 0 {
				t.Fatal("a hung server produced success")
			}
			if el < 25*time.Second || el > 36*time.Second {
				t.Fatalf("gave up after %v, want about 30s (M-D31: kairanctl client timeout 30s)", el)
			}
		})
	}
}

// --- unbounded answers ---

func TestHugeAnswerIsBounded(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		w.Header().Set("Content-Type", wire.ContentTypeJSON)
		io.WriteString(w, `{"tenant":"bank-a","proxies":[`)
		chunk := strings.Repeat(`{"proxy_id":"p-1","group":"g","health":"healthy","state":"enforcing","desired_version":1,"applied_version":1,"drift":0,"last_seen_unix_ms":1},`, 1000)
		for i := 0; i < 3000; i++ { // ~400 MB
			if _, err := io.WriteString(w, chunk); err != nil {
				return
			}
		}
	})
	start := time.Now()
	r := runIn(t, bin, d, connEnv(tok), "", "fleet", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
	if r.code == 0 {
		t.Fatalf("a 400 MB answer was accepted")
	}
	if len(r.stdout) > 1<<20 {
		t.Fatalf("printed %d bytes from an unbounded answer", len(r.stdout))
	}
	if time.Since(start) > 15*time.Second {
		t.Fatalf("took %v to refuse an oversized answer", time.Since(start))
	}
}
