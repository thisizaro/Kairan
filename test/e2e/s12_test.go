package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// S12 rogue control plane (I1, I2, THREATS #1-#3): a REAL kairan-proxy is pointed at a hostile control plane
// that serves forged, 1-signature, duplicate-signature, wrong-tenant, older-version, equal-version, expired,
// tampered, wrong-payload-type, too-many-signature, oversize, malformed and version-lying answers, every one
// of them carrying a policy that would widen permissions.
//
// Topology (own containers next to the demo stack, nothing simulated; the rogue is deploy/compose/rogue, a
// scripted stdlib server built on the host and mounted into a kairan:demo container, like the S9 forward proxy):
//
//	s12 network: kairan-s12-rogue (alias rogue-cp), kairan-s12-px (the real proxy), kairan-s12-fakemcp
//
// Pass, for every bad offer: 0 applied (self-reported applied version and policy hash unchanged, the apply
// counter unchanged, calls still answered by the baseline policy), the proxy keeps polling with have=<applied
// version>, the rejection counter grows, and the reject reason reaches the control plane in its status
// report (the code the wire contract names for that defect). Afterwards a good newer policy is applied, so
// the proxy was never wedged.
const (
	s12Net     = "kairan-s12"
	s12Tenant  = "rogue-t"
	s12Proxy   = "rogue-px"
	s12PxMCP   = 18290
	s12PxMet   = 19290
	s12Base    = 5
	s12Rogue   = "kairan-s12-rogue"
	s12PxName  = "kairan-s12-px"
	s12MCPName = "kairan-s12-fakemcp"
)

func s12Cleanup() {
	for _, c := range []string{s12Rogue, s12PxName, s12MCPName} {
		_, _ = docker("rm", "-f", "-v", c)
	}
	_, _ = docker("volume", "rm", "-f", "kairan-s12-px-data")
	_, _ = docker("network", "rm", s12Net)
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func genKey() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}

// widePayload is the policy a rogue would love to push: it grants every role the forbidden tools.
func widePayload(tenant string, version uint64, issued, expires time.Time) []byte {
	doc := map[string]any{
		"tenant": tenant, "version": version,
		"issued_at":  issued.UTC().Format(time.RFC3339),
		"expires_at": expires.UTC().Format(time.RFC3339),
		"default":    "deny",
		"roles": map[string]any{
			"sales":  map[string]string{"notes.read": "R", "notes.write": "W", "crm.read_*": "R", "crm.export": "X", "admin.shutdown": "X"},
			"intern": map[string]string{"notes.read": "R", "notes.write": "W", "crm.export": "X", "admin.shutdown": "X"},
		},
	}
	b, _ := json.Marshal(doc)
	return b
}

type s12Case struct {
	name string
	want wire.ErrorCode // "" = no particular reason is required (the answer is not even a valid poll response)
	body func() []byte
}

func pollResp(version uint64, env wire.Envelope) []byte {
	b, _ := json.Marshal(wire.PollResponse{Version: version, Envelope: env})
	return b
}

func TestS12RogueControlPlane(t *testing.T) {
	w := need(t)
	s12Cleanup()
	t.Cleanup(s12Cleanup)

	dir := filepath.Join(w.run, "s12")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o777)
	for _, f := range []string{"poll.log", "status.log", "offer.json", "offer.status"} {
		_ = os.Remove(filepath.Join(dir, f))
	}
	root := filepath.Join(w.compose, "..", "..")
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "rogue"), "./deploy/compose/rogue")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build rogue: %v\n%s", err, out)
	}
	rb := make([]byte, 16)
	_, _ = rand.Read(rb)
	pxTok := "tok-s12-" + hex.EncodeToString(rb)
	var pubs []string
	pb, err := os.ReadFile(filepath.Join(w.run, "trusted-keys.json"))
	if err != nil || json.Unmarshal(pb, &pubs) != nil {
		t.Fatalf("trusted-keys.json: %v", err)
	}
	pxCfg, _ := json.Marshal(map[string]any{
		"tenant": s12Tenant, "proxy_id": s12Proxy, "cp_url": "http://rogue-cp:8080", "token": pxTok,
		"trusted_keys": pubs, "threshold": 2, "allow_plaintext": true,
		"listen": "0.0.0.0:8080", "metrics_listen": "0.0.0.0:9090", "upstream": "http://fakemcp-s12:9000",
		"api_keys": map[string]string{w.salesKey: "sales", w.internKey: "intern"}, "data_dir": "/data",
	})
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), pxCfg, 0o644); err != nil {
		t.Fatal(err)
	}

	setOffer := func(body []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "offer.json"), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	clearOffer := func() { setOffer(nil) }
	pollLines := func() []string {
		b, _ := os.ReadFile(filepath.Join(dir, "poll.log"))
		var out []string
		for _, ln := range strings.Split(string(b), "\n") {
			if ln != "" {
				out = append(out, ln)
			}
		}
		return out
	}
	served := func() int {
		n := 0
		for _, ln := range pollLines() {
			if strings.Contains(ln, " served=1 ") {
				n++
			}
		}
		return n
	}
	lastStatus := func() (wire.StatusReport, int) {
		b, _ := os.ReadFile(filepath.Join(dir, "status.log"))
		var last wire.StatusReport
		n := 0
		for _, ln := range strings.Split(string(b), "\n") {
			if ln == "" {
				continue
			}
			var sr wire.StatusReport
			if json.Unmarshal([]byte(ln), &sr) == nil {
				last = sr
				n++
			}
		}
		return last, n
	}

	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	run := func(args ...string) { t.Helper(); mustDocker(t, append([]string{"run", "-d"}, args...)...) }
	mustDocker(t, "network", "create", s12Net)
	mustDocker(t, "volume", "create", "kairan-s12-px-data")
	run(append(hard, "--name", s12Rogue, "--network", s12Net, "--network-alias", "rogue-cp", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		"-v", dir+":/rogue", "-v", filepath.Join(dir, "rogue")+":/usr/local/bin/rogue:ro", image, "rogue", "-listen", "0.0.0.0:8080", "-dir", "/rogue")...)
	run(append(hard, "--name", s12MCPName, "--network", s12Net, "--network-alias", "fakemcp-s12", image, "fakemcp", "-addr", "0.0.0.0:9000")...)

	now := time.Now()
	good := func(v uint64) []byte {
		return payload(s12Tenant, v, now.Add(-time.Minute), now.Add(72*time.Hour), nil)
	}
	// baseline: the rogue starts honest, so the proxy has something to lose
	baseEnv := w.envelope(good(s12Base), "admin-a", "admin-b")
	baseHash := sha256hex(baseEnv.Payload)
	setOffer(pollResp(s12Base, baseEnv))
	run(append(hard, "--name", s12PxName, "--network", s12Net, "-v", "kairan-s12-px-data:/data",
		"-v", filepath.Join(dir, "proxy.json")+":/etc/kairan/proxy.json:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", s12PxMCP), "-p", fmt.Sprintf("127.0.0.1:%d:9090", s12PxMet),
		image, "kairan-proxy", "-config", "/etc/kairan/proxy.json")...)
	pxs := px{ID: s12Proxy, Tenant: s12Tenant, MCP: s12PxMCP, Metrics: s12PxMet}
	eventually(t, 90*time.Second, 500*time.Millisecond, fmt.Sprintf("the proxy to apply the honest baseline v%d", s12Base), func() (bool, string) {
		s, err := w.self(pxs)
		if err != nil {
			return false, err.Error()
		}
		return s.AppliedVersion == s12Base && s.State == string(wire.StateEnforcing), fmt.Sprintf("v%d %s", s.AppliedVersion, s.State)
	})
	clearOffer()
	base, err := w.self(pxs)
	if err != nil || base.PolicyHash != baseHash {
		t.Fatalf("baseline self view %+v (%v), want hash %s", base, err, baseHash)
	}
	appliedBefore, err := w.metric(pxs, "kairan_proxy_policies_applied_total")
	if err != nil {
		t.Fatalf("applied counter: %v", err)
	}
	time.Sleep(3 * time.Second)

	attacker1, attacker2 := genKey(), genKey()
	keyID := func(name string) wire.Hash { return trust.KeyID(w.keys[name].Public().(ed25519.PublicKey)) }
	wide := func(v uint64) []byte { return widePayload(s12Tenant, v, now.Add(-time.Minute), now.Add(72*time.Hour)) }
	signWith := func(env wire.Envelope, keys ...ed25519.PrivateKey) wire.Envelope {
		env.Signatures = []wire.Signature{}
		for _, k := range keys {
			trust.Sign(&env, k)
		}
		return env
	}
	raw := func(payload []byte) wire.Envelope {
		return wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload, Signatures: []wire.Signature{}}
	}
	ab := []ed25519.PrivateKey{w.keys["admin-a"], w.keys["admin-b"]}
	junkSig := func() []byte {
		s := make([]byte, wire.SignatureSize)
		_, _ = rand.Read(s)
		return s
	}

	cases := []s12Case{
		{"forged: two signatures from keys the proxy does not trust", wire.ErrThreshold, func() []byte {
			return pollResp(s12Base+1, signWith(raw(wide(s12Base+1)), attacker1, attacker2))
		}},
		{"forged: real key IDs of two trusted admins, random signature bytes", wire.ErrThreshold, func() []byte {
			e := raw(wide(s12Base + 1))
			for _, n := range []string{"admin-a", "admin-b"} {
				e.Signatures = append(e.Signatures, wire.Signature{KeyID: keyID(n), Sig: junkSig()})
			}
			return pollResp(s12Base+1, e)
		}},
		{"1 signature: only admin-a signed a wider policy", wire.ErrThreshold, func() []byte {
			return pollResp(s12Base+1, signWith(raw(wide(s12Base+1)), w.keys["admin-a"]))
		}},
		{"duplicate signature: admin-a signed twice", wire.ErrThreshold, func() []byte {
			return pollResp(s12Base+1, signWith(raw(wide(s12Base+1)), w.keys["admin-a"], w.keys["admin-a"]))
		}},
		{"one trusted signature plus one forged", wire.ErrThreshold, func() []byte {
			return pollResp(s12Base+1, signWith(raw(wide(s12Base+1)), w.keys["admin-a"], attacker1))
		}},
		{"tampered payload: valid signatures on the good v6, payload swapped for the wider policy", wire.ErrThreshold, func() []byte {
			e := signWith(raw(good(s12Base+1)), ab...)
			e.Payload = wide(s12Base + 1)
			return pollResp(s12Base+1, e)
		}},
		{"wrong tenant: two valid signatures, payload names bank-a", wire.ErrWrongTenant, func() []byte {
			p := widePayload("bank-a", s12Base+1, now.Add(-time.Minute), now.Add(72*time.Hour))
			return pollResp(s12Base+1, signWith(raw(p), ab...))
		}},
		{"older version: two valid signatures, v3 (wider) while v5 is applied", wire.ErrNotNewer, func() []byte {
			return pollResp(s12Base-2, signWith(raw(wide(s12Base-2)), ab...))
		}},
		{"equal version: two valid signatures, a wider policy at the applied v5", wire.ErrNotNewer, func() []byte {
			return pollResp(s12Base, signWith(raw(wide(s12Base)), ab...))
		}},
		{"version lie: poll response says v99, signed payload is the older v4", wire.ErrNotNewer, func() []byte {
			return pollResp(99, signWith(raw(wide(s12Base-1)), ab...))
		}},
		{"expired: two valid signatures, newer version, already expired", wire.ErrExpired, func() []byte {
			p := widePayload(s12Tenant, s12Base+1, now.Add(-48*time.Hour), now.Add(-24*time.Hour))
			return pollResp(s12Base+1, signWith(raw(p), ab...))
		}},
		{"wrong payload type: valid signatures over another type", wire.ErrPayloadType, func() []byte {
			e := wire.Envelope{PayloadType: "application/json", Payload: wide(s12Base + 1), Signatures: []wire.Signature{}}
			return pollResp(s12Base+1, signWith(e, ab...))
		}},
		{"9 signatures (limit 8): two valid ones among seven junk", wire.ErrMalformed, func() []byte {
			e := signWith(raw(wide(s12Base+1)), ab...)
			for i := 0; i < 7; i++ {
				k := make([]byte, 32)
				_, _ = rand.Read(k)
				e.Signatures = append(e.Signatures, wire.Signature{KeyID: wire.Hash(hex.EncodeToString(k)), Sig: junkSig()})
			}
			return pollResp(s12Base+1, e)
		}},
		{"oversize: valid, newer, two signatures, but the envelope is over 256 KiB", "", func() []byte {
			p := append(wide(s12Base+1), bytes.Repeat([]byte(" "), 300<<10)...)
			return pollResp(s12Base+1, signWith(raw(p), ab...))
		}},
		{"unknown field: a valid answer with one extra JSON field", "", func() []byte {
			e := signWith(raw(wide(s12Base+1)), ab...)
			var m map[string]any
			_ = json.Unmarshal(pollResp(s12Base+1, e), &m)
			m["evil"] = true
			b, _ := json.Marshal(m)
			return b
		}},
		{"garbage: not JSON at all", "", func() []byte { return []byte("\x00\x01 not json {{{") }},
		{"truncated: a valid answer cut in half", "", func() []byte {
			b := pollResp(s12Base+1, signWith(raw(wide(s12Base+1)), ab...))
			return b[:len(b)/2]
		}},
	}

	checkUnchanged := func(t *testing.T, label string) {
		t.Helper()
		s, err := w.self(pxs)
		if err != nil || s.AppliedVersion != s12Base || s.PolicyHash != baseHash || s.State != string(wire.StateEnforcing) {
			t.Errorf("%s: proxy changed: %+v (%v), want v%d hash %.12s enforcing", label, s, err, s12Base, baseHash)
		}
		if a, err := w.metric(pxs, "kairan_proxy_policies_applied_total"); err != nil || a != appliedBefore {
			t.Errorf("%s: kairan_proxy_policies_applied_total %v -> %v (%v)", label, appliedBefore, a, err)
		}
		for _, cm := range callMix {
			if r := w.call(pxs, w.keyFor(cm.role), cm.tool); r.Err != nil || r.Allowed != wantAllowed(cm.role, cm.tool, s12Base) {
				t.Errorf("%s: %s/%s allowed=%v err=%v; the baseline v%d decides otherwise", label, cm.role, cm.tool, r.Allowed, r.Err, s12Base)
			}
		}
		if r := w.call(pxs, w.salesKey, "crm.export"); r.Allowed {
			t.Errorf("%s: I1/I3 violated: crm.export (X) is allowed", label)
		}
		if r := w.call(pxs, w.internKey, "notes.write"); r.Allowed {
			t.Errorf("%s: I1 violated: the intern can write notes", label)
		}
	}
	checkUnchanged(t, "baseline")

	reasons := map[string]string{}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			rejBefore, _ := w.metric(pxs, "kairan_proxy_policies_rejected_total")
			servedBefore := served()
			_, reportsBefore := lastStatus()
			setOffer(c.body())
			eventually(t, 30*time.Second, 200*time.Millisecond, "the proxy to fetch the offer", func() (bool, string) {
				return served() > servedBefore, "not fetched"
			})
			if c.want != "" {
				eventually(t, 30*time.Second, 200*time.Millisecond, "the proxy to report the rejection as "+string(c.want), func() (bool, string) {
					sr, _ := lastStatus()
					if sr.LastError == nil {
						return false, "no last_error in the latest status report"
					}
					return sr.LastError.Code == c.want, "last_error " + string(sr.LastError.Code)
				})
				rej, err := w.metric(pxs, "kairan_proxy_policies_rejected_total")
				if err != nil || rej < rejBefore+1 {
					t.Errorf("kairan_proxy_policies_rejected_total %v -> %v (%v), want it to grow", rejBefore, rej, err)
				}
				reasons[c.name] = string(c.want)
			} else {
				time.Sleep(4 * time.Second)
				sr, n := lastStatus()
				got := "none"
				if sr.LastError != nil {
					got = string(sr.LastError.Code)
				}
				t.Logf("not a well-formed poll answer: the proxy kept going; %d status reports since, last_error now %s", n-reportsBefore, got)
				reasons[c.name] = got
			}
			clearOffer()
			time.Sleep(2500 * time.Millisecond)
			checkUnchanged(t, c.name)
			sr, _ := lastStatus()
			if sr.AppliedVersion != s12Base || string(sr.PolicyHash) != baseHash {
				t.Errorf("the rogue control plane was told applied v%d hash %.12s, want v%d hash %.12s", sr.AppliedVersion, sr.PolicyHash, s12Base, baseHash)
			}
			if sr.State != wire.StateEnforcing {
				t.Errorf("reported state %s, want enforcing", sr.State)
			}
		})
	}

	// every poll asked "newer than v5?" (have=5) or, before the baseline, have=0: the proxy never advanced
	for _, ln := range pollLines() {
		if strings.Contains(ln, "have=") && !strings.Contains(ln, "have=5") && !strings.Contains(ln, "have=0") {
			t.Errorf("a poll asked for something other than have=5 (or the initial have=0): %q", ln)
		}
	}

	// the proxy is not wedged: a good newer policy from the same rogue is applied
	good7 := w.envelope(good(s12Base+2), "admin-b", "admin-c")
	setOffer(pollResp(s12Base+2, good7))
	eventually(t, 60*time.Second, 300*time.Millisecond, "the proxy to apply the good v7 after the attacks", func() (bool, string) {
		s, err := w.self(pxs)
		if err != nil {
			return false, err.Error()
		}
		return s.AppliedVersion == s12Base+2 && s.PolicyHash == sha256hex(good7.Payload), fmt.Sprintf("v%d", s.AppliedVersion)
	})
	clearOffer()
	n := 0
	for _, c := range cases {
		if c.want != "" {
			n++
		}
	}
	t.Logf("S12: %d bad offers (%d with a specific wire reason) -> 0 applied, applied version stayed v%d, then a good v%d applied; reasons reported: %v",
		len(cases), n, s12Base, s12Base+2, reasons)
}
