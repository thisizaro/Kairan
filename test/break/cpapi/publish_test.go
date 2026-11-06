package cpapibreak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"kairan/internal/cp/api"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

func envBody(payload []byte, ks ...keyPair) []byte { return mustJSON(signed(payload, ks...)) }

// storedEnvelope returns what the CP serves back for version v of tenant via a canary poll, which is
// the only API path that returns an envelope.
func (e *env) servedEnvelope(tenant string, v uint64) wire.PollResponse {
	e.t.Helper()
	if r := e.startRollout(tenant, v); r.code != 200 {
		e.t.Fatalf("rollout: %d %s", r.code, r.body)
	}
	r := e.do("GET", pollPath(tenant, "c1", 0), tokOf("c1"), nil)
	if r.code != 200 {
		e.t.Fatalf("poll: %d %s", r.code, r.body)
	}
	var pr wire.PollResponse
	if err := json.Unmarshal(r.body, &pr); err != nil {
		e.t.Fatal(err)
	}
	return pr
}

// G1/I1 sanity check: the CP verifies against the tenant's admin keys (it is not the judge, but it must
// not store what clearly fails).
func TestPublishVerdicts(t *testing.T) {
	good := policyJSON("bank-a", 1)
	oneSigDup := signed(good, keyA)
	trust.Sign(&oneSigDup, keyA.priv)
	wrongType := signed(good, keyA, keyB)
	wrongType.PayloadType = "application/json"
	tamperedAfterSign := signed(good, keyA, keyB)
	tamperedAfterSign.Payload = bytes.Replace(good, []byte(`"version":1`), []byte(`"version":9`), 1)
	badSig := signed(good, keyA, keyB)
	badSig.Signatures[1].Sig[0] ^= 0xff
	shortSig := signed(good, keyA, keyB)
	shortSig.Signatures[1].Sig = shortSig.Signatures[1].Sig[:63]
	nineSigs := signed(good, keyA, keyB, keyC, keyOut, keyD, keyE, mkKey("f"), mkKey("g"), mkKey("h"))

	type c struct {
		name string
		body []byte
		code int
		want wire.ErrorCode
	}
	cases := []c{
		{"two-trusted-signatures", envBody(good, keyA, keyB), 200, ""},
		{"three-trusted-signatures", envBody(good, keyA, keyB, keyC), 200, ""},
		{"no-signatures", envBody(good), 400, wire.ErrMalformed},
		{"one-signature", envBody(good, keyA), 400, wire.ErrThreshold},
		{"same-key-twice (G1: counts once)", mustJSON(oneSigDup), 400, wire.ErrThreshold},
		{"one-trusted-one-outsider", envBody(good, keyA, keyOut), 400, wire.ErrThreshold},
		{"two-outsiders", envBody(good, keyOut, mkKey("x")), 400, wire.ErrThreshold},
		{"signers-of-another-tenant", envBody(good, keyD, keyE), 400, wire.ErrThreshold},
		{"payload-changed-after-signing", mustJSON(tamperedAfterSign), 400, wire.ErrThreshold},
		{"corrupt-signature", mustJSON(badSig), 400, wire.ErrThreshold},
		{"wrong-payload-type", mustJSON(wrongType), 400, wire.ErrPayloadType},
		{"payload-not-json", envBody([]byte("not json"), keyA, keyB), 400, wire.ErrMalformed},
		{"payload-empty", envBody([]byte{}, keyA, keyB), 400, ""},
		{"payload-has-extra-field", envBody(bytes.Replace(good, []byte(`"default"`), []byte(`"x":1,"default"`), 1), keyA, keyB), 400, wire.ErrMalformed},
		{"payload-duplicate-key", envBody(bytes.Replace(good, []byte(`"default":"deny"`), []byte(`"default":"deny","default":"allow"`), 1), keyA, keyB), 400, wire.ErrMalformed},
		{"unknown-tenant", envBody(policyJSON("bank-zzz", 1), keyA, keyB), 400, wire.ErrWrongTenant},
		{"tenant-of-other-roots-keys", envBody(policyJSON("bank-b", 1), keyA, keyB), 400, wire.ErrThreshold},
		{"too-many-signatures", mustJSON(nineSigs), 400, ""},
		{"short-signature", mustJSON(shortSig), 400, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			r := e.do("POST", wire.PathPolicies, adminTok, tc.body)
			if r.code != tc.code {
				t.Fatalf("got %d %s, want %d", r.code, r.body, tc.code)
			}
			if tc.code == 200 {
				var pr wire.PublishResponse
				if err := json.Unmarshal(r.body, &pr); err != nil {
					t.Fatalf("answer is not a PublishResponse: %v", err)
				}
				if pr.Tenant != "bank-a" || pr.Version != 1 || pr.PolicyHash != hashOf(good) {
					t.Fatalf("answer %+v, want bank-a v1 %s", pr, hashOf(good))
				}
				return
			}
			if tc.want != "" && r.errCode() != tc.want {
				t.Fatalf("code %q, want %q (%s)", r.errCode(), tc.want, r.body)
			}
			if !r.errCode().Valid() {
				t.Fatalf("invalid error code in %s", r.body)
			}
			// I3: a rejected publish stores nothing: a rollout of that version is 404.
			if rr := e.startRollout("bank-a", 1); rr.code != 404 {
				t.Fatalf("rejected publish left something behind: rollout answers %d %s", rr.code, rr.body)
			}
		})
	}
}

// Strict decoding (cp/api LLD, wire.Decode): unknown fields, trailing data, wrong types, duplicate and
// case-variant keys are 400 bad_request. Most defensible reading of "strict decoding": the same strictness
// trust.DecodeEnvelope documents, so two admins cannot approve different bytes from the same body.
func TestPublishStrictBodyDecoding(t *testing.T) {
	good := envBody(policyJSON("bank-a", 1), keyA, keyB)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(good, &m); err != nil {
		t.Fatal(err)
	}
	payloadB64 := string(m["payload"])
	sigs := string(m["signatures"])
	ptype := string(m["payloadType"])
	mk := func(s string) []byte { return []byte(s) }
	cases := map[string][]byte{
		"empty":                mk(""),
		"null":                 mk("null"),
		"array":                mk("[]"),
		"string":               mk(`"x"`),
		"number":               mk("1"),
		"object-empty":         mk("{}"),
		"unknown-field":        mk(fmt.Sprintf(`{"payloadType":%s,"payload":%s,"signatures":%s,"extra":1}`, ptype, payloadB64, sigs)),
		"unknown-field-in-sig": bytes.Replace(good, []byte(`"keyid"`), []byte(`"x":1,"keyid"`), 1),
		"trailing-object":      append(append([]byte{}, good...), []byte(`{}`)...),
		"trailing-garbage":     append(append([]byte{}, good...), []byte(`xx`)...),
		"two-documents":        append(append(append([]byte{}, good...), '\n'), good...),
		"payload-not-base64":   mk(fmt.Sprintf(`{"payloadType":%s,"payload":"!!!","signatures":%s}`, ptype, sigs)),
		"payload-number":       mk(fmt.Sprintf(`{"payloadType":%s,"payload":1,"signatures":%s}`, ptype, sigs)),
		"signatures-object":    mk(fmt.Sprintf(`{"payloadType":%s,"payload":%s,"signatures":{}}`, ptype, payloadB64)),
		"signatures-null-item": mk(fmt.Sprintf(`{"payloadType":%s,"payload":%s,"signatures":[null,null]}`, ptype, payloadB64)),
		"truncated":            good[:len(good)/2],
		"bom-prefixed":         append([]byte("\xef\xbb\xbf"), good...),
		"duplicate-payload-key": mk(fmt.Sprintf(`{"payloadType":%s,"payload":%s,"payload":%s,"signatures":%s}`,
			ptype, payloadB64, `"e30="`, sigs)),
		"duplicate-signatures-key": mk(fmt.Sprintf(`{"payloadType":%s,"payload":%s,"signatures":[],"signatures":%s}`, ptype, payloadB64, sigs)),
		"case-variant-payload":     mk(fmt.Sprintf(`{"payloadType":%s,"Payload":%s,"signatures":%s}`, ptype, payloadB64, sigs)),
		"case-variant-type":        mk(fmt.Sprintf(`{"PAYLOADTYPE":%s,"payload":%s,"signatures":%s}`, ptype, payloadB64, sigs)),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			r := e.do("POST", wire.PathPolicies, adminTok, body)
			if r.code/100 == 2 {
				t.Fatalf("accepted: %d %s", r.code, r.body)
			}
			if r.code != 400 || (!r.errCode().Valid()) {
				t.Fatalf("got %d %s, want 400 with a wire error code", r.code, r.body)
			}
			if rr := e.startRollout("bank-a", 1); rr.code != 404 {
				t.Fatalf("a refused body left a stored envelope: %d", rr.code)
			}
		})
	}
	// Whitespace after the single JSON value is allowed (RFC 8259) or refused as trailing data; both are
	// safe, so only check it does not store anything unexpected: it either succeeds with v1 or is 400.
	e := newEnv(t)
	r := e.do("POST", wire.PathPolicies, adminTok, append(append([]byte{}, good...), '\n'))
	if r.code != 200 && r.code != 400 {
		t.Errorf("trailing newline: %d", r.code)
	}
}

// Doc: every body goes through MaxBytesReader with the wire limits; oversize is 413 too_large.
func TestBodyLimits(t *testing.T) {
	e := newEnv(t)
	pad := func(n int) []byte { return bytes.Repeat([]byte(" "), n) }
	validEnv := envBody(policyJSON("bank-a", 1), keyA, keyB)
	type c struct {
		name string
		path string
		tok  string
		body []byte
		code int
	}
	over := func(limit int) []byte {
		b := append([]byte(nil), `{"x":"`...)
		b = append(b, bytes.Repeat([]byte("a"), limit)...)
		return append(b, `"}`...)
	}
	cases := []c{
		{"publish-limit+1", wire.PathPolicies, adminTok, append(append([]byte{}, validEnv...), pad(wire.MaxEnvelopeBytes+1-len(validEnv))...), 413},
		{"publish-way-over", wire.PathPolicies, adminTok, over(wire.MaxEnvelopeBytes * 4), 413},
		{"publish-over-garbage", wire.PathPolicies, adminTok, bytes.Repeat([]byte("{"), wire.MaxEnvelopeBytes+10), 413},
		{"status-limit+1", wire.PathStatus, tokOf("p1"), append(mustJSON(report("bank-a", "p1", 0, 1)), pad(wire.MaxStatusBytes)...), 413},
		{"status-way-over", wire.PathStatus, tokOf("p1"), over(wire.MaxStatusBytes * 100), 413},
		{"rollout-limit+1", wire.PathRollouts, adminTok, append(mustJSON(wire.RolloutRequest{Tenant: "bank-a", Version: 1}), pad(wire.MaxSmallRequestBytes)...), 413},
		{"rollout-way-over", wire.PathRollouts, adminTok, over(wire.MaxSmallRequestBytes * 1000), 413},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := e.do("POST", tc.path, tc.tok, tc.body)
			if r.code != tc.code || r.errCode() != wire.ErrTooLarge {
				t.Fatalf("got %d %s, want 413 too_large", r.code, r.body)
			}
		})
	}
	// Chunked bodies (no Content-Length) are limited too.
	r := e.do("POST", wire.PathStatus, tokOf("p1"), nil)
	_ = r
	chunk := over(wire.MaxStatusBytes * 4)
	if rr := e.doChunked("POST", wire.PathStatus, tokOf("p1"), chunk); rr.code != 413 {
		t.Errorf("chunked oversize status: %d %s", rr.code, rr.body)
	}
	if rr := e.doChunked("POST", wire.PathPolicies, adminTok, bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes*2)); rr.code != 413 {
		t.Errorf("chunked oversize publish: %d %s", rr.code, rr.body)
	}
	// A body exactly at the status limit that is otherwise a valid report must not be rejected for size:
	// valid JSON whitespace pads it. (MaxStatusBytes is "JSON-encoded StatusReport".)
	okBody := mustJSON(report("bank-a", "p1", 0, 2))
	if len(okBody) < wire.MaxStatusBytes {
		okBody = append(okBody, pad(wire.MaxStatusBytes-len(okBody))...)
	}
	if rr := e.do("POST", wire.PathStatus, tokOf("p1"), okBody); rr.code == 413 {
		t.Errorf("a body of exactly %d bytes was refused as too large", len(okBody))
	}
}

func (e *env) doChunked(method, path, token string, body []byte) resp {
	e.t.Helper()
	return e.do(method, path, token, body, "Transfer-Encoding", "chunked")
}

// Publish stores exactly the bytes admins signed and the proxies later verify (I1 relies on it): the
// payload and every signature come back unchanged, in order.
func TestPublishNeverAltersTheEnvelope(t *testing.T) {
	e := newEnv(t)
	payload := policyJSON("bank-a", 1)
	// Whitespace and key order in the payload are part of the signed bytes.
	payload = []byte(strings.Replace(string(payload), `"tenant":"bank-a",`, "\n  \"tenant\" : \"bank-a\" ,\n  ", 1))
	env := signed(payload, keyB, keyA, keyC)
	if r := e.do("POST", wire.PathPolicies, adminTok, mustJSON(env)); r.code != 200 {
		t.Fatalf("publish: %d %s", r.code, r.body)
	}
	got := e.servedEnvelope("bank-a", 1)
	if !bytes.Equal(got.Envelope.Payload, payload) {
		t.Fatalf("payload bytes changed:\n%q\n%q", got.Envelope.Payload, payload)
	}
	if got.Envelope.PayloadType != env.PayloadType || len(got.Envelope.Signatures) != 3 {
		t.Fatalf("envelope changed: %+v", got.Envelope)
	}
	for i, s := range env.Signatures {
		if got.Envelope.Signatures[i].KeyID != s.KeyID || !bytes.Equal(got.Envelope.Signatures[i].Sig, s.Sig) {
			t.Fatalf("signature %d changed", i)
		}
	}
	if got.Version != 1 {
		t.Fatalf("advisory version %d", got.Version)
	}
	// And the served envelope still verifies under the tenant root (nothing was re-encoded).
	if _, code, err := trust.Verify(got.Envelope, rootFor("bank-a", keyA, keyB, keyC)); err != nil {
		t.Fatalf("served envelope does not verify: %q %v", code, err)
	}
}

// ARCH: publish conflict 409 when the version exists, even with different content; the first stays.
func TestPublishVersionConflict(t *testing.T) {
	e := newEnv(t)
	e.publish("bank-a", 1)
	other := bytes.Replace(policyJSON("bank-a", 1), []byte(`"crm.read_*":"R"`), []byte(`"crm.*":"X"`), 1)
	for _, body := range [][]byte{envBody(policyJSON("bank-a", 1), keyA, keyB), envBody(policyJSON("bank-a", 1), keyB, keyC), envBody(other, keyA, keyB)} {
		r := e.do("POST", wire.PathPolicies, adminTok, body)
		if r.code != 409 || r.errCode() != wire.ErrConflict {
			t.Fatalf("got %d %s, want 409 conflict", r.code, r.body)
		}
	}
	got := e.servedEnvelope("bank-a", 1)
	if !bytes.Equal(got.Envelope.Payload, policyJSON("bank-a", 1)) {
		t.Fatalf("the first published content was replaced")
	}
}

// Same tenant+version published concurrently: exactly one wins (never two stored, never a 5xx).
func TestPublishRaceHasOneWinner(t *testing.T) {
	e := newEnv(t)
	var wins, conflicts, other atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			signers := [][]keyPair{{keyA, keyB}, {keyB, keyC}, {keyA, keyC}}[i%3]
			r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-a", 5), signers...))
			switch r.code {
			case 200:
				wins.Add(1)
			case 409:
				conflicts.Add(1)
			default:
				other.Add(1)
				t.Errorf("unexpected %d %s", r.code, r.body)
			}
		}(i)
	}
	wg.Wait()
	if wins.Load() != 1 || conflicts.Load() != 23 {
		t.Fatalf("wins=%d conflicts=%d other=%d, want 1/23/0", wins.Load(), conflicts.Load(), other.Load())
	}
}

// Tenants are isolated: bank-b's admin keys cannot publish a bank-a policy and vice versa, and a policy
// whose tenant field differs from the keys' tenant is not stored under either.
func TestPublishTenantIsolation(t *testing.T) {
	e := newEnv(t)
	if r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-a", 1), keyD, keyE)); r.code/100 == 2 {
		t.Fatalf("bank-b keys published bank-a: %d", r.code)
	}
	if r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-b", 1), keyA, keyB)); r.code/100 == 2 {
		t.Fatalf("bank-a keys published bank-b: %d", r.code)
	}
	if rr := e.startRollout("bank-a", 1); rr.code != 404 {
		t.Fatalf("bank-a has a stored v1: %d", rr.code)
	}
	if rr := e.startRollout("bank-b", 1); rr.code != 404 {
		t.Fatalf("bank-b has a stored v1: %d", rr.code)
	}
}

// A misconfigured admin root (threshold below the floor of 2) is never a pass (trust.ErrBadRoot).
func TestBadAdminRootNeverPublishes(t *testing.T) {
	for name, root := range map[string]trust.Root{
		"threshold-1":    {Tenant: "bank-a", Keys: rootFor("bank-a", keyA, keyB).Keys, Threshold: 1},
		"threshold-0":    {Tenant: "bank-a", Keys: rootFor("bank-a", keyA, keyB).Keys, Threshold: 0},
		"threshold-high": {Tenant: "bank-a", Keys: rootFor("bank-a", keyA, keyB).Keys, Threshold: 3},
		"no-keys":        {Tenant: "bank-a", Threshold: 2},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, func(c *api.Config) { c.AdminKeys["bank-a"] = root })
			r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-a", 1), keyA))
			if r.code/100 == 2 {
				t.Fatalf("published under a bad root: %d", r.code)
			}
			r = e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-a", 2), keyA, keyB))
			if r.code/100 == 2 {
				t.Fatalf("published under a bad root: %d", r.code)
			}
		})
	}
}

// No admin keys at all for the tenant: nothing can be published for it.
func TestNoAdminKeysNoPublish(t *testing.T) {
	e := newEnv(t, func(c *api.Config) { c.AdminKeys = nil })
	if r := e.do("POST", wire.PathPolicies, adminTok, envBody(policyJSON("bank-a", 1), keyA, keyB)); r.code/100 == 2 {
		t.Fatalf("published with no admin keys: %d", r.code)
	}
}
