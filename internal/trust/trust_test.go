package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

const fixtures = "../../test/fixtures"

type manifest struct {
	Root struct {
		Tenant      string   `json:"tenant"`
		Threshold   int      `json:"threshold"`
		TrustedKeys []string `json:"trusted_keys"`
		Now         string   `json:"now"`
		SkewSeconds int      `json:"skew_seconds"`
	} `json:"root"`
	Cases []struct {
		Name string         `json:"name"`
		File string         `json:"file"`
		Have uint64         `json:"have"`
		Want wire.ErrorCode `json:"want"`
	} `json:"cases"`
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureRoot(t *testing.T, m manifest) Root {
	t.Helper()
	root := Root{Tenant: wire.ID(m.Root.Tenant), Threshold: m.Root.Threshold, Keys: map[wire.Hash]ed25519.PublicKey{}}
	for _, f := range m.Root.TrustedKeys {
		raw, err := hex.DecodeString(strings.TrimSpace(string(readFixture(t, f))))
		if err != nil {
			t.Fatal(err)
		}
		pub := ed25519.PublicKey(raw)
		root.Keys[KeyID(pub)] = pub
	}
	return root
}

// TestGoldenCases is the acceptance test: every committed vector must give
// exactly the expected code from Accept.
func TestGoldenCases(t *testing.T) {
	var m manifest
	if err := json.Unmarshal(readFixture(t, "cases.json"), &m); err != nil {
		t.Fatal(err)
	}
	if len(m.Cases) != 24 {
		t.Fatalf("cases.json has %d cases, want 24", len(m.Cases))
	}
	root := fixtureRoot(t, m)
	now, err := time.Parse(time.RFC3339, m.Root.Now)
	if err != nil {
		t.Fatal(err)
	}
	skew := time.Duration(m.Root.SkewSeconds) * time.Second
	for _, c := range m.Cases {
		t.Run(c.Name, func(t *testing.T) {
			env, err := DecodeEnvelope(readFixture(t, c.File))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			v, code, err := Accept(env, root, c.Have, now, skew)
			if code != c.Want {
				t.Fatalf("code = %q (err %v), want %q", code, err, c.Want)
			}
			if (err == nil) != (c.Want == "") {
				t.Fatalf("err = %v for want %q", err, c.Want)
			}
			if c.Want != "" {
				if v.Policy != nil || v.Hash != "" || v.Signers != nil {
					t.Fatalf("rejected envelope returned data: %+v", v)
				}
				return
			}
			if v.Policy == nil || !v.Hash.Valid() || len(v.Signers) < root.Threshold {
				t.Fatalf("accepted but result incomplete: %+v", v)
			}
			if v.Policy.Version <= c.Have {
				t.Fatalf("accepted version %d with have %d", v.Policy.Version, c.Have)
			}
			// Verify is Accept minus version and expiry: it must agree on accepted cases.
			v2, code, err := Verify(env, root)
			if err != nil || code != "" || v2.Hash != v.Hash {
				t.Fatalf("Verify disagrees: %v %q", err, code)
			}
		})
	}
}

// helpers for synthetic envelopes

func policyJSON(tenant string, version int, issued, expires time.Time) []byte {
	return []byte(`{"tenant":"` + tenant + `","version":` + itoa(version) +
		`,"issued_at":"` + issued.UTC().Format(time.RFC3339) +
		`","expires_at":"` + expires.UTC().Format(time.RFC3339) +
		`","default":"deny","roles":{"sales":{"crm.read_*":"R"}}}`)
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

var testNow = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func testRoot(threshold int, names ...string) (Root, map[string]ed25519.PrivateKey) {
	r := Root{Tenant: "bank-a", Threshold: threshold, Keys: map[wire.Hash]ed25519.PublicKey{}}
	privs := map[string]ed25519.PrivateKey{}
	for _, n := range names {
		k := testKey(n)
		privs[n] = k
		r.Keys[KeyID(pub(k))] = pub(k)
	}
	return r, privs
}

func signed(payload []byte, keys ...ed25519.PrivateKey) wire.Envelope {
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for _, k := range keys {
		Sign(&env, k)
	}
	return env
}

func TestRootFloors(t *testing.T) {
	_, privs := testRoot(2, "admin-a", "admin-b", "admin-c")
	payload := policyJSON("bank-a", 2, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	env := signed(payload, privs["admin-a"], privs["admin-b"], privs["admin-c"])

	three := func() map[wire.Hash]ed25519.PublicKey {
		r, _ := testRoot(2, "admin-a", "admin-b", "admin-c")
		return r.Keys
	}
	two := func() map[wire.Hash]ed25519.PublicKey {
		r, _ := testRoot(2, "admin-a", "admin-b")
		return r.Keys
	}
	badID := three()
	for id, k := range badID { // key stored under a wrong ID
		delete(badID, id)
		badID[KeyID(pub(testKey("outsider")))] = k
		break
	}
	alias := two() // the same key under a second, fake ID
	for _, k := range alias {
		alias[KeyID(pub(testKey("outsider")))] = k
		break
	}
	shortKey := two()
	for id := range shortKey {
		shortKey[id] = shortKey[id][:5]
		break
	}

	tests := []struct {
		name string
		root Root
	}{
		{"threshold 0", Root{Tenant: "bank-a", Keys: three(), Threshold: 0}},
		{"threshold 1", Root{Tenant: "bank-a", Keys: three(), Threshold: 1}},
		{"negative threshold", Root{Tenant: "bank-a", Keys: three(), Threshold: -1}},
		{"3-of-2 keys", Root{Tenant: "bank-a", Keys: two(), Threshold: 3}},
		{"no keys", Root{Tenant: "bank-a", Threshold: 2}},
		{"nil root", Root{}},
		{"bad tenant", Root{Tenant: "Bank A", Keys: three(), Threshold: 2}},
		{"key under wrong ID", Root{Tenant: "bank-a", Keys: badID, Threshold: 2}},
		{"one key under two IDs", Root{Tenant: "bank-a", Keys: alias, Threshold: 2}},
		{"short key", Root{Tenant: "bank-a", Keys: shortKey, Threshold: 2}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, code, err := Verify(env, tc.root)
			if !errors.Is(err, ErrBadRoot) || code != "" || v.Policy != nil {
				t.Fatalf("Verify = %+v %q %v, want ErrBadRoot", v, code, err)
			}
			v, code, err = Accept(env, tc.root, 1, testNow, time.Minute)
			if !errors.Is(err, ErrBadRoot) || code != "" || v.Policy != nil {
				t.Fatalf("Accept = %+v %q %v, want ErrBadRoot", v, code, err)
			}
		})
	}

	// The floor itself passes: 2-of-2 and 2-of-3.
	for _, root := range []Root{{Tenant: "bank-a", Keys: two(), Threshold: 2}, {Tenant: "bank-a", Keys: three(), Threshold: 2}} {
		if _, code, err := Verify(env, root); err != nil || code != "" {
			t.Fatalf("Verify(%d keys) = %q %v", len(root.Keys), code, err)
		}
	}
}

func TestVerifyReportsSigners(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b", "admin-c")
	payload := policyJSON("bank-a", 5, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	out := testKey("outsider")
	env := signed(payload, p["admin-c"], p["admin-a"], out, p["admin-a"])
	v, code, err := Verify(env, root)
	if err != nil || code != "" {
		t.Fatal(code, err)
	}
	if len(v.Signers) != 2 || v.Signers[0] >= v.Signers[1] {
		t.Fatalf("Signers = %v, want 2 sorted distinct", v.Signers)
	}
	for _, id := range v.Signers {
		if _, ok := root.Keys[id]; !ok {
			t.Fatalf("signer %s not in root", id)
		}
	}
	if v.Policy.Version != 5 || v.Policy.Tenant != "bank-a" {
		t.Fatalf("policy = %+v", v.Policy)
	}
	// Hash is SHA-256 of the exact payload bytes.
	sum := sha256.Sum256(payload)
	if v.Hash != wire.Hash(hex.EncodeToString(sum[:])) {
		t.Fatalf("Hash = %s", v.Hash)
	}
	env2 := signed(append(append([]byte{}, payload...), ' '), p["admin-a"], p["admin-b"])
	v2, _, err := Verify(env2, root)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Hash == v.Hash {
		t.Fatal("hash ignores trailing byte")
	}
}

func TestVerifyIgnoresVersionAndExpiry(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b")
	old := policyJSON("bank-a", 1, testNow.Add(-1000*time.Hour), testNow.Add(-900*time.Hour))
	env := signed(old, p["admin-a"], p["admin-b"])
	if _, code, err := Verify(env, root); err != nil || code != "" {
		t.Fatalf("Verify = %q %v", code, err)
	}
	if _, code, _ := Accept(env, root, 0, testNow, 0); code != wire.ErrExpired {
		t.Fatalf("Accept code = %q", code)
	}
}

func TestAcceptCheckOrder(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b")
	a, b, out := p["admin-a"], p["admin-b"], testKey("outsider")
	live := func(tenant string, v int) []byte {
		return policyJSON(tenant, v, testNow.Add(-time.Hour), testNow.Add(time.Hour))
	}
	dead := policyJSON("other", 1, testNow.Add(-100*time.Hour), testNow.Add(-90*time.Hour))
	tests := []struct {
		name string
		env  wire.Envelope
		have uint64
		want wire.ErrorCode
	}{
		{"payload type before signatures",
			wire.Envelope{PayloadType: "x", Payload: live("bank-a", 2), Signatures: signed(nil, out).Signatures}, 1, wire.ErrPayloadType},
		{"one well-formed signature is under threshold", signed(live("bank-a", 2), a), 1, wire.ErrThreshold},
		{"empty payload is malformed", signed(nil, a, b), 1, wire.ErrMalformed},
		{"no signatures is malformed", signed(live("bank-a", 2)), 1, wire.ErrMalformed},
		{"signatures before parse", signed([]byte("not json"), a, out), 1, wire.ErrThreshold},
		{"parse before tenant", signed([]byte(`{"tenant":"other"}`), a, b), 1, wire.ErrMalformed},
		{"tenant before version", signed(live("other", 1), a, b), 5, wire.ErrWrongTenant},
		{"tenant before expiry", signed(dead, a, b), 0, wire.ErrWrongTenant},
		{"version before expiry",
			signed(policyJSON("bank-a", 1, testNow.Add(-100*time.Hour), testNow.Add(-90*time.Hour)), a, b), 1, wire.ErrNotNewer},
		{"expiry last",
			signed(policyJSON("bank-a", 2, testNow.Add(-100*time.Hour), testNow.Add(-90*time.Hour)), a, b), 1, wire.ErrExpired},
		{"version at max", signed(live("bank-a", 2), a, b), math.MaxUint64, wire.ErrNotNewer},
		{"equal version", signed(live("bank-a", 2), a, b), 2, wire.ErrNotNewer},
		{"newer by one", signed(live("bank-a", 2), a, b), 1, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, code, err := Accept(tc.env, root, tc.have, testNow, 0)
			if code != tc.want || (err == nil) != (tc.want == "") {
				t.Fatalf("code = %q err = %v, want %q", code, err, tc.want)
			}
			if err != nil && !wire.ErrorCode(code).Valid() {
				t.Fatalf("code %q is not a wire code", code)
			}
		})
	}
}

func TestAcceptExpiryAndSkew(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b")
	expires := testNow.Add(-time.Minute) // expired one minute before now
	env := signed(policyJSON("bank-a", 2, expires.Add(-time.Hour), expires), p["admin-a"], p["admin-b"])
	tests := []struct {
		name string
		now  time.Time
		skew time.Duration
		want wire.ErrorCode
	}{
		{"before expiry, no skew", expires.Add(-time.Second), 0, ""},
		{"exactly at expiry, no skew", expires, 0, wire.ErrExpired},
		{"one second after, no skew", expires.Add(time.Second), 0, wire.ErrExpired},
		{"inside skew", expires.Add(time.Minute), 2 * time.Minute, ""},
		{"one second inside skew", expires.Add(2*time.Minute - time.Second), 2 * time.Minute, ""},
		{"exactly at skew edge", expires.Add(2 * time.Minute), 2 * time.Minute, wire.ErrExpired},
		{"beyond skew", expires.Add(3 * time.Minute), 2 * time.Minute, wire.ErrExpired},
		{"max skew inside", expires.Add(5*time.Minute - time.Second), MaxSkew, ""},
		{"max skew edge", expires.Add(5 * time.Minute), MaxSkew, wire.ErrExpired},
		{"now far in the future", expires.Add(1000 * time.Hour), MaxSkew, wire.ErrExpired},
		{"zero now", time.Time{}, 0, ""}, // year 1 is before expiry: caller's problem, not a panic
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, code, err := Accept(env, root, 1, tc.now, tc.skew)
			if code != tc.want || (err == nil) != (tc.want == "") {
				t.Fatalf("code = %q err = %v, want %q", code, err, tc.want)
			}
		})
	}
}

func TestAcceptRejectsBadSkew(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b")
	env := signed(policyJSON("bank-a", 2, testNow.Add(-time.Hour), testNow.Add(time.Hour)), p["admin-a"], p["admin-b"])
	for _, skew := range []time.Duration{-1, -time.Hour, MaxSkew + 1, time.Hour, math.MaxInt64} {
		v, code, err := Accept(env, root, 1, testNow, skew)
		if !errors.Is(err, ErrBadSkew) || code != "" || v.Policy != nil {
			t.Fatalf("skew %v: %+v %q %v", skew, v, code, err)
		}
	}
	if _, _, err := Accept(env, root, 1, testNow, MaxSkew); err != nil {
		t.Fatalf("skew at the maximum: %v", err)
	}
}

func TestErrorsDoNotEchoPayload(t *testing.T) {
	root, p := testRoot(2, "admin-a", "admin-b")
	env := signed([]byte(`{"tenant":"SECRET-TENANT-VALUE"}`), p["admin-a"], p["admin-b"])
	_, _, err := Verify(env, root)
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func FuzzVerify(f *testing.F) {
	root, p := testRoot(2, "admin-a", "admin-b", "admin-c")
	ok := signed(policyJSON("bank-a", 2, testNow.Add(-time.Hour), testNow.Add(time.Hour)), p["admin-a"], p["admin-b"])
	raw, _ := json.Marshal(ok)
	f.Add(raw, uint64(1))
	f.Add([]byte(`{}`), uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, have uint64) {
		env, err := DecodeEnvelope(data)
		if err != nil {
			return
		}
		v, code, err := Accept(env, root, have, testNow, time.Minute)
		if err == nil {
			// An accepted envelope must satisfy every rule independently.
			if code != "" || v.Policy == nil || len(v.Signers) < root.Threshold ||
				v.Policy.Version <= have || v.Policy.Tenant != root.Tenant || env.ValidateShape() != nil {
				t.Fatalf("accepted a bad envelope: %+v", v)
			}
			return
		}
		if code != "" && !code.Valid() {
			t.Fatalf("bad code %q", code)
		}
	})
}
