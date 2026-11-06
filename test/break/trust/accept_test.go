package trustbreak

import (
	"crypto/ed25519"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// M-D33 / M-D39: a Root below the floor is never a pass, from Verify or Accept,
// with an empty code and ErrBadRoot, never a panic (I1, I3).
func TestBadRootNeverPasses(t *testing.T) {
	k := loadKeys(t)
	env := signed(goodPayload(), k.a, k.b)
	three := rootOf("bank-a", 2, k.a, k.b, k.c).Keys

	mut := func(f func(r *trust.Root)) trust.Root {
		r := rootOf("bank-a", 2, k.a, k.b, k.c)
		f(&r)
		return r
	}
	shortKey := ed25519.PublicKey(make([]byte, 31))
	longKey := ed25519.PublicKey(make([]byte, 33))
	cases := []struct {
		name string
		ref  string
		root trust.Root
	}{
		{"threshold-0", "M-D33 floor", mut(func(r *trust.Root) { r.Threshold = 0 })},
		{"threshold-1", "M-D33 floor: single signature must never pass", mut(func(r *trust.Root) { r.Threshold = 1 })},
		{"threshold-negative", "floor", mut(func(r *trust.Root) { r.Threshold = -1 })},
		{"threshold-minint", "floor", mut(func(r *trust.Root) { r.Threshold = math.MinInt })},
		{"threshold-above-keys", "Threshold <= len(Keys)", mut(func(r *trust.Root) { r.Threshold = 4 })},
		{"threshold-maxint", "Threshold <= len(Keys)", mut(func(r *trust.Root) { r.Threshold = math.MaxInt })},
		{"nil-keys", "fewer keys than threshold", mut(func(r *trust.Root) { r.Keys = nil })},
		{"empty-keys", "fewer keys than threshold", mut(func(r *trust.Root) { r.Keys = map[wire.Hash]ed25519.PublicKey{} })},
		{"one-key-threshold-2", "fewer keys than threshold", rootOf("bank-a", 2, k.a)},
		{"one-key-threshold-1", "floor and keys", rootOf("bank-a", 1, k.a)},
		{"zero-value-root", "zero Root", trust.Root{}},
		{"key-under-wrong-id", "doc: a key stored under the wrong ID", mut(func(r *trust.Root) {
			r.Keys = map[wire.Hash]ed25519.PublicKey{kid(pub(k.a)): pub(k.a), kid(pub(k.b)): pub(k.c), kid(pub(k.c)): pub(k.c)}
		})},
		{"outsider-key-under-trusted-id", "key/ID mismatch", mut(func(r *trust.Root) {
			r.Keys = map[wire.Hash]ed25519.PublicKey{kid(pub(k.a)): pub(k.a), kid(pub(k.b)): pub(k.out)}
		})},
		{"key-31-bytes", "doc: key of the wrong size", mut(func(r *trust.Root) { r.Keys[kid(shortKey)] = shortKey })},
		{"key-33-bytes", "doc: key of the wrong size", mut(func(r *trust.Root) { r.Keys[kid(longKey)] = longKey })},
		{"key-nil", "doc: key of the wrong size", mut(func(r *trust.Root) { r.Keys[kid(pub(k.a))] = nil })},
		{"key-empty-under-garbage-id", "wrong size", mut(func(r *trust.Root) { r.Keys["zz"] = ed25519.PublicKey{} })},
		{"keyid-uppercase", "ID must be canonical lowercase hex", mut(func(r *trust.Root) {
			delete(r.Keys, kid(pub(k.c)))
			r.Keys[wire.Hash(strings.ToUpper(string(kid(pub(k.c)))))] = pub(k.c)
			r.Threshold = 3
		})},
		{"empty-tenant", "doc: a bad tenant", mut(func(r *trust.Root) { r.Tenant = "" })},
		{"uppercase-tenant", "wire.ID pattern", mut(func(r *trust.Root) { r.Tenant = "Bank-A" })},
		{"tenant-space", "wire.ID pattern", mut(func(r *trust.Root) { r.Tenant = "bank-a " })},
		{"tenant-leading-dash", "wire.ID pattern", mut(func(r *trust.Root) { r.Tenant = "-bank" })},
		{"tenant-64-chars", "wire.ID pattern max 63", mut(func(r *trust.Root) { r.Tenant = wire.ID(strings.Repeat("a", 64)) })},
		{"tenant-wildcard", "tenant must be a valid ID", mut(func(r *trust.Root) { r.Tenant = "*" })},
	}
	_ = three
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC on bad root (%s): %v", c.ref, r)
				}
			}()
			v, code, err := trust.Verify(env, c.root)
			if !errors.Is(err, trust.ErrBadRoot) || code != "" || v.Policy != nil {
				t.Fatalf("Verify (%s): code %q err %v policy %v; want ErrBadRoot, empty code, zero Verified", c.ref, code, err, v.Policy)
			}
			v, code, err = trust.Accept(env, c.root, 1, now, skew)
			if !errors.Is(err, trust.ErrBadRoot) || code != "" || v.Policy != nil {
				t.Fatalf("Accept (%s): code %q err %v policy %v; want ErrBadRoot, empty code, zero Verified", c.ref, code, err, v.Policy)
			}
		})
	}
}

// A bad root is reported before any envelope problem (doc: Verify checks the
// root floor first), so a broken config can never hide behind a bad envelope.
func TestBadRootBeatsEnvelopeErrors(t *testing.T) {
	k := loadKeys(t)
	bad := rootOf("bank-a", 1, k.a, k.b)
	envs := map[string]wire.Envelope{
		"wrong-payload-type": {PayloadType: "text/plain", Payload: goodPayload(), Signatures: signed(goodPayload(), k.a).Signatures},
		"no-sigs":            {PayloadType: wire.PayloadTypePolicy, Payload: goodPayload()},
		"zero-envelope":      {},
	}
	for n, e := range envs {
		_, code, err := trust.Accept(e, bad, 1, now, skew)
		if !errors.Is(err, trust.ErrBadRoot) || code != "" {
			t.Fatalf("%s: code %q err %v, want ErrBadRoot first", n, code, err)
		}
	}
}

// A threshold-1 root must not turn a one-signature policy (hand-edited file with
// one key) into an accepted one (I1, M-D33).
func TestThresholdOneRootNeverAcceptsOneSig(t *testing.T) {
	k := loadKeys(t)
	r := rootOf("bank-a", 1, k.a, k.b, k.c)
	for _, e := range []wire.Envelope{signed(goodPayload(), k.a), signed(goodPayload(), k.a, k.b)} {
		if v, code, err := trust.Accept(e, r, 1, now, skew); err == nil || code != "" || v.Policy != nil {
			t.Fatalf("threshold-1 root produced a pass: code %q err %v", code, err)
		}
	}
}

// Largest legal roots work (no overflow in counting); minimal root works.
func TestLegalRootShapes(t *testing.T) {
	k := loadKeys(t)
	expectAccept(t, "minimal root 2-of-2", signed(goodPayload(), k.a, k.b), rootOf("bank-a", 2, k.a, k.b), 1, now, skew)
	var ks []ed25519.PrivateKey
	for i := 0; i < 40; i++ {
		_, p, _ := ed25519.GenerateKey(nil)
		ks = append(ks, p)
	}
	big := rootOf("bank-a", 5, ks...)
	expectAccept(t, "5-of-40", signed(goodPayload(), ks[3], ks[39], ks[0], ks[7], ks[20]), big, 1, now, skew)
	expectReject(t, "4-of-40 vs threshold 5", signed(goodPayload(), ks[3], ks[39], ks[0], ks[7]), big, 1, now, skew, wire.ErrThreshold)
	// Tenant is a 63 char ID: legal.
	long := strings.Repeat("a", 63)
	expectAccept(t, "63-char tenant", signed(pol{tenant: long}.bytes(), k.a, k.b), rootOf(long, 2, k.a, k.b), 1, now, skew)
}

// M-D34 check order, one test per adjacent pair. Each envelope trips both
// checks; the earlier one must win.
func TestCheckOrder(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	pt := wire.PayloadTypePolicy
	bad := []byte(`{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","default":"allow","roles":{}}`)
	t.Run("payload_type-before-threshold", func(t *testing.T) {
		e := signed(goodPayload(), k.a) // one sig
		e.PayloadType = "text/plain"
		expectReject(t, "type+threshold", e, root, 1, now, skew, wire.ErrPayloadType)
	})
	t.Run("shape-before-threshold", func(t *testing.T) {
		e := signed(goodPayload(), k.a)
		e.Signatures[0].Sig = e.Signatures[0].Sig[:5]
		expectReject(t, "short sig + threshold", e, root, 1, now, skew, wire.ErrMalformed)
	})
	t.Run("threshold-before-parse", func(t *testing.T) {
		expectReject(t, "malformed policy with 1 sig", signed(bad, k.a), root, 1, now, skew, wire.ErrThreshold)
		expectReject(t, "malformed policy with unsigned garbage", signed([]byte("garbage"), k.a, k.a), root, 1, now, skew, wire.ErrThreshold)
	})
	t.Run("parse-before-tenant", func(t *testing.T) {
		b := []byte(strings.Replace(string(pol{tenant: "city-b"}.bytes()), `"default":"deny"`, `"default":"allow"`, 1))
		expectReject(t, "malformed + other tenant", signed(b, k.a, k.b), root, 1, now, skew, wire.ErrMalformed)
	})
	t.Run("tenant-before-version", func(t *testing.T) {
		expectReject(t, "other tenant + old version", signed(pol{tenant: "city-b", version: 1}.bytes(), k.a, k.b), root, 5, now, skew, wire.ErrWrongTenant)
	})
	t.Run("tenant-before-expiry", func(t *testing.T) {
		old := now.Add(-30 * 24 * time.Hour)
		expectReject(t, "other tenant + expired", signed(pol{tenant: "city-b", issued: old}.bytes(), k.a, k.b), root, 1, now, skew, wire.ErrWrongTenant)
	})
	t.Run("version-before-expiry", func(t *testing.T) {
		old := now.Add(-30 * 24 * time.Hour)
		expectReject(t, "old version + expired", signed(pol{version: 3, issued: old}.bytes(), k.a, k.b), root, 3, now, skew, wire.ErrNotNewer)
		expectReject(t, "older version + expired", signed(pol{version: 2, issued: old}.bytes(), k.a, k.b), root, 3, now, skew, wire.ErrNotNewer)
	})
	_ = pt
}

// Doc ambiguity: ARCHITECTURE trust LLD lists "shape, payload type" while go doc
// and cases.json list payload type / shape in the other order. Both are fine for
// every golden case; this pins only that BOTH checks reject.
func TestPayloadTypeAndShapeBothRejected(t *testing.T) {
	k := loadKeys(t)
	e := signed(goodPayload(), k.a, k.b)
	e.PayloadType = "text/plain"
	e.Signatures = nil // bad shape AND bad type
	_, code, err := trust.Verify(e, k.root())
	if err == nil || (code != wire.ErrPayloadType && code != wire.ErrMalformed) {
		t.Fatalf("code %q err %v: must reject as payload_type or malformed", code, err)
	}
}

// I2: version rule (Accept).
func TestVersionBoundaries(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	rows := []struct {
		name     string
		pv, have uint64
		accept   bool
	}{
		{"have-0-v1", 1, 0, true},
		{"have-v-1", 7, 6, true},
		{"have-equal", 7, 7, false},
		{"have-v+1", 7, 8, false},
		{"have-much-higher", 7, 1 << 40, false},
		{"v-1-have-0", 1, 1, false},
		{"v-max-have-max-1", math.MaxUint64, math.MaxUint64 - 1, true},
		{"v-max-have-max", math.MaxUint64, math.MaxUint64, false},
		{"v-2^63-have-2^63-1", 1 << 63, 1<<63 - 1, true},
		{"v-2^53+1-have-2^53", 1<<53 + 1, 1 << 53, true}, // float64 precision trap
		{"v-2^53-have-2^53+1", 1 << 53, 1<<53 + 1, false},
		{"v-small-have-max", 3, math.MaxUint64, false},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			e := signed(pol{version: r.pv}.bytes(), k.a, k.b)
			if r.accept {
				v := expectAccept(t, r.name, e, root, r.have, now, skew)
				if v.Policy.Version != r.pv {
					t.Fatalf("version %d, want %d", v.Policy.Version, r.pv)
				}
			} else {
				expectReject(t, r.name, e, root, r.have, now, skew, wire.ErrNotNewer)
			}
		})
	}
	// Verify ignores version (boot recheck): stored v3 re-verifies regardless.
	if _, code, err := trust.Verify(signed(pol{version: 3}.bytes(), k.a, k.b), root); code != "" || err != nil {
		t.Fatalf("Verify must not apply the version rule: %q %v", code, err)
	}
	// An envelope's advisory version (PollResponse.Version) cannot be injected: only
	// payload version counts. Policy.Version comes from signed bytes.
}

// Expiry boundaries (doc: exclusive; expired when now >= expires_at + skew).
func TestExpiryBoundaries(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	exp := time.Date(2026, 11, 6, 0, 0, 0, 0, time.UTC)
	env := signed(pol{issued: exp.Add(-72 * time.Hour), expires: exp}.bytes(), k.a, k.b)
	rows := []struct {
		name string
		at   time.Time
		sk   time.Duration
		ok   bool
	}{
		{"skew0-1ns-before", exp.Add(-time.Nanosecond), 0, true},
		{"skew0-exactly-at-expiry", exp, 0, false},
		{"skew0-1ns-after", exp.Add(time.Nanosecond), 0, false},
		{"skew0-1s-before", exp.Add(-time.Second), 0, true},
		{"skew2m-at-expiry", exp, 2 * time.Minute, true},
		{"skew2m-1ns-before-edge", exp.Add(2*time.Minute - time.Nanosecond), 2 * time.Minute, true},
		{"skew2m-exactly-edge", exp.Add(2 * time.Minute), 2 * time.Minute, false},
		{"skew2m-1ns-past-edge", exp.Add(2*time.Minute + time.Nanosecond), 2 * time.Minute, false},
		{"skew5m-1ns-before-edge", exp.Add(trust.MaxSkew - time.Nanosecond), trust.MaxSkew, true},
		{"skew5m-exactly-edge", exp.Add(trust.MaxSkew), trust.MaxSkew, false},
		{"skew1ns-at-expiry", exp, time.Nanosecond, true},
		{"skew1ns-at-edge", exp.Add(time.Nanosecond), time.Nanosecond, false},
		{"far-future-now", exp.Add(100 * 365 * 24 * time.Hour), trust.MaxSkew, false},
		{"far-past-now", exp.Add(-100 * 365 * 24 * time.Hour), 0, true},
		{"non-utc-location-same-instant", exp.Add(-time.Second).In(time.FixedZone("JST", 9*3600)), 0, true},
		{"non-utc-location-at-expiry", exp.In(time.FixedZone("JST", 9*3600)), 0, false},
		{"non-utc-negative-zone-past", exp.Add(time.Second).In(time.FixedZone("X", -11*3600)), 0, false},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			if r.ok {
				expectAccept(t, r.name, env, root, 1, r.at, r.sk)
			} else {
				expectReject(t, r.name, env, root, 1, r.at, r.sk, wire.ErrExpired)
			}
		})
	}
	t.Run("monotonic-reading-ignored", func(t *testing.T) {
		// time.Now() carries a monotonic clock reading; the wall instant decides.
		n := time.Now()
		pastExp := n.Add(-time.Second)
		e := signed(pol{issued: pastExp.Add(-time.Hour), expires: pastExp}.bytes(), k.a, k.b)
		expectReject(t, "expired one second ago", e, root, 1, n, 0, wire.ErrExpired)
	})
}

// Skew outside [0, MaxSkew] is ErrBadSkew and never a pass (I3).
func TestSkewBounds(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	env := signed(goodPayload(), k.a, k.b)
	for _, sk := range []time.Duration{-1, -time.Second, trust.MaxSkew + 1, trust.MaxSkew + time.Nanosecond, time.Hour, math.MaxInt64, math.MinInt64} {
		v, code, err := trust.Accept(env, root, 1, now, sk)
		if !errors.Is(err, trust.ErrBadSkew) || v.Policy != nil || code != "" {
			t.Fatalf("skew %v: code %q err %v policy %v; want ErrBadSkew and zero Verified", sk, code, err, v.Policy)
		}
	}
	if trust.MaxSkew != 5*time.Minute {
		t.Fatalf("MaxSkew = %v, want 5m (M-D33)", trust.MaxSkew)
	}
	// An expired policy plus a huge skew must not become valid (skew overflow trap).
	old := signed(pol{issued: now.Add(-1000 * time.Hour)}.bytes(), k.a, k.b)
	if _, code, err := trust.Accept(old, root, 1, now, math.MaxInt64); err == nil || code == "" && !errors.Is(err, trust.ErrBadSkew) {
		t.Fatalf("expired policy with MaxInt64 skew passed: %q %v", code, err)
	}
	// Exactly the allowed edges work.
	expectAccept(t, "skew 0", env, root, 1, now, 0)
	expectAccept(t, "skew MaxSkew", env, root, 1, now, trust.MaxSkew)
}

// Skew applies to expiry only: it must not weaken the version or signature rules.
func TestSkewDoesNotWidenOtherChecks(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	expectReject(t, "max skew, same version", signed(goodPayload(), k.a, k.b), root, 2, now, trust.MaxSkew, wire.ErrNotNewer)
	expectReject(t, "max skew, one sig", signed(goodPayload(), k.a), root, 1, now, trust.MaxSkew, wire.ErrThreshold)
	// Time-travel: signatures do not carry a signing time, issued_at in the far
	// future is not rejected by docs; but expires before issued_at is malformed.
	exp := now.Add(-time.Minute)
	expectReject(t, "expires before issued", signed(pol{issued: now.Add(time.Hour), expires: exp}.bytes(), k.a, k.b), root, 1, now, skew, wire.ErrMalformed)
}

// Tenant attacks (I1 scope, M-D26).
func TestTenantAttacks(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	for _, tn := range []string{"city-b", "bank-b", "bank-", "bank", "bank-a-", "a", "bank-a2", "0bank-a"} {
		expectReject(t, "tenant "+tn, signed(pol{tenant: tn}.bytes(), k.a, k.b), root, 1, now, skew, wire.ErrWrongTenant)
	}
	// Homoglyph / case / padding variants of the right tenant must not match: they
	// are either malformed (not a wire.ID) or wrong_tenant, never accepted.
	for _, tn := range []string{"BANK-A", "bank-a ", " bank-a", "bank-a\u200b", "bаnk-a" /* cyrillic a */, "bank-a\x00", "bank‐a", "ｂank-a"} {
		e := signed(pol{tenant: tn}.bytes(), k.a, k.b)
		v, code, err := trust.Accept(e, root, 1, now, skew)
		if err == nil || v.Policy != nil || (code != wire.ErrMalformed && code != wire.ErrWrongTenant) {
			t.Fatalf("tenant %q: code %q err %v; want malformed or wrong_tenant", tn, code, err)
		}
	}
	// The right tenant on a root of another tenant.
	expectReject(t, "bank-a policy on city-b proxy", signed(goodPayload(), k.a, k.b), rootOf("city-b", 2, k.a, k.b, k.c), 1, now, skew, wire.ErrWrongTenant)
	// Cross-tenant replay of a city-b policy that city-b's root would accept.
	cb := signed(pol{tenant: "city-b"}.bytes(), k.a, k.b)
	expectAccept(t, "city-b on city-b", cb, rootOf("city-b", 2, k.a, k.b, k.c), 1, now, skew)
	expectReject(t, "same envelope on bank-a", cb, k.root(), 1, now, skew, wire.ErrWrongTenant)
}

// M-D44: signing fresh bytes with trailing whitespace is a valid policy and its
// hash is over the exact (padded) bytes; any other trailing byte is malformed.
func TestSignedTrailingBytes(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	base := goodPayload()
	for _, tail := range []string{" ", "\n", "\r\n", "\t", " \n\t\r "} {
		p := append(append([]byte(nil), base...), tail...)
		v := expectAccept(t, "trailing "+tail, signed(p, k.a, k.b), root, 1, now, skew)
		if v.Hash != sha(p) {
			t.Fatalf("hash %s is not over the exact signed bytes %s", v.Hash, sha(p))
		}
		if v.Hash == sha(base) {
			t.Fatal("hash ignores the trailing whitespace; policy hash must cover exact payload bytes")
		}
	}
	for _, tail := range []string{"\x00", "\v", "\f", " ", "\ufeff", "x", "{}", ",", " \x00", " "} {
		p := append(append([]byte(nil), base...), tail...)
		expectReject(t, "trailing "+tail, signed(p, k.a, k.b), root, 1, now, skew, wire.ErrMalformed)
	}
	// Leading BOM or whitespace: only trailing whitespace is promised; a BOM must not be accepted.
	expectReject(t, "BOM", signed(append([]byte("\ufeff"), base...), k.a, k.b), root, 1, now, skew, wire.ErrMalformed)
}

// Error values never echo envelope content (I4, doc: fixed text).
func TestErrorsDoNotEchoEnvelope(t *testing.T) {
	k := loadKeys(t)
	const canary = "CANARY-SECRET-7f3a91"
	root := k.root()
	envs := []wire.Envelope{
		func() wire.Envelope { e := signed(goodPayload(), k.a, k.b); e.PayloadType = canary; return e }(),
		signed([]byte(`{"`+canary+`":1}`), k.a, k.b),
		signed([]byte(`{"tenant":"`+canary+`"}`), k.a, k.b),
		signed([]byte(strings.Replace(string(goodPayload()), "sales", canary, 1)+canary), k.a, k.b),
		signed([]byte(canary), k.a),
		signed(pol{tenant: "city-b", extraRole: `,"` + canary + `":{}`}.bytes(), k.a, k.b),
		{PayloadType: wire.PayloadTypePolicy, Payload: []byte(canary), Signatures: []wire.Signature{{KeyID: wire.Hash(canary), Sig: []byte(canary)}}},
	}
	for i, e := range envs {
		_, code, err := trust.Accept(e, root, 1, now, skew)
		if err == nil {
			t.Fatalf("env %d accepted", i)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(string(code), canary) {
			t.Fatalf("env %d: error %q echoes envelope content (I4)", i, err)
		}
	}
}
