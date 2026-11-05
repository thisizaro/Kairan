package trustbreak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

func sha(b []byte) wire.Hash {
	s := sha256.Sum256(b)
	return wire.Hash(hex.EncodeToString(s[:]))
}

// PAE and KeyID against the DSSE spec vector and independent code (M-D2).
func TestPAEAndKeyID(t *testing.T) {
	cases := []struct {
		pt      string
		payload []byte
	}{
		{"http://example.com/HelloWorld", []byte("hello world")}, // DSSE spec vector
		{"", nil},
		{"", []byte{}},
		{wire.PayloadTypePolicy, []byte("{}")},
		{"a b", []byte("c d")},
		{"x", []byte{0, 1, 2, 0xff, ' ', '\n'}},
		{strings.Repeat("t", 1000), bytes.Repeat([]byte("p"), 70000)},
		{"日本語", []byte("日本語")}, // len is bytes, not runes
	}
	for _, c := range cases {
		got := trust.PAE(c.pt, c.payload)
		if !bytes.Equal(got, pae(c.pt, c.payload)) {
			t.Fatalf("PAE(%q,%d bytes) differs from DSSE v1 reference", abbr(c.pt), len(c.payload))
		}
	}
	if s := string(trust.PAE("http://example.com/HelloWorld", []byte("hello world"))); s != "DSSEv1 29 http://example.com/HelloWorld 11 hello world" {
		t.Fatalf("DSSE spec vector: %q", s)
	}
	// Fresh slice: mutating the result must not touch the input.
	in := []byte("abc")
	out := trust.PAE("t", in)
	for i := range out {
		out[i] = 'Z'
	}
	if string(in) != "abc" {
		t.Fatal("PAE result aliases its input")
	}
	// Fresh per call.
	a, b := trust.PAE("t", in), trust.PAE("t", in)
	a[0] = 'X'
	if b[0] != 'D' {
		t.Fatal("PAE results share memory")
	}
	k := loadKeys(t)
	if got, want := trust.KeyID(pub(k.a)), kid(pub(k.a)); got != want || !got.Valid() {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}
	// Distinct keys distinct IDs; 4 test keys.
	ids := map[wire.Hash]bool{}
	for _, x := range []ed25519.PrivateKey{k.a, k.b, k.c, k.out} {
		ids[trust.KeyID(pub(x))] = true
	}
	if len(ids) != 4 {
		t.Fatal("key ID collision among distinct keys")
	}
}

func abbr(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

// Sign appends exactly one valid PAE signature per call and does not touch the
// payload (trust doc). The result must verify under independent ed25519.
func TestSignHelper(t *testing.T) {
	k := loadKeys(t)
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: goodPayload()}
	orig := append([]byte(nil), env.Payload...)
	trust.Sign(&env, k.a)
	trust.Sign(&env, k.b)
	if len(env.Signatures) != 2 {
		t.Fatalf("Sign appended %d signatures, want 2", len(env.Signatures))
	}
	if !bytes.Equal(env.Payload, orig) {
		t.Fatal("Sign changed the payload")
	}
	for i, kk := range []ed25519.PrivateKey{k.a, k.b} {
		s := env.Signatures[i]
		if s.KeyID != kid(pub(kk)) {
			t.Fatalf("sig %d key ID %s, want %s", i, s.KeyID, kid(pub(kk)))
		}
		if !ed25519.Verify(pub(kk), pae(env.PayloadType, env.Payload), s.Sig) {
			t.Fatalf("sig %d does not verify over the DSSE PAE", i)
		}
	}
	expectAccept(t, "Sign()-built envelope", env, k.root(), 1, now, skew)
	// Differential: an envelope signed independently is accepted equally.
	expectAccept(t, "independently signed", signed(orig, k.a, k.b), k.root(), 1, now, skew)
}

// I1: forgery attempts. Each row is an envelope that must NOT be accepted.
func TestForgeryAttacks(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	p := goodPayload()
	pt := wire.PayloadTypePolicy
	good := pae(pt, p)

	// relabel returns a copy of sig with another key's ID.
	relabel := func(s wire.Signature, as ed25519.PrivateKey) wire.Signature {
		return wire.Signature{KeyID: kid(pub(as)), Sig: s.Sig}
	}
	upper := func(h wire.Hash) wire.Hash { return wire.Hash(strings.ToUpper(string(h))) }
	rePadded := append([]byte(" "), p...) // not the signed bytes
	compact := bytes.ReplaceAll(p, []byte(`"sales":`), []byte(`"sales": `))
	var pretty bytes.Buffer
	pretty.WriteString("\n")
	pretty.Write(p)

	type row struct {
		name, ref string
		env       wire.Envelope
		want      wire.ErrorCode
	}
	mk := func(sigs ...wire.Signature) wire.Envelope {
		return wire.Envelope{PayloadType: pt, Payload: p, Signatures: sigs}
	}
	rows := []row{
		{"same-key-twice", "I1/M-D2 duplicate key counts once", mk(sigOf(k.a, good), sigOf(k.a, good)), wire.ErrThreshold},
		{"same-key-4x", "I1", mk(sigOf(k.a, good), sigOf(k.a, good), sigOf(k.a, good), sigOf(k.a, good)), wire.ErrThreshold},
		{"b-signature-labelled-a-and-real-a", "mislabeled keyid never lends a vote", mk(sigOf(k.a, good), relabel(sigOf(k.b, good), k.a)), wire.ErrThreshold},
		{"b-labelled-c-plus-a", "M-D34 mislabeled-keyid", mk(sigOf(k.a, good), relabel(sigOf(k.b, good), k.c)), wire.ErrThreshold},
		{"swapped-labels", "both labels swapped", mk(relabel(sigOf(k.a, good), k.b), relabel(sigOf(k.b, good), k.a)), wire.ErrThreshold},
		{"outsider-labelled-as-trusted", "untrusted key claims a trusted ID", mk(sigOf(k.a, good), relabel(sigOf(k.out, good), k.b)), wire.ErrThreshold},
		{"outsider-only-and-a", "untrusted second signer", mk(sigOf(k.a, good), sigOf(k.out, good)), wire.ErrThreshold},
		{"keyid-uppercase-alias", "key ID is lowercase hex (wire.Hash); alias must not match", mk(sigOf(k.a, good), wire.Signature{KeyID: upper(kid(pub(k.b))), Sig: ed25519.Sign(k.b, good)}), wire.ErrMalformed},
		{"keyid-short", "wire.Hash length", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b))[:63], Sig: ed25519.Sign(k.b, good)}), wire.ErrMalformed},
		{"keyid-prefix-0x", "wire.Hash charset", mk(sigOf(k.a, good), wire.Signature{KeyID: wire.Hash("0x" + string(kid(pub(k.b)))[2:]), Sig: ed25519.Sign(k.b, good)}), wire.ErrMalformed},
		{"keyid-empty", "wire.Hash", mk(sigOf(k.a, good), wire.Signature{KeyID: "", Sig: ed25519.Sign(k.b, good)}), wire.ErrMalformed},
		{"keyid-trailing-space", "no trimming of IDs", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b)) + " ", Sig: ed25519.Sign(k.b, good)}), wire.ErrMalformed},
		{"raw-payload-signature", "M-D2/M-D34: signatures cover PAE, not raw bytes", mk(sigOf(k.a, p), sigOf(k.b, p)), wire.ErrThreshold},
		{"sig-over-payload-only-one-pae", "one raw one PAE", mk(sigOf(k.a, good), sigOf(k.b, p)), wire.ErrThreshold},
		{"sig-over-other-payload-type", "payloadType is inside the PAE", mk(sigOf(k.a, pae("text/plain", p)), sigOf(k.b, pae("text/plain", p))), wire.ErrThreshold},
		{"sig-over-pae-with-wrong-length", "length prefix is part of PAE", mk(sigOf(k.a, append([]byte("DSSEv1 35 "+pt+" 1 "), p...)), sigOf(k.b, append([]byte("DSSEv1 35 "+pt+" 1 "), p...))), wire.ErrThreshold},
		{"sig-over-pae-without-prefix", "PAE magic", mk(sigOf(k.a, append([]byte(pt+" "), p...)), sigOf(k.b, append([]byte(pt+" "), p...))), wire.ErrThreshold},
		{"sig-over-pae-lowercase-magic", "PAE magic exact", mk(sigOf(k.a, bytes.Replace(good, []byte("DSSEv1"), []byte("dsseV1"), 1)), sigOf(k.b, bytes.Replace(good, []byte("DSSEv1"), []byte("dsseV1"), 1))), wire.ErrThreshold},
		{"sig-over-pae-newline-sep", "PAE separators are single spaces", mk(sigOf(k.a, bytes.Replace(good, []byte(" "), []byte("\n"), 1)), sigOf(k.b, bytes.Replace(good, []byte(" "), []byte("\n"), 1))), wire.ErrThreshold},
		{"sigs-over-prefixed-payload", "signatures bind exact bytes: payload has a leading space", wire.Envelope{PayloadType: pt, Payload: rePadded, Signatures: []wire.Signature{sigOf(k.a, good), sigOf(k.b, good)}}, wire.ErrThreshold},
		{"sigs-over-reencoded-json", "sign bytes, never re-encoded JSON (PRD Envelope)", wire.Envelope{PayloadType: pt, Payload: compact, Signatures: []wire.Signature{sigOf(k.a, good), sigOf(k.b, good)}}, wire.ErrThreshold},
		{"sigs-over-leading-newline-variant", "same JSON, different bytes", wire.Envelope{PayloadType: pt, Payload: pretty.Bytes(), Signatures: []wire.Signature{sigOf(k.a, good), sigOf(k.b, good)}}, wire.ErrThreshold},
		{"sig-all-zero", "64 zero bytes", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b)), Sig: make([]byte, 64)}), wire.ErrThreshold},
		{"sig-all-ff", "64 0xff bytes", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b)), Sig: bytes.Repeat([]byte{0xff}, 64)}), wire.ErrThreshold},
		{"both-sigs-all-zero", "no signature at all", mk(wire.Signature{KeyID: kid(pub(k.a)), Sig: make([]byte, 64)}, wire.Signature{KeyID: kid(pub(k.b)), Sig: make([]byte, 64)}), wire.ErrThreshold},
		{"sig-63-bytes", "shape: SignatureSize", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b)), Sig: ed25519.Sign(k.b, good)[:63]}), wire.ErrMalformed},
		{"sig-65-bytes", "shape: SignatureSize", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b)), Sig: append(ed25519.Sign(k.b, good), 0)}), wire.ErrMalformed},
		{"sig-nil", "shape", mk(sigOf(k.a, good), wire.Signature{KeyID: kid(pub(k.b))}), wire.ErrMalformed},
		{"no-signatures", "shape: 1-8 sigs", mk(), wire.ErrMalformed},
		{"nil-signatures", "shape", wire.Envelope{PayloadType: pt, Payload: p}, wire.ErrMalformed},
		{"empty-payload", "shape: empty payload", wire.Envelope{PayloadType: pt, Signatures: []wire.Signature{sigOf(k.a, pae(pt, nil)), sigOf(k.b, pae(pt, nil))}}, wire.ErrMalformed},
		{"payload-type-case", "payload type exact", wire.Envelope{PayloadType: strings.ToUpper(pt), Payload: p, Signatures: []wire.Signature{sigOf(k.a, pae(strings.ToUpper(pt), p)), sigOf(k.b, pae(strings.ToUpper(pt), p))}}, wire.ErrPayloadType},
		{"payload-type-trailing-space", "payload type exact", wire.Envelope{PayloadType: pt + " ", Payload: p, Signatures: []wire.Signature{sigOf(k.a, pae(pt+" ", p)), sigOf(k.b, pae(pt+" ", p))}}, wire.ErrPayloadType},
		{"payload-type-empty", "payloadType confusion", wire.Envelope{PayloadType: "", Payload: p, Signatures: []wire.Signature{sigOf(k.a, pae("", p)), sigOf(k.b, pae("", p))}}, wire.ErrPayloadType},
		{"payload-type-embeds-length", "payloadType confusion: type contains a PAE fragment", wire.Envelope{PayloadType: "x 1 y", Payload: p, Signatures: []wire.Signature{sigOf(k.a, pae("x 1 y", p)), sigOf(k.b, pae("x 1 y", p))}}, wire.ErrPayloadType},
		{"payload-type-nul", "payloadType confusion", wire.Envelope{PayloadType: pt + "\x00", Payload: p, Signatures: []wire.Signature{sigOf(k.a, pae(pt+"\x00", p)), sigOf(k.b, pae(pt+"\x00", p))}}, wire.ErrPayloadType},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			expectReject(t, r.ref, r.env, root, 1, now, skew, r.want)
			// Verify must agree on the signature outcome (no version/expiry involved).
			v, code, err := trust.Verify(r.env, root)
			if code != r.want || err == nil || v.Policy != nil {
				t.Fatalf("Verify: code %q err %v policy %v; want %q", code, err, v.Policy, r.want)
			}
		})
	}
}

// PAE binds both the type and the payload: a signature made for one (type,payload)
// pair must not carry to a colliding pair like (A+" "+n+" "+B, C).
func TestPAEDomainSeparation(t *testing.T) {
	a := trust.PAE("ab", []byte("c"))
	b := trust.PAE("a", []byte("b c"))
	if bytes.Equal(a, b) {
		t.Fatal("PAE collision between different (type, payload) pairs")
	}
	// Length-extension style: type that embeds the rest of the framing.
	c := trust.PAE("a 1 b", []byte("c"))
	d := trust.PAE("a", []byte("1 b 1 c"))
	if bytes.Equal(c, d) {
		t.Fatal("PAE collision using embedded framing")
	}
}

// Ed25519 malleability: S + L is a different byte string that a lax verifier
// accepts. It must neither count as a vote nor as a second distinct vote (I1).
func TestSignatureMalleability(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	p := goodPayload()
	good := pae(wire.PayloadTypePolicy, p)

	l, _ := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	malleate := func(sig []byte) []byte {
		// S is little-endian in sig[32:].
		s := new(big.Int).SetBytes(reverse(sig[32:]))
		s.Add(s, l)
		sb := s.Bytes() // big endian
		if len(sb) > 32 {
			t.Fatal("S+L overflowed 32 bytes")
		}
		out := append([]byte(nil), sig[:32]...)
		buf := make([]byte, 32)
		copy(buf[32-len(sb):], sb)
		return append(out, reverse(buf)...)
	}
	sa, sb := ed25519.Sign(k.a, good), ed25519.Sign(k.b, good)
	ma, mb := malleate(sa), malleate(sb)
	if ed25519.Verify(pub(k.a), good, ma) {
		t.Skip("stdlib accepts non-canonical S; test premise void")
	}
	if bytes.Equal(ma, sa) {
		t.Fatal("test bug: malleated equals original")
	}
	sig := func(key ed25519.PrivateKey, s []byte) wire.Signature {
		return wire.Signature{KeyID: kid(pub(key)), Sig: s}
	}
	mk := func(sigs ...wire.Signature) wire.Envelope {
		return wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: p, Signatures: sigs}
	}
	t.Run("one-malleated-one-good", func(t *testing.T) {
		expectReject(t, "S+L signature must not count", mk(sig(k.a, sa), sig(k.b, mb)), root, 1, now, skew, wire.ErrThreshold)
	})
	t.Run("both-malleated", func(t *testing.T) {
		expectReject(t, "S+L x2", mk(sig(k.a, ma), sig(k.b, mb)), root, 1, now, skew, wire.ErrThreshold)
	})
	t.Run("original-plus-malleated-same-key", func(t *testing.T) {
		expectReject(t, "one key, two encodings, still one vote", mk(sig(k.a, sa), sig(k.a, ma)), root, 1, now, skew, wire.ErrThreshold)
	})
	// A different R with a recomputed-looking but invalid tail.
	t.Run("high-bit-set-in-S", func(t *testing.T) {
		x := append([]byte(nil), sb...)
		x[63] |= 0xe0
		expectReject(t, "S >= 2^253", mk(sig(k.a, sa), sig(k.b, x)), root, 1, now, skew, wire.ErrThreshold)
	})
	t.Run("R-bit-flips", func(t *testing.T) {
		for i := 0; i < 32; i++ {
			x := append([]byte(nil), sb...)
			x[i] ^= 1
			expectReject(t, "R byte flipped", mk(sig(k.a, sa), sig(k.b, x)), root, 1, now, skew, wire.ErrThreshold)
		}
	})
}

func reverse(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

// Every single-bit-position tamper of the payload and of each signature must be
// caught (I1). Sweeps every byte of the golden valid envelope.
func TestSingleByteTamperSweep(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	p := goodPayload()
	base := signed(p, k.a, k.b)

	t.Run("payload", func(t *testing.T) {
		for i := range base.Payload {
			e := clone(base)
			e.Payload[i] ^= 0x01
			v, code, _ := trust.Accept(e, root, 1, now, skew)
			if code == "" || v.Policy != nil {
				t.Fatalf("payload byte %d flipped, still accepted", i)
			}
			if code != wire.ErrThreshold {
				// Check order (M-D34): signatures come before policy parse.
				t.Fatalf("payload byte %d flipped: code %q, want threshold_not_met", i, code)
			}
		}
	})
	t.Run("payload-truncate-and-extend", func(t *testing.T) {
		for _, f := range []func([]byte) []byte{
			func(b []byte) []byte { return b[:len(b)-1] },
			func(b []byte) []byte { return append(b, ' ') },
			func(b []byte) []byte { return append(b, '\n') },
			func(b []byte) []byte { return append(b, 0) },
			func(b []byte) []byte { return append([]byte{' '}, b...) },
		} {
			e := clone(base)
			e.Payload = f(e.Payload)
			expectReject(t, "payload changed after signing", e, root, 1, now, skew, wire.ErrThreshold)
		}
	})
	t.Run("signature-bytes", func(t *testing.T) {
		for si := range base.Signatures {
			for i := 0; i < wire.SignatureSize; i++ {
				e := clone(base)
				e.Signatures[si].Sig[i] ^= 0x80
				expectReject(t, "signature byte flipped", e, root, 1, now, skew, wire.ErrThreshold)
			}
		}
	})
	t.Run("payload-type", func(t *testing.T) {
		for i := range base.PayloadType {
			e := clone(base)
			b := []byte(e.PayloadType)
			b[i] ^= 0x01
			e.PayloadType = string(b)
			expectReject(t, "payloadType byte flipped", e, root, 1, now, skew, wire.ErrPayloadType)
		}
	})
	t.Run("keyid-nibble", func(t *testing.T) {
		for si := range base.Signatures {
			for i := 0; i < 64; i++ {
				e := clone(base)
				b := []byte(e.Signatures[si].KeyID)
				if b[i] == '0' {
					b[i] = '1'
				} else {
					b[i] = '0'
				}
				e.Signatures[si].KeyID = wire.Hash(b)
				expectReject(t, "key ID altered", e, root, 1, now, skew, wire.ErrThreshold)
			}
		}
	})
	t.Run("three-sigs-one-flip-still-ok-two-flips-not", func(t *testing.T) {
		e := signed(p, k.a, k.b, k.c)
		e.Signatures[2].Sig[10] ^= 1
		v := expectAccept(t, "2 of 3 valid", e, root, 1, now, skew)
		if len(v.Signers) != 2 {
			t.Fatalf("Signers = %d, want 2", len(v.Signers))
		}
		for _, s := range v.Signers {
			if s == kid(pub(k.c)) {
				t.Fatal("a failed signature's key is listed as a signer")
			}
		}
		e.Signatures[1].Sig[10] ^= 1
		expectReject(t, "1 of 3 valid", e, root, 1, now, skew, wire.ErrThreshold)
	})
}

// Counting: duplicates are legal as noise but never as votes; 8 vs 9 (cap).
func TestSignatureCounting(t *testing.T) {
	k := loadKeys(t)
	p := goodPayload()
	root := k.root()

	t.Run("a-b-b-accepted-with-two-signers", func(t *testing.T) {
		e := signed(p, k.a, k.b, k.b)
		v := expectAccept(t, "2 distinct + repeat", e, root, 1, now, skew)
		if len(v.Signers) != 2 {
			t.Fatalf("Signers %v, want exactly 2 distinct", v.Signers)
		}
	})
	t.Run("a-a-a-b-c-with-threshold-3", func(t *testing.T) {
		r3 := rootOf("bank-a", 3, k.a, k.b, k.c)
		expectReject(t, "a,a,a,b = 2 distinct", signed(p, k.a, k.a, k.a, k.b), r3, 1, now, skew, wire.ErrThreshold)
		expectAccept(t, "a,b,c", signed(p, k.a, k.b, k.c), r3, 1, now, skew)
	})
	t.Run("order-independent", func(t *testing.T) {
		expectAccept(t, "c,a", signed(p, k.c, k.a), root, 1, now, skew)
		expectAccept(t, "b,c,a", signed(p, k.b, k.c, k.a), root, 1, now, skew)
	})
	t.Run("invalid-sigs-interleaved-do-not-hide-valid-ones", func(t *testing.T) {
		e := signed(p, k.a, k.b)
		junk := wire.Signature{KeyID: kid(pub(k.out)), Sig: make([]byte, 64)}
		e.Signatures = append([]wire.Signature{junk, junk}, e.Signatures...)
		expectAccept(t, "junk then valid", e, root, 1, now, skew)
	})
	t.Run("eight-sigs-ok-nine-malformed", func(t *testing.T) {
		var ks []ed25519.PrivateKey
		for i := 0; i < 9; i++ {
			seed := sha256.Sum256([]byte{byte(i), 'Q', 'b', 'r', 'e', 'a', 'k'})
			ks = append(ks, ed25519.NewKeyFromSeed(seed[:]))
		}
		r8 := rootOf("bank-a", 8, ks[:8]...)
		expectAccept(t, "exactly 8 sigs, threshold 8", signed(p, ks[:8]...), r8, 1, now, skew)
		r9 := rootOf("bank-a", 2, ks...)
		expectReject(t, "9 sigs (cap 8, wire.MaxSignatures)", signed(p, ks...), r9, 1, now, skew, wire.ErrMalformed)
		// 9 signatures where only the 9th is the second trusted one: still malformed, not a pass.
		e := signed(p, ks[0])
		for i := 0; i < 7; i++ {
			e.Signatures = append(e.Signatures, wire.Signature{KeyID: kid(pub(k.out)), Sig: make([]byte, 64)})
		}
		e.Signatures = append(e.Signatures, signed(p, ks[1]).Signatures[0])
		expectReject(t, "9 sigs hiding the 2nd vote at the end", e, r9, 1, now, skew, wire.ErrMalformed)
	})
	t.Run("threshold-above-signers-present", func(t *testing.T) {
		r := rootOf("bank-a", 3, k.a, k.b, k.c)
		expectReject(t, "2 valid, threshold 3", signed(p, k.a, k.b), r, 1, now, skew, wire.ErrThreshold)
	})
	t.Run("threshold-equals-all-keys", func(t *testing.T) {
		r := rootOf("bank-a", 2, k.a, k.b)
		expectAccept(t, "a,b of {a,b}", signed(p, k.a, k.b), r, 1, now, skew)
		expectReject(t, "a,c of {a,b}", signed(p, k.a, k.c), r, 1, now, skew, wire.ErrThreshold)
	})
}

// Model-based differential: random mixes of valid/forged/mislabeled/duplicate
// signatures against a trivially-correct model of "distinct trusted valid keys".
func TestSignatureModelDifferential(t *testing.T) {
	k := loadKeys(t)
	p := goodPayload()
	good := pae(wire.PayloadTypePolicy, p)
	all := []ed25519.PrivateKey{k.a, k.b, k.c, k.out}
	trusted := map[wire.Hash]bool{kid(pub(k.a)): true, kid(pub(k.b)): true, kid(pub(k.c)): true}
	root := k.root()
	state := uint64(0x9e3779b97f4a7c15)
	rnd := func(n int) int {
		state ^= state << 13
		state ^= state >> 7
		state ^= state << 17
		return int(state % uint64(n))
	}
	for iter := 0; iter < 3000; iter++ {
		n := 1 + rnd(8)
		var sigs []wire.Signature
		distinct := map[wire.Hash]bool{}
		for j := 0; j < n; j++ {
			signer := all[rnd(4)]
			label := all[rnd(4)]
			kind := rnd(4)
			var s wire.Signature
			valid := false
			switch kind {
			case 0, 1: // genuine, own label
				s = sigOf(signer, good)
				label = signer
				valid = true
			case 2: // genuine signature under someone's label
				s = wire.Signature{KeyID: kid(pub(label)), Sig: ed25519.Sign(signer, good)}
				valid = signer.Equal(label)
			case 3: // signature over raw payload
				s = wire.Signature{KeyID: kid(pub(label)), Sig: ed25519.Sign(label, p)}
			}
			if valid && trusted[kid(pub(label))] {
				distinct[kid(pub(label))] = true
			}
			sigs = append(sigs, s)
		}
		env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: p, Signatures: sigs}
		v, code, err := trust.Accept(env, root, 1, now, skew)
		wantOK := len(distinct) >= 2
		if wantOK != (code == "") {
			t.Fatalf("iter %d: model says accept=%v with %d distinct trusted votes; got code %q err %v", iter, wantOK, len(distinct), code, err)
		}
		if wantOK && len(v.Signers) != len(distinct) {
			t.Fatalf("iter %d: Signers %d, model %d", iter, len(v.Signers), len(distinct))
		}
	}
}

// Verify and Accept must not mutate the envelope or root the caller owns, and the
// returned Policy must not alias the payload (TOCTOU safety).
func TestNoMutationNoAliasing(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	env := signed(goodPayload(), k.a, k.b)
	before := clone(env)
	nKeys := len(root.Keys)
	v := expectAccept(t, "valid", env, root, 1, now, skew)
	if string(env.Payload) != string(before.Payload) || len(env.Signatures) != len(before.Signatures) || len(root.Keys) != nKeys {
		t.Fatal("Accept mutated its inputs")
	}
	for i := range env.Signatures {
		if !bytes.Equal(env.Signatures[i].Sig, before.Signatures[i].Sig) || env.Signatures[i].KeyID != before.Signatures[i].KeyID {
			t.Fatal("Accept mutated signatures")
		}
	}
	d1 := v.Policy.Decide("sales", "crm.update_deal", false)
	// Caller scribbles over the payload after verification.
	for i := range env.Payload {
		env.Payload[i] = 'x'
	}
	for i := range v.Signers {
		_ = v.Signers[i]
	}
	if d2 := v.Policy.Decide("sales", "crm.update_deal", false); d1 != d2 {
		t.Fatalf("policy changed after the payload buffer was overwritten: %+v vs %+v", d1, d2)
	}
	if v.Policy.Version != 2 || v.Policy.Tenant != "bank-a" {
		t.Fatalf("policy fields changed: %+v", v.Policy)
	}
	// Mutating a returned Signers slice must not corrupt the next verification.
	e2 := signed(goodPayload(), k.a, k.b)
	v1 := expectAccept(t, "again", e2, root, 1, now, skew)
	v1.Signers[0] = "zzz"
	v2 := expectAccept(t, "again2", e2, root, 1, now, skew)
	if v2.Signers[0] == "zzz" {
		t.Fatal("Signers slice shared between calls")
	}
}

// -race: many goroutines verify one shared envelope/root; also one failing mix.
func TestConcurrentAccept(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	good := signed(goodPayload(), k.a, k.b)
	bad := signed(goodPayload(), k.a, k.a)
	done := make(chan string, 64)
	for g := 0; g < 32; g++ {
		go func(g int) {
			for i := 0; i < 50; i++ {
				_, c, _ := trust.Accept(good, root, 1, now, skew)
				if c != "" {
					done <- "good rejected: " + string(c)
					return
				}
				_, c, _ = trust.Accept(bad, root, 1, now, skew)
				if c != wire.ErrThreshold {
					done <- "bad not rejected: " + string(c)
					return
				}
				e := clone(good)
				e.Payload[g%len(e.Payload)] ^= 1
				if _, c, _ = trust.Verify(e, root); c == "" {
					done <- "tampered accepted"
					return
				}
			}
			done <- ""
		}(g)
	}
	for g := 0; g < 32; g++ {
		if m := <-done; m != "" {
			t.Fatal(m)
		}
	}
}
