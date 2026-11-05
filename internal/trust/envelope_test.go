package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"testing"

	"kairan/internal/wire"
)

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kairan TEST-ONLY " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestPAE(t *testing.T) {
	tests := []struct {
		name, typ string
		payload   []byte
		want      string
	}{
		{"spec example", "http://example.com/HelloWorld", []byte("hello world"),
			"DSSEv1 29 http://example.com/HelloWorld 11 hello world"},
		{"empty", "", nil, "DSSEv1 0  0 "},
		{"binary", "t", []byte{0, 1, 0xff}, "DSSEv1 1 t 3 \x00\x01\xff"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := PAE(tc.typ, tc.payload); string(got) != tc.want {
				t.Fatalf("PAE = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestPAEDoesNotAliasPayload(t *testing.T) {
	p := make([]byte, 4, 64)
	got := PAE("t", p)
	got[len(got)-1] = 9
	if p[:4][3] != 0 {
		t.Fatal("PAE wrote into the payload's backing array")
	}
}

func TestKeyID(t *testing.T) {
	k := testKey("admin-a")
	sum := sha256.Sum256(pub(k))
	want := wire.Hash(hex.EncodeToString(sum[:]))
	got := KeyID(pub(k))
	if got != want || !got.Valid() {
		t.Fatalf("KeyID = %q, want %q", got, want)
	}
	// Pinned against the fixture generator: admin-a's key ID in valid.json.
	if got != "95f9872ca090c9dda41fb865ba7383733c7872c0a79b88199b8e12e9932eb9de" {
		t.Fatalf("KeyID(admin-a) = %q", got)
	}
}

func TestSignAppendsVerifiableSignature(t *testing.T) {
	a, b := testKey("admin-a"), testKey("admin-b")
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(`{"x":1}`)}
	Sign(&env, a)
	Sign(&env, b)
	if len(env.Signatures) != 2 {
		t.Fatalf("got %d signatures", len(env.Signatures))
	}
	if err := env.ValidateShape(); err != nil {
		t.Fatal(err)
	}
	keys := map[wire.Hash]ed25519.PublicKey{KeyID(pub(a)): pub(a), KeyID(pub(b)): pub(b)}
	got := validSigners(env, keys)
	if len(got) != 2 {
		t.Fatalf("validSigners = %v", got)
	}
}

func TestValidSigners(t *testing.T) {
	a, b, c := testKey("admin-a"), testKey("admin-b"), testKey("admin-c")
	idA, idB, idC := KeyID(pub(a)), KeyID(pub(b)), KeyID(pub(c))
	keys := map[wire.Hash]ed25519.PublicKey{idA: pub(a), idB: pub(b)}
	payload := []byte(`{"p":1}`)
	pt := wire.PayloadTypePolicy
	mk := func(sigs ...wire.Signature) wire.Envelope {
		return wire.Envelope{PayloadType: pt, Payload: payload, Signatures: sigs}
	}
	sig := func(k ed25519.PrivateKey, id wire.Hash, msg []byte) wire.Signature {
		return wire.Signature{KeyID: id, Sig: ed25519.Sign(k, msg)}
	}
	good := PAE(pt, payload)
	flipped := sig(b, idB, good)
	flipped.Sig[0] ^= 1

	tests := []struct {
		name string
		env  wire.Envelope
		want []wire.Hash
	}{
		{"two distinct", mk(sig(a, idA, good), sig(b, idB, good)), []wire.Hash{idA, idB}},
		{"same key twice counts once", mk(sig(a, idA, good), sig(a, idA, good)), []wire.Hash{idA}},
		{"unknown keyid ignored", mk(sig(c, idC, good), sig(a, idA, good)), []wire.Hash{idA}},
		{"mislabeled keyid", mk(sig(a, idA, good), sig(b, idA, good)), []wire.Hash{idA}},
		{"mislabeled under other trusted key", mk(sig(b, idA, good)), nil},
		{"flipped bit", mk(sig(a, idA, good), flipped), []wire.Hash{idA}},
		{"raw payload signed", mk(sig(a, idA, payload), sig(b, idB, payload)), nil},
		{"wrong payload type signed", mk(sig(a, idA, PAE("other", payload))), nil},
		{"short sig", mk(wire.Signature{KeyID: idA, Sig: []byte{1}}), nil},
		{"nil sig", mk(wire.Signature{KeyID: idA}), nil},
		{"no sigs", mk(), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validSigners(tc.env, keys)
			want := append([]wire.Hash(nil), tc.want...)
			sort.Slice(want, func(i, j int) bool { return want[i] < want[j] })
			if len(got) != len(want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			for i := range got { // result is sorted
				if got[i] != want[i] {
					t.Fatalf("got %v, want %v", got, want)
				}
			}
		})
	}
}

func TestValidSignersSkipsBadKeyLength(t *testing.T) {
	// A malformed trusted key must not panic ed25519.Verify.
	a := testKey("admin-a")
	id := KeyID(pub(a))
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte("x")}
	Sign(&env, a)
	if got := validSigners(env, map[wire.Hash]ed25519.PublicKey{id: pub(a)[:5]}); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestDecodeEnvelope(t *testing.T) {
	a := testKey("admin-a")
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(`{"x":1}`)}
	Sign(&env, a)
	good, _ := json.Marshal(env)

	big := append([]byte(`{"payloadType":"`), bytes.Repeat([]byte("a"), wire.MaxEnvelopeBytes)...)

	tests := []struct {
		name string
		in   []byte
		err  error
	}{
		{"ok", good, nil},
		{"trailing data", append(append([]byte{}, good...), []byte(` {}`)...), wire.ErrBodyInvalid},
		{"unknown field", []byte(`{"payloadType":"x","payload":"","signatures":[],"extra":1}`), wire.ErrBodyInvalid},
		{"not json", []byte(`nope`), wire.ErrBodyInvalid},
		{"empty", nil, wire.ErrBodyInvalid},
		{"too large", big, wire.ErrBodyTooLarge},
		{"bad base64", []byte(`{"payloadType":"x","payload":"!!","signatures":[]}`), wire.ErrBodyInvalid},
		{"duplicate payload", []byte(`{"payloadType":"x","payload":"AA==","payload":"AQ==","signatures":[]}`), wire.ErrBodyInvalid},
		{"duplicate payloadType", []byte(`{"payloadType":"x","payloadType":"y","payload":"AA==","signatures":[]}`), wire.ErrBodyInvalid},
		{"duplicate signatures", []byte(`{"payloadType":"x","payload":"AA==","signatures":[],"signatures":[]}`), wire.ErrBodyInvalid},
		{"case variant payload", []byte(`{"payloadType":"x","Payload":"AA==","signatures":[]}`), wire.ErrBodyInvalid},
		{"upper case payloadType", []byte(`{"PAYLOADTYPE":"x","payload":"AA==","signatures":[]}`), wire.ErrBodyInvalid},
		{"case variant and exact", []byte(`{"payloadType":"x","payload":"AA==","PAYLOAD":"AQ==","signatures":[]}`), wire.ErrBodyInvalid},
		{"case variant signatures", []byte(`{"payloadType":"x","payload":"AA==","Signatures":[]}`), wire.ErrBodyInvalid},
		{"duplicate keyid", []byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","keyid":"b","sig":""}]}`), wire.ErrBodyInvalid},
		{"duplicate sig", []byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","sig":"","sig":""}]}`), wire.ErrBodyInvalid},
		{"case variant keyid", []byte(`{"payloadType":"x","payload":"AA==","signatures":[{"KeyID":"a","sig":""}]}`), wire.ErrBodyInvalid},
		{"case variant sig", []byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","SIG":""}]}`), wire.ErrBodyInvalid},
		{"escaped duplicate", []byte(`{"payloadType":"x","payload":"AA==","\u0070ayload":"AQ==","signatures":[]}`), wire.ErrBodyInvalid},
		{"same key in two signatures is fine", []byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","sig":""},{"keyid":"a","sig":""}]}`), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeEnvelope(tc.in)
			if !errors.Is(err, tc.err) && !(tc.err == nil && err == nil) {
				t.Fatalf("err = %v, want %v", err, tc.err)
			}
			if tc.err != nil && err != tc.err {
				t.Fatalf("err = %v, want the bare sentinel %v", err, tc.err)
			}
			if err == nil && tc.name == "ok" && !bytes.Equal(got.Payload, env.Payload) {
				t.Fatal("payload changed")
			}
		})
	}
}

func FuzzDecodeEnvelope(f *testing.F) {
	a, b := testKey("admin-a"), testKey("admin-b")
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(`{"x":1}`)}
	Sign(&env, a)
	Sign(&env, b)
	good, _ := json.Marshal(env)
	f.Add(good)
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"","sig":""}]}`))
	f.Add(append(append([]byte{}, good...), 'x'))
	f.Add([]byte(`{"payloadType":"x","payload":"AA==","payload":"AQ==","signatures":[]}`))
	f.Add([]byte(`{"payloadType":"x","Payload":"AA==","signatures":[]}`))
	f.Add([]byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","keyid":"b","sig":""}]}`))
	f.Add([]byte(`{"payloadType":"x","payload":"AA==","signatures":[{"keyid":"a","SIG":""}]}`))
	keys := map[wire.Hash]ed25519.PublicKey{KeyID(pub(a)): pub(a), KeyID(pub(b)): pub(b)}

	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := DecodeEnvelope(data)
		if err != nil {
			if !errors.Is(err, wire.ErrBodyInvalid) && !errors.Is(err, wire.ErrBodyTooLarge) {
				t.Fatalf("unexpected error type: %v", err)
			}
			return
		}
		// Anything that decodes must be safe to check, and the signers it
		// yields must be distinct trusted keys.
		_ = env.ValidateShape()
		seen := map[wire.Hash]bool{}
		for _, id := range validSigners(env, keys) {
			if seen[id] {
				t.Fatalf("duplicate signer %s", id)
			}
			if _, ok := keys[id]; !ok {
				t.Fatalf("untrusted signer %s", id)
			}
			seen[id] = true
		}
		// Decoding is stable: re-encode and decode gives the same envelope bytes.
		again, _ := json.Marshal(env)
		env2, err := DecodeEnvelope(again)
		if err != nil || !bytes.Equal(env2.Payload, env.Payload) || len(env2.Signatures) != len(env.Signatures) {
			t.Fatalf("re-decode mismatch: %v", err)
		}
	})
}
