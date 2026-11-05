// Package trust decides whether a signed policy envelope may be enforced.
//
// It implements invariant I1 (only a policy signed by at least Threshold
// distinct trusted keys is enforced) and, through Accept, I2 (versions only
// move forward). The package is pure: no I/O and no wall clock. Callers pass
// the time to judge expiry at (the proxy passes effective_now, M-D30).
//
// Signatures are checked over the DSSE v1 pre-authentication encoding of the
// envelope's exact payload bytes. The payload is never re-encoded.
package trust

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"

	"kairan/internal/wire"
)

// PAE returns the DSSE v1 pre-authentication encoding:
//
//	"DSSEv1" SP len(payloadType) SP payloadType SP len(payload) SP payload
//
// The result is a fresh slice.
func PAE(payloadType string, payload []byte) []byte {
	b := make([]byte, 0, 32+len(payloadType)+len(payload))
	b = append(b, "DSSEv1 "...)
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(payload)), 10)
	b = append(b, ' ')
	return append(b, payload...)
}

// KeyID is the SHA-256 of the raw public key, as lowercase hex.
func KeyID(pub ed25519.PublicKey) wire.Hash {
	sum := sha256.Sum256(pub)
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// Sign appends one signature over PAE(env.PayloadType, env.Payload). It is
// the signing helper for kairanctl and tests; the proxy never signs.
func Sign(env *wire.Envelope, priv ed25519.PrivateKey) {
	pub := priv.Public().(ed25519.PublicKey)
	env.Signatures = append(env.Signatures, wire.Signature{
		KeyID: KeyID(pub),
		Sig:   ed25519.Sign(priv, PAE(env.PayloadType, env.Payload)),
	})
}

// DecodeEnvelope parses one JSON-encoded envelope: at most
// wire.MaxEnvelopeBytes, no unknown fields, no trailing data. Like
// policy.Parse (M-D32) it also rejects a duplicate key and a key that is not
// spelled exactly (encoding/json would accept "Payload" for "payload" and keep
// the last of two equal keys), at the top level and inside each signature.
// Errors are the bare wire sentinels (wire.ErrBodyTooLarge, wire.ErrBodyInvalid).
// It does not check the shape or any signature.
func DecodeEnvelope(data []byte) (wire.Envelope, error) {
	var env wire.Envelope
	if len(data) > wire.MaxEnvelopeBytes {
		return wire.Envelope{}, wire.ErrBodyTooLarge
	}
	if !strictKeys(data) {
		return wire.Envelope{}, wire.ErrBodyInvalid
	}
	if err := wire.Decode(bytes.NewReader(data), wire.MaxEnvelopeBytes, &env); err != nil {
		return wire.Envelope{}, err
	}
	return env, nil
}

// validSigners returns, sorted, the IDs of the distinct trusted keys that
// have a valid signature in env. A signature counts only if it verifies under
// the key its keyid names (a mislabeled keyid never counts, even if another
// trusted key would verify it). Unknown keyids, malformed signatures and
// repeats of a key already counted are ignored.
func validSigners(env wire.Envelope, keys map[wire.Hash]ed25519.PublicKey) []wire.Hash {
	var msg []byte
	var out []wire.Hash
	seen := make(map[wire.Hash]bool, len(env.Signatures))
	for _, s := range env.Signatures {
		key, ok := keys[s.KeyID]
		if !ok || seen[s.KeyID] || len(key) != ed25519.PublicKeySize || len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		if msg == nil {
			msg = PAE(env.PayloadType, env.Payload)
		}
		if ed25519.Verify(key, msg, s.Sig) {
			seen[s.KeyID] = true
			out = append(out, s.KeyID)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var (
	envelopeKeys  = map[string]bool{"payloadType": true, "payload": true, "signatures": true}
	signatureKeys = map[string]bool{"keyid": true, "sig": true}
)

// strictKeys reports whether every object key in an envelope document is one
// of the exact, known names and appears once in its object. Documents that are
// not well formed are left to the normal decoder to reject, so it returns true
// for them only if no key rule is broken before the syntax error.
func strictKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	t, err := dec.Token()
	if err != nil || t != json.Delim('{') {
		return true // not an object: the decoder rejects it
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true
		}
		key, ok := t.(string)
		if !ok || !envelopeKeys[key] || seen[key] {
			return false
		}
		seen[key] = true
		if key != "signatures" {
			if !skipValue(dec) {
				return true
			}
			continue
		}
		t, err = dec.Token()
		if err != nil {
			return true
		}
		if t != json.Delim('[') {
			continue // null or a wrong type: the decoder decides
		}
		for dec.More() {
			t, err := dec.Token()
			if err != nil {
				return true
			}
			if t != json.Delim('{') {
				if d, isDelim := t.(json.Delim); isDelim && !skipRest(dec, d) {
					return true
				}
				continue
			}
			sigSeen := map[string]bool{}
			for dec.More() {
				t, err := dec.Token()
				if err != nil {
					return true
				}
				k, ok := t.(string)
				if !ok || !signatureKeys[k] || sigSeen[k] {
					return false
				}
				sigSeen[k] = true
				if !skipValue(dec) {
					return true
				}
			}
			if _, err := dec.Token(); err != nil { // closing }
				return true
			}
		}
		if _, err := dec.Token(); err != nil { // closing ]
			return true
		}
	}
	return true
}

// skipValue consumes one JSON value. It reports false on a syntax error.
func skipValue(dec *json.Decoder) bool {
	t, err := dec.Token()
	if err != nil {
		return false
	}
	if d, ok := t.(json.Delim); ok {
		return skipRest(dec, d)
	}
	return true
}

// skipRest consumes the rest of a container whose opening delimiter d was
// just read.
func skipRest(dec *json.Decoder, d json.Delim) bool {
	if d != '{' && d != '[' {
		return false
	}
	depth := 1
	for depth > 0 {
		t, err := dec.Token()
		if err != nil {
			return false
		}
		if d, ok := t.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return true
}
