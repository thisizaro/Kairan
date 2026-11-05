package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// The committed fixtures must be exactly what the generator produces.
func TestCommittedFixturesAreFresh(t *testing.T) {
	files, _ := build()
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join("..", name))
		if err != nil {
			t.Fatalf("%s: %v (run: go run ./test/fixtures/gen -out test/fixtures)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale (run: go run ./test/fixtures/gen -out test/fixtures)", name)
		}
	}
}

func TestKeyFilesAreTestOnly(t *testing.T) {
	files, _ := build()
	for name := range files {
		if !strings.HasPrefix(name, "envelopes/") && name != "cases.json" && !strings.HasPrefix(name, "TEST-ONLY-") {
			t.Errorf("%s: key material must be named TEST-ONLY-*", name)
		}
	}
}

// validlySignedMalformed are the malformed cases whose signatures are fine:
// they fail after the signature check (parse), or at the shape check for a
// reason other than a bad signature (the signature cap).
var validlySignedMalformed = map[string]bool{
	"malformed-policy":     true,
	"duplicate-role":       true,
	"duplicate-tool":       true,
	"case-variant-field":   true,
	"trailing-bytes":       true,
	"issued-after-expires": true,
	"nine-sigs":            true,
}

// Independent sanity check of the vectors with nothing but crypto/ed25519:
// count distinct trusted keys whose signature verifies over PAE.
func TestSignatureCountsMatchCases(t *testing.T) {
	files, m := build()
	trusted := map[wire.Hash]ed25519.PublicKey{}
	for _, f := range m.Root.TrustedKeys {
		raw, err := hex.DecodeString(strings.TrimSpace(string(files[f])))
		if err != nil {
			t.Fatal(err)
		}
		pub := ed25519.PublicKey(raw)
		trusted[keyID(pub)] = pub
	}
	for _, c := range m.Cases {
		var env wire.Envelope
		if err := json.Unmarshal(files[c.File], &env); err != nil {
			t.Fatalf("%s: %v", c.Name, err)
		}
		valid := map[wire.Hash]bool{}
		for _, s := range env.Signatures {
			if pub, ok := trusted[s.KeyID]; ok && len(s.Sig) == ed25519.SignatureSize &&
				ed25519.Verify(pub, pae(env.PayloadType, env.Payload), s.Sig) {
				valid[s.KeyID] = true
			}
		}
		sigsOK := len(valid) >= m.Root.Threshold
		if wantSigsOK := c.Want != wire.ErrThreshold && c.Want != wire.ErrMalformed || validlySignedMalformed[c.Name]; sigsOK != wantSigsOK {
			t.Errorf("%s: %d distinct valid trusted signatures, but case expects %q", c.Name, len(valid), c.Want)
		}
	}
}

// Expiry cases must sit where their names say, relative to Now and Skew.
func TestExpiryCasesAreWhereTheySayTheyAre(t *testing.T) {
	files, m := build()
	want := map[string]func(expires time.Time) bool{
		"expired":             func(e time.Time) bool { return e.Before(Now.Add(-Skew)) },
		"expired-within-skew": func(e time.Time) bool { return e.Before(Now) && !e.Before(Now.Add(-Skew)) },
		"valid":               func(e time.Time) bool { return e.After(Now) },
	}
	for _, c := range m.Cases {
		check, ok := want[c.Name]
		if !ok {
			continue
		}
		var env wire.Envelope
		var p policyDoc
		if err := json.Unmarshal(files[c.File], &env); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(env.Payload, &p); err != nil {
			t.Fatal(err)
		}
		e, err := time.Parse(time.RFC3339, p.ExpiresAt)
		if err != nil {
			t.Fatal(err)
		}
		if !check(e) {
			t.Errorf("%s: expires_at %s is in the wrong place relative to Now %s and skew %s", c.Name, e, Now, Skew)
		}
	}
}

// payloadDefects scans a payload with nothing but encoding/json tokens and
// lists every strictness defect of ARCHITECTURE 10.0 / M-D32 it finds:
// "duplicate" (a repeated key at any object level), "field-case" (a
// top-level field name that is not one of the exact lowercase names) and
// "trailing" (anything but whitespace after the first JSON value).
func payloadDefects(t *testing.T, payload []byte) map[string]bool {
	t.Helper()
	fields := map[string]bool{"tenant": true, "version": true, "issued_at": true, "expires_at": true, "default": true, "roles": true}
	out := map[string]bool{}
	dec := json.NewDecoder(bytes.NewReader(payload))
	var value func(depth int)
	value = func(depth int) {
		tok, err := dec.Token()
		if err != nil {
			t.Fatalf("payload is not JSON: %v", err)
		}
		switch tok {
		case json.Delim('{'):
			seen := map[string]bool{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					t.Fatal(err)
				}
				key := k.(string)
				if seen[key] {
					out["duplicate"] = true
				}
				seen[key] = true
				if depth == 0 && !fields[key] {
					out["field-case"] = true
				}
				value(depth + 1)
			}
			dec.Token() // }
		case json.Delim('['):
			for dec.More() {
				value(depth + 1)
			}
			dec.Token() // ]
		}
	}
	value(0)
	if _, err := dec.Token(); err != io.EOF {
		out["trailing"] = true
	}
	return out
}

// lenient decodes the first JSON value the way a careless parser would
// (case-insensitive names, last duplicate wins, trailing data ignored).
func lenient(t *testing.T, payload []byte) policyDoc {
	t.Helper()
	var p policyDoc
	if err := json.NewDecoder(bytes.NewReader(payload)).Decode(&p); err != nil {
		t.Fatalf("lenient decode: %v", err)
	}
	return p
}

// M-D34: the eight G0 cases exist, and each trips exactly its intended check
// in the documented order (shape/payload type -> signatures -> parse ->
// tenant -> version -> expiry).
func TestG0Cases(t *testing.T) {
	files, m := build()
	want := map[string]wire.ErrorCode{
		"duplicate-role":       wire.ErrMalformed,
		"duplicate-tool":       wire.ErrMalformed,
		"case-variant-field":   wire.ErrMalformed,
		"raw-payload-sig":      wire.ErrThreshold,
		"mislabeled-keyid":     wire.ErrThreshold,
		"nine-sigs":            wire.ErrMalformed,
		"trailing-bytes":       wire.ErrMalformed,
		"issued-after-expires": wire.ErrMalformed,
	}
	defect := map[string]string{ // the one payload defect each parse case must have
		"duplicate-role":     "duplicate",
		"duplicate-tool":     "duplicate",
		"case-variant-field": "field-case",
		"trailing-bytes":     "trailing",
	}
	pubs := map[string]ed25519.PublicKey{}
	for _, n := range keyNames {
		pubs[n] = key(n).Public().(ed25519.PublicKey)
	}
	trusted := map[wire.Hash]ed25519.PublicKey{}
	for _, n := range []string{"admin-a", "admin-b", "admin-c"} {
		trusted[keyID(pubs[n])] = pubs[n]
	}
	got := map[string]Case{}
	for _, c := range m.Cases {
		got[c.Name] = c
	}
	for name, w := range want {
		t.Run(name, func(t *testing.T) {
			c, ok := got[name]
			if !ok {
				t.Fatalf("case %s missing", name)
			}
			if c.Want != w {
				t.Fatalf("want = %q, expected %q", c.Want, w)
			}
			var env wire.Envelope
			if err := json.Unmarshal(files[c.File], &env); err != nil {
				t.Fatal(err)
			}
			// Distinct trusted keys whose signature verifies over PAE under
			// the key ID it claims.
			valid := map[wire.Hash]bool{}
			for _, s := range env.Signatures {
				if pub, ok := trusted[s.KeyID]; ok && ed25519.Verify(pub, pae(env.PayloadType, env.Payload), s.Sig) {
					valid[s.KeyID] = true
				}
			}

			// Shape: only nine-sigs fails it, and only on the cap.
			shapeErr := env.ValidateShape()
			if name == "nine-sigs" {
				if len(env.Signatures) != wire.MaxSignatures+1 || shapeErr == nil {
					t.Fatalf("%d signatures, shape err %v; want %d and a shape failure", len(env.Signatures), shapeErr, wire.MaxSignatures+1)
				}
				for i, s := range env.Signatures {
					if pub, ok := trusted[s.KeyID]; !ok || !ed25519.Verify(pub, pae(env.PayloadType, env.Payload), s.Sig) {
						t.Errorf("signature %d is not a valid trusted signature: only the count may be wrong", i)
					}
				}
			} else if shapeErr != nil {
				t.Fatalf("shape check fails (%v): this case must get past it", shapeErr)
			}

			// Signatures.
			switch name {
			case "raw-payload-sig":
				if len(valid) != 0 {
					t.Fatalf("%d signatures verify over PAE, want 0", len(valid))
				}
				for i, s := range env.Signatures {
					if pub, ok := trusted[s.KeyID]; !ok || !ed25519.Verify(pub, env.Payload, s.Sig) {
						t.Errorf("signature %d is not a trusted signature over the raw payload", i)
					}
				}
				if len(env.Signatures) < m.Root.Threshold {
					t.Fatalf("needs >= %d raw signatures to be a real test", m.Root.Threshold)
				}
			case "mislabeled-keyid":
				if len(valid) != m.Root.Threshold-1 {
					t.Fatalf("%d valid labeled signatures, want %d", len(valid), m.Root.Threshold-1)
				}
				// The other signature is genuine, from a trusted key that is
				// not the one its key ID names.
				mislabeled := 0
				for _, s := range env.Signatures {
					if valid[s.KeyID] {
						continue
					}
					for id, pub := range trusted {
						if id != s.KeyID && !valid[id] && ed25519.Verify(pub, pae(env.PayloadType, env.Payload), s.Sig) {
							if _, labelTrusted := trusted[s.KeyID]; labelTrusted {
								mislabeled++
							}
						}
					}
				}
				if mislabeled != 1 {
					t.Fatalf("%d genuine signatures carry another trusted key's ID, want 1", mislabeled)
				}
			default:
				if len(valid) < m.Root.Threshold {
					t.Fatalf("%d distinct valid trusted signatures, want >= %d", len(valid), m.Root.Threshold)
				}
			}

			// Parse: exactly the intended defect, nothing else.
			d := payloadDefects(t, env.Payload)
			wantDefects := map[string]bool{}
			if k, ok := defect[name]; ok {
				wantDefects[k] = true
			}
			if len(d) != len(wantDefects) || !d[defect[name]] && len(wantDefects) > 0 {
				t.Fatalf("payload defects %v, want %v", d, wantDefects)
			}
			p := lenient(t, env.Payload)
			issued, err1 := time.Parse(time.RFC3339, p.IssuedAt)
			expires, err2 := time.Parse(time.RFC3339, p.ExpiresAt)
			if err1 != nil || err2 != nil {
				t.Fatalf("times do not parse: %v %v", err1, err2)
			}
			if inverted := !expires.After(issued); inverted != (name == "issued-after-expires") {
				t.Fatalf("issued_at %s, expires_at %s: inverted=%v", issued, expires, inverted)
			}
			if p.Default != "deny" {
				t.Fatalf("default %q", p.Default)
			}

			// Later checks must all pass, so the case cannot fail for them.
			if p.Tenant != m.Root.Tenant || p.Version <= c.Have || !expires.After(Now) {
				t.Fatalf("tenant %q, version %d (have %d), expires %s: a later check would also fail", p.Tenant, p.Version, c.Have, expires)
			}
		})
	}
}
