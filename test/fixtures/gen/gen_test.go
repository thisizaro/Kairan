package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
		if wantSigsOK := c.Want != wire.ErrThreshold && c.Want != wire.ErrMalformed || c.Name == "malformed-policy"; sigsOK != wantSigsOK {
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
