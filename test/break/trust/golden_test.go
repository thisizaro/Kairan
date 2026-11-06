package trustbreak

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

type goldenCase struct {
	Name string         `json:"name"`
	File string         `json:"file"`
	Have uint64         `json:"have"`
	Want wire.ErrorCode `json:"want"`
	Why  string         `json:"why"`
}

type goldenDoc struct {
	Root struct {
		Tenant      string   `json:"tenant"`
		Threshold   int      `json:"threshold"`
		TrustedKeys []string `json:"trusted_keys"`
		Now         string   `json:"now"`
		SkewSeconds int      `json:"skew_seconds"`
	} `json:"root"`
	Cases []goldenCase `json:"cases"`
}

func loadGolden(t *testing.T) (goldenDoc, trust.Root, time.Time, time.Duration) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureRoot(), "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var d goldenDoc
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	root := trust.Root{Tenant: wire.ID(d.Root.Tenant), Threshold: d.Root.Threshold, Keys: map[wire.Hash]ed25519.PublicKey{}}
	for _, f := range d.Root.TrustedKeys {
		b, err := os.ReadFile(filepath.Join(fixtureRoot(), f))
		if err != nil {
			t.Fatal(err)
		}
		pk, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil {
			t.Fatal(err)
		}
		// Key ID is computed by the independent helper AND by trust.KeyID: they must agree (M-D2).
		if trust.KeyID(pk) != kid(pk) {
			t.Fatalf("trust.KeyID(%s) = %s, want SHA-256 of raw key %s", f, trust.KeyID(pk), kid(pk))
		}
		root.Keys[kid(pk)] = pk
	}
	at, err := time.Parse(time.RFC3339, d.Root.Now)
	if err != nil {
		t.Fatal(err)
	}
	return d, root, at, time.Duration(d.Root.SkewSeconds) * time.Second
}

// Every golden case (24) through Accept with both decoders (ARCH section 2, M-D34).
func TestGoldenAccept(t *testing.T) {
	d, root, at, sk := loadGolden(t)
	if len(d.Cases) != 24 {
		t.Fatalf("expected 24 golden cases, found %d", len(d.Cases))
	}
	for _, c := range d.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(fixtureRoot(), c.File))
			if err != nil {
				t.Fatal(err)
			}
			env, err := trust.DecodeEnvelope(raw)
			if err != nil {
				t.Fatalf("DecodeEnvelope of golden file failed: %v", err)
			}
			var std wire.Envelope
			if err := json.Unmarshal(raw, &std); err != nil {
				t.Fatal(err)
			}
			if string(std.Payload) != string(env.Payload) || len(std.Signatures) != len(env.Signatures) {
				t.Fatalf("DecodeEnvelope and encoding/json disagree on a golden file")
			}
			if c.Want == "" {
				v := expectAccept(t, c.Why, env, root, c.Have, at, sk)
				if len(v.Signers) < 2 {
					t.Fatalf("accepted with %d signers (I1)", len(v.Signers))
				}
				if v.Policy.Tenant != "bank-a" || v.Policy.Version <= c.Have {
					t.Fatalf("accepted wrong policy: %+v", v.Policy)
				}
				return
			}
			expectReject(t, c.Why, env, root, c.Have, at, sk, c.Want)
		})
	}
}

// Verify = Accept minus version and expiry (trust LLD). Boot re-check must not
// reject an old or expired but genuinely signed policy.
func TestGoldenVerify(t *testing.T) {
	d, root, _, _ := loadGolden(t)
	for _, c := range d.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			raw, _ := os.ReadFile(filepath.Join(fixtureRoot(), c.File))
			env, err := trust.DecodeEnvelope(raw)
			if err != nil {
				t.Fatal(err)
			}
			v, code, err := trust.Verify(env, root)
			want := c.Want
			if want == wire.ErrNotNewer || want == wire.ErrExpired {
				want = ""
			}
			if code != want {
				t.Fatalf("Verify code %q, want %q (err=%v)", code, want, err)
			}
			if want == "" {
				if err != nil || v.Policy == nil || len(v.Signers) < 2 {
					t.Fatalf("Verify should pass: err=%v v=%+v", err, v)
				}
				return
			}
			if !errors.Is(err, trust.ErrRejected) || v.Policy != nil || v.Hash != "" || v.Signers != nil {
				t.Fatalf("Verify rejection must wrap ErrRejected and return zero Verified: err=%v v=%+v", err, v)
			}
		})
	}
}

// Golden valid: Hash = sha256 of exact payload, Signers sorted + distinct (trust doc).
func TestVerifiedFields(t *testing.T) {
	d, root, at, sk := loadGolden(t)
	for _, c := range d.Cases {
		if c.Name != "valid-three-sigs" && c.Name != "valid" {
			continue
		}
		raw, _ := os.ReadFile(filepath.Join(fixtureRoot(), c.File))
		env, _ := trust.DecodeEnvelope(raw)
		v := expectAccept(t, c.Name, env, root, c.Have, at, sk)
		if want := sha(env.Payload); v.Hash != want {
			t.Fatalf("%s: Hash %s, want sha256(payload) %s", c.Name, v.Hash, want)
		}
		seen := map[wire.Hash]bool{}
		for i, s := range v.Signers {
			if !s.Valid() || seen[s] {
				t.Fatalf("%s: signer %q invalid or repeated", c.Name, s)
			}
			seen[s] = true
			if _, ok := root.Keys[s]; !ok {
				t.Fatalf("%s: signer %s is not in the root", c.Name, s)
			}
			if i > 0 && v.Signers[i-1] >= s {
				t.Fatalf("%s: Signers not sorted: %v", c.Name, v.Signers)
			}
		}
		if c.Name == "valid-three-sigs" && len(v.Signers) != 3 {
			t.Fatalf("3 valid trusted signatures but Signers = %d", len(v.Signers))
		}
	}
}

var _ = time.Second
