// Command gen writes Kairan's TEST-ONLY keys, golden envelopes and the
// expected-result table (PLAN O-05).
//
//	go run ./test/fixtures/gen -out test/fixtures
//
// Keys come from fixed public seeds, and ed25519 signatures are deterministic,
// so the output is byte-for-byte reproducible. Signing here is written
// independently of internal/trust on purpose: the files are test vectors that
// trust must agree with. Nothing here is a real secret.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kairan/internal/wire"
)

// Now is the reference time every case is judged at.
var Now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const Skew = 2 * time.Minute

// Keys: admin-a, admin-b, admin-c are trusted for bank-a (threshold 2);
// outsider is not.
var keyNames = []string{"admin-a", "admin-b", "admin-c", "outsider"}

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("kairan TEST-ONLY " + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func keyID(pub ed25519.PublicKey) wire.Hash {
	sum := sha256.Sum256(pub)
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// pae is the DSSE v1 pre-authentication encoding.
func pae(payloadType string, payload []byte) []byte {
	b := []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType + " " + strconv.Itoa(len(payload)) + " ")
	return append(b, payload...)
}

type policyDoc struct {
	Tenant    string                       `json:"tenant"`
	Version   uint64                       `json:"version"`
	IssuedAt  string                       `json:"issued_at"`
	ExpiresAt string                       `json:"expires_at"`
	Default   string                       `json:"default"`
	Roles     map[string]map[string]string `json:"roles"`
}

func policy(tenant string, version uint64, issued time.Time, validity time.Duration) policyDoc {
	return policyDoc{
		Tenant:    tenant,
		Version:   version,
		IssuedAt:  issued.UTC().Format(time.RFC3339),
		ExpiresAt: issued.Add(validity).UTC().Format(time.RFC3339),
		Default:   "deny",
		Roles: map[string]map[string]string{
			"sales":    {"crm.read_*": "R", "crm.update_deal": "W"},
			"engineer": {"github.*": "R", "github.create_issue": "W", "ci.rerun": "X"},
		},
	}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// edit replaces old with new in payload exactly once; it panics otherwise so a
// change to the canonical encoding cannot silently produce a wrong vector.
func edit(payload []byte, old, new string) []byte {
	s := string(payload)
	if strings.Count(s, old) != 1 {
		panic(fmt.Sprintf("gen: %q appears %d times in %s", old, strings.Count(s, old), s))
	}
	return []byte(strings.Replace(s, old, new, 1))
}

func sign(payloadType string, payload []byte, signers ...string) wire.Envelope {
	env := wire.Envelope{PayloadType: payloadType, Payload: payload, Signatures: []wire.Signature{}}
	for _, s := range signers {
		k := key(s)
		env.Signatures = append(env.Signatures, wire.Signature{
			KeyID: keyID(k.Public().(ed25519.PublicKey)),
			Sig:   ed25519.Sign(k, pae(payloadType, payload)),
		})
	}
	return env
}

// Case is one row of cases.json: apply File to a proxy of tenant bank-a that
// currently has version Have, at time Now; the result must be Want
// ("" = accepted).
type Case struct {
	Name string         `json:"name"`
	File string         `json:"file"`
	Have uint64         `json:"have"`
	Want wire.ErrorCode `json:"want"`
	Why  string         `json:"why"`
}

// Root describes the trust root the cases assume.
type Root struct {
	Tenant      string   `json:"tenant"`
	Threshold   int      `json:"threshold"`
	TrustedKeys []string `json:"trusted_keys"` // file names of the .pub files
	Now         string   `json:"now"`
	SkewSeconds int      `json:"skew_seconds"`
}

type Manifest struct {
	Root  Root   `json:"root"`
	Order string `json:"check_order"`
	Cases []Case `json:"cases"`
}

func build() (map[string][]byte, Manifest) {
	files := map[string][]byte{}
	for _, n := range keyNames {
		k := key(n)
		files["TEST-ONLY-"+n+".pub"] = []byte(hex.EncodeToString(k.Public().(ed25519.PublicKey)) + "\n")
		files["TEST-ONLY-"+n+".seed"] = []byte(hex.EncodeToString(k.Seed()) + "\n")
	}

	pt := wire.PayloadTypePolicy
	issued := Now.Add(-time.Hour)
	v1 := mustJSON(policy("bank-a", 1, issued, 72*time.Hour))
	v2 := mustJSON(policy("bank-a", 2, issued, 72*time.Hour))

	flipped := sign(pt, v2, "admin-a", "admin-b")
	flipped.Signatures[1].Sig[0] ^= 0xff

	tampered := sign(pt, v2, "admin-a", "admin-b")
	tampered.Payload = []byte(string(v2[:len(v2)-1]) + ` `)
	tampered.Payload = append(tampered.Payload, '}')

	short := sign(pt, v2, "admin-a", "admin-b")
	short.Signatures[0].Sig = short.Signatures[0].Sig[:10]

	badDefault := policy("bank-a", 2, issued, 72*time.Hour)
	badDefault.Default = "allow"

	// G0 cases (M-D34). Each is v2 for bank-a, unexpired, offered to a proxy
	// on v1, so it trips only its own check.
	dupRole := edit(v2, `"sales":{"crm.read_*":"R","crm.update_deal":"W"}}`,
		`"sales":{"crm.read_*":"R","crm.update_deal":"W"},"sales":{"crm.*":"X"}}`)
	dupTool := edit(v2, `"crm.read_*":"R","crm.update_deal":"W"`,
		`"crm.read_*":"R","crm.update_deal":"W","crm.read_*":"X"`)
	caseVariant := edit(v2, `{"tenant":`, `{"Tenant":`)
	trailing := append(append([]byte{}, v2...), []byte(` {"version":99}`)...)
	inverted := policy("bank-a", 2, Now.Add(48*time.Hour), 72*time.Hour)
	inverted.ExpiresAt = Now.Add(24 * time.Hour).UTC().Format(time.RFC3339)

	rawSig := wire.Envelope{PayloadType: pt, Payload: v2, Signatures: []wire.Signature{}}
	for _, n := range []string{"admin-a", "admin-b"} {
		k := key(n)
		rawSig.Signatures = append(rawSig.Signatures, wire.Signature{
			KeyID: keyID(k.Public().(ed25519.PublicKey)),
			Sig:   ed25519.Sign(k, v2), // no PAE
		})
	}

	mislabeled := sign(pt, v2, "admin-a", "admin-b")
	mislabeled.Signatures[1].KeyID = keyID(key("admin-c").Public().(ed25519.PublicKey))

	envs := []struct {
		c   Case
		env wire.Envelope
	}{
		{Case{Name: "valid", Have: 1, Want: "", Why: "2 distinct trusted signatures, newer, unexpired"}, sign(pt, v2, "admin-a", "admin-b")},
		{Case{Name: "valid-three-sigs", Have: 1, Want: "", Why: "3 of 3 trusted signatures"}, sign(pt, v2, "admin-a", "admin-b", "admin-c")},
		{Case{Name: "valid-from-empty", Have: 0, Want: "", Why: "first policy on a fresh proxy"}, sign(pt, v1, "admin-b", "admin-c")},
		{Case{Name: "one-sig", Have: 1, Want: wire.ErrThreshold, Why: "only 1 signature, threshold is 2"}, sign(pt, v2, "admin-a")},
		{Case{Name: "duplicate-key", Have: 1, Want: wire.ErrThreshold, Why: "same key twice counts once"}, sign(pt, v2, "admin-a", "admin-a")},
		{Case{Name: "untrusted-second", Have: 1, Want: wire.ErrThreshold, Why: "outsider is not in the trust root"}, sign(pt, v2, "admin-a", "outsider")},
		{Case{Name: "flipped-sig", Have: 1, Want: wire.ErrThreshold, Why: "admin-b's signature bytes altered"}, flipped},
		{Case{Name: "tampered-payload", Have: 1, Want: wire.ErrThreshold, Why: "payload changed after signing (one added space)"}, tampered},
		{Case{Name: "short-sig", Have: 1, Want: wire.ErrMalformed, Why: "signature is not 64 bytes: shape check fails first"}, short},
		{Case{Name: "wrong-payload-type", Have: 1, Want: wire.ErrPayloadType, Why: "validly signed, but not a Kairan policy"}, sign("text/plain", v2, "admin-a", "admin-b")},
		{Case{Name: "malformed-policy", Have: 1, Want: wire.ErrMalformed, Why: `validly signed, but default is "allow"`}, sign(pt, mustJSON(badDefault), "admin-a", "admin-b")},
		{Case{Name: "wrong-tenant", Have: 1, Want: wire.ErrWrongTenant, Why: "validly signed policy for city-b"}, sign(pt, mustJSON(policy("city-b", 2, issued, 72*time.Hour)), "admin-a", "admin-b")},
		{Case{Name: "old-version", Have: 2, Want: wire.ErrNotNewer, Why: "v1 offered to a proxy on v2 (rollback replay)"}, sign(pt, v1, "admin-a", "admin-b")},
		{Case{Name: "same-version", Have: 2, Want: wire.ErrNotNewer, Why: "v2 offered to a proxy already on v2"}, sign(pt, v2, "admin-a", "admin-b")},
		{Case{Name: "expired", Have: 1, Want: wire.ErrExpired, Why: "expired a day before Now"}, sign(pt, mustJSON(policy("bank-a", 2, Now.Add(-96*time.Hour), 72*time.Hour)), "admin-a", "admin-b")},
		{Case{Name: "expired-within-skew", Have: 1, Want: "", Why: "expired 1 minute before Now; skew is 2 minutes"}, sign(pt, mustJSON(policy("bank-a", 2, Now.Add(-72*time.Hour-time.Minute), 72*time.Hour)), "admin-a", "admin-b")},
		{Case{Name: "duplicate-role", Have: 1, Want: wire.ErrMalformed, Why: `validly signed, but role "sales" appears twice (the second grants crm.* X)`}, sign(pt, dupRole, "admin-a", "admin-b")},
		{Case{Name: "duplicate-tool", Have: 1, Want: wire.ErrMalformed, Why: `validly signed, but tool "crm.read_*" appears twice in role sales (R, then X)`}, sign(pt, dupTool, "admin-a", "admin-b")},
		{Case{Name: "case-variant-field", Have: 1, Want: wire.ErrMalformed, Why: `validly signed, but the field is "Tenant", not "tenant"`}, sign(pt, caseVariant, "admin-a", "admin-b")},
		{Case{Name: "raw-payload-sig", Have: 1, Want: wire.ErrThreshold, Why: "admin-a and admin-b signed the raw payload, not the DSSE PAE"}, rawSig},
		{Case{Name: "mislabeled-keyid", Have: 1, Want: wire.ErrThreshold, Why: "admin-b's genuine signature carries admin-c's key ID; only admin-a counts"}, mislabeled},
		{Case{Name: "nine-sigs", Have: 1, Want: wire.ErrMalformed, Why: "9 valid trusted signatures, over the cap of 8: shape check fails first"}, sign(pt, v2, "admin-a", "admin-b", "admin-c", "admin-a", "admin-b", "admin-c", "admin-a", "admin-b", "admin-c")},
		{Case{Name: "trailing-bytes", Have: 1, Want: wire.ErrMalformed, Why: "validly signed, but a second JSON value follows the policy"}, sign(pt, trailing, "admin-a", "admin-b")},
		{Case{Name: "issued-after-expires", Have: 1, Want: wire.ErrMalformed, Why: "validly signed, but issued_at is a day after expires_at (both in the future)"}, sign(pt, mustJSON(inverted), "admin-a", "admin-b")},
	}

	m := Manifest{
		Root: Root{
			Tenant: "bank-a", Threshold: 2,
			TrustedKeys: []string{"TEST-ONLY-admin-a.pub", "TEST-ONLY-admin-b.pub", "TEST-ONLY-admin-c.pub"},
			Now:         Now.Format(time.RFC3339), SkewSeconds: int(Skew / time.Second),
		},
		Order: "shape (malformed) / payload type (payload_type) -> signatures (threshold_not_met) -> policy parse (malformed) -> tenant (wrong_tenant) -> version (version_not_newer) -> expiry (expired)",
	}
	for _, e := range envs {
		e.c.File = "envelopes/" + e.c.Name + ".json"
		files[e.c.File] = append(mustJSON(e.env), '\n')
		m.Cases = append(m.Cases, e.c)
	}
	mj, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		panic(err)
	}
	files["cases.json"] = append(mj, '\n')
	return files, m
}

func write(dir string, files map[string][]byte) error {
	for name, b := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	out := flag.String("out", "test/fixtures", "output directory")
	flag.Parse()
	files, m := build()
	if err := write(*out, files); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d files, %d cases to %s\n", len(files), len(m.Cases), *out)
}
