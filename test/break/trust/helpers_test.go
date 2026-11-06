// Package trustbreak holds black-box attack tests for the trust package
// (tasks T-03, T-04). Sources: ARCHITECTURE section 2, section 8, section 10
// (trust LLD), invariants I1/I2, decisions M-D2, M-D33, M-D34, M-D39, M-D44,
// the wire package, test/fixtures and the go doc of the trust package.
package trustbreak

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const skew = 2 * time.Minute

func fixtureRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures")
}

// priv loads a TEST-ONLY seed (hex ed25519 seed).
func priv(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureRoot(), "TEST-ONLY-"+name+".seed"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("bad seed %s", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func pub(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

// kid computes a key ID independently of trust.KeyID (M-D2: SHA-256 of raw key).
func kid(p ed25519.PublicKey) wire.Hash {
	s := sha256.Sum256(p)
	return wire.Hash(hex.EncodeToString(s[:]))
}

// pae is an independent DSSE v1 PAE.
func pae(pt string, payload []byte) []byte {
	return append([]byte("DSSEv1 "+strconv.Itoa(len(pt))+" "+pt+" "+strconv.Itoa(len(payload))+" "), payload...)
}

type keys struct {
	a, b, c, out ed25519.PrivateKey
}

func loadKeys(t testing.TB) keys {
	return keys{priv(t, "admin-a"), priv(t, "admin-b"), priv(t, "admin-c"), priv(t, "outsider")}
}

// rootOf builds a Root trusting the given keys.
func rootOf(tenant string, threshold int, ks ...ed25519.PrivateKey) trust.Root {
	m := map[wire.Hash]ed25519.PublicKey{}
	for _, k := range ks {
		m[kid(pub(k))] = pub(k)
	}
	return trust.Root{Tenant: wire.ID(tenant), Keys: m, Threshold: threshold}
}

func (k keys) root() trust.Root { return rootOf("bank-a", 2, k.a, k.b, k.c) }

// sigOf signs msg with k and labels it with k's real key ID.
func sigOf(k ed25519.PrivateKey, msg []byte) wire.Signature {
	return wire.Signature{KeyID: kid(pub(k)), Sig: ed25519.Sign(k, msg)}
}

// signed builds an envelope with PAE signatures from each key.
func signed(payload []byte, ks ...ed25519.PrivateKey) wire.Envelope {
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload, Signatures: []wire.Signature{}}
	for _, k := range ks {
		env.Signatures = append(env.Signatures, sigOf(k, pae(env.PayloadType, payload)))
	}
	return env
}

type pol struct {
	tenant    string
	version   uint64
	issued    time.Time
	expires   time.Time
	extraRole string
}

func (p pol) bytes() []byte {
	if p.tenant == "" {
		p.tenant = "bank-a"
	}
	if p.version == 0 {
		p.version = 2
	}
	if p.issued.IsZero() {
		p.issued = now.Add(-time.Hour)
	}
	if p.expires.IsZero() {
		p.expires = p.issued.Add(72 * time.Hour)
	}
	return []byte(fmt.Sprintf(
		`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}%s}}`,
		p.tenant, p.version, p.issued.UTC().Format(time.RFC3339), p.expires.UTC().Format(time.RFC3339), p.extraRole))
}

// goodPayload is a v2 bank-a policy valid at now.
func goodPayload() []byte { return pol{}.bytes() }

func clone(e wire.Envelope) wire.Envelope {
	c := wire.Envelope{PayloadType: e.PayloadType, Payload: append([]byte(nil), e.Payload...)}
	for _, s := range e.Signatures {
		c.Signatures = append(c.Signatures, wire.Signature{KeyID: s.KeyID, Sig: append([]byte(nil), s.Sig...)})
	}
	return c
}

// expectReject asserts a rejection with the wanted code, ErrRejected wrapping,
// and a zero Verified (I1, I3).
func expectReject(t *testing.T, why string, env wire.Envelope, root trust.Root, have uint64, at time.Time, sk time.Duration, want wire.ErrorCode) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC (%s): %v", why, r)
		}
	}()
	v, code, err := trust.Accept(env, root, have, at, sk)
	if code != want {
		t.Fatalf("%s: code %q, want %q (err=%v)", why, code, want, err)
	}
	if err == nil || !errors.Is(err, trust.ErrRejected) {
		t.Fatalf("%s: err %v must wrap trust.ErrRejected", why, err)
	}
	if v.Policy != nil || v.Hash != "" || len(v.Signers) != 0 {
		t.Fatalf("%s: rejected but Verified is not zero: %+v", why, v)
	}
}

func expectAccept(t *testing.T, why string, env wire.Envelope, root trust.Root, have uint64, at time.Time, sk time.Duration) trust.Verified {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIC (%s): %v", why, r)
		}
	}()
	v, code, err := trust.Accept(env, root, have, at, sk)
	if code != "" || err != nil {
		t.Fatalf("%s: rejected with code %q err %v, want accepted", why, code, err)
	}
	if v.Policy == nil {
		t.Fatalf("%s: accepted but Policy nil", why)
	}
	return v
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
