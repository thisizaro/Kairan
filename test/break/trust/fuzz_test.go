package trustbreak

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

func goldenBytes(f testing.TB) [][]byte {
	files, _ := filepath.Glob(filepath.Join(fixtureRoot(), "envelopes", "*.json"))
	var out [][]byte
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, b)
	}
	return out
}

// FuzzDecodeEnvelope: the decoder never panics, always returns a bare sentinel on
// error, and nothing it returns is accepted by Accept unless it carries the
// payload of a known genuine envelope (I1: only signed bytes are enforced).
func FuzzDecodeEnvelope(f *testing.F) {
	for _, b := range goldenBytes(f) {
		f.Add(b)
	}
	for _, s := range []string{"", "null", "{}", "[]", `{"payloadType":"x"}`, `{"payload":"AA=="}`, "{\"a\":" + "[[[[[[[["} {
		f.Add([]byte(s))
	}
	k := loadKeys(f)
	root := k.root()
	genuine := map[string]bool{}
	for _, b := range goldenBytes(f) {
		if e, err := trust.DecodeEnvelope(b); err == nil {
			genuine[string(e.Payload)] = true
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := trust.DecodeEnvelope(data)
		if err != nil {
			if err != wire.ErrBodyInvalid && err != wire.ErrBodyTooLarge {
				t.Fatalf("non-sentinel error %v", err)
			}
			return
		}
		v, code, aerr := trust.Accept(env, root, 0, now, skew)
		if code == "" && aerr == nil {
			if !genuine[string(env.Payload)] {
				t.Fatalf("accepted an envelope with an unknown payload: %q", env.Payload)
			}
			if len(v.Signers) < 2 {
				t.Fatalf("accepted with %d signers", len(v.Signers))
			}
		} else if v.Policy != nil || v.Hash != "" {
			t.Fatalf("rejected but non-zero Verified")
		}
	})
}

// FuzzMutatedEnvelope starts from genuine envelopes, applies byte-level edits to
// the JSON, and demands: any accepted result has the genuine payload bytes and
// at least 2 distinct genuine signers (I1).
func FuzzMutatedEnvelope(f *testing.F) {
	k := loadKeys(f)
	root := k.root()
	p := goodPayload()
	base := mustJSON(signed(p, k.a, k.b))
	f.Add(base, 0, byte(0))
	f.Add(base, 40, byte(1))
	f.Add(base, len(base)-3, byte(0xff))
	f.Add(mustJSON(signed(p, k.a, k.b, k.c)), 100, byte(2))
	f.Fuzz(func(t *testing.T, data []byte, pos int, x byte) {
		if len(data) == 0 {
			return
		}
		if pos < 0 {
			pos = -pos
			if pos < 0 {
				pos = 0
			}
		}
		m := append([]byte(nil), data...)
		m[pos%len(m)] ^= x
		env, err := trust.DecodeEnvelope(m)
		if err != nil {
			return
		}
		v, code, aerr := trust.Accept(env, root, 1, now, skew)
		if code != "" || aerr != nil {
			if v.Policy != nil {
				t.Fatal("rejected with non-zero Verified")
			}
			return
		}
		// Accepted: independent crypto must find >= 2 distinct trusted valid signers.
		msg := pae(env.PayloadType, env.Payload)
		valid := map[wire.Hash]bool{}
		for _, sg := range env.Signatures {
			for _, kk := range []ed25519.PrivateKey{k.a, k.b, k.c} {
				if sg.KeyID == kid(pub(kk)) && ed25519.Verify(pub(kk), msg, sg.Sig) {
					valid[sg.KeyID] = true
				}
			}
		}
		if len(valid) < 2 || len(v.Signers) != len(valid) {
			t.Fatalf("accepted with %d independently valid signers (Signers=%v)", len(valid), v.Signers)
		}
	})
}
