package kairancpbreak

import (
	"math/rand"
	"testing"
)

// Random damage to a valid config must end in exit 0 or 2, never a crash, never exit 1 (which means "started
// and failed to serve") and never a hang. Deterministic seed so a failure repeats.
func TestConfigMutationsNeverCrash(t *testing.T) {
	good := baseCfg(t, t.TempDir()).bytes(t)
	rng := rand.New(rand.NewSource(20261105))
	for i := 0; i < 150; i++ {
		b := append([]byte(nil), good...)
		switch rng.Intn(5) {
		case 0: // flip a byte
			b[rng.Intn(len(b))] ^= byte(1 << rng.Intn(8))
		case 1: // delete a span
			p := rng.Intn(len(b))
			q := p + rng.Intn(20)
			if q > len(b) {
				q = len(b)
			}
			b = append(b[:p], b[q:]...)
		case 2: // truncate
			b = b[:rng.Intn(len(b))]
		case 3: // duplicate a span
			p := rng.Intn(len(b))
			q := p + rng.Intn(30)
			if q > len(b) {
				q = len(b)
			}
			b = append(b[:q], append(append([]byte(nil), b[p:q]...), b[q:]...)...)
		case 4: // insert a random byte
			p := rng.Intn(len(b))
			b = append(b[:p], append([]byte{byte(rng.Intn(256))}, b[p:]...)...)
		}
		r := check(t, b)
		noPanic(t, r)
		if r.code != 0 && r.code != 2 {
			t.Fatalf("mutation %d: exit %d for %q: %s", i, r.code, clip(string(b)), clip(r.all()))
		}
	}
}

func FuzzConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"listen":"127.0.0.1:0","data_dir":"x","allow_plaintext":true}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := check(t, b)
		noPanic(t, r)
		if r.code != 0 && r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
	})
}
