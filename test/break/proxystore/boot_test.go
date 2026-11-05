package proxystorebreak

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kairan/internal/proxy/state"
	"kairan/internal/proxy/store"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

var now = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const canary = "CANARY-9f3b27-SECRET"

type oracleOut struct {
	ev     state.Event
	repair bool
}

// oracle is the boot rule of ARCHITECTURE section 4 / M-D33 and the DecideBoot doc, written
// independently of the implementation.
func oracle(st store.Stored, lg store.LogView, n time.Time) oracleOut {
	switch {
	case lg.OpenErr != nil:
		return oracleOut{ev: state.BootTampered}
	case st.Err != nil:
		return oracleOut{ev: state.BootTampered}
	case !st.Found:
		if lg.AppliedVer == 0 {
			return oracleOut{ev: state.BootNoPolicy}
		}
		return oracleOut{ev: state.BootTampered}
	}
	v := st.Checked.Version
	switch {
	case v < lg.AppliedVer:
		return oracleOut{ev: state.BootTampered}
	case v == lg.AppliedVer && st.Checked.Hash != lg.AppliedHash:
		return oracleOut{ev: state.BootTampered}
	}
	out := oracleOut{repair: v > lg.AppliedVer}
	if !n.Before(st.Checked.Expires) {
		out.ev = state.BootExpired
	} else {
		out.ev = state.BootValid
	}
	return out
}

func TestDecideBootExhaustiveAgainstTheDocumentedRule(t *testing.T) {
	errX := errors.New("boom " + canary)
	hashes := []wire.Hash{hx("A"), hx("B"), ""}
	versions := []uint64{1, 2, 5, 6, math.MaxUint64 - 1, math.MaxUint64}
	applied := []uint64{0, 1, 2, 5, 6, math.MaxUint64 - 1, math.MaxUint64}
	expires := []time.Time{now.Add(-time.Hour), now.Add(-time.Nanosecond), now, now.Add(time.Nanosecond), now.Add(72 * time.Hour), {}, time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)}
	nows := []time.Time{now, {}, now.Add(-time.Hour * 24 * 365)}
	n := 0
	for _, openErr := range []error{nil, errX} {
		for _, found := range []bool{false, true} {
			for _, stErr := range []error{nil, errX, store.ErrCorrupt} {
				for _, v := range versions {
					for _, av := range applied {
						for _, sh := range hashes {
							for _, ah := range hashes {
								for _, exp := range expires {
									for _, nw := range nows {
										seq := uint64(0)
										if av > 0 {
											seq = av
											if seq > 50 {
												seq = 50
											}
										} else if v%2 == 0 {
											seq = 3 // rejections-only log
										}
										st := store.Stored{Found: found, Err: stErr, Checked: store.Checked{Version: v, Hash: sh, Expires: exp}}
										lg := store.LogView{OpenErr: openErr, Seq: seq, AppliedVer: av, AppliedHash: ah}
										if av == 0 {
											lg.AppliedHash = ""
										}
										got := store.DecideBoot(st, lg, nw)
										want := oracle(st, lg, nw)
										n++
										if got.Event != want.ev || got.Repair != want.repair {
											t.Fatalf("DecideBoot(%+v, %+v, now=%v) = {%v repair=%v}, want {%v repair=%v}", st, lg, nw, got.Event, got.Repair, want.ev, want.repair)
										}
										if got.Repair && got.Event != state.BootValid && got.Event != state.BootExpired {
											t.Fatalf("Repair with event %v", got.Event)
										}
										if got.Reason == "" {
											t.Fatalf("empty Reason for %+v %+v", st, lg)
										}
										if strings.Contains(got.Reason, canary) || strings.Contains(got.Reason, "boom") {
											t.Fatalf("Reason echoes error text: %q", got.Reason)
										}
										if len(got.Reason) > 200 {
											t.Fatalf("Reason is %d bytes: %q", len(got.Reason), got.Reason)
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}
	t.Logf("%d combinations checked", n)
}

// ARCH section 4 / failure table: each sentence of the rule as one named case.
func TestDecideBootNamedRules(t *testing.T) {
	future := now.Add(48 * time.Hour)
	ok := func(v uint64, h wire.Hash, exp time.Time) store.Stored {
		return store.Stored{Found: true, Checked: store.Checked{Version: v, Hash: h, Expires: exp}}
	}
	cases := []struct {
		name   string
		st     store.Stored
		lg     store.LogView
		want   state.Event
		repair bool
	}{
		{"fresh proxy: no file, empty log", store.Stored{}, store.LogView{}, state.BootNoPolicy, false},
		{"P-03 ruling: no file, log holds only rejections -> NoPolicy", store.Stored{}, store.LogView{Seq: 4}, state.BootNoPolicy, false},
		{"no file but the log says a policy was applied -> Tampered (file deleted)", store.Stored{}, store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"file equal to log, unexpired -> Valid", ok(3, hx("A"), future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootValid, false},
		{"file equal to log, expired -> Expired (safe mode)", ok(3, hx("A"), now.Add(-time.Second)), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootExpired, false},
		{"older valid policy put back -> Tampered", ok(2, hx("B"), future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"older valid policy with the same hash -> Tampered", ok(2, hx("A"), future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"P-03 ruling: same version, different hash -> Tampered", ok(3, hx("B"), future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"same version, hash empty in the file -> Tampered", ok(3, "", future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"crash between Save and Append: newer file -> accept with repair", ok(4, hx("B"), future), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootValid, true},
		{"newer file, expired -> Expired with repair", ok(4, hx("B"), now), store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootExpired, true},
		{"first ever apply crashed before Append: empty log, file present -> repair", ok(1, hx("A"), future), store.LogView{}, state.BootValid, true},
		{"file present, log holds only rejections -> repair", ok(1, hx("A"), future), store.LogView{Seq: 2}, state.BootValid, true},
		{"log does not open -> Tampered even with a perfect file", ok(3, hx("A"), future), store.LogView{OpenErr: errors.New("chain broken"), Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"log does not open and there is no file -> Tampered, not NoPolicy", store.Stored{}, store.LogView{OpenErr: errors.New("truncated last line")}, state.BootTampered, false},
		{"file fails verification -> Tampered", store.Stored{Found: true, Err: errors.New("bad sig")}, store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}, state.BootTampered, false},
		{"file fails verification on a fresh proxy -> Tampered, not NoPolicy", store.Stored{Found: true, Err: errors.New("bad sig")}, store.LogView{}, state.BootTampered, false},
		{"Load error without Found -> Tampered, never NoPolicy", store.Stored{Found: false, Err: errors.New("io")}, store.LogView{}, state.BootTampered, false},
		{"corrupt file -> Tampered", store.Stored{Found: true, Err: store.ErrCorrupt}, store.LogView{}, state.BootTampered, false},
		{"expiry is exclusive of 'before': now == expires_at is expired (M-D30)", ok(1, hx("A"), now), store.LogView{Seq: 1, AppliedVer: 1, AppliedHash: hx("A")}, state.BootExpired, false},
		{"one nanosecond before expiry is valid", ok(1, hx("A"), now.Add(time.Nanosecond)), store.LogView{Seq: 1, AppliedVer: 1, AppliedHash: hx("A")}, state.BootValid, false},
		{"file valid but a stale Checked left behind with Err set -> Tampered", store.Stored{Found: true, Err: errors.New("x"), Checked: store.Checked{Version: 9, Hash: hx("A"), Expires: future}}, store.LogView{Seq: 1, AppliedVer: 9, AppliedHash: hx("A")}, state.BootTampered, false},
		{"max version in the log, smaller file", ok(math.MaxUint64-1, hx("A"), future), store.LogView{Seq: 1, AppliedVer: math.MaxUint64, AppliedHash: hx("A")}, state.BootTampered, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := store.DecideBoot(c.st, c.lg, now)
			if got.Event != c.want || got.Repair != c.repair {
				t.Fatalf("got {%v repair=%v reason=%q}, want {%v repair=%v}", got.Event, got.Repair, got.Reason, c.want, c.repair)
			}
		})
	}
}

// I3: nothing a corrupted input can do makes DecideBoot trust a file that failed anything.
func TestDecideBootNeverTrustsAFailedFile(t *testing.T) {
	future := now.Add(time.Hour)
	for _, openErr := range []error{nil, errors.New("x")} {
		for _, stErr := range []error{nil, errors.New("x")} {
			for _, found := range []bool{false, true} {
				for _, av := range []uint64{0, 3} {
					st := store.Stored{Found: found, Err: stErr, Checked: store.Checked{Version: 3, Hash: hx("A"), Expires: future}}
					lg := store.LogView{OpenErr: openErr, Seq: av, AppliedVer: av}
					if av > 0 {
						lg.AppliedHash = hx("A")
					}
					d := store.DecideBoot(st, lg, now)
					trusted := d.Event == state.BootValid || d.Event == state.BootExpired
					allowed := openErr == nil && stErr == nil && found
					if trusted && !allowed {
						t.Fatalf("trusted a file with openErr=%v stErr=%v found=%v", openErr, stErr, found)
					}
				}
			}
		}
	}
}

func TestDecideBootIsPureAndDeterministic(t *testing.T) {
	st := store.Stored{Found: true, Checked: store.Checked{Version: 4, Hash: hx("B"), Expires: now.Add(time.Hour)}}
	lg := store.LogView{Seq: 1, AppliedVer: 3, AppliedHash: hx("A")}
	first := store.DecideBoot(st, lg, now)
	for i := 0; i < 100; i++ {
		if got := store.DecideBoot(st, lg, now); got != first {
			t.Fatalf("not deterministic: %+v vs %+v", got, first)
		}
	}
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 1000; j++ {
				if store.DecideBoot(st, lg, now) != first {
					t.Error("concurrent result differs")
					return
				}
			}
		}()
	}
	for i := 0; i < 8; i++ {
		<-done
	}
}

// ---- end to end with the real trust.Verify and the golden fixtures ----

func fixtures() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "fixtures")
}

func fixtureRoot(t *testing.T) trust.Root {
	t.Helper()
	root := trust.Root{Tenant: "bank-a", Keys: map[wire.Hash]ed25519.PublicKey{}, Threshold: 2}
	for _, n := range []string{"admin-a", "admin-b", "admin-c"} {
		b, err := os.ReadFile(filepath.Join(fixtures(), "TEST-ONLY-"+n+".pub"))
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			t.Fatalf("bad pub %s", n)
		}
		pub := ed25519.PublicKey(raw)
		root.Keys[trust.KeyID(pub)] = pub
	}
	return root
}

func verifier(root trust.Root) store.Verifier {
	return func(env wire.Envelope) (store.Checked, error) {
		v, code, err := trust.Verify(env, root)
		if err != nil {
			return store.Checked{}, fmt.Errorf("%s: %w", code, err)
		}
		return store.Checked{Version: v.Policy.Version, Hash: v.Hash, Expires: v.Policy.ExpiresAt}, nil
	}
}

func TestEveryGoldenFixtureThroughInspectAndDecideBoot(t *testing.T) {
	root := fixtureRoot(t)
	raw, err := os.ReadFile(filepath.Join(fixtures(), "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cf struct {
		Cases []struct {
			Name string `json:"name"`
			File string `json:"file"`
			Have uint64 `json:"have"`
			Want string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &cf); err != nil {
		t.Fatal(err)
	}
	if len(cf.Cases) < 20 {
		t.Fatalf("only %d fixture cases", len(cf.Cases))
	}
	bootNow := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	for _, c := range cf.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(fixtures(), c.File))
			if err != nil {
				t.Fatal(err)
			}
			s, _ := openIn(t)
			// Put the fixture on disk exactly as given (it may not pass Save's shape check).
			if err := os.WriteFile(s.Path(), b, 0o600); err != nil {
				t.Fatal(err)
			}
			st, env := store.Inspect(s, verifier(root))
			// trust.Verify ignores version and expiry, so these three outcomes all verify.
			verifies := c.Want == "" || c.Want == "version_not_newer" || c.Want == "expired"
			if verifies {
				if !st.Found || st.Err != nil {
					t.Fatalf("a fixture that Verify accepts was rejected: found=%v err=%v", st.Found, st.Err)
				}
				if st.Checked.Version == 0 || !st.Checked.Hash.Valid() || st.Checked.Expires.IsZero() {
					t.Fatalf("Checked not filled: %+v", st.Checked)
				}
				if env.PayloadType == "" || len(env.Payload) == 0 {
					t.Fatal("verified envelope not returned for installation")
				}
				// boot with an empty log: repair + valid (or expired)
				d := store.DecideBoot(st, store.LogView{}, bootNow)
				wantEv := state.BootValid
				if !bootNow.Before(st.Checked.Expires) {
					wantEv = state.BootExpired
				}
				if d.Event != wantEv || !d.Repair {
					t.Fatalf("empty log: %+v, want %v with repair", d, wantEv)
				}
				// boot with a log that matches
				d = store.DecideBoot(st, store.LogView{Seq: 1, AppliedVer: st.Checked.Version, AppliedHash: st.Checked.Hash}, bootNow)
				if d.Event != wantEv || d.Repair {
					t.Fatalf("matching log: %+v, want %v without repair", d, wantEv)
				}
				// replay protection at boot: the log has already applied something newer
				d = store.DecideBoot(st, store.LogView{Seq: 2, AppliedVer: st.Checked.Version + 1, AppliedHash: hx("other")}, bootNow)
				if d.Event != state.BootTampered {
					t.Fatalf("older-than-log fixture boots as %v, want Tampered", d.Event)
				}
				// same version, other content
				d = store.DecideBoot(st, store.LogView{Seq: 2, AppliedVer: st.Checked.Version, AppliedHash: hx("other")}, bootNow)
				if d.Event != state.BootTampered {
					t.Fatalf("same version other hash boots as %v, want Tampered", d.Event)
				}
				return
			}
			if st.Err == nil {
				t.Fatalf("fixture %q (want %q) passed Inspect: a policy that fails trust.Verify would be enforced", c.Name, c.Want)
			}
			for _, lg := range []store.LogView{{}, {Seq: 1, AppliedVer: 1, AppliedHash: hx("x")}, {Seq: 3}} {
				d := store.DecideBoot(st, lg, bootNow)
				if d.Event != state.BootTampered {
					t.Fatalf("failing fixture boots as %v with log %+v, want Tampered", d.Event, lg)
				}
			}
		})
	}
}

// Inspect: the verifier is not consulted for a file that does not load, and a verifier error is a tamper.
func TestInspectEdgeCases(t *testing.T) {
	root := fixtureRoot(t)
	good, _ := os.ReadFile(filepath.Join(fixtures(), "envelopes", "valid.json"))

	t.Run("no file", func(t *testing.T) {
		s, _ := openIn(t)
		called := false
		st, _ := store.Inspect(s, func(wire.Envelope) (store.Checked, error) { called = true; return store.Checked{}, nil })
		if st.Found || st.Err != nil || called {
			t.Fatalf("%+v called=%v", st, called)
		}
		if d := store.DecideBoot(st, store.LogView{}, now); d.Event != state.BootNoPolicy {
			t.Fatalf("event %v", d.Event)
		}
	})
	t.Run("corrupt file does not reach the verifier", func(t *testing.T) {
		s, _ := openIn(t)
		os.WriteFile(s.Path(), []byte("{not json"), 0o600)
		called := false
		st, env := store.Inspect(s, func(wire.Envelope) (store.Checked, error) { called = true; return store.Checked{Version: 9}, nil })
		if called {
			t.Error("verifier called on a file that did not load")
		}
		if st.Err == nil {
			t.Fatal("corrupt file reported no error")
		}
		if len(env.Payload) != 0 {
			t.Error("an envelope is returned for a corrupt file")
		}
		if d := store.DecideBoot(st, store.LogView{}, now); d.Event != state.BootTampered {
			t.Fatalf("event %v, want Tampered", d.Event)
		}
	})
	t.Run("verifier error wins over a filled Checked", func(t *testing.T) {
		s, _ := openIn(t)
		os.WriteFile(s.Path(), good, 0o600)
		st, _ := store.Inspect(s, func(wire.Envelope) (store.Checked, error) {
			return store.Checked{Version: 99, Hash: hx("A"), Expires: now.Add(time.Hour)}, errors.New("nope " + canary)
		})
		if st.Err == nil {
			t.Fatal("a verifier error was swallowed")
		}
		if d := store.DecideBoot(st, store.LogView{}, now); d.Event != state.BootTampered || strings.Contains(d.Reason, canary) {
			t.Fatalf("decision %+v", d)
		}
	})
	t.Run("verifier receives the stored bytes, not something re-encoded", func(t *testing.T) {
		s, _ := openIn(t)
		os.WriteFile(s.Path(), good, 0o600)
		var seen wire.Envelope
		st, env := store.Inspect(s, func(e wire.Envelope) (store.Checked, error) { seen = e; return verifier(root)(e) })
		if st.Err != nil {
			t.Fatalf("valid fixture rejected: %v", st.Err)
		}
		if string(seen.Payload) != string(env.Payload) {
			t.Fatal("returned envelope differs from the verified one")
		}
	})
	t.Run("verified file swapped between Inspect and later reads is the caller's envelope", func(t *testing.T) {
		s, _ := openIn(t)
		os.WriteFile(s.Path(), good, 0o600)
		st, env := store.Inspect(s, verifier(root))
		if st.Err != nil {
			t.Fatal(st.Err)
		}
		// the returned envelope is a value: mutating the file after Inspect cannot change it
		os.WriteFile(s.Path(), []byte("tampered"), 0o600)
		v, _, err := trust.Verify(env, root)
		if err != nil || v.Hash != st.Checked.Hash {
			t.Fatalf("the returned envelope no longer verifies: %v", err)
		}
	})
	t.Run("save then inspect is stable", func(t *testing.T) {
		s, _ := openIn(t)
		var env wire.Envelope
		if err := json.Unmarshal(good, &env); err != nil {
			t.Fatal(err)
		}
		if err := s.Save(env); err != nil {
			t.Fatal(err)
		}
		st, _ := store.Inspect(s, verifier(root))
		if st.Err != nil || !st.Found {
			t.Fatalf("a fixture saved by Save does not verify after Load: %+v", st)
		}
	})
}
