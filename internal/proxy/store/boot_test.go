package store

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

func jsonOf(env wire.Envelope) ([]byte, error) { return json.Marshal(env) }

var (
	t0   = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	hash = func(c string) wire.Hash { return wire.Hash(strings.Repeat(c, 64)) }
)

func ok(version uint64, h wire.Hash, expires time.Time) Stored {
	return Stored{Found: true, Checked: Checked{Version: version, Hash: h, Expires: expires}}
}

func TestDecideBoot(t *testing.T) {
	later, earlier := t0.Add(time.Hour), t0.Add(-time.Hour)
	bad := errors.New("verify failed")
	tests := []struct {
		name       string
		st         Stored
		lg         LogView
		wantEvent  state.Event
		wantRepair bool
	}{
		{"no file, empty log", Stored{}, LogView{}, state.BootNoPolicy, false},
		{"no file, log with applied versions", Stored{}, LogView{Seq: 3, AppliedVer: 3, AppliedHash: hash("a")}, state.BootTampered, false},
		{"no file, log with only rejected attempts", Stored{}, LogView{Seq: 2}, state.BootNoPolicy, false},
		{"truncated log, otherwise fine", ok(5, hash("a"), later), LogView{OpenErr: errors.New("x"), Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootTampered, false},
		{"truncated log, no file", Stored{}, LogView{OpenErr: errors.New("x")}, state.BootTampered, false},
		{"load error", Stored{Found: true, Err: ErrCorrupt}, LogView{}, state.BootTampered, false},
		{"load io error, not found flag", Stored{Err: errors.New("EIO")}, LogView{}, state.BootTampered, false},
		{"verify fails", Stored{Found: true, Err: bad}, LogView{Seq: 1, AppliedVer: 1, AppliedHash: hash("a")}, state.BootTampered, false},
		{"stored older than log", ok(4, hash("a"), later), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("b")}, state.BootTampered, false},
		{"stored older than log, much", ok(1, hash("a"), later), LogView{Seq: 9, AppliedVer: 900, AppliedHash: hash("b")}, state.BootTampered, false},
		{"stored older than log and expired", ok(4, hash("a"), earlier), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("b")}, state.BootTampered, false},
		{"same version, different hash", ok(5, hash("a"), later), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("b")}, state.BootTampered, false},
		{"stored version zero", ok(0, hash("a"), later), LogView{}, state.BootTampered, false},
		{"same version, same hash", ok(5, hash("a"), later), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootValid, false},
		{"same version, same hash, expired", ok(5, hash("a"), earlier), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootExpired, false},
		{"expires exactly now", ok(5, hash("a"), t0), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootExpired, false},
		{"newer stored, valid: repair", ok(6, hash("c"), later), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootValid, true},
		{"newer stored, expired: repair", ok(6, hash("c"), earlier), LogView{Seq: 5, AppliedVer: 5, AppliedHash: hash("a")}, state.BootExpired, true},
		{"newer stored, empty log (crash on first apply)", ok(1, hash("c"), later), LogView{}, state.BootValid, true},
		{"newer stored, log has only rejects", ok(2, hash("c"), later), LogView{Seq: 4}, state.BootValid, true},
		{"newer stored but newer-version verify failed", Stored{Found: true, Err: bad}, LogView{Seq: 5, AppliedVer: 5}, state.BootTampered, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideBoot(tc.st, tc.lg, t0)
			if got.Event != tc.wantEvent || got.Repair != tc.wantRepair {
				t.Fatalf("DecideBoot = %+v, want event %v repair %v", got, tc.wantEvent, tc.wantRepair)
			}
			if got.Reason == "" {
				t.Fatal("empty reason")
			}
			if got.Repair && got.Event != state.BootValid && got.Event != state.BootExpired {
				t.Fatal("repair with a non-accepting event")
			}
			if next := state.Next(wire.StateBooting, got.Event); next == wire.StateEnforcing && got.Event != state.BootValid {
				t.Fatalf("event %v led to Enforcing", got.Event)
			}
		})
	}
}

// Nothing in the inputs can make the result Enforcing unless the file was
// found, verified, not older than the log and not expired.
func TestDecideBootNeverValidWithoutGoodInputs(t *testing.T) {
	versions := []uint64{0, 1, 4, 5, 6}
	hashes := []wire.Hash{"", hash("a"), hash("b")}
	exps := []time.Time{{}, t0.Add(-time.Second), t0, t0.Add(time.Second)}
	errs := []error{nil, errors.New("e")}
	for _, found := range []bool{false, true} {
		for _, se := range errs {
			for _, le := range errs {
				for _, v := range versions {
					for _, h := range hashes {
						for _, x := range exps {
							for _, av := range versions {
								for _, ah := range hashes {
									st := Stored{Found: found, Err: se, Checked: Checked{Version: v, Hash: h, Expires: x}}
									lg := LogView{OpenErr: le, AppliedVer: av, AppliedHash: ah}
									d := DecideBoot(st, lg, t0)
									if d.Event != state.BootValid {
										continue
									}
									if !found || se != nil || le != nil || v == 0 || v < av || x.Before(t0.Add(time.Nanosecond)) || (v == av && h != ah) {
										t.Fatalf("BootValid for %+v %+v", st, lg)
									}
									if d.Repair != (v > av) {
										t.Fatalf("repair=%v for v=%d av=%d", d.Repair, v, av)
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

func TestInspect(t *testing.T) {
	good := testEnv(1)
	pass := func(env wire.Envelope) (Checked, error) {
		return Checked{Version: 7, Hash: hash("a"), Expires: t0.Add(time.Hour)}, nil
	}
	fail := func(env wire.Envelope) (Checked, error) { return Checked{Version: 99}, errors.New("nope") }

	t.Run("missing", func(t *testing.T) {
		s := newStore(t)
		st, env := Inspect(s, pass)
		if st.Found || st.Err != nil || !reflect.DeepEqual(env, wire.Envelope{}) {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("verified", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save(good); err != nil {
			t.Fatal(err)
		}
		st, env := Inspect(s, pass)
		if !st.Found || st.Err != nil || st.Checked.Version != 7 || !reflect.DeepEqual(env, good) {
			t.Fatalf("got %+v", st)
		}
	})
	t.Run("verify fails", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save(good); err != nil {
			t.Fatal(err)
		}
		st, env := Inspect(s, fail)
		if !st.Found || st.Err == nil || !reflect.DeepEqual(env, wire.Envelope{}) {
			t.Fatalf("got %+v", st)
		}
		if d := DecideBoot(st, LogView{}, t0); d.Event != state.BootTampered {
			t.Fatalf("event %v", d.Event)
		}
	})
	t.Run("nil verifier", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save(good); err != nil {
			t.Fatal(err)
		}
		st, _ := Inspect(s, nil)
		if st.Err == nil {
			t.Fatal("nil verifier accepted the file")
		}
	})
	t.Run("corrupt file", func(t *testing.T) {
		s := newStore(t)
		if err := writeRaw(s, []byte("junk")); err != nil {
			t.Fatal(err)
		}
		called := false
		st, _ := Inspect(s, func(wire.Envelope) (Checked, error) { called = true; return Checked{}, nil })
		if called || !errors.Is(st.Err, ErrCorrupt) {
			t.Fatalf("called=%v err=%v", called, st.Err)
		}
		if d := DecideBoot(st, LogView{}, t0); d.Event != state.BootTampered {
			t.Fatalf("event %v, want BootTampered (never BootNoPolicy)", d.Event)
		}
	})
}

func writeRaw(s *Store, data []byte) error { return os.WriteFile(s.Path(), data, 0o600) }
