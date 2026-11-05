package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kairan/internal/wire"
)

func testEnv(tag byte) wire.Envelope {
	h := wire.Hash(strings.Repeat("ab", 32))
	return wire.Envelope{
		PayloadType: wire.PayloadTypePolicy,
		Payload:     []byte(`{"version":` + string('0'+tag) + `}`),
		Signatures: []wire.Signature{
			{KeyID: h, Sig: bytes.Repeat([]byte{tag}, wire.SignatureSize)},
			{KeyID: wire.Hash(strings.Repeat("cd", 32)), Sig: bytes.Repeat([]byte{tag + 1}, wire.SignatureSize)},
		},
	}
}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadMissing(t *testing.T) {
	s := newStore(t)
	env, found, err := s.Load()
	if found || err != nil || !reflect.DeepEqual(env, wire.Envelope{}) {
		t.Fatalf("Load() = %+v, %v, %v; want empty, false, nil", env, found, err)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	s := newStore(t)
	for _, tag := range []byte{1, 2} { // second Save replaces the first
		want := testEnv(tag)
		if err := s.Save(want); err != nil {
			t.Fatal(err)
		}
		got, found, err := s.Load()
		if err != nil || !found {
			t.Fatalf("Load: found=%v err=%v", found, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestSaveModesAndNoTempLeft(t *testing.T) {
	s := newStore(t)
	if err := s.Save(testEnv(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testEnv(2)); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %v, want 0600", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(filepath.Dir(s.Path()))
	if len(ents) != 1 || ents[0].Name() != "policy.json" {
		t.Fatalf("directory has %v, want only policy.json", ents)
	}
}

func TestSaveRejectsBadEnvelope(t *testing.T) {
	big := testEnv(1)
	big.Payload = bytes.Repeat([]byte("x"), wire.MaxEnvelopeBytes)
	noSig := testEnv(1)
	noSig.Signatures = nil
	badType := testEnv(1)
	badType.PayloadType = "text/plain"
	for name, env := range map[string]wire.Envelope{"too large": big, "no signatures": noSig, "payload type": badType, "zero": {}} {
		t.Run(name, func(t *testing.T) {
			s := newStore(t)
			if err := s.Save(testEnv(1)); err != nil {
				t.Fatal(err)
			}
			if err := s.Save(env); err == nil {
				t.Fatal("Save accepted a bad envelope")
			}
			got, found, err := s.Load()
			if err != nil || !found || !reflect.DeepEqual(got, testEnv(1)) {
				t.Fatalf("previous file not intact: %+v %v %v", got, found, err)
			}
		})
	}
}

func TestSaveFailureKeepsOldFileAndLeavesNoTemp(t *testing.T) {
	boom := errors.New("disk on fire")
	tests := []struct {
		name    string
		failOn  int // which sync call fails: 1 = file, 2 = directory
		wantOld bool
	}{
		{"file fsync fails", 1, true},
		{"dir fsync fails", 2, false}, // rename already happened
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			if err := s.Save(testEnv(1)); err != nil {
				t.Fatal(err)
			}
			calls := 0
			s.sync = func(f *os.File) error {
				calls++
				if calls == tc.failOn {
					return boom
				}
				return f.Sync()
			}
			err := s.Save(testEnv(2))
			if !errors.Is(err, boom) {
				t.Fatalf("Save error = %v, want %v", err, boom)
			}
			got, found, lerr := s.Load()
			if lerr != nil || !found {
				t.Fatalf("Load after failed save: %v %v", found, lerr)
			}
			want := testEnv(2)
			if tc.wantOld {
				want = testEnv(1)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("stored envelope is not the expected one")
			}
			ents, _ := os.ReadDir(filepath.Dir(s.Path()))
			if len(ents) != 1 {
				t.Fatalf("temp file left behind: %v", ents)
			}
		})
	}
}

func TestOpenRemovesStaleTemp(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "d")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(testEnv(1)); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(dir, ".policy-123.tmp")
	other := filepath.Join(dir, "keep.txt")
	for _, p := range []string{stale, other} {
		if err := os.WriteFile(p, []byte("half"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp still there: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("unrelated file removed: %v", err)
	}
	if got, found, err := s2.Load(); err != nil || !found || !reflect.DeepEqual(got, testEnv(1)) {
		t.Fatalf("policy lost across reopen: %v %v", found, err)
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("Open(\"\") succeeded")
	}
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(f); err == nil {
		t.Fatal("Open on a regular file succeeded")
	}
}

func TestLoadCorrupt(t *testing.T) {
	good, _ := jsonOf(testEnv(1))
	tests := []struct {
		name string
		data []byte
	}{
		{"empty file", nil},
		{"garbage", []byte("\x00\x01 not json")},
		{"truncated", good[:len(good)/2]},
		{"trailing data", append(append([]byte{}, good...), []byte(` {}`)...)},
		{"two envelopes", append(append([]byte{}, good...), good...)},
		{"unknown field", bytes.Replace(good, []byte(`{"payloadType"`), []byte(`{"extra":1,"payloadType"`), 1)},
		{"json null", []byte("null")},
		{"empty object", []byte("{}")},
		{"empty array", []byte("[]")},
		{"no signatures", []byte(`{"payloadType":"` + wire.PayloadTypePolicy + `","payload":"eA==","signatures":[]}`)},
		{"too large", bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes+10)},
		{"bad base64", bytes.Replace(good, []byte(`"payload":"`), []byte(`"payload":"!!`), 1)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			if err := os.WriteFile(s.Path(), tc.data, 0o600); err != nil {
				t.Fatal(err)
			}
			env, found, err := s.Load()
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Load error = %v, want ErrCorrupt", err)
			}
			if !found {
				t.Fatal("corrupt file reported as not found (would look like no policy)")
			}
			if !reflect.DeepEqual(env, wire.Envelope{}) {
				t.Fatal("Load returned a non-zero envelope with an error")
			}
		})
	}
}

func TestLoadNotRegularFile(t *testing.T) {
	s := newStore(t)
	if err := s.Save(testEnv(1)); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(filepath.Dir(s.Path()), "real.json")
	if err := os.Rename(s.Path(), real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, s.Path()); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, found, err := s.Load(); !errors.Is(err, ErrCorrupt) || !found {
		t.Fatalf("symlink: found=%v err=%v, want ErrCorrupt", found, err)
	}
	os.Remove(s.Path())
	if err := os.Mkdir(s.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Load(); !errors.Is(err, ErrCorrupt) || !found {
		t.Fatalf("directory: found=%v err=%v, want ErrCorrupt", found, err)
	}
}

func TestLoadErrorMessageDoesNotEchoContent(t *testing.T) {
	s := newStore(t)
	secret := "SECRET-PAYLOAD-TEXT"
	if err := os.WriteFile(s.Path(), []byte(`{"payloadType":"`+secret+`","bogus":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := s.Load()
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error %v echoes file content", err)
	}
}

func FuzzDecode(f *testing.F) {
	good, _ := jsonOf(testEnv(1))
	f.Add(good)
	f.Add([]byte("null"))
	f.Add([]byte(`{"payloadType":"x","payload":"","signatures":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := decode(data)
		if err != nil {
			if !errors.Is(err, ErrCorrupt) {
				t.Fatalf("error does not wrap ErrCorrupt: %v", err)
			}
			return
		}
		if err := env.ValidateShape(); err != nil {
			t.Fatalf("decode accepted an invalid shape: %v", err)
		}
	})
}
