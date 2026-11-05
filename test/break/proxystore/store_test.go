// Package proxystorebreak holds black-box attack tests for the proxy's policy
// store and boot decision (task P-03). Sources: ARCHITECTURE section 4 (boot
// rule, M-D33), the proxy/store LLD, section 8 (failure table), invariants I2
// and I3, test/fixtures and the go doc of the proxy store package.
package proxystorebreak

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kairan/internal/proxy/store"
	"kairan/internal/wire"
)

func hx(s string) wire.Hash {
	sum := sha256.Sum256([]byte(s))
	return wire.Hash(hex.EncodeToString(sum[:]))
}

func envOf(payload []byte, nsig int) wire.Envelope {
	e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	for i := 0; i < nsig; i++ {
		s := make([]byte, wire.SignatureSize)
		for j := range s {
			s[j] = byte(i + 1)
		}
		e.Signatures = append(e.Signatures, wire.Signature{KeyID: hx(fmt.Sprint("k", i)), Sig: s})
	}
	return e
}

func openIn(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s, dir
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func TestSaveLoadRoundTripIsByteExact(t *testing.T) {
	payloads := map[string][]byte{
		"json":             []byte(`{"tenant":"bank-a","version":1}`),
		"trailing-space":   []byte(`{"tenant":"bank-a","version":1} `),
		"trailing-nl":      []byte("{\"a\":1}\n\n"),
		"crlf":             []byte("{\r\n}\r\n"),
		"not-utf8":         {0xff, 0xfe, 0x00, 0x01, 0xc0, 0xaf},
		"nul":              {0, 0, 0},
		"html-chars":       []byte(`{"x":"<script>&amp; "}`),
		"big":              bytes.Repeat([]byte("A"), 150<<10),
		"one-byte":         {'x'},
		"base64-lookalike": []byte("eyJhIjoxfQ=="),
	}
	for name, p := range payloads {
		t.Run(name, func(t *testing.T) {
			s, dir := openIn(t)
			in := envOf(p, 2)
			if err := s.Save(in); err != nil {
				t.Fatalf("Save: %v", err)
			}
			for round, st := range []*store.Store{s, mustOpen(t, dir)} {
				out, found, err := st.Load()
				if err != nil || !found {
					t.Fatalf("round %d: Load = found %v err %v", round, found, err)
				}
				if !reflect.DeepEqual(out, in) {
					t.Fatalf("round %d: envelope changed on the way through the store (signed bytes must never be re-encoded)", round)
				}
			}
		})
	}
}

func mustOpen(t *testing.T, dir string) *store.Store {
	t.Helper()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoadMissingIsNotFoundNotError(t *testing.T) {
	s, _ := openIn(t)
	env, found, err := s.Load()
	if found || err != nil {
		t.Fatalf("Load on an empty dir = %+v, %v, %v", env, found, err)
	}
}

func TestOpenDoesNotReadThePolicy(t *testing.T) {
	s, dir := openIn(t)
	if err := os.WriteFile(s.Path(), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Open(dir); err != nil {
		t.Fatalf("Open must not look at the policy file: %v", err)
	}
	if filepath.Dir(s.Path()) != dir {
		t.Fatalf("Path %q is not inside the data dir %q", s.Path(), dir)
	}
}

func TestOpenCreatesDirWithPrivateMode(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "data")
	if _, err := store.Open(deep); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(deep)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("data dir mode %o: group/others have access (doc: 0700)", info.Mode().Perm())
	}
	for i := 0; i < 3; i++ {
		if _, err := store.Open(deep); err != nil {
			t.Fatalf("re-Open %d: %v", i, err)
		}
	}
	file := filepath.Join(root, "afile")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := store.Open(file); err == nil {
		t.Error("Open on a regular file succeeded")
	}
	if _, err := store.Open(filepath.Join(file, "sub")); err == nil {
		t.Error("Open under a regular file succeeded")
	}
}

func TestSavedFileModeIsPrivate(t *testing.T) {
	s, dir := openIn(t)
	if err := s.Save(envOf([]byte("x"), 2)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("policy file mode %o, doc says 0600", info.Mode().Perm())
	}
	if info.Mode().Perm()&0o111 != 0 {
		t.Errorf("policy file is executable: %o", info.Mode().Perm())
	}
	// a pre-existing file with loose permissions is replaced by a private one
	os.Chmod(s.Path(), 0o666)
	if err := s.Save(envOf([]byte("y"), 2)); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(s.Path())
	if info.Mode().Perm()&0o022 != 0 {
		t.Errorf("after overwrite the file is group/world writable: %o", info.Mode().Perm())
	}
	if n := len(entries(t, dir)); n != 1 {
		t.Errorf("data dir has %d entries after Save: %v", n, entries(t, dir))
	}
}

func TestSaveRejectsBadEnvelopesAndKeepsTheOldFile(t *testing.T) {
	good := envOf([]byte(`{"v":1}`), 2)
	bad := map[string]wire.Envelope{
		"wrong-type": func() wire.Envelope { e := envOf([]byte("x"), 2); e.PayloadType = "text/plain"; return e }(),
		"empty":      envOf(nil, 2),
		"no-sigs":    envOf([]byte("x"), 0),
		"nine-sigs":  envOf([]byte("x"), 9),
		"short-sig": func() wire.Envelope {
			e := envOf([]byte("x"), 2)
			e.Signatures[0].Sig = e.Signatures[0].Sig[:63]
			return e
		}(),
		"bad-keyid":   func() wire.Envelope { e := envOf([]byte("x"), 2); e.Signatures[1].KeyID = "nope"; return e }(),
		"zero-value":  {},
		"too-big":     envOf(bytes.Repeat([]byte("A"), wire.MaxEnvelopeBytes), 2),
		"way-too-big": envOf(bytes.Repeat([]byte("A"), 4*wire.MaxEnvelopeBytes), 2),
	}
	for name, env := range bad {
		t.Run(name, func(t *testing.T) {
			s, dir := openIn(t)
			if err := s.Save(good); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(s.Path())
			if err := s.Save(env); err == nil {
				t.Fatal("Save accepted a bad envelope")
			}
			after, _ := os.ReadFile(s.Path())
			if !bytes.Equal(before, after) {
				t.Fatal("a failed Save changed the stored file")
			}
			if n := len(entries(t, dir)); n != 1 {
				t.Fatalf("failed Save left files behind: %v", entries(t, dir))
			}
			out, found, err := s.Load()
			if err != nil || !found || !reflect.DeepEqual(out, good) {
				t.Fatalf("old policy not loadable after a failed Save: %v %v", found, err)
			}
		})
	}
}

// "encode within wire.MaxEnvelopeBytes": the largest envelope Save accepts must also be loadable,
// or a good apply turns into Tampered at the next boot.
func TestSizeBoundarySaveAndLoadAgree(t *testing.T) {
	enc := func(n int) int {
		b, _ := json.Marshal(envOf(bytes.Repeat([]byte("A"), n), 2))
		return len(b)
	}
	// largest payload whose JSON encoding fits
	lo, hi := 1, wire.MaxEnvelopeBytes
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if enc(mid) <= wire.MaxEnvelopeBytes {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	for _, n := range []int{lo - 3, lo - 1, lo, lo + 1, lo + 2, lo + 3, lo + 10} {
		t.Run(fmt.Sprintf("payload=%d(encoded %d)", n, enc(n)), func(t *testing.T) {
			s, _ := openIn(t)
			env := envOf(bytes.Repeat([]byte("A"), n), 2)
			err := s.Save(env)
			fits := enc(n) <= wire.MaxEnvelopeBytes
			if fits && err != nil {
				t.Fatalf("Save refused an envelope that encodes to %d <= %d bytes: %v", enc(n), wire.MaxEnvelopeBytes, err)
			}
			if !fits && err == nil {
				t.Fatalf("Save accepted an envelope that encodes to %d > %d bytes", enc(n), wire.MaxEnvelopeBytes)
			}
			if err != nil {
				return
			}
			out, found, lerr := s.Load()
			if lerr != nil || !found || !reflect.DeepEqual(out, env) {
				t.Fatalf("Save accepted it but Load fails: found=%v err=%v (the proxy would boot Tampered after a good apply)", found, lerr)
			}
		})
	}
}

func TestLoadCorruptFiles(t *testing.T) {
	good, _ := json.Marshal(envOf([]byte(`{"v":1}`), 2))
	withField := func(k string, v any) []byte {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		m[k] = v
		b, _ := json.Marshal(m)
		return b
	}
	mut := func(f func(m map[string]any)) []byte {
		var m map[string]any
		_ = json.Unmarshal(good, &m)
		f(m)
		b, _ := json.Marshal(m)
		return b
	}
	cases := map[string][]byte{
		"empty":               {},
		"spaces":              []byte("   \n"),
		"null":                []byte("null"),
		"array":               []byte("[]"),
		"number":              []byte("1"),
		"string":              []byte(`"x"`),
		"empty-object":        []byte("{}"),
		"nul-bytes":           {0, 0, 0, 0},
		"bom":                 append([]byte("\xef\xbb\xbf"), good...),
		"truncated-half":      good[:len(good)/2],
		"truncated-last-byte": good[:len(good)-1],
		"trailing-garbage":    append(append([]byte{}, good...), []byte("garbage")...),
		"second-object":       append(append([]byte{}, good...), []byte(`{}`)...),
		"second-envelope":     append(append([]byte{}, good...), good...),
		"unknown-field":       withField("debug", 1),
		"wrong-type":          mut(func(m map[string]any) { m["payloadType"] = "text/html" }),
		"no-signatures":       mut(func(m map[string]any) { m["signatures"] = []any{} }),
		"null-signatures":     mut(func(m map[string]any) { m["signatures"] = nil }),
		"nine-signatures": mut(func(m map[string]any) {
			s := m["signatures"].([]any)
			for len(s) < 9 {
				s = append(s, s[0])
			}
			m["signatures"] = s
		}),
		"sig-too-short": mut(func(m map[string]any) { m["signatures"].([]any)[0].(map[string]any)["sig"] = "AAAA" }),
		"keyid-uppercase": mut(func(m map[string]any) {
			m["signatures"].([]any)[0].(map[string]any)["keyid"] = strings.ToUpper(string(hx("z")))
		}),
		"payload-not-base64":   mut(func(m map[string]any) { m["payload"] = "!!!not base64!!!" }),
		"payload-number":       mut(func(m map[string]any) { m["payload"] = 12 }),
		"payload-empty":        mut(func(m map[string]any) { m["payload"] = "" }),
		"payload-null":         mut(func(m map[string]any) { m["payload"] = nil }),
		"deep-nesting":         []byte(strings.Repeat("[", 1<<20)),
		"deep-nesting-object":  []byte(strings.Repeat(`{"a":`, 200000)),
		"huge-string":          []byte(`{"payloadType":"` + strings.Repeat("a", 5<<20) + `"}`),
		"too-large-valid-json": append(append([]byte(`{"payloadType":"x","pad":"`), bytes.Repeat([]byte("a"), 2*wire.MaxEnvelopeBytes)...), []byte(`"}`)...),
		"html":                 []byte("<html>not json</html>"),
		"git-conflict":         []byte("<<<<<<< HEAD\n" + string(good) + "\n=======\n>>>>>>> x\n"),
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			s, _ := openIn(t)
			if err := os.WriteFile(s.Path(), content, 0o600); err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			var env wire.Envelope
			var found bool
			var err error
			go func() { defer close(done); env, found, err = s.Load() }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Load hung or recursed")
			}
			if err == nil {
				t.Fatalf("a corrupt file loaded without error: found=%v env payload len %d (must be ErrCorrupt)", found, len(env.Payload))
			}
			if !errors.Is(err, store.ErrCorrupt) {
				t.Fatalf("err = %v, want it to wrap ErrCorrupt", err)
			}
			if strings.Contains(err.Error(), "garbage") || strings.Contains(err.Error(), "html") {
				t.Errorf("error text echoes file content: %q", err.Error())
			}
		})
	}
	// control: the good bytes do load
	s, _ := openIn(t)
	os.WriteFile(s.Path(), good, 0o600)
	if _, found, err := s.Load(); err != nil || !found {
		t.Fatalf("control file did not load: %v %v", found, err)
	}
}

// A non-regular file in place of the policy must never read as "no policy".
func TestNonRegularFileInPlaceOfThePolicy(t *testing.T) {
	good, _ := json.Marshal(envOf([]byte(`{"v":1}`), 2))
	mk := map[string]func(t *testing.T, s *store.Store, dir string){
		"directory": func(t *testing.T, s *store.Store, dir string) {
			if err := os.Mkdir(s.Path(), 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"directory-with-policy-inside": func(t *testing.T, s *store.Store, dir string) {
			os.Mkdir(s.Path(), 0o700)
			os.WriteFile(filepath.Join(s.Path(), filepath.Base(s.Path())), good, 0o600)
		},
		"symlink-to-valid-file": func(t *testing.T, s *store.Store, dir string) {
			other := filepath.Join(dir, "other.json")
			os.WriteFile(other, good, 0o600)
			if err := os.Symlink(other, s.Path()); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-dangling": func(t *testing.T, s *store.Store, dir string) {
			if err := os.Symlink(filepath.Join(dir, "does-not-exist"), s.Path()); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-to-dev-zero": func(t *testing.T, s *store.Store, dir string) {
			if err := os.Symlink("/dev/zero", s.Path()); err != nil {
				t.Fatal(err)
			}
		},
		"symlink-to-self": func(t *testing.T, s *store.Store, dir string) {
			if err := os.Symlink(s.Path(), s.Path()); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, s *store.Store, dir string) {
			if err := syscall.Mkfifo(s.Path(), 0o600); err != nil {
				t.Skipf("mkfifo: %v", err)
			}
		},
		"unreadable-file": func(t *testing.T, s *store.Store, dir string) {
			os.WriteFile(s.Path(), good, 0o000)
		},
	}
	for name, f := range mk {
		t.Run(name, func(t *testing.T) {
			s, dir := openIn(t)
			f(t, s, dir)
			done := make(chan struct{})
			var found bool
			var err error
			go func() { defer close(done); _, found, err = s.Load() }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				if fh, e := os.OpenFile(s.Path(), os.O_RDWR, 0); e == nil {
					fh.Close() // release a reader stuck on a FIFO
				}
				t.Fatal("Load blocks forever on a special file: a planted FIFO would stop the proxy from booting")
			}
			if err == nil {
				t.Fatalf("Load returned found=%v with no error for a non-regular file: it must be an error (never 'no policy', never loaded)", found)
			}
			if name != "unreadable-file" && !errors.Is(err, store.ErrCorrupt) {
				t.Errorf("err = %v; doc: 'not a regular file' wraps ErrCorrupt", err)
			}
		})
	}
}

func TestLargeSparseFileIsRejectedWithoutReadingItAll(t *testing.T) {
	s, _ := openIn(t)
	f, err := os.Create(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(2 << 30); err != nil { // 2 GiB of zeros, no disk used
		t.Skipf("sparse files unsupported: %v", err)
	}
	f.Close()
	start := time.Now()
	_, _, err = s.Load()
	if !errors.Is(err, store.ErrCorrupt) {
		t.Fatalf("2 GiB file: err = %v, want ErrCorrupt (too large)", err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("rejecting a 2 GiB file took %v: it was read, not size-checked", d)
	}
}

func TestSaveWriteFailuresKeepOldPolicy(t *testing.T) {
	good := envOf([]byte(`{"v":1}`), 2)
	t.Run("read-only-dir", func(t *testing.T) {
		s, dir := openIn(t)
		if err := s.Save(good); err != nil {
			t.Fatal(err)
		}
		os.Chmod(dir, 0o500)
		defer os.Chmod(dir, 0o700)
		if err := s.Save(envOf([]byte(`{"v":2}`), 2)); err == nil {
			t.Fatal("Save into a read-only dir returned nil")
		}
		os.Chmod(dir, 0o700)
		out, found, err := s.Load()
		if err != nil || !found || !reflect.DeepEqual(out, good) {
			t.Fatalf("old policy lost: %v %v", found, err)
		}
		if n := len(entries(t, dir)); n != 1 {
			t.Fatalf("temp files left: %v", entries(t, dir))
		}
	})
	t.Run("dir-removed", func(t *testing.T) {
		s, dir := openIn(t)
		os.RemoveAll(dir)
		if err := s.Save(good); err == nil {
			if _, found, _ := s.Load(); !found {
				t.Fatal("Save returned nil but nothing is stored")
			}
		}
	})
	t.Run("target-is-a-directory", func(t *testing.T) {
		s, dir := openIn(t)
		os.Mkdir(s.Path(), 0o700)
		os.WriteFile(filepath.Join(s.Path(), "keep"), []byte("x"), 0o600)
		if err := s.Save(good); err == nil {
			t.Fatal("Save over a non-empty directory returned nil")
		}
		if n := len(entries(t, dir)); n != 1 {
			t.Fatalf("temp file left after failed rename: %v", entries(t, dir))
		}
	})
	t.Run("symlink-target-not-written-through", func(t *testing.T) {
		s, dir := openIn(t)
		victim := filepath.Join(filepath.Dir(dir), "victim.txt")
		os.WriteFile(victim, []byte("DO NOT TOUCH"), 0o600)
		os.Symlink(victim, s.Path())
		_ = s.Save(good)
		if b, _ := os.ReadFile(victim); string(b) != "DO NOT TOUCH" {
			t.Fatalf("Save wrote through a symlink and overwrote %q", b)
		}
		out, found, err := s.Load()
		if err != nil || !found || !reflect.DeepEqual(out, good) {
			t.Fatalf("after Save over a symlink: found=%v err=%v", found, err)
		}
		if info, _ := os.Lstat(s.Path()); info.Mode()&os.ModeSymlink != 0 {
			t.Fatal("the symlink is still in place after Save")
		}
	})
}

// Readers during writes see the old or the new envelope, whole; never a mix, never corrupt.
func TestConcurrentSaveAndLoadNeverTorn(t *testing.T) {
	s, dir := openIn(t)
	const writers, rounds = 6, 40
	var variants []wire.Envelope
	for w := 0; w < writers; w++ {
		variants = append(variants, envOf(bytes.Repeat([]byte{byte('a' + w)}, 40000+w*997), 2+w%3))
	}
	if err := s.Save(variants[0]); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var rwg sync.WaitGroup
	second := mustOpen(t, dir) // opened once, before any write: Open removes crash leftovers
	for r := 0; r < 4; r++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// readers use their own handle too, as a second process would
				for _, st := range []*store.Store{s, second} {
					out, found, err := st.Load()
					if err != nil || !found {
						t.Errorf("Load during writes: found=%v err=%v", found, err)
						return
					}
					ok := false
					for _, v := range variants {
						if reflect.DeepEqual(out, v) {
							ok = true
						}
					}
					if !ok {
						t.Errorf("Load returned an envelope nobody saved (torn write)")
						return
					}
				}
			}
		}()
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				if err := s.Save(variants[w]); err != nil {
					t.Errorf("Save: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	rwg.Wait()
	if n := len(entries(t, dir)); n != 1 {
		t.Fatalf("temp files left after concurrent saves: %v", entries(t, dir))
	}
}

// Learn the real temp-file name by watching a Save, then plant leftovers like it.
func TestCrashLeftoversAreRemovedAndNeverLoaded(t *testing.T) {
	s, dir := openIn(t)
	base := filepath.Base(s.Path())
	old := envOf([]byte(`{"v":"old"}`), 2)
	if err := s.Save(old); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 400; i++ {
			_ = s.Save(envOf(bytes.Repeat([]byte("p"), 200<<10), 2))
		}
	}()
loop:
	for {
		select {
		case <-done:
			break loop
		default:
			ents, _ := os.ReadDir(dir)
			for _, e := range ents {
				if e.Name() != base {
					seen[e.Name()] = true
				}
			}
		}
	}
	if len(seen) == 0 {
		t.Skip("could not observe the temp file name during Save; cannot plant a realistic leftover")
	}
	// Reset to the old policy.
	if err := s.Save(old); err != nil {
		t.Fatal(err)
	}
	newer, _ := json.Marshal(envOf([]byte(`{"v":"newer-never-applied"}`), 2))
	var planted []string
	i := 0
	for name := range seen {
		for _, content := range [][]byte{newer, newer[:len(newer)/2], {}, []byte("garbage")} {
			n := fmt.Sprintf("%s-crash%d", name, i)
			i++
			if err := os.WriteFile(filepath.Join(dir, n), content, 0o600); err != nil {
				t.Fatal(err)
			}
			planted = append(planted, n)
		}
		// also the observed name itself
		os.WriteFile(filepath.Join(dir, name), newer, 0o600)
		planted = append(planted, name)
	}
	s2, err := store.Open(dir)
	if err != nil {
		t.Fatalf("Open with leftovers: %v", err)
	}
	for _, n := range planted {
		if _, err := os.Lstat(filepath.Join(dir, n)); err == nil {
			t.Errorf("leftover %q survived Open (doc: removes temp files left by a crash)", n)
		}
	}
	out, found, err := s2.Load()
	if err != nil || !found || !reflect.DeepEqual(out, old) {
		t.Fatalf("after leftovers the stored policy is %v/%v (a never-applied newer policy must not be picked up)", found, err)
	}
	if got := entries(t, dir); len(got) != 1 || got[0] != base {
		t.Fatalf("data dir after Open: %v", got)
	}
}

func TestOpenKeepsUnrelatedFilesAndTheRealPolicy(t *testing.T) {
	s, dir := openIn(t)
	env := envOf([]byte(`{"v":1}`), 2)
	if err := s.Save(env); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, "highwater"), []byte("2026-11-05T12:00:00Z"), 0o600)
	os.WriteFile(filepath.Join(dir, "apply.log"), []byte("x"), 0o600)
	s2, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if out, found, err := s2.Load(); err != nil || !found || !reflect.DeepEqual(out, env) {
		t.Fatalf("policy lost by Open: %v %v", found, err)
	}
	for _, f := range []string{"highwater", "apply.log"} {
		if b, err := os.ReadFile(filepath.Join(dir, f)); err != nil || len(b) == 0 {
			t.Errorf("Open removed or emptied the unrelated file %q (the high-water mark and the apply log share this directory)", f)
		}
	}
}

func FuzzLoad(f *testing.F) {
	good, _ := json.Marshal(envOf([]byte(`{"v":1}`), 2))
	f.Add(good)
	f.Add([]byte(`{"payloadType":"application/vnd.kairan.policy+json","payload":"eA==","signatures":[]}`))
	f.Add([]byte("{"))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := filepath.Join(t.TempDir(), "d")
		s, err := store.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(s.Path(), data, 0o600)
		env, found, err := s.Load()
		if err != nil {
			if !errors.Is(err, store.ErrCorrupt) {
				t.Fatalf("content error is not ErrCorrupt: %v", err)
			}
			return
		}
		if !found {
			t.Fatal("a file exists but found=false with nil error")
		}
		if verr := env.ValidateShape(); verr != nil {
			t.Fatalf("Load returned an envelope that fails ValidateShape: %v", verr)
		}
		// whatever loads must re-save byte-identically in meaning
		if err := s.Save(env); err != nil {
			t.Fatalf("Load result cannot be saved again: %v", err)
		}
		again, _, err := s.Load()
		if err != nil || !reflect.DeepEqual(again, env) {
			t.Fatalf("second round trip differs: %v", err)
		}
	})
}
