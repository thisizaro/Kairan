package cpstorebreak

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

// populated builds a state dir with one of every file kind.
func populated(t *testing.T) (root, dir string) {
	t.Helper()
	root, dir = sandbox(t)
	s := open(t, dir)
	mustPut(t, s, "bank-a", 1, `{"policy":"one"}`)
	mustPut(t, s, "bank-a", 2, `{"policy":"two"}`)
	if err := s.PutRollout(rolloutFor("bank-a", 2, 1)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(1)), t0)); err != nil {
		t.Fatal(err)
	}
	return
}

func snapshotAll(t *testing.T, dir string) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, f := range files(t, dir) {
		b, err := os.ReadFile(filepath.Join(dir, f))
		if err != nil {
			t.Fatal(err)
		}
		m[f] = string(b)
	}
	return m
}

// Doc: "Temp files left by a crash are ignored and removed on open." A temp file may hold anything,
// including a newer-looking complete file; it must never be loaded.
func TestCrashLeftoverTempFilesIgnoredAndRemoved(t *testing.T) {
	_, dir := populated(t)
	before := snapshotAll(t, dir)
	envPath := findFile(t, dir, "envelopes", "bank-a", "02.json")
	rolPath := findFile(t, dir, "rollouts", "bank-a")
	fleetPath := findFile(t, dir, "fleet", "bank-a", "p1")
	envBytes, _ := os.ReadFile(envPath)
	rolBytes, _ := os.ReadFile(rolPath)

	leftovers := []string{
		filepath.Join(dir, "envelopes", "bank-a", ".tmp-1234"),
		filepath.Join(dir, "envelopes", "bank-a", ".tmp-trunc"),
		filepath.Join(dir, "envelopes", ".tmp-top"),
		filepath.Join(dir, "rollouts", ".tmp-9999"),
		filepath.Join(dir, "fleet", "bank-a", ".tmp-7"),
	}
	// a complete, valid-looking newer envelope in a temp file (must not appear as v3)
	newer := strings.ReplaceAll(string(envBytes), "0002", "0003")
	_ = newer
	contents := []string{string(envBytes[:len(envBytes)/2]), "", string(envBytes), string(rolBytes), "\x00\x00garbage"}
	for i, p := range leftovers {
		if err := os.WriteFile(p, []byte(contents[i]), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = fleetPath
	s, err := store.OpenFiles(dir)
	if err != nil {
		t.Fatalf("OpenFiles with crash leftovers: %v", err)
	}
	for _, p := range leftovers {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("leftover %s was not removed", p)
		}
	}
	after := snapshotAll(t, dir)
	for f, c := range before {
		if after[f] != c {
			t.Errorf("real file %s changed by cleanup", f)
		}
	}
	if len(after) != len(before) {
		t.Errorf("file set changed: %d -> %d", len(before), len(after))
	}
	if _, err := s.Envelope("bank-a", 3); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a leftover temp file became version 3: %v", err)
	}
	// v3 is still publishable
	mustPut(t, s, "bank-a", 3, "three")
}

// A crash between temp write and rename leaves the old file: simulate "temp present next to final".
func TestCrashMidWriteKeepsOldContent(t *testing.T) {
	_, dir := populated(t)
	rolPath := findFile(t, dir, "rollouts", "bank-a")
	old, _ := os.ReadFile(rolPath)
	// temp holding a *different but valid* rollout (what the next write would have been)
	_, other := sandbox(t)
	so := open(t, other)
	r := rolloutFor("bank-a", 9, 2)
	r.Phase = wire.PhaseComplete
	_ = so.PutRollout(r)
	nb, _ := os.ReadFile(findFile(t, other, "rollouts", "bank-a"))
	if err := os.WriteFile(filepath.Join(filepath.Dir(rolPath), ".tmp-5551"), nb, 0o600); err != nil {
		t.Fatal(err)
	}
	s := open(t, dir)
	got, ok, err := s.Rollout("bank-a")
	if err != nil || !ok || got.Version != 2 || got.Phase != wire.PhaseCanary {
		t.Fatalf("rollout after crash = %+v ok=%v err=%v, want the old v2 canary", got, ok, err)
	}
	if cur, _ := os.ReadFile(rolPath); string(cur) != string(old) {
		t.Fatal("old rollout file modified")
	}
}

func TestCorruptFilesFailOpenNeverEmpty(t *testing.T) {
	type mutation struct {
		name string
		pick func(t *testing.T, dir string) string // file to mutate
		f    func(t *testing.T, path string)
	}
	env2 := func(t *testing.T, dir string) string { return findFile(t, dir, "envelopes", "bank-a", "02.json") }
	rol := func(t *testing.T, dir string) string { return findFile(t, dir, "rollouts", "bank-a") }
	flt := func(t *testing.T, dir string) string { return findFile(t, dir, "fleet", "bank-a", "p1") }
	write := func(content string) func(*testing.T, string) {
		return func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	truncate := func(frac int) func(*testing.T, string) {
		return func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, b[:len(b)*frac/10], 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	appendBytes := func(s string) func(*testing.T, string) {
		return func(t *testing.T, p string) {
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(p, append(b, s...), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	addField := func(t *testing.T, p string) { editJSON(t, p, func(m map[string]any) { m["debug_note"] = "hi" }) }
	var muts []mutation
	for _, k := range []struct {
		name string
		pick func(*testing.T, string) string
	}{{"envelope", env2}, {"rollout", rol}, {"fleet", flt}} {
		k := k
		muts = append(muts,
			mutation{k.name + "/empty", k.pick, write("")},
			mutation{k.name + "/null", k.pick, write("null")},
			mutation{k.name + "/array", k.pick, write("[]")},
			mutation{k.name + "/empty-object", k.pick, write("{}")},
			mutation{k.name + "/string", k.pick, write(`"x"`)},
			mutation{k.name + "/nul-bytes", k.pick, write("\x00\x00\x00\x00")},
			mutation{k.name + "/truncated-half", k.pick, truncate(5)},
			mutation{k.name + "/truncated-last-byte", k.pick, truncate(9)},
			mutation{k.name + "/trailing-garbage", k.pick, appendBytes("garbage")},
			mutation{k.name + "/trailing-second-object", k.pick, appendBytes("{}")},
			mutation{k.name + "/unknown-field", k.pick, addField},
			mutation{k.name + "/bom", k.pick, func(t *testing.T, p string) {
				b, _ := os.ReadFile(p)
				_ = os.WriteFile(p, append([]byte("\xef\xbb\xbf"), b...), 0o600)
			}},
		)
	}
	for _, m := range muts {
		t.Run(m.name, func(t *testing.T) {
			_, dir := populated(t)
			m.f(t, m.pick(t, dir))
			expectCorrupt(t, dir)
		})
	}
}

// Doc: the file must match its own name; and the hash must match the payload (M-D41).
func TestEnvelopeFilesMustMatchTheirNameAndHash(t *testing.T) {
	t.Run("renamed-to-other-version", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		if err := os.Rename(p, filepath.Join(filepath.Dir(p), "00000000000000000007.json")); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("copied-to-other-version-keeps-both", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		b, _ := os.ReadFile(p)
		if err := os.WriteFile(filepath.Join(filepath.Dir(p), "00000000000000000003.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("moved-to-other-tenant-dir", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		other := filepath.Join(dir, "envelopes", "city-b")
		if err := os.MkdirAll(other, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(p, filepath.Join(other, filepath.Base(p))); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("file-name-version-zero", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		b, _ := os.ReadFile(p)
		_ = os.WriteFile(filepath.Join(filepath.Dir(p), "00000000000000000000.json"), b, 0o600)
		expectCorrupt(t, dir)
	})
	t.Run("payload-swapped-hash-kept", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		other := findFile(t, dir, "envelopes", "bank-a", "01.json")
		var otherPayload any
		editJSON(t, other, func(m map[string]any) { otherPayload = m["envelope"].(map[string]any)["payload"] })
		editJSON(t, p, func(m map[string]any) { m["envelope"].(map[string]any)["payload"] = otherPayload })
		expectCorrupt(t, dir)
	})
	t.Run("hash-field-flipped", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		want := string(payloadHash([]byte(`{"policy":"two"}`)))
		changed := false
		editJSON(t, p, func(m map[string]any) {
			changed = walkStrings(m, func(k, s string) (string, bool) {
				if s == want {
					return string(hx("not the payload")), true
				}
				return "", false
			})
		})
		if !changed {
			t.Fatal("the file does not store the hash (M-D41 says the store checks hash = SHA-256(payload))")
		}
		expectCorrupt(t, dir)
	})
	t.Run("payload-edited", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) {
			m["envelope"].(map[string]any)["payload"] = "eyJwb2xpY3kiOiJ0aHIifQ==" // {"policy":"thr"}
		})
		expectCorrupt(t, dir)
	})
	t.Run("inner-version-differs-from-name", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) { m["version"] = 3 })
		expectCorrupt(t, dir)
	})
	t.Run("inner-tenant-differs-from-dir", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) { m["tenant"] = "city-b" })
		expectCorrupt(t, dir)
	})
	t.Run("inner-tenant-traversal", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) { m["tenant"] = "../../x" })
		expectCorrupt(t, dir)
	})
	t.Run("signature-shape-broken", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) { m["envelope"].(map[string]any)["signatures"] = []any{} })
		expectCorrupt(t, dir)
	})
	t.Run("payload-type-changed", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "envelopes", "bank-a", "02.json")
		editJSON(t, p, func(m map[string]any) { m["envelope"].(map[string]any)["payloadType"] = "text/html" })
		expectCorrupt(t, dir)
	})
}

func TestFleetFileMustMatchItsName(t *testing.T) {
	t.Run("renamed-proxy", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		if err := os.Rename(p, filepath.Join(filepath.Dir(p), "p2.json")); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("moved-to-other-tenant", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		os.MkdirAll(filepath.Join(dir, "fleet", "city-b"), 0o700)
		if err := os.Rename(p, filepath.Join(dir, "fleet", "city-b", "p1.json")); err != nil {
			t.Fatal(err)
		}
		expectCorrupt(t, dir)
	})
	t.Run("inner-report-proxy-differs", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) { m["report"].(map[string]any)["proxy_id"] = "p2" })
		expectCorrupt(t, dir)
	})
	t.Run("inner-report-tenant-differs", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) { m["report"].(map[string]any)["tenant"] = "city-b" })
		expectCorrupt(t, dir)
	})
	t.Run("invalid-state-inside", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) { m["report"].(map[string]any)["state"] = "pwned" })
		expectCorrupt(t, dir)
	})
	t.Run("invalid-group-inside", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) { m["group"] = "../x" })
		expectCorrupt(t, dir)
	})
	t.Run("timeline-entry-of-another-proxy", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) {
			m["timeline"].([]any)[0].(map[string]any)["proxy_id"] = "p9"
		})
		expectCorrupt(t, dir)
	})
	t.Run("timeline-last-before-first", func(t *testing.T) {
		_, dir := populated(t)
		p := findFile(t, dir, "fleet", "bank-a", "p1")
		editJSON(t, p, func(m map[string]any) {
			e := m["timeline"].([]any)[0].(map[string]any)
			e["last_seen_unix_ms"] = float64(1)
		})
		expectCorrupt(t, dir)
	})
	t.Run("hostile-names", func(t *testing.T) {
		for _, name := range []string{"P1.json", "..json", "a b.json", "-x.json", ".hidden.json"} {
			_, dir := populated(t)
			p := findFile(t, dir, "fleet", "bank-a", "p1")
			b, _ := os.ReadFile(p)
			if err := os.WriteFile(filepath.Join(filepath.Dir(p), name), b, 0o600); err != nil {
				t.Fatal(err)
			}
			func() {
				done := make(chan error, 1)
				go func() { _, err := store.OpenFiles(dir); done <- err }()
				select {
				case err := <-done:
					// Either refusing (ErrCorrupt) or ignoring is safe; loading it as a proxy is not.
					if err != nil && !errors.Is(err, store.ErrCorrupt) {
						t.Errorf("%q: unexpected error %v", name, err)
					}
					if err == nil {
						s, _ := store.OpenFiles(dir)
						f, _ := s.Fleet("bank-a")
						if len(f) != 1 {
							t.Errorf("%q was loaded as an extra proxy: %d rows", name, len(f))
						}
					}
				case <-time.After(10 * time.Second):
					t.Errorf("%q: OpenFiles hung", name)
				}
			}()
		}
	})
}

// Unknown entries in the state dir: refusing or ignoring is fine, but never a panic, a hang, or
// lost data.
func TestUnexpectedEntriesDoNotCrashOrHide(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T, dir string){
		"stray-text-file": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "envelopes", "bank-a", "README"), []byte("hi"), 0o600)
		},
		"bad-tenant-dir": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "envelopes", "Bad Tenant"), 0o700)
			os.WriteFile(filepath.Join(dir, "envelopes", "Bad Tenant", "00000000000000000001.json"), []byte("{}"), 0o600)
		},
		"short-version-name": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "envelopes", "bank-a", "3.json"), []byte("{}"), 0o600)
		},
		"huge-version-name": func(t *testing.T, dir string) {
			os.WriteFile(filepath.Join(dir, "envelopes", "bank-a", "99999999999999999999.json"), []byte("{}"), 0o600)
		},
		"dir-named-like-envelope": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "envelopes", "bank-a", "00000000000000000009.json"), 0o700)
		},
		"dir-named-like-rollout": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "rollouts", "city-b.json"), 0o700)
		},
		"rollout-in-subdir": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "rollouts", "sub"), 0o700)
			os.WriteFile(filepath.Join(dir, "rollouts", "sub", "x.json"), []byte("{}"), 0o600)
		},
		"unknown-top-level-dir": func(t *testing.T, dir string) {
			os.MkdirAll(filepath.Join(dir, "other"), 0o700)
			os.WriteFile(filepath.Join(dir, "other", "x"), []byte("x"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, dir := populated(t)
			mk(t, dir)
			done := make(chan struct{})
			var s store.Store
			var err error
			go func() { defer close(done); s, err = store.OpenFiles(dir) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("OpenFiles hung")
			}
			if err != nil {
				if !errors.Is(err, store.ErrCorrupt) {
					t.Fatalf("err = %v, want nil or ErrCorrupt", err)
				}
				return
			}
			if e, err := s.Envelope("bank-a", 2); err != nil || string(e.Payload) != `{"policy":"two"}` {
				t.Fatalf("real data lost beside a stray entry: %v", err)
			}
		})
	}
}

// A FIFO (or other non-regular file) with a state-file name must not hang the CP at boot.
func TestNonRegularStateFileDoesNotHang(t *testing.T) {
	_, dir := populated(t)
	fifo := filepath.Join(dir, "envelopes", "bank-a", "00000000000000000009.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan error, 1)
	go func() { _, err := store.OpenFiles(dir); done <- err }()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, store.ErrCorrupt) {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		// unblock the stuck reader so the test binary can exit cleanly
		if f, err := os.OpenFile(fifo, os.O_RDWR, 0); err == nil {
			f.Close()
		}
		t.Fatal("OpenFiles blocks forever on a FIFO named like an envelope: a planted special file stops the control plane from starting")
	}
}

// Symlinks: whatever Open decides, writes must never go through a link to a file outside the state dir.
func TestSymlinkedStateFileIsNotWrittenThrough(t *testing.T) {
	root, dir := populated(t)
	victim := filepath.Join(root, "victim.txt")
	if err := os.WriteFile(victim, []byte("DO NOT TOUCH"), 0o600); err != nil {
		t.Fatal(err)
	}
	rolPath := findFile(t, dir, "rollouts", "bank-a")
	fleetPath := findFile(t, dir, "fleet", "bank-a", "p1")
	for _, p := range []string{rolPath, fleetPath} {
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(victim, p); err != nil {
			t.Fatal(err)
		}
	}
	s, err := store.OpenFiles(dir)
	if err != nil {
		return // refusing links is a valid answer
	}
	_ = s.PutRollout(rolloutFor("bank-a", 5, 2))
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withVersion(4)), t0.Add(time.Hour)))
	b, _ := os.ReadFile(victim)
	if string(b) != "DO NOT TOUCH" {
		t.Fatalf("the store wrote through a symlink and overwrote a file outside the state dir: %q", b)
	}
}

// Reading through a symlink to a valid file outside the state dir must not import foreign state.
func TestSymlinkedDirectoryNotFollowedOutOfStateDir(t *testing.T) {
	root, dir := populated(t)
	// foreign store with tenant "evil"
	foreign := filepath.Join(root, "foreign")
	fs := open(t, foreign)
	mustPut(t, fs, "evil", 1, "foreign data")
	if err := os.Symlink(filepath.Join(foreign, "envelopes", "evil"), filepath.Join(dir, "envelopes", "evil")); err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenFiles(dir)
	if err != nil {
		return
	}
	if e, err := s.Envelope("evil", 1); err == nil {
		t.Fatalf("store served an envelope from outside its directory via a symlink: %q", e.Payload)
	}
}

func TestOpenFilesOnBadPaths(t *testing.T) {
	root, _ := sandbox(t)
	file := filepath.Join(root, "afile")
	os.WriteFile(file, []byte("x"), 0o600)
	if _, err := store.OpenFiles(file); err == nil {
		t.Fatal("OpenFiles on a regular file succeeded")
	}
	if _, err := store.OpenFiles(filepath.Join(file, "sub")); err == nil {
		t.Fatal("OpenFiles under a regular file succeeded")
	}
	ro := filepath.Join(root, "ro")
	os.MkdirAll(ro, 0o500)
	defer os.Chmod(ro, 0o700)
	if _, err := store.OpenFiles(filepath.Join(ro, "state")); err == nil {
		t.Fatal("OpenFiles in a read-only parent succeeded")
	}
	// opening creates nested dirs and is idempotent
	deep := filepath.Join(root, "a", "b", "c")
	for i := 0; i < 2; i++ {
		if _, err := store.OpenFiles(deep); err != nil {
			t.Fatalf("OpenFiles(%s) round %d: %v", deep, i, err)
		}
	}
}

// Failure to write must be reported for rollout and status as well, and not corrupt what is there.
func TestWriteFailureKeepsOldRolloutAndStatus(t *testing.T) {
	_, dir := populated(t)
	s := open(t, dir)
	ro := filepath.Join(dir, "rollouts")
	fl := filepath.Join(dir, "fleet", "bank-a")
	os.Chmod(ro, 0o500)
	os.Chmod(fl, 0o500)
	defer os.Chmod(ro, 0o700)
	defer os.Chmod(fl, 0o700)
	if err := s.PutRollout(rolloutFor("bank-a", 9, 2)); err == nil {
		t.Fatal("PutRollout on read-only dir returned nil")
	}
	got, _, _ := s.Rollout("bank-a")
	if got.Version != 2 {
		t.Fatalf("failed PutRollout changed the visible rollout to %+v", got)
	}
	// important change must fail loudly, not be swallowed in the coalescing buffer
	err := s.RecordStatus(last("main", rep("bank-a", "p1", withVersion(5), withAnchor(9)), t0.Add(time.Minute)))
	if err == nil {
		t.Fatal("RecordStatus of a version change returned nil although the disk write cannot work (silent loss on crash)")
	}
	os.Chmod(ro, 0o700)
	os.Chmod(fl, 0o700)
	s2 := open(t, dir)
	f, _ := s2.Fleet("bank-a")
	if len(f) != 1 || f[0].Report.AppliedVersion != 1 {
		t.Fatalf("old status lost: %+v", f)
	}
	r2, _, _ := s2.Rollout("bank-a")
	if r2.Version != 2 {
		t.Fatalf("old rollout lost: %+v", r2)
	}
}
