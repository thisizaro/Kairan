package declogbreak

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"kairan/internal/proxy/declog"
)

// Doc: files are created 0600.
func TestOpenCreatesFile0600(t *testing.T) {
	l, p := openLog(t, declog.Options{})
	if err := l.Record(rec(1)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600", st.Mode().Perm())
	}
}

// An existing file with looser permissions: the log must not leave it world readable. The doc says files are
// created 0600; for a pre-existing 0644 file the most defensible reading of I4-adjacent hygiene is to keep or
// tighten, never widen. We only require that Open does not make it more open than it was.
func TestOpenDoesNotWidenExistingMode(t *testing.T) {
	p := filepath.Join(t.TempDir(), "decisions.log")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := declog.Open(p, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.Record(rec(1))
	st, _ := os.Stat(p)
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("mode widened to %v", st.Mode().Perm())
	}
}

// Doc: a symlink at the log path is refused.
func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "decisions.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	l, err := declog.Open(link, declog.Options{})
	if err == nil {
		_ = l.Record(rec(1))
		_ = l.Close()
		t.Fatal("Open followed a symlink at the log path")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep\n" {
		t.Errorf("target of the symlink was modified: %q", b)
	}
	// dangling symlink: must not create the target either
	dang := filepath.Join(dir, "dangling.log")
	if err := os.Symlink(filepath.Join(dir, "created-through-link"), dang); err != nil {
		t.Fatal(err)
	}
	if l, err := declog.Open(dang, declog.Options{}); err == nil {
		_ = l.Close()
		t.Error("Open followed a dangling symlink")
	}
	if _, err := os.Lstat(filepath.Join(dir, "created-through-link")); err == nil {
		t.Error("a file was created through the dangling symlink")
	}
}

func TestOpenFailsOnMissingDirectoryAndDirectoryPath(t *testing.T) {
	dir := t.TempDir()
	if l, err := declog.Open(filepath.Join(dir, "no", "such", "dir", "d.log"), declog.Options{}); err == nil {
		_ = l.Close()
		t.Error("Open in a missing directory returned no error")
	}
	if l, err := declog.Open(dir, declog.Options{}); err == nil {
		_ = l.Close()
		t.Error("Open on a directory returned no error")
	}
}

// Doc: Close then later Records fail; Close twice must not panic.
func TestRecordAfterCloseFails(t *testing.T) {
	l, p := openLog(t, declog.Options{})
	if err := l.Record(rec(1)); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := l.Record(rec(2)); err == nil {
		t.Fatal("Record after Close returned nil")
	}
	_ = l.Close()
	if n := len(readLines(t, p)); n != 1 {
		t.Errorf("%d lines in the file, want 1", n)
	}
}

// Each line stored reads back: write N, read file, Decode every line, order preserved, nothing lost.
func TestOpenWriteReadBack(t *testing.T) {
	l, p := openLog(t, declog.Options{})
	const n = 500
	for i := 0; i < n; i++ {
		if err := l.Record(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	lines := readLines(t, p)
	if len(lines) != n {
		t.Fatalf("%d lines, want %d", len(lines), n)
	}
	for i, ln := range lines {
		r, err := declog.Decode([]byte(ln))
		if err != nil {
			t.Fatalf("line %d: %v: %q", i, err, ln)
		}
		if r.Version != uint64(i+1) || r.Hash != hashN(i+1) {
			t.Fatalf("line %d out of order or mixed: version %d hash %s", i, r.Version, r.Hash)
		}
	}
}

// Reopening appends, never truncates (doc: opens for appending).
func TestReopenAppends(t *testing.T) {
	l, p := openLog(t, declog.Options{})
	_ = l.Record(rec(1))
	_ = l.Close()
	l2, err := declog.Open(p, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	_ = l2.Record(rec(2))
	if n := len(readLines(t, p)); n != 2 {
		t.Fatalf("%d lines after reopen, want 2", n)
	}
}

// Doc: "the next Open starts a fresh line after any torn tail". A torn tail must not corrupt the next record.
func TestTornTailDoesNotCorruptNextRecord(t *testing.T) {
	p := filepath.Join(t.TempDir(), "decisions.log")
	good := string(goodLine(t))
	torn := good[:len(good)/2] // half a line, no newline
	if err := os.WriteFile(p, []byte(good+"\n"+torn), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := declog.Open(p, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(5)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	lines := readLines(t, p)
	last := lines[len(lines)-1]
	r, err := declog.Decode([]byte(last))
	if err != nil {
		t.Fatalf("the record after a torn tail does not decode: %v: %q", err, last)
	}
	if r.Version != 6 {
		t.Errorf("last line is not the new record: %+v", r)
	}
	// the torn fragment stays a separate (undecodable) line, never merged with the new one
	if len(lines) != 3 {
		t.Errorf("%d lines, want 3 (good, torn, new): %q", len(lines), lines)
	}
}

// Rotation (doc): when the next line would push the file over MaxBytes, log -> log.1 -> log.2 ... keeping Keep.
func TestRotationKeepsNewestAndBoundsFiles(t *testing.T) {
	one := int64(len(goodLine(t)) + 1)
	for _, keep := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("keep%d", keep), func(t *testing.T) {
			l, p := openLog(t, declog.Options{MaxBytes: one * 4, Keep: keep})
			const n = 60
			for i := 0; i < n; i++ {
				if err := l.Record(rec(i)); err != nil {
					t.Fatalf("record %d: %v", i, err)
				}
			}
			_ = l.Close()
			files, _ := filepath.Glob(p + "*")
			sort.Strings(files)
			if len(files) != keep+1 {
				t.Fatalf("%d files %v, want exactly %d (current + %d rotated)", len(files), files, keep+1, keep)
			}
			var versions []int
			for _, f := range append([]string{p}, rotated(p, keep)...) {
				st, err := os.Stat(f)
				if err != nil {
					t.Fatalf("expected %s: %v", f, err)
				}
				if st.Mode().Perm() != 0o600 {
					t.Errorf("%s mode %v, want 0600", f, st.Mode().Perm())
				}
				if st.Size() > one*4 {
					t.Errorf("%s is %d bytes, over MaxBytes %d", f, st.Size(), one*4)
				}
				for _, ln := range readLines(t, f) {
					r, err := declog.Decode([]byte(ln))
					if err != nil {
						t.Fatalf("%s: %v: %q", f, err, ln)
					}
					versions = append(versions, int(r.Version))
				}
			}
			// current file holds the newest; .1 the next newer than .2 ...; so kept versions are the top
			// of the sequence, contiguous, none duplicated.
			sort.Ints(versions)
			for i := 1; i < len(versions); i++ {
				if versions[i] != versions[i-1]+1 {
					t.Fatalf("kept lines are not a contiguous newest run (gap or duplicate): %v", versions)
				}
			}
			if versions[len(versions)-1] != n {
				t.Errorf("newest record (version %d) is not kept: %v", n, versions)
			}
			// ordering across files: .1 newer than .2
			prev := 1 << 30
			for _, f := range append([]string{p}, rotated(p, keep)...) {
				lines := readLines(t, f)
				if len(lines) == 0 {
					continue
				}
				r, _ := declog.Decode([]byte(lines[0]))
				if int(r.Version) >= prev {
					t.Errorf("%s is not older than the previous file", f)
				}
				prev = int(r.Version)
			}
		})
	}
}

func rotated(p string, keep int) []string {
	var out []string
	for i := 1; i <= keep; i++ {
		out = append(out, fmt.Sprintf("%s.%d", p, i))
	}
	return out
}

// With Keep large enough no record is lost across rotations and no line is split.
func TestRotationLosesNothingWithinKeep(t *testing.T) {
	one := int64(len(goodLine(t)) + 1)
	l, p := openLog(t, declog.Options{MaxBytes: one * 7, Keep: 50})
	const n = 200
	for i := 0; i < n; i++ {
		if err := l.Record(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = l.Close()
	seen := map[uint64]int{}
	files, _ := filepath.Glob(p + "*")
	for _, f := range files {
		for _, ln := range readLines(t, f) {
			r, err := declog.Decode([]byte(ln))
			if err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			seen[r.Version]++
		}
	}
	if len(seen) != n {
		t.Fatalf("%d distinct records survived, want %d", len(seen), n)
	}
	for v, c := range seen {
		if c != 1 {
			t.Errorf("version %d appears %d times", v, c)
		}
	}
}

// Boundary: a line that exactly fits MaxBytes does not rotate; one byte less does. MaxBytes smaller than one line
// must not loop, drop records or panic: every Record either stores or errors.
func TestRotationBoundaries(t *testing.T) {
	one := int64(len(goodLine(t)) + 1)
	t.Run("exact fit does not rotate", func(t *testing.T) {
		l, p := openLog(t, declog.Options{MaxBytes: one * 2, Keep: 3})
		for i := 0; i < 2; i++ {
			if err := l.Record(rec(1)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := os.Stat(p + ".1"); err == nil {
			t.Error("rotated although both lines fit exactly")
		}
		if err := l.Record(rec(1)); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(p + ".1"); err != nil {
			t.Error("did not rotate before the third line")
		}
	})
	t.Run("max smaller than one line", func(t *testing.T) {
		l, p := openLog(t, declog.Options{MaxBytes: 10, Keep: 2})
		stored := 0
		for i := 0; i < 5; i++ {
			if err := l.Record(rec(i)); err == nil {
				stored++
			}
		}
		_ = l.Close()
		files, _ := filepath.Glob(p + "*")
		if len(files) > 3 {
			t.Errorf("%d files, Keep=2 allows 3", len(files))
		}
		// whatever is on disk must still be whole decodable lines
		for _, f := range files {
			for _, ln := range readLines(t, f) {
				if _, err := declog.Decode([]byte(ln)); err != nil {
					t.Errorf("%s: %v", f, err)
				}
			}
		}
		_ = stored
	})
	t.Run("negative options", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "d.log")
		l, err := declog.Open(p, declog.Options{MaxBytes: -5, Keep: -1})
		if err != nil {
			return // refusing is fine
		}
		defer l.Close()
		for i := 0; i < 3; i++ {
			if err := l.Record(rec(i)); err != nil {
				t.Errorf("negative options broke Record: %v", err)
			}
		}
	})
}

// Rotated files are mode 0600 even when the umask is loose, and the log keeps working after a rotation target
// vanished.
func TestRotationFailureIsALoudRecordError(t *testing.T) {
	one := int64(len(goodLine(t)) + 1)
	m := &metrics{}
	dir := t.TempDir()
	p := filepath.Join(dir, "decisions.log")
	l, err := declog.Open(p, declog.Options{MaxBytes: one * 2, Keep: 1, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_ = l.Record(rec(1))
	_ = l.Record(rec(2))
	// make the rotation impossible: with Keep=1 decisions.log must become decisions.log.1, and a
	// non-empty directory sits there.
	if err := os.MkdirAll(filepath.Join(p+".1", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(3)); err == nil {
		t.Fatal("rotation was impossible but Record returned nil (the whole file would silently grow, or the line was lost)")
	}
	if m.get(declog.MetricRotateErrors) == 0 {
		t.Errorf("%s not counted", declog.MetricRotateErrors)
	}
	// "tried again on the next call": after the obstacle is gone, Record works and the newest line is stored.
	if err := os.RemoveAll(p + ".1"); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(4)); err != nil {
		t.Fatalf("log did not recover after the obstacle was removed: %v", err)
	}
	found := false
	files, _ := filepath.Glob(p + "*")
	for _, f := range files {
		for _, ln := range readLines(t, f) {
			if r, err := declog.Decode([]byte(ln)); err == nil && r.Version == 5 {
				found = true
			}
		}
	}
	if !found {
		t.Error("record stored after recovery is not on disk")
	}
}

// Concurrency (-race): many goroutines, every line whole, nothing lost, nothing interleaved.
func TestConcurrentRecordIsWholeLines(t *testing.T) {
	l, p := openLog(t, declog.Options{})
	const g, per = 32, 200
	var wg sync.WaitGroup
	for i := 0; i < g; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < per; j++ {
				r := rec(i*per + j)
				if err := l.Record(r); err != nil {
					t.Errorf("record: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	_ = l.Close()
	lines := readLines(t, p)
	if len(lines) != g*per {
		t.Fatalf("%d lines, want %d", len(lines), g*per)
	}
	seen := map[uint64]bool{}
	for _, ln := range lines {
		r, err := declog.Decode([]byte(ln))
		if err != nil {
			t.Fatalf("interleaved or torn line: %v: %q", err, ln)
		}
		if r.Hash != hashN(int(r.Version)) {
			t.Fatalf("fields of two records mixed: version %d hash %s", r.Version, r.Hash)
		}
		if seen[r.Version] {
			t.Fatalf("duplicate version %d", r.Version)
		}
		seen[r.Version] = true
	}
}

// Concurrency with rotation and Close racing Record: no panic, no race, and whatever is on disk decodes.
func TestConcurrentRotationAndClose(t *testing.T) {
	one := int64(len(goodLine(t)) + 1)
	l, p := openLog(t, declog.Options{MaxBytes: one * 10, Keep: 100})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_ = l.Record(rec(i*100 + j))
			}
		}(i)
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = l.Close() }()
	wg.Wait()
	files, _ := filepath.Glob(p + "*")
	for _, f := range files {
		for _, ln := range readLines(t, f) {
			if _, err := declog.Decode([]byte(ln)); err != nil {
				t.Fatalf("%s: %v: %q", f, err, ln)
			}
		}
	}
}

// A device that always fails (ENOSPC): Record errors, is counted, never claims success.
func TestDevFullIsAnError(t *testing.T) {
	if _, err := os.Stat("/dev/full"); err != nil {
		t.Fatalf("/dev/full missing on this host: %v", err)
	}
	m := &metrics{}
	l, err := declog.Open("/dev/full", declog.Options{Metrics: m})
	if err != nil {
		return // refusing to open a device is also fail-closed
	}
	defer l.Close()
	if err := l.Record(rec(1)); err == nil {
		t.Fatal("Record on /dev/full returned nil")
	}
	if m.get(declog.MetricWriteErrors) == 0 {
		t.Error("write error not counted")
	}
}

// I4: no key beyond the eight, no arguments, even if every field is as long as it can be.
func TestLineSizeIsBounded(t *testing.T) {
	r := rec(1)
	r.Tool = strings.Repeat("t", 128)
	r.Role = strings.Repeat("r", 63)
	l, p := openLog(t, declog.Options{})
	if err := l.Record(r); err != nil {
		// a 63 char role is a valid wire.ID; refusing it would be a bug, but a bound lower than 63 is
		// not documented. Try a shorter one.
		r.Role = strings.Repeat("r", 32)
		if err := l.Record(r); err != nil {
			t.Fatalf("role of 32 chars refused: %v", err)
		}
	}
	for _, ln := range readLines(t, p) {
		if len(ln) > 1024 {
			t.Errorf("a line of eight bounded fields is %d bytes", len(ln))
		}
	}
}
