package agent

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/clock"
)

// Q-D10: caller-supplied times may carry a monotonic reading; the result must not.
func TestEffectiveNowStripsMonotonicOnEveryPath(t *testing.T) {
	withMono := time.Now() // carries m=
	if !strings.Contains(withMono.String(), "m=") {
		t.Fatal("test precondition: time.Now has no monotonic reading")
	}
	f := clock.NewFake(t0)
	tests := []struct {
		name string
		a    Anchor
		hw   time.Time
	}{
		{"wall wins", Anchor{}, time.Time{}},
		{"high-water wins", Anchor{}, withMono.Add(24 * time.Hour)},
		{"anchor wins", Anchor{Wall: withMono.Add(48 * time.Hour), Mono: 0}, time.Time{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveNow(f, tc.a, tc.hw)
			if s := got.String(); strings.Contains(s, "m=") {
				t.Fatalf("result carries a monotonic reading: %s", s)
			}
			if got.Location() != time.UTC {
				t.Fatalf("result not UTC: %v", got.Location())
			}
		})
	}
}

// Q-D11: a second guard with a lower mark must not lower a higher file.
func TestSaveNeverLowersHigherFileWrittenByAnotherGuard(t *testing.T) {
	dir := t.TempDir()
	hi := clock.NewFake(t0.Add(10 * time.Hour))
	lo := clock.NewFake(t0)
	g1 := open(t, hi, dir)
	g2 := open(t, lo, dir) // opened before g1 saved: knows nothing of the higher mark
	if err := g1.Save(); err != nil {
		t.Fatal(err)
	}
	want := readFile(t, g1.Path())
	if err := g2.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, g2.Path()); got != want {
		t.Fatalf("file lowered: %q -> %q", want, got)
	}
	// A lower file is still raised.
	lo.Advance(20 * time.Hour)
	g2.Now()
	if err := g2.Save(); err != nil {
		t.Fatal(err)
	}
	if !fileHas(g2.Path(), t0.Add(20*time.Hour)) {
		t.Fatalf("file not raised: %q", readFile(t, g2.Path()))
	}
}

func TestConcurrentGuardsOnOneDirKeepMax(t *testing.T) {
	dir := t.TempDir()
	const n = 8
	done := make(chan struct{})
	for i := 0; i < n; i++ {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			f := clock.NewFake(t0.Add(time.Duration(i) * time.Hour))
			g, err := OpenClockGuard(f, dir)
			if err != nil {
				t.Error(err)
				return
			}
			for j := 0; j < 20; j++ {
				g.Save()
			}
		}(i)
	}
	for i := 0; i < n; i++ {
		<-done
	}
	p := filepath.Join(dir, HighWaterFile)
	if !fileHas(p, t0.Add((n-1)*time.Hour)) {
		t.Fatalf("max not kept: %q", readFile(t, p))
	}
}

// Q-D12: a FIFO at the high-water path must not block Open.
func TestOpenRefusesFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, HighWaterFile), 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	type res struct {
		g   *ClockGuard
		err error
	}
	ch := make(chan res, 1)
	go func() {
		g, err := OpenClockGuard(clock.NewFake(t0), dir)
		ch <- res{g, err}
	}()
	select {
	case r := <-ch:
		if r.g == nil || !errors.Is(r.err, ErrHighWaterCorrupt) {
			t.Fatalf("guard=%v err=%v, want usable guard and ErrHighWaterCorrupt", r.g != nil, r.err)
		}
		if err := r.g.Save(); err != nil { // repairs: rename replaces the FIFO
			t.Fatalf("save over fifo: %v", err)
		}
		if !fileHas(r.g.Path(), t0) {
			t.Fatalf("not repaired: %q", readFile(t, r.g.Path()))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("OpenClockGuard blocked on a FIFO")
	}
}

func TestOpenRefusesDirectoryAndSymlinkAtPath(t *testing.T) {
	for _, kind := range []string{"dir", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, HighWaterFile)
			if kind == "dir" {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			} else {
				target := filepath.Join(dir, "elsewhere")
				if err := os.WriteFile(target, formatHighWater(t0), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatalf("symlink: %v", err)
				}
			}
			g, err := OpenClockGuard(clock.NewFake(t0.Add(-time.Hour)), dir)
			if g == nil || !errors.Is(err, ErrHighWaterCorrupt) {
				t.Fatalf("guard=%v err=%v, want usable guard and ErrHighWaterCorrupt", g != nil, err)
			}
			if !g.Now().Equal(t0.Add(-time.Hour)) {
				t.Fatalf("a non-regular file must not feed the high-water: %v", g.Now())
			}
		})
	}
}

// Q-D13: Save clamps to year 9999 so its own loader accepts the file.
func TestSaveClampsToYear9999(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC))
	g := open(t, f, dir)
	f.Advance(48 * time.Hour) // wall and mono into year 10000
	if got := g.Now(); got.Year() != 10000 {
		t.Fatalf("precondition: effective_now year = %d", got.Year())
	}
	if err := g.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	want := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
	if !fileHas(g.Path(), want) {
		t.Fatalf("file = %q, want clamp to %v", readFile(t, g.Path()), want)
	}
	g2, err := OpenClockGuard(clock.NewFake(t0), dir)
	if err != nil || g2 == nil {
		t.Fatalf("own loader rejects the saved file: %v", err)
	}
	if err := g.Save(); err != nil { // idempotent at the clamp
		t.Fatalf("second save: %v", err)
	}
}
