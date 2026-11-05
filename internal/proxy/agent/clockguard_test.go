package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, clk clock.Clock, dir string) *ClockGuard {
	t.Helper()
	g, err := OpenClockGuard(clk, dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return g
}

func TestEffectiveNow(t *testing.T) {
	// Fake: Advance moves wall and mono, Set moves wall only.
	tests := []struct {
		name string
		run  func(f *clock.Fake) (Anchor, time.Time) // returns anchor and high-water to use
		want time.Time
	}{
		{
			name: "no anchor, no high-water: wall",
			run:  func(f *clock.Fake) (Anchor, time.Time) { return Anchor{}, time.Time{} },
			want: t0,
		},
		{
			name: "high-water ahead of wall wins",
			run:  func(f *clock.Fake) (Anchor, time.Time) { return Anchor{}, t0.Add(time.Hour) },
			want: t0.Add(time.Hour),
		},
		{
			name: "wall ahead of high-water wins",
			run:  func(f *clock.Fake) (Anchor, time.Time) { return Anchor{}, t0.Add(-time.Hour) },
			want: t0,
		},
		{
			name: "anchor plus mono beats a wall set back",
			run: func(f *clock.Fake) (Anchor, time.Time) {
				a := Anchor{Wall: f.Now(), Mono: f.Mono()}
				f.Advance(10 * time.Minute)
				f.Set(f.Now().Add(-time.Hour))
				return a, time.Time{}
			},
			want: t0.Add(10 * time.Minute),
		},
		{
			name: "wall forward jump wins over anchor",
			run: func(f *clock.Fake) (Anchor, time.Time) {
				a := Anchor{Wall: f.Now(), Mono: f.Mono()}
				f.Set(f.Now().Add(24 * time.Hour))
				return a, time.Time{}
			},
			want: t0.Add(24 * time.Hour),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := clock.NewFake(t0)
			a, hw := tc.run(f)
			if got := EffectiveNow(f, a, hw); !got.Equal(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

// A wall clock set back after apply must not delay expiry (THREATS #12).
func TestExpiryStillFiresAfterWallSetBack(t *testing.T) {
	f := clock.NewFake(t0)
	g := open(t, f, t.TempDir())
	expires := t0.Add(10 * time.Minute)
	g.MarkApplied()

	f.Set(f.Now().Add(-time.Hour)) // attacker or NTP steps back 1h
	f.Advance(9 * time.Minute)
	if now := g.Now(); !now.Before(expires) {
		t.Fatalf("expired early: %v", now)
	}
	f.Advance(2 * time.Minute) // 11 minutes of monotonic time since apply
	if now := g.Now(); now.Before(expires) {
		t.Fatalf("not expired at 11m of mono time: effective_now=%v", now)
	}
}

func TestClockUntrustedDetection(t *testing.T) {
	f := clock.NewFake(t0)
	g := open(t, f, t.TempDir())
	g.MarkApplied()
	f.Advance(time.Minute)

	if g.Untrusted() || g.LastError() != nil || g.UntrustedCount() != 0 {
		t.Fatal("fresh clock reported untrusted")
	}

	f.Set(f.Now().Add(-4 * time.Minute)) // inside the 5m margin
	if g.Untrusted() {
		t.Fatal("4m behind is within the margin")
	}

	f.Set(f.Now().Add(-2 * time.Minute)) // now 6m behind
	if !g.Untrusted() {
		t.Fatal("6m behind not detected")
	}
	e := g.LastError()
	if e == nil || e.Code != wire.ErrClockUntrusted {
		t.Fatalf("LastError = %+v", e)
	}
	g.Now()
	g.Untrusted()
	if g.UntrustedCount() != 1 {
		t.Fatalf("count = %d, want 1 (one episode)", g.UntrustedCount())
	}

	f.Set(f.Now().Add(time.Hour)) // wall catches up
	if g.Untrusted() || g.LastError() != nil {
		t.Fatal("still untrusted after wall recovered")
	}
	f.Set(f.Now().Add(-2 * time.Hour))
	if !g.Untrusted() || g.UntrustedCount() != 2 {
		t.Fatalf("second episode: untrusted=%v count=%d", g.Untrusted(), g.UntrustedCount())
	}
}

func TestHighWaterSurvivesRestartWithBackwardWall(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	f.Advance(30 * time.Minute)
	want := g.Now() // t0+30m
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}

	// Restart: new process, new clock whose wall is an hour behind.
	f2 := clock.NewFake(t0.Add(-time.Hour))
	g2 := open(t, f2, dir)
	if got := g2.Now(); !got.Equal(want) {
		t.Fatalf("effective_now went back: %v want %v", got, want)
	}
	if !g2.Untrusted() || g2.LastError().Code != wire.ErrClockUntrusted {
		t.Fatal("backward wall at restart not reported")
	}
	// It keeps advancing from the high-water via mono.
	f2.Advance(10 * time.Minute)
	g2.MarkApplied()
	f2.Advance(5 * time.Minute)
	if got := g2.Now(); got.Before(want.Add(5 * time.Minute)) {
		t.Fatalf("did not advance: %v", got)
	}
}

func TestHighWaterNeverMovesBackwards(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	f.Advance(time.Hour)
	g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	first := readFile(t, g.Path())

	f.Set(t0.Add(-24 * time.Hour)) // wall far back, no mono progress
	g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, g.Path()); got != first {
		t.Fatalf("file moved: %q -> %q", first, got)
	}
	if hw := g.HighWater(); hw.Before(t0.Add(time.Hour)) {
		t.Fatalf("in-memory high-water moved back: %v", hw)
	}
}

func TestForwardJumpPersistedThenRecoveryByDeletingFile(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	f.Set(t0.Add(30 * 24 * time.Hour)) // bad forward jump
	g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	f.Set(t0) // clock repaired

	// Restart: the persisted future high-water holds effective_now there.
	g2 := open(t, f, dir)
	if got := g2.Now(); got.Before(t0.Add(30 * 24 * time.Hour)) {
		t.Fatalf("effective_now %v below persisted high-water", got)
	}
	if !g2.Untrusted() {
		t.Fatal("wall 30 days behind high-water must be untrusted")
	}

	// Documented recovery: the operator deletes the file.
	if err := os.Remove(g2.Path()); err != nil {
		t.Fatal(err)
	}
	g3 := open(t, f, dir)
	if got := g3.Now(); !got.Equal(t0) || g3.Untrusted() {
		t.Fatalf("after deleting the file: now=%v untrusted=%v", got, g3.Untrusted())
	}
}

func TestSaveFileMode0600AndFormat(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(g.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if filepath.Dir(g.Path()) != dir {
		t.Fatalf("path %q", g.Path())
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

func TestSaveFailureKeepsOldFileAndLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	old := readFile(t, g.Path())

	f.Advance(time.Hour)
	g.Now()
	g.syncFn = func(*os.File) error { return errors.New("disk on fire") }
	if err := g.Save(); err == nil {
		t.Fatal("expected error")
	}
	if got := readFile(t, g.Path()); got != old {
		t.Fatalf("old file changed: %q", got)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("leftovers: %v", ents)
	}
}

func TestOpenCorruptFile(t *testing.T) {
	tests := []struct{ name, content string }{
		{"garbage", "hello"},
		{"empty", ""},
		{"two lines", t0.Format(time.RFC3339Nano) + "\n" + t0.Format(time.RFC3339Nano) + "\n"},
		{"zero time", "0001-01-01T00:00:00Z\n"},
		{"huge", strings.Repeat("a", 4096)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, HighWaterFile), []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			f := clock.NewFake(t0)
			g, err := OpenClockGuard(f, dir)
			if !errors.Is(err, ErrHighWaterCorrupt) {
				t.Fatalf("err = %v, want ErrHighWaterCorrupt", err)
			}
			if g == nil {
				t.Fatal("guard must still be usable so the caller can fail safe")
			}
			if got := g.Now(); !got.Equal(t0) {
				t.Fatalf("now = %v", got)
			}
			// A later Save repairs the file.
			if err := g.Save(); err != nil {
				t.Fatal(err)
			}
			if _, err := OpenClockGuard(f, dir); err != nil {
				t.Fatalf("reopen after repair: %v", err)
			}
		})
	}
}

func TestOpenFailsOnUnusableDir(t *testing.T) {
	file := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if g, err := OpenClockGuard(clock.NewFake(t0), file); err == nil || g != nil {
		t.Fatalf("g=%v err=%v", g, err)
	}
	if g, err := OpenClockGuard(clock.NewFake(t0), ""); err == nil || g != nil {
		t.Fatalf("empty dir accepted: %v %v", g, err)
	}
}

func TestRunSavesEvery60sAndAtShutdown(t *testing.T) {
	dir := t.TempDir()
	f := clock.NewFake(t0)
	g := open(t, f, dir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, nil) }()

	f.BlockUntil(1)
	f.Advance(HighWaterInterval)
	waitFor(t, func() bool { return fileHas(g.Path(), t0.Add(HighWaterInterval)) })

	f.BlockUntil(1)
	f.Advance(HighWaterInterval)
	waitFor(t, func() bool { return fileHas(g.Path(), t0.Add(2*HighWaterInterval)) })

	f.Advance(20 * time.Second) // progress, then shut down before the next tick
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("run: %v", err)
	}
	if !fileHas(g.Path(), t0.Add(2*HighWaterInterval+20*time.Second)) {
		t.Fatalf("shutdown did not persist: %q", readFile(t, g.Path()))
	}
}

func TestRealClockTimesCarryNoMonotonicReading(t *testing.T) {
	// time.Time from clock.Real has a monotonic reading; comparing two such
	// values would ignore a wall step. The guard must strip it.
	g := open(t, clock.NewReal(), t.TempDir())
	if s := g.Now().String(); strings.Contains(s, "m=") {
		t.Fatalf("effective_now carries a monotonic reading: %s", s)
	}
	if s := g.HighWater().String(); strings.Contains(s, "m=") {
		t.Fatalf("high-water carries a monotonic reading: %s", s)
	}
}

func TestConcurrentUse(t *testing.T) {
	f := clock.NewFake(t0)
	g := open(t, f, t.TempDir())
	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 200; j++ {
				g.Now()
				g.Untrusted()
				g.MarkApplied()
				_ = g.Save()
				f.Advance(time.Second)
			}
		}()
	}
	for i := 0; i < 4; i++ {
		<-done
	}
}

func FuzzParseHighWater(f *testing.F) {
	f.Add([]byte(t0.Format(time.RFC3339Nano) + "\n"))
	f.Add([]byte(""))
	f.Add([]byte("\x00\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		ts, err := parseHighWater(b)
		if err == nil {
			if ts.IsZero() {
				t.Fatal("accepted zero time")
			}
			if got, err := parseHighWater(formatHighWater(ts)); err != nil || !got.Equal(ts) {
				t.Fatalf("round trip: %v %v", got, err)
			}
		}
	})
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fileHas(p string, want time.Time) bool {
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	got, err := parseHighWater(b)
	return err == nil && got.Equal(want)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
