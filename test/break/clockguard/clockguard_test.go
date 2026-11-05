// Package clockguardbreak holds black-box attack tests for the proxy agent's
// clock guard (task P-10). Sources: decisions M-D30 (effective_now = max(wall,
// high-water, apply wall + mono since apply), 5 minute untrusted margin,
// deleting the high-water file as recovery) and M-D23 (Fake: Advance moves wall
// and mono, Set moves wall only), ARCHITECTURE section 8 rows on clock changes,
// and the go doc of the agent package.
package clockguardbreak

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func open(t *testing.T, clk clock.Clock, dir string) *agent.ClockGuard {
	t.Helper()
	g, err := agent.OpenClockGuard(clk, dir)
	if err != nil {
		t.Fatalf("OpenClockGuard: %v", err)
	}
	return g
}

func newDir(t *testing.T) string { return filepath.Join(t.TempDir(), "data") }

func readHW(t *testing.T, dir string) (time.Time, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, agent.HighWaterFile))
	if err != nil {
		if os.IsNotExist(err) {
			return time.Time{}, false
		}
		t.Fatal(err)
	}
	s := strings.TrimSuffix(string(b), "\n")
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("high-water file is not an RFC 3339 timestamp: %q: %v", b, err)
	}
	if !strings.HasSuffix(s, "Z") {
		t.Fatalf("high-water file is not UTC: %q", s)
	}
	return ts, true
}

func TestConstants(t *testing.T) {
	if agent.UntrustedMargin != 5*time.Minute {
		t.Errorf("UntrustedMargin = %v, M-D30 says 5m", agent.UntrustedMargin)
	}
	if agent.HighWaterInterval != 60*time.Second {
		t.Errorf("HighWaterInterval = %v, M-D30 says at least every 60s", agent.HighWaterInterval)
	}
	if agent.HighWaterFile != "highwater" {
		t.Errorf("HighWaterFile = %q", agent.HighWaterFile)
	}
}

// ---- EffectiveNow: the pure formula of M-D30 ----

func TestEffectiveNowIsTheMaxOfThree(t *testing.T) {
	fake := clock.NewFake(t0)
	anchor := agent.Anchor{Wall: t0, Mono: fake.Mono()}
	hw := t0.Add(-time.Hour)
	steps := []struct {
		name         string
		advance      time.Duration
		setWall      *time.Time
		anchor       agent.Anchor
		hw           time.Time
		wantWall     time.Time // expected wall input
		wantEffNow   time.Time
		wantFromWhat string
	}{}
	_ = steps
	type c struct {
		name      string
		advance   time.Duration
		setWall   time.Time // zero = leave
		anchor    agent.Anchor
		hw        time.Time
		want      time.Time
		wallAfter time.Time
	}
	jump := func(d time.Duration) time.Time { return t0.Add(d) }
	cases := []c{
		{"wall wins", 10 * time.Minute, time.Time{}, anchor, hw, jump(10 * time.Minute), time.Time{}},
		{"wall set back, anchor+mono wins", 10 * time.Minute, jump(-5 * time.Hour), anchor, hw, jump(10 * time.Minute), time.Time{}},
		{"wall set back, high-water wins", 0, jump(-5 * time.Hour), agent.Anchor{}, jump(3 * time.Hour), jump(3 * time.Hour), time.Time{}},
		{"zero high-water ignored", 0, jump(-1 * time.Hour), anchor, time.Time{}, t0, time.Time{}},
		{"zero anchor ignored", 0, jump(-1 * time.Hour), agent.Anchor{}, hw, jump(-1 * time.Hour), time.Time{}},
		{"all ignored: wall", 0, jump(-9 * time.Hour), agent.Anchor{}, time.Time{}, jump(-9 * time.Hour), time.Time{}},
		{"wall forward jump wins over everything", 0, jump(1000 * time.Hour), anchor, hw, jump(1000 * time.Hour), time.Time{}},
		{"mono elapsed counts even while wall is frozen", 90 * time.Minute, jump(-1 * time.Hour), anchor, time.Time{}, jump(90 * time.Minute), time.Time{}},
	}
	for _, x := range cases {
		t.Run(x.name, func(t *testing.T) {
			f := clock.NewFake(t0)
			if x.advance > 0 {
				f.Advance(x.advance)
			}
			if !x.setWall.IsZero() {
				f.Set(x.setWall)
			}
			got := agent.EffectiveNow(f, x.anchor, x.hw)
			if !got.Equal(x.want) {
				t.Fatalf("EffectiveNow = %v, want %v", got, x.want)
			}
		})
	}
}

func TestEffectiveNowResultCarriesNoMonotonicReading(t *testing.T) {
	r := clock.NewReal()
	a := agent.Anchor{Wall: time.Now(), Mono: r.Mono()}
	got := agent.EffectiveNow(r, a, time.Now().Add(-time.Hour))
	if strings.Contains(got.String(), "m=") {
		t.Fatalf("result still has a monotonic reading: %v (comparisons would mix wall and monotonic time)", got)
	}
	got = agent.EffectiveNow(r, agent.Anchor{}, time.Time{})
	if strings.Contains(got.String(), "m=") {
		t.Fatalf("wall-only result has a monotonic reading: %v", got)
	}
}

func TestEffectiveNowNeverBelowAnyInput(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		f := clock.NewFake(t0)
		f.Advance(time.Duration(rng.Int63n(int64(100 * time.Hour))))
		f.Set(t0.Add(time.Duration(rng.Int63n(int64(400*time.Hour))) - 200*time.Hour))
		a := agent.Anchor{Wall: t0.Add(time.Duration(rng.Int63n(int64(400*time.Hour))) - 200*time.Hour), Mono: time.Duration(rng.Int63n(int64(50 * time.Hour)))}
		hw := t0.Add(time.Duration(rng.Int63n(int64(400*time.Hour))) - 200*time.Hour)
		got := agent.EffectiveNow(f, a, hw)
		if got.Before(f.Now()) || got.Before(hw) || got.Before(a.Wall.Add(f.Mono()-a.Mono)) {
			t.Fatalf("iteration %d: %v is below one of its inputs (wall %v, hw %v, anchor %v+%v)", i, got, f.Now(), hw, a.Wall, f.Mono()-a.Mono)
		}
	}
}

func TestEffectiveNowExtremes(t *testing.T) {
	f := clock.NewFake(t0)
	f.Advance(time.Hour)
	for name, a := range map[string]agent.Anchor{
		"mono-in-the-future": {Wall: t0, Mono: 100 * time.Hour}, // anchor from a later clock reading: delta negative
		"huge-mono-delta":    {Wall: t0, Mono: -time.Duration(math.MaxInt64 / 2)},
		"year-9999":          {Wall: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), Mono: 0},
		"year-1":             {Wall: time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), Mono: 0},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			got := agent.EffectiveNow(f, a, time.Time{})
			if got.Before(f.Now()) {
				t.Fatalf("EffectiveNow %v is below wall %v (overflow made time go backwards?)", got, f.Now())
			}
		})
	}
	// a negative anchor delta must not pull effective_now below wall
	got := agent.EffectiveNow(f, agent.Anchor{Wall: t0, Mono: 100 * time.Hour}, time.Time{})
	if got.Before(f.Now()) {
		t.Fatalf("anchor with a later mono: %v < wall %v", got, f.Now())
	}
}

// ---- the guard: wall set back ----

func TestWallSetBackDoesNotMoveEffectiveNowBack(t *testing.T) {
	clk := clock.NewFake(t0)
	g := open(t, clk, newDir(t))
	if got := g.Now(); !got.Equal(t0) {
		t.Fatalf("first Now = %v, want wall %v", got, t0)
	}
	clk.Advance(time.Hour)
	if got := g.Now(); !got.Equal(t0.Add(time.Hour)) {
		t.Fatalf("after +1h Now = %v", got)
	}
	if g.Untrusted() || g.LastError() != nil {
		t.Fatal("untrusted while the clock behaves")
	}
	clk.Set(t0.Add(-2 * time.Hour)) // NTP rewind by 3 hours
	if got := g.Now(); got.Before(t0.Add(time.Hour)) {
		t.Fatalf("effective_now fell back to %v after the wall was set back (policy would outlive its expiry)", got)
	}
	if !g.Untrusted() {
		t.Fatal("wall 3h behind effective_now is not reported untrusted")
	}
	if le := g.LastError(); le == nil || le.Code != wire.ErrClockUntrusted {
		t.Fatalf("LastError = %+v, want code clock_untrusted", le)
	}
	// time keeps passing on the monotonic clock while the wall is stuck in the past
	clk.Advance(10 * time.Minute)
	if got, want := g.Now(), t0.Add(time.Hour+10*time.Minute); !got.Equal(want) {
		t.Fatalf("mono time ignored: Now = %v, want %v", got, want)
	}
	// wall repaired
	clk.Set(t0.Add(time.Hour + 20*time.Minute))
	if g.Untrusted() || g.LastError() != nil {
		t.Fatal("still untrusted after the wall caught up")
	}
	if g.UntrustedCount() != 1 {
		t.Fatalf("UntrustedCount = %d, want 1 episode", g.UntrustedCount())
	}
	// second rewind = second episode
	clk.Set(t0.Add(-10 * time.Hour))
	_ = g.Now()
	_ = g.Untrusted()
	if g.UntrustedCount() != 2 {
		t.Fatalf("UntrustedCount = %d, want 2", g.UntrustedCount())
	}
}

func TestUntrustedThresholdIsExactlyFiveMinutesAndNotCountedRepeatedly(t *testing.T) {
	clk := clock.NewFake(t0)
	g := open(t, clk, newDir(t))
	clk.Advance(time.Hour)
	eff := g.Now()
	for _, c := range []struct {
		behind time.Duration
		want   bool
	}{
		{0, false}, {time.Second, false}, {4*time.Minute + 59*time.Second, false},
		{5 * time.Minute, false}, // "more than" the margin
		{5*time.Minute + time.Nanosecond, true}, {5*time.Minute + time.Second, true}, {time.Hour, true},
	} {
		clk.Set(eff.Add(-c.behind))
		if got := g.Untrusted(); got != c.want {
			t.Errorf("wall %v behind: Untrusted = %v, want %v", c.behind, got, c.want)
		}
		if (g.LastError() != nil) != c.want {
			t.Errorf("wall %v behind: LastError = %v, want set = %v", c.behind, g.LastError(), c.want)
		}
	}
	// one long episode polled many times is one episode
	before := g.UntrustedCount()
	clk.Set(eff.Add(-6 * time.Hour))
	for i := 0; i < 200; i++ {
		_ = g.Untrusted()
		_ = g.Now()
		_ = g.LastError()
	}
	clk.Set(eff.Add(-6 * time.Hour))
	if got := g.UntrustedCount(); got > before+1 {
		t.Fatalf("one episode counted %d times", got-before)
	}
}

// ---- forward jump and the documented limitation / recovery ----

func TestForwardJumpIsKeptAndRecoveryByDeletingTheFile(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	clk.Set(t0.Add(1000 * time.Hour)) // clock forward jump
	jumped := g.Now()
	if !jumped.Equal(t0.Add(1000 * time.Hour)) {
		t.Fatalf("Now = %v", jumped)
	}
	clk.Set(t0) // corrected
	if got := g.Now(); got.Before(jumped) {
		t.Fatalf("effective_now went back to %v after correcting a forward jump; M-D30 says the high-water keeps the jump", got)
	}
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	if hw, ok := readHW(t, dir); !ok || hw.Before(jumped) {
		t.Fatalf("persisted high-water %v (found %v) is below the jump %v", hw, ok, jumped)
	}
	// a restart keeps it
	g2 := open(t, clk, dir)
	if got := g2.Now(); got.Before(jumped) {
		t.Fatalf("restart forgot the jump: %v", got)
	}
	if !g2.Untrusted() {
		t.Fatal("after restart the wall is 1000h behind the high-water but Untrusted() is false")
	}
	if le := g2.LastError(); le == nil || le.Code != wire.ErrClockUntrusted {
		t.Fatalf("LastError after restart = %+v", le)
	}
	// operator recovery: delete the file
	if err := os.Remove(g2.Path()); err != nil {
		t.Fatal(err)
	}
	g3 := open(t, clk, dir)
	if got := g3.Now(); !got.Equal(t0) {
		t.Fatalf("after deleting the file Now = %v, want the wall %v", got, t0)
	}
	if g3.Untrusted() {
		t.Fatal("still untrusted after the operator deleted the file")
	}
}

// ---- persistence: the file never moves backwards ----

func TestSaveNeverMovesTheFileBackwards(t *testing.T) {
	dir := newDir(t)
	clkA := clock.NewFake(t0)
	clkB := clock.NewFake(t0)
	a := open(t, clkA, dir)
	b := open(t, clkB, dir) // second guard on the same directory (restart race, or a second process)
	clkA.Advance(10 * time.Hour)
	_ = a.Now()
	if err := a.Save(); err != nil {
		t.Fatal(err)
	}
	high, _ := readHW(t, dir)
	clkB.Advance(time.Hour)
	_ = b.Now()
	if err := b.Save(); err != nil {
		t.Fatal(err)
	}
	if got, _ := readHW(t, dir); got.Before(high) {
		t.Fatalf("a guard with a lower high-water overwrote the file: %v < %v (doc: Save persists only if higher than what is on disk)", got, high)
	}
}

func TestFileIsMonotoneAcrossRandomHistory(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		rng := rand.New(rand.NewSource(seed))
		dir := newDir(t)
		clk := clock.NewFake(t0)
		g := open(t, clk, dir)
		var lastDisk time.Time
		var maxEff time.Time
		for step := 0; step < 200; step++ {
			switch rng.Intn(8) {
			case 0, 1:
				clk.Advance(time.Duration(rng.Int63n(int64(3 * time.Hour))))
			case 2:
				clk.Set(t0.Add(time.Duration(rng.Int63n(int64(2000*time.Hour))) - 500*time.Hour))
			case 3:
				if n := g.Now(); n.After(maxEff) {
					maxEff = n
				} else if n.Before(maxEff) {
					t.Fatalf("seed %d step %d: effective_now fell from %v to %v", seed, step, maxEff, n)
				}
			case 4, 5:
				if err := g.Save(); err != nil {
					t.Fatalf("seed %d: Save: %v", seed, err)
				}
			case 6:
				g = open(t, clk, dir) // restart: unsaved progress is lost by design (saved every 60s)
				maxEff = g.Now()
			case 7:
				// delete the file only if the operator would: not in this history
			}
			if hw, ok := readHW(t, dir); ok {
				if hw.Before(lastDisk) {
					t.Fatalf("seed %d step %d: file moved backwards %v -> %v", seed, step, lastDisk, hw)
				}
				lastDisk = hw
				if hw.After(maxEff) && hw.After(g.HighWater()) {
					t.Fatalf("seed %d step %d: file %v is above anything the guard observed (%v)", seed, step, hw, maxEff)
				}
			}
		}
		if hw := g.HighWater(); hw.Before(maxEff) {
			t.Fatalf("seed %d: HighWater %v below the highest effective_now %v", seed, hw, maxEff)
		}
	}
}

// A model of the guard written from M-D30; Now() must agree exactly.
func TestGuardMatchesTheMD30Model(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed * 31))
		dir := newDir(t)
		clk := clock.NewFake(t0)
		g := open(t, clk, dir)
		var (
			eff       = t0 // model effective_now at the last observation
			lastMono  = clk.Mono()
			disk      time.Time
			haveDisk  bool
			wasUntr   bool
			episodes  uint64
			maxEffAll = t0
		)
		observe := func() time.Time {
			n := clk.Now()
			e := eff.Add(clk.Mono() - lastMono)
			if n.After(e) {
				e = n
			}
			return e
		}
		for step := 0; step < 150; step++ {
			switch rng.Intn(7) {
			case 0, 1:
				d := time.Duration(rng.Int63n(int64(2 * time.Hour)))
				clk.Advance(d)
			case 2:
				clk.Set(t0.Add(time.Duration(rng.Int63n(int64(3000*time.Hour))) - 1000*time.Hour))
			case 3: // observe
				want := observe()
				got := g.Now()
				if !got.Equal(want) {
					t.Fatalf("seed %d step %d: Now = %v, model says %v", seed, step, got, want)
				}
				eff, lastMono = want, clk.Mono()
				if eff.After(maxEffAll) {
					maxEffAll = eff
				}
			case 4:
				if err := g.Save(); err != nil {
					t.Fatal(err)
				}
				if hw := g.HighWater(); !haveDisk || hw.After(disk) {
					disk, haveDisk = hw, true
				}
			case 5: // restart: new guard anchored at max(wall, disk)
				g = open(t, clk, dir)
				start := clk.Now()
				if haveDisk && disk.After(start) {
					start = disk
				}
				eff, lastMono = start, clk.Mono()
				if got := g.Now(); !got.Equal(start) {
					t.Fatalf("seed %d step %d: after restart Now = %v, want max(wall, disk) = %v (disk %v wall %v)", seed, step, got, start, disk, clk.Now())
				}
				wasUntr, episodes = false, 0
			case 6: // MarkApplied re-anchors at effective_now
				want := observe()
				a := g.MarkApplied()
				if !a.Wall.Equal(want) {
					t.Fatalf("seed %d step %d: MarkApplied wall %v, want effective_now %v", seed, step, a.Wall, want)
				}
				if a.Mono != clk.Mono() {
					t.Fatalf("seed %d step %d: MarkApplied mono %v, want %v", seed, step, a.Mono, clk.Mono())
				}
				eff, lastMono = want, clk.Mono()
			}
			// Untrusted must follow the model after every step
			e := observe()
			wantUntr := clk.Now().Before(e.Add(-agent.UntrustedMargin))
			if got := g.Untrusted(); got != wantUntr {
				t.Fatalf("seed %d step %d: Untrusted = %v, model %v (wall %v, effective %v)", seed, step, got, wantUntr, clk.Now(), e)
			}
			if wantUntr && !wasUntr {
				episodes++
			}
			wasUntr = wantUntr
			// keep the model's anchor in step with the guard's re-anchoring on observation
			eff, lastMono = e, clk.Mono()
			if (g.LastError() != nil) != wantUntr {
				t.Fatalf("seed %d step %d: LastError %v with untrusted=%v", seed, step, g.LastError(), wantUntr)
			}
			if got := g.UntrustedCount(); got != episodes {
				t.Fatalf("seed %d step %d: UntrustedCount = %d, model %d", seed, step, got, episodes)
			}
		}
		_ = maxEffAll
	}
}

func TestMarkAppliedBoundsExpiryByMonotonicTime(t *testing.T) {
	clk := clock.NewFake(t0)
	g := open(t, clk, newDir(t))
	expires := t0.Add(time.Hour)
	anchor := g.MarkApplied()
	if !anchor.Wall.Equal(t0) {
		t.Fatalf("anchor wall %v", anchor.Wall)
	}
	// the attacker rewinds the wall clock by 5 hours and waits
	clk.Set(t0.Add(-5 * time.Hour))
	clk.Advance(30 * time.Minute)
	if now := agent.EffectiveNow(clk, anchor, time.Time{}); !now.Before(expires) {
		t.Fatalf("expired too early: %v", now)
	}
	clk.Advance(31 * time.Minute)
	if now := agent.EffectiveNow(clk, anchor, time.Time{}); now.Before(expires) {
		t.Fatalf("a wall rewind kept the policy alive past its expiry: effective_now %v < expiry %v (M-D30)", now, expires)
	}
	if now := g.Now(); now.Before(expires) {
		t.Fatalf("guard.Now %v < expiry %v after 61 minutes of monotonic time", now, expires)
	}
}

func TestMarkAppliedWhileClockUntrustedAnchorsAtEffectiveNow(t *testing.T) {
	clk := clock.NewFake(t0)
	g := open(t, clk, newDir(t))
	clk.Advance(2 * time.Hour)
	eff := g.Now()
	clk.Set(t0.Add(-10 * time.Hour))
	a := g.MarkApplied()
	if a.Wall.Before(eff) {
		t.Fatalf("anchor.Wall %v is the rewound wall, not effective_now %v: a policy applied during a rewind would live too long", a.Wall, eff)
	}
}

// ---- hostile and corrupt high-water files ----

func TestCorruptHighWaterFile(t *testing.T) {
	good := t0.Add(5*time.Hour).UTC().Format(time.RFC3339Nano) + "\n"
	cases := map[string]string{
		"empty":               "",
		"newline":             "\n",
		"garbage":             "not a time\n",
		"binary":              "\x00\x01\x02\xff",
		"two-lines":           good + good,
		"trailing-text":       strings.TrimSuffix(good, "\n") + " extra\n",
		"leading-space":       " " + good,
		"offset-not-utc":      "2026-11-05T21:00:00+09:00\n",
		"lowercase-z":         "2026-11-05T12:00:00z\n",
		"date-only":           "2026-11-05\n",
		"unix-seconds":        "1793880000\n",
		"year-10000":          "10000-01-01T00:00:00Z\n",
		"negative-year":       "-0001-01-01T00:00:00Z\n",
		"month-13":            "2026-13-05T12:00:00Z\n",
		"feb-30":              "2026-02-30T12:00:00Z\n",
		"bom":                 "\xef\xbb\xbf" + good,
		"crlf":                strings.TrimSuffix(good, "\n") + "\r\n",
		"huge":                strings.Repeat("2026-11-05T12:00:00Z\n", 100000),
		"huge-one-line":       strings.Repeat("9", 1<<20) + "\n",
		"quoted":              `"` + strings.TrimSuffix(good, "\n") + `"` + "\n",
		"json":                `{"hw":"` + strings.TrimSuffix(good, "\n") + `"}` + "\n",
		"nan":                 "NaN\n",
		"all-zero-time":       "0001-01-01T00:00:00Z\n",
		"with-monotonic-text": strings.TrimSuffix(good, "\n") + " m=+12.3\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			dir := newDir(t)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, agent.HighWaterFile)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			clk := clock.NewFake(t0)
			g, err := agent.OpenClockGuard(clk, dir)
			if name == "all-zero-time" {
				// a legitimate-looking zero timestamp is harmless either way
				if g == nil {
					t.Fatalf("nil guard: %v", err)
				}
				return
			}
			if err == nil {
				// accepted as a valid timestamp: then it must have been honoured, not ignored
				if g == nil {
					t.Fatal("nil guard with nil error")
				}
				return
			}
			if !errors.Is(err, agent.ErrHighWaterCorrupt) {
				t.Fatalf("err = %v, want ErrHighWaterCorrupt (and a usable guard)", err)
			}
			if g == nil {
				t.Fatal("corrupt file must still give a usable guard (the proxy has to boot)")
			}
			if got := g.Now(); !got.Equal(t0) {
				t.Fatalf("corrupt file: Now = %v, want the wall %v", got, t0)
			}
			if g.Untrusted() {
				t.Fatal("a corrupt file made the clock untrusted")
			}
			clk.Advance(time.Minute)
			_ = g.Now()
			if err := g.Save(); err != nil {
				t.Fatalf("Save over a corrupt file: %v", err)
			}
			if hw, ok := readHW(t, dir); !ok || hw.Before(t0) {
				t.Fatalf("the next Save did not repair the file: %v %v", hw, ok)
			}
			// and the repaired file opens clean
			if _, err := agent.OpenClockGuard(clk, dir); err != nil {
				t.Fatalf("repaired file still reports %v", err)
			}
		})
	}
}

func TestSpecialFilesInPlaceOfTheHighWaterFile(t *testing.T) {
	mk := map[string]func(path string) error{
		"directory":    func(p string) error { return os.Mkdir(p, 0o700) },
		"symlink-self": func(p string) error { return os.Symlink(p, p) },
		"symlink-zero": func(p string) error { return os.Symlink("/dev/zero", p) },
		"fifo":         func(p string) error { return syscall.Mkfifo(p, 0o600) },
		"unreadable":   func(p string) error { return os.WriteFile(p, []byte("2026-11-05T12:00:00Z\n"), 0o000) },
	}
	for name, f := range mk {
		t.Run(name, func(t *testing.T) {
			dir := newDir(t)
			os.MkdirAll(dir, 0o700)
			path := filepath.Join(dir, agent.HighWaterFile)
			if err := f(path); err != nil {
				t.Fatalf("environment: setup: %v", err)
			}
			type res struct {
				g   *agent.ClockGuard
				err error
			}
			ch := make(chan res, 1)
			go func() {
				g, err := agent.OpenClockGuard(clock.NewFake(t0), dir)
				ch <- res{g, err}
			}()
			select {
			case r := <-ch:
				if r.err == nil {
					t.Fatal("a special file in place of the high-water file opened without any error")
				}
				if r.g != nil && !errors.Is(r.err, agent.ErrHighWaterCorrupt) {
					t.Fatalf("guard returned with %v; non-corrupt failures must return a nil guard", r.err)
				}
				if r.g != nil {
					_ = r.g.Now() // usable
				}
			case <-time.After(5 * time.Second):
				if fh, e := os.OpenFile(path, os.O_RDWR, 0); e == nil {
					fh.Close()
				}
				t.Fatal("OpenClockGuard blocks forever: a planted FIFO would stop the proxy from booting")
			}
		})
	}
}

func TestOpenCreatesDirAndRefusesFiles(t *testing.T) {
	root := t.TempDir()
	deep := filepath.Join(root, "a", "b", "data")
	g := open(t, clock.NewFake(t0), deep)
	info, err := os.Stat(deep)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir not created: %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("dir mode %o, doc says 0700", info.Mode().Perm())
	}
	if filepath.Dir(g.Path()) != deep || filepath.Base(g.Path()) != agent.HighWaterFile {
		t.Errorf("Path = %q", g.Path())
	}
	file := filepath.Join(root, "afile")
	os.WriteFile(file, []byte("x"), 0o600)
	if g, err := agent.OpenClockGuard(clock.NewFake(t0), file); err == nil || g != nil {
		t.Errorf("dir path is a regular file: g=%v err=%v", g, err)
	}
	if g, err := agent.OpenClockGuard(clock.NewFake(t0), filepath.Join(file, "x")); err == nil || g != nil {
		t.Errorf("dir under a regular file: g=%v err=%v", g, err)
	}
}

func TestSavedFileFormatModeAndFirstBoot(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(time.Date(2026, 11, 5, 21, 0, 0, 123456789, time.FixedZone("JST", 9*3600)))
	g := open(t, clk, dir)
	if _, ok := readHW(t, dir); ok {
		t.Fatal("a file exists before any Save")
	}
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	hw, ok := readHW(t, dir) // asserts RFC 3339 and Z
	if !ok {
		t.Fatal("Save wrote nothing on first boot")
	}
	if !hw.Equal(g.HighWater()) {
		t.Fatalf("file %v != HighWater %v (precision lost?)", hw, g.HighWater())
	}
	info, _ := os.Stat(g.Path())
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("file mode %o is not private", info.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temp files left behind: %v", ents)
	}
	// round trip keeps the exact instant
	g2 := open(t, clk, dir)
	if !g2.HighWater().Equal(g.HighWater()) {
		t.Fatalf("restart high-water %v != saved %v", g2.HighWater(), g.HighWater())
	}
}

func TestSaveFailureAndRecovery(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	clk.Advance(time.Hour)
	_ = g.Now()
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	good, _ := readHW(t, dir)
	clk.Advance(time.Hour)
	_ = g.Now()
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	if err := g.Save(); err == nil {
		t.Fatal("Save into a read-only dir returned nil")
	}
	if g.SaveErr() == nil {
		t.Fatal("SaveErr is nil after a failed Save")
	}
	os.Chmod(dir, 0o700)
	if now, _ := readHW(t, dir); !now.Equal(good) {
		t.Fatalf("a failed Save changed the file: %v -> %v", good, now)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left: %v", ents)
	}
	if err := g.Save(); err != nil || g.SaveErr() != nil {
		t.Fatalf("recovery: Save %v SaveErr %v", err, g.SaveErr())
	}
	if now, _ := readHW(t, dir); !now.After(good) {
		t.Fatal("recovered Save did not advance the file")
	}
	// the in-memory mark is unaffected by failures: still never lower
	if g.HighWater().Before(t0.Add(2 * time.Hour)) {
		t.Fatalf("HighWater %v", g.HighWater())
	}
}

func TestSaveWithNothingNewDoesNotRewriteOrFail(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	st1, _ := os.Stat(g.Path())
	for i := 0; i < 5; i++ {
		clk.Set(t0.Add(-time.Hour)) // wall back: nothing higher to write
		if err := g.Save(); err != nil {
			t.Fatal(err)
		}
	}
	st2, _ := os.Stat(g.Path())
	if !os.SameFile(st1, st2) {
		t.Error("Save rewrote the file although the high-water did not move (needless fsync on a 60s tick)")
	}
}

// ---- Run ----

func TestRunSavesEveryIntervalAndOnShutdown(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, nil) }()
	clk.BlockUntil(1)
	clk.Advance(agent.HighWaterInterval)
	waitFor(t, func() bool { hw, ok := readHW(t, dir); return ok && !hw.Before(t0.Add(agent.HighWaterInterval)) }, "periodic save after 60s")
	clk.BlockUntil(1)
	clk.Advance(agent.HighWaterInterval)
	waitFor(t, func() bool { hw, ok := readHW(t, dir); return ok && !hw.Before(t0.Add(2*agent.HighWaterInterval)) }, "second periodic save")
	// 30 s more of wall time pass, then shutdown: the final save must catch them
	clk.BlockUntil(1)
	clk.Advance(30 * time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v on a clean shutdown", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the context ended")
	}
	if hw, _ := readHW(t, dir); hw.Before(t0.Add(2*agent.HighWaterInterval + 30*time.Second)) {
		t.Fatalf("shutdown save missing: file %v", hw)
	}
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func TestRunWithAlreadyCancelledContextStillSaves(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, nil) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run hangs on a cancelled context")
	}
	if _, ok := readHW(t, dir); !ok {
		t.Fatal("no save on shutdown")
	}
}

func TestRunSurvivesFailingSavesAndNilLogger(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	if err := g.Save(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- g.Run(ctx, nil) }()
	clk.BlockUntil(1)
	os.Chmod(dir, 0o500)
	defer os.Chmod(dir, 0o700)
	for i := 0; i < 3; i++ {
		clk.Advance(agent.HighWaterInterval)
		clk.BlockUntil(1) // Run is still ticking after a failed save
	}
	waitFor(t, func() bool { return g.SaveErr() != nil }, "SaveErr after failing periodic saves")
	os.Chmod(dir, 0o700)
	clk.Advance(agent.HighWaterInterval)
	waitFor(t, func() bool { return g.SaveErr() == nil }, "SaveErr cleared once the disk works again")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

// ---- concurrency ----

func TestConcurrentUseIsRaceFreeAndNeverGoesBack(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(t0)
	g := open(t, clk, dir)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	rng := rand.New(rand.NewSource(1))
	var rmu sync.Mutex
	driver := func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			rmu.Lock()
			v := rng.Intn(10)
			d := time.Duration(rng.Int63n(int64(time.Hour)))
			rmu.Unlock()
			switch {
			case v < 5:
				clk.Advance(d)
			case v < 8:
				clk.Set(t0.Add(d - 30*time.Minute))
			default:
				time.Sleep(time.Millisecond)
			}
		}
	}
	wg.Add(1)
	go driver()
	var workers sync.WaitGroup
	for w := 0; w < 12; w++ {
		workers.Add(1)
		go func(w int) {
			defer workers.Done()
			var prev time.Time
			for i := 0; i < 400; i++ {
				switch (w + i) % 6 {
				case 0, 1, 2:
					n := g.Now()
					if n.Before(prev) {
						t.Errorf("worker %d: effective_now went back %v -> %v", w, prev, n)
						return
					}
					prev = n
				case 3:
					a := g.MarkApplied()
					if a.Wall.Before(prev) {
						t.Errorf("worker %d: anchor %v below an earlier Now %v", w, a.Wall, prev)
						return
					}
					prev = a.Wall
				case 4:
					_ = g.Save()
					_ = g.SaveErr()
					_ = g.HighWater()
				case 5:
					_ = g.Untrusted()
					_ = g.LastError()
					_ = g.UntrustedCount()
				}
			}
		}(w)
	}
	// a reader that watches the file
	wg.Add(1)
	go func() {
		defer wg.Done()
		var lastRead time.Time
		for {
			select {
			case <-stop:
				return
			default:
			}
			b, err := os.ReadFile(filepath.Join(dir, agent.HighWaterFile))
			if err != nil {
				continue
			}
			ts, perr := time.Parse(time.RFC3339Nano, strings.TrimSuffix(string(b), "\n"))
			if perr != nil {
				t.Errorf("reader saw a torn or invalid file %q: %v", b, perr)
				return
			}
			if ts.Before(lastRead) {
				t.Errorf("file went backwards %v -> %v", lastRead, ts)
				return
			}
			lastRead = ts
		}
	}()
	workers.Wait()
	close(stop)
	wg.Wait()
	if hw, ok := readHW(t, dir); ok && hw.After(g.HighWater()) {
		t.Fatalf("file %v above in-memory high-water %v", hw, g.HighWater())
	}
}

// Save must never write a file that OpenClockGuard calls corrupt: a wall clock pushed to the end of
// year 9999 and a little further would make the next Save write year 10000.
func TestSaveAtTheEdgeOfTheCalendarReopensCleanly(t *testing.T) {
	dir := newDir(t)
	clk := clock.NewFake(time.Date(9999, 12, 31, 23, 59, 58, 0, time.UTC))
	g := open(t, clk, dir)
	clk.Advance(5 * time.Second)
	_ = g.Now()
	if err := g.Save(); err != nil {
		return // refusing to write an unrepresentable time is fine
	}
	if _, err := agent.OpenClockGuard(clk, dir); err != nil {
		t.Fatalf("Save wrote a high-water file that its own loader rejects (%v): the next boot forgets the high-water mark and effective_now falls back to the wall clock", err)
	}
}

func FuzzHighWaterFile(f *testing.F) {
	f.Add([]byte("2026-11-05T12:00:00Z\n"))
	f.Add([]byte(""))
	f.Add([]byte("\xff"))
	f.Add([]byte("2026-12-31T23:59:59.999999999Z\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		dir := filepath.Join(t.TempDir(), "d")
		os.MkdirAll(dir, 0o700)
		os.WriteFile(filepath.Join(dir, agent.HighWaterFile), data, 0o600)
		clk := clock.NewFake(t0)
		g, err := agent.OpenClockGuard(clk, dir)
		if g == nil {
			t.Fatalf("no guard for file content %q: %v", data, err)
		}
		if err != nil && !errors.Is(err, agent.ErrHighWaterCorrupt) {
			t.Fatalf("unexpected error %v", err)
		}
		now := g.Now()
		if now.Before(t0) {
			t.Fatalf("effective_now %v below the wall %v", now, t0)
		}
		clk.Advance(time.Second)
		if err := g.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if _, err := agent.OpenClockGuard(clk, dir); err != nil {
			t.Fatalf("file written by Save does not reopen cleanly: %v", err)
		}
	})
}
