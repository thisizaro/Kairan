package clock

import (
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)

func TestRealNowMoves(t *testing.T) {
	var c Clock = Real{}
	a := c.Now()
	<-c.After(time.Millisecond)
	if b := c.Now(); !b.After(a) {
		t.Fatalf("Real.Now did not advance: %v then %v", a, b)
	}
}

func TestFakeNowOnlyMovesWhenTold(t *testing.T) {
	f := NewFake(t0)
	if got := f.Now(); !got.Equal(t0) {
		t.Fatalf("Now = %v, want %v", got, t0)
	}
	f.Advance(90 * time.Second)
	if got, want := f.Now(), t0.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("after Advance: Now = %v, want %v", got, want)
	}
}

func TestFakeSetCanJumpBackwards(t *testing.T) {
	// THREATS #12 tests need a wall clock that goes backwards.
	f := NewFake(t0)
	back := t0.Add(-time.Hour)
	f.Set(back)
	if got := f.Now(); !got.Equal(back) {
		t.Fatalf("Now = %v, want %v", got, back)
	}
}

func TestFakeAfterFiresOnlyAtDeadline(t *testing.T) {
	f := NewFake(t0)
	ch := f.After(10 * time.Second)

	f.Advance(9 * time.Second)
	select {
	case <-ch:
		t.Fatal("fired 1s early")
	default:
	}

	f.Advance(time.Second)
	select {
	case got := <-ch:
		if want := t0.Add(10 * time.Second); !got.Equal(want) {
			t.Fatalf("fired with %v, want %v", got, want)
		}
	default:
		t.Fatal("did not fire at deadline")
	}
}

func TestFakeAfterNonPositiveFiresImmediately(t *testing.T) {
	f := NewFake(t0)
	for _, d := range []time.Duration{0, -time.Second} {
		select {
		case <-f.After(d):
		default:
			t.Fatalf("After(%v) did not fire immediately", d)
		}
	}
}

func TestFakeSetBackwardsDoesNotFireTimers(t *testing.T) {
	f := NewFake(t0)
	ch := f.After(time.Second)
	f.Set(t0.Add(-time.Hour))
	select {
	case <-ch:
		t.Fatal("timer fired after the clock went backwards")
	default:
	}
	if n := f.Waiters(); n != 1 {
		t.Fatalf("Waiters = %d, want 1", n)
	}
}

func TestFakeBlockUntilSyncsWithGoroutines(t *testing.T) {
	f := NewFake(t0)
	done := make(chan time.Time)
	go func() { done <- <-f.After(5 * time.Second) }()

	f.BlockUntil(1) // the goroutine is now waiting
	f.Advance(5 * time.Second)
	if got := <-done; !got.Equal(t0.Add(5 * time.Second)) {
		t.Fatalf("goroutine woke with %v", got)
	}
	if n := f.Waiters(); n != 0 {
		t.Fatalf("Waiters = %d after firing, want 0", n)
	}
}

func TestFakeConcurrentUse(t *testing.T) {
	f := NewFake(t0)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); <-f.After(time.Second) }()
		go func() { defer wg.Done(); _ = f.Now() }()
	}
	f.BlockUntil(50)
	f.Advance(time.Second)
	wg.Wait()
}

func TestRealMonoMovesForward(t *testing.T) {
	var c Clock = NewReal()
	a := c.Mono()
	if a < 0 {
		t.Fatalf("Mono = %v, want >= 0", a)
	}
	<-c.After(time.Millisecond)
	if b := c.Mono(); b <= a {
		t.Fatalf("Real.Mono did not advance: %v then %v", a, b)
	}
}

func TestZeroRealIsUsable(t *testing.T) {
	// Real{} must keep working (existing callers); its Mono is non-decreasing.
	var c Clock = Real{}
	a := c.Mono()
	if b := c.Mono(); b < a {
		t.Fatalf("zero Real.Mono went backwards: %v then %v", a, b)
	}
}

func TestFakeMonoStartsAtZero(t *testing.T) {
	f := NewFake(t0)
	if got := f.Mono(); got != 0 {
		t.Fatalf("Mono = %v, want 0", got)
	}
}

func TestFakeAdvanceMovesWallAndMono(t *testing.T) {
	f := NewFake(t0)
	f.Advance(90 * time.Second)
	if got := f.Mono(); got != 90*time.Second {
		t.Fatalf("Mono = %v, want 90s", got)
	}
	if got, want := f.Now(), t0.Add(90*time.Second); !got.Equal(want) {
		t.Fatalf("Now = %v, want %v", got, want)
	}
}

func TestFakeSetMovesWallOnly(t *testing.T) {
	// M-D23: a wall-clock change (NTP step, operator) must not move Mono.
	f := NewFake(t0)
	f.Advance(time.Minute)
	f.Set(t0.Add(-time.Hour))
	if got := f.Mono(); got != time.Minute {
		t.Fatalf("after Set backwards: Mono = %v, want 1m", got)
	}
	f.Set(t0.Add(24 * time.Hour))
	if got := f.Mono(); got != time.Minute {
		t.Fatalf("after Set forwards: Mono = %v, want 1m", got)
	}
	f.Advance(time.Second)
	if got, want := f.Now(), t0.Add(24*time.Hour+time.Second); !got.Equal(want) {
		t.Fatalf("Advance after Set: Now = %v, want %v", got, want)
	}
}

func TestFakeSetForwardsDoesNotFireTimers(t *testing.T) {
	// Timers run on the monotonic clock, like Go's: a wall jump never fires
	// them early.
	f := NewFake(t0)
	ch := f.After(time.Second)
	f.Set(t0.Add(time.Hour))
	select {
	case <-ch:
		t.Fatal("timer fired on a forward wall jump")
	default:
	}
	f.Advance(time.Second)
	select {
	case got := <-ch:
		if want := t0.Add(time.Hour + time.Second); !got.Equal(want) {
			t.Fatalf("fired with %v, want wall now %v", got, want)
		}
	default:
		t.Fatal("did not fire after 1s of monotonic time")
	}
}

func TestFakeTimerAfterBackwardsSetFiresOnMonoDeadline(t *testing.T) {
	f := NewFake(t0)
	ch := f.After(10 * time.Second)
	f.Set(t0.Add(-time.Hour))
	f.Advance(10 * time.Second)
	select {
	case <-ch:
	default:
		t.Fatal("timer did not fire after its monotonic duration elapsed")
	}
}

func TestFakeAdvanceNegativePanics(t *testing.T) {
	f := NewFake(t0)
	defer func() {
		if recover() == nil {
			t.Fatal("Advance(-1s) did not panic")
		}
		if got := f.Mono(); got != 0 {
			t.Fatalf("Mono = %v after rejected Advance, want 0", got)
		}
	}()
	f.Advance(-time.Second)
}
