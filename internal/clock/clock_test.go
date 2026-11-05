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
