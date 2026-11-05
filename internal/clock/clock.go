// Package clock is the only source of time in Kairan.
//
// Core packages take the current time as an argument. Shell packages hold a
// Clock so tests can swap in Fake and control time exactly (PLAN O-04).
package clock

import (
	"sync"
	"time"
)

// Clock tells the time and makes timers.
type Clock interface {
	// Now is the wall-clock time. It can jump forwards or backwards.
	Now() time.Time
	// After returns a channel that receives the clock's wall time once d of
	// monotonic time has passed. Wall-clock jumps do not move timers.
	After(d time.Duration) <-chan time.Time
	// Mono is monotonic time since an arbitrary origin fixed per clock
	// (M-D23). It never goes backwards and ignores wall-clock changes; only
	// differences between two readings of the same clock mean anything.
	Mono() time.Duration
}

// origin is the monotonic origin for a zero Real.
var origin = time.Now()

// Real is the system clock. Use NewReal so Mono counts from construction;
// a zero Real is usable and counts from process start.
type Real struct {
	start time.Time // carries Go's monotonic reading
}

// NewReal returns the system clock with its Mono origin at the call.
func NewReal() Real { return Real{start: time.Now()} }

func (Real) Now() time.Time                         { return time.Now() }
func (Real) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Mono uses Go's monotonic clock reading (time.Since on a time.Now value).
func (r Real) Mono() time.Duration {
	if r.start.IsZero() {
		return time.Since(origin)
	}
	return time.Since(r.start)
}

// Fake is a manual clock for tests. Time moves only through Advance or Set.
// Advance moves wall and monotonic time; Set moves wall time only. Timers run
// on monotonic time, so only Advance fires them. It is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	mono    time.Duration
	waiters []waiter
}

type waiter struct {
	deadline time.Duration // monotonic
	ch       chan time.Time
}

// NewFake returns a Fake clock reading start, with Mono at 0.
func NewFake(start time.Time) *Fake {
	f := &Fake{now: start}
	f.cond = sync.NewCond(&f.mu)
	return f
}

// Mono returns the fake's monotonic time since NewFake: the sum of all
// Advance calls.
func (f *Fake) Mono() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mono
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After fires immediately when d <= 0, otherwise once Advance has moved
// monotonic time by d. It delivers the wall time at that moment.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- f.now
		return ch
	}
	f.waiters = append(f.waiters, waiter{deadline: f.mono + d, ch: ch})
	f.cond.Broadcast()
	return ch
}

// Advance moves wall and monotonic time forward by d and fires every timer
// that is due. It panics on a negative d: monotonic time never goes
// backwards (use Set to move the wall clock back).
func (f *Fake) Advance(d time.Duration) {
	if d < 0 {
		panic("clock: Fake.Advance with negative duration; use Set to move the wall clock back")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	f.mono += d
	kept := f.waiters[:0]
	for _, w := range f.waiters {
		if f.mono >= w.deadline {
			w.ch <- f.now
			continue
		}
		kept = append(kept, w)
	}
	f.waiters = kept
	f.cond.Broadcast()
}

// Set jumps the wall clock to t, forwards or backwards (an NTP step or an
// operator change). Mono does not move and no timer fires.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = t
}

// Waiters reports how many timers have not fired yet.
func (f *Fake) Waiters() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.waiters)
}

// BlockUntil waits until at least n timers are pending, so a test knows its
// goroutines are parked in After before it advances time.
func (f *Fake) BlockUntil(n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.waiters) < n {
		f.cond.Wait()
	}
}
