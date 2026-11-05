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
	Now() time.Time
	// After returns a channel that receives the clock's time once d has passed.
	After(d time.Duration) <-chan time.Time
}

// Real is the system clock.
type Real struct{}

func (Real) Now() time.Time                         { return time.Now() }
func (Real) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Fake is a manual clock for tests. Time moves only through Advance or Set.
// It is safe for concurrent use.
type Fake struct {
	mu      sync.Mutex
	cond    *sync.Cond
	now     time.Time
	waiters []waiter
}

type waiter struct {
	deadline time.Time
	ch       chan time.Time
}

// NewFake returns a Fake clock reading start.
func NewFake(start time.Time) *Fake {
	f := &Fake{now: start}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// After fires immediately when d <= 0, otherwise when the clock reaches now+d.
func (f *Fake) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch := make(chan time.Time, 1)
	if d <= 0 {
		ch <- f.now
		return ch
	}
	f.waiters = append(f.waiters, waiter{deadline: f.now.Add(d), ch: ch})
	f.cond.Broadcast()
	return ch
}

// Advance moves the clock forward by d and fires every timer that is due.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setLocked(f.now.Add(d))
}

// Set jumps the clock to t, forwards or backwards (a wall-clock change).
// Timers fire only if t reaches their deadline.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setLocked(t)
}

func (f *Fake) setLocked(t time.Time) {
	f.now = t
	kept := f.waiters[:0]
	for _, w := range f.waiters {
		if !t.Before(w.deadline) {
			w.ch <- t
			continue
		}
		kept = append(kept, w)
	}
	f.waiters = kept
	f.cond.Broadcast()
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
