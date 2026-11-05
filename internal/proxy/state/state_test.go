package state

import (
	"math/rand"
	"testing"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// AllowsDecision must agree with Allows on every Decision the policy can give.
func TestAllowsDecision(t *testing.T) {
	for _, s := range allStates {
		for _, mode := range []SafeMode{ReadOnly, DenyAll, "", "wide_open"} {
			for _, allowed := range []bool{false, true} {
				for _, c := range []policy.Class{0, policy.ClassR, policy.ClassW, policy.ClassX, 'r'} {
					d := policy.Decision{Allowed: allowed, Class: c, Rule: "x"}
					if got, want := AllowsDecision(s, d, mode), Allows(s, allowed, byte(c), mode); got != want {
						t.Errorf("AllowsDecision(%s,%+v,%q) = %v, want %v", s, d, mode, got, want)
					}
				}
			}
		}
	}
	if AllowsDecision(wire.StateEnforcing, policy.Decision{}, ReadOnly) {
		t.Error("zero Decision allowed")
	}
}

var allEvents = []Event{BootNoPolicy, BootTampered, BootValid, BootExpired, Applied, Rejected, Expired}

var allStates = []wire.ProxyState{
	wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode,
}

func TestNext(t *testing.T) {
	B, D, T, E, S := wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode
	tests := []struct {
		from wire.ProxyState
		ev   Event
		want wire.ProxyState
	}{
		// Booting: only boot events leave it.
		{B, BootNoPolicy, D},
		{B, BootTampered, T},
		{B, BootValid, E},
		{B, BootExpired, S},
		{B, Applied, B},
		{B, Rejected, B},
		{B, Expired, B},
		// DenyAll: first valid policy opens it, nothing else.
		{D, Applied, E},
		{D, Rejected, D},
		{D, Expired, D},
		{D, BootNoPolicy, D},
		{D, BootTampered, D},
		{D, BootValid, D},
		{D, BootExpired, D},
		// Tampered: a valid policy from the control plane recovers it.
		{T, Applied, E},
		{T, Rejected, T},
		{T, Expired, T},
		{T, BootValid, T},
		{T, BootExpired, T},
		{T, BootNoPolicy, T},
		{T, BootTampered, T},
		// Enforcing.
		{E, Applied, E},
		{E, Rejected, E},
		{E, Expired, S},
		{E, BootNoPolicy, E},
		{E, BootTampered, E},
		{E, BootValid, E},
		{E, BootExpired, E},
		// SafeMode: only a newer valid policy leaves it.
		{S, Applied, E},
		{S, Rejected, S},
		{S, Expired, S},
		{S, BootNoPolicy, S},
		{S, BootTampered, S},
		{S, BootValid, S},
		{S, BootExpired, S},
	}
	seen := map[[2]int]bool{}
	for _, tc := range tests {
		if got := Next(tc.from, tc.ev); got != tc.want {
			t.Errorf("Next(%s, %d) = %s, want %s", tc.from, tc.ev, got, tc.want)
		}
		seen[[2]int{stateIdx(tc.from), int(tc.ev)}] = true
	}
	// The table must cover every (state, event) pair.
	for i, s := range allStates {
		for _, e := range allEvents {
			if !seen[[2]int{i, int(e)}] {
				t.Errorf("table misses (%s, %d)", s, e)
			}
		}
	}
}

func stateIdx(s wire.ProxyState) int {
	for i, x := range allStates {
		if x == s {
			return i
		}
	}
	return -1
}

func TestNextUnknownInputsChangeNothing(t *testing.T) {
	for _, s := range allStates {
		if got := Next(s, Event(99)); got != s {
			t.Errorf("unknown event moved %s to %s", s, got)
		}
		if got := Next(s, Event(-1)); got != s {
			t.Errorf("negative event moved %s to %s", s, got)
		}
	}
	for _, e := range allEvents {
		if got := Next("bogus", e); got != "bogus" {
			t.Errorf("unknown state moved by %d to %s", e, got)
		}
	}
	if Allows("bogus", true, 'R', ReadOnly) {
		t.Error("unknown state allowed a call")
	}
}

func TestAllows(t *testing.T) {
	B, D, T, E, S := wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode
	tests := []struct {
		name    string
		s       wire.ProxyState
		allowed bool
		class   byte
		mode    SafeMode
		want    bool
	}{
		{"enforcing allowed R", E, true, 'R', ReadOnly, true},
		{"enforcing allowed W", E, true, 'W', ReadOnly, true},
		{"enforcing allowed X", E, true, 'X', ReadOnly, true},
		{"enforcing allowed X deny_all mode", E, true, 'X', DenyAll, true},
		{"enforcing denied", E, false, 'R', ReadOnly, false},
		{"safe read_only R", S, true, 'R', ReadOnly, true},
		{"safe read_only W", S, true, 'W', ReadOnly, false},
		{"safe read_only X", S, true, 'X', ReadOnly, false},
		{"safe read_only R but policy denies", S, false, 'R', ReadOnly, false},
		{"safe read_only unknown class", S, true, 0, ReadOnly, false},
		{"safe read_only lowercase class", S, true, 'r', ReadOnly, false},
		{"safe deny_all R", S, true, 'R', DenyAll, false},
		{"safe unknown mode", S, true, 'R', SafeMode("wide_open"), false},
		{"safe empty mode", S, true, 'R', SafeMode(""), false},
		{"denyall R", D, true, 'R', ReadOnly, false},
		{"tampered R", T, true, 'R', ReadOnly, false},
		{"booting R", B, true, 'R', ReadOnly, false},
	}
	for _, tc := range tests {
		if got := Allows(tc.s, tc.allowed, tc.class, tc.mode); got != tc.want {
			t.Errorf("%s: Allows = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParseSafeMode(t *testing.T) {
	tests := []struct {
		in      string
		want    SafeMode
		wantErr bool
	}{
		{"", ReadOnly, false},
		{"read_only", ReadOnly, false},
		{"deny_all", DenyAll, false},
		{"allow_all", "", true},
		{"READ_ONLY", "", true},
		{" read_only", "", true},
	}
	for _, tc := range tests {
		got, err := ParseSafeMode(tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ParseSafeMode(%q) = %q, %v", tc.in, got, err)
		}
	}
}

// Property (I3): over random event sequences from Booting, a call that the
// state allows is always one that the current policy allows (Enforcing's
// answer); DenyAll, Tampered and Booting allow nothing; SafeMode read_only
// allows R only and deny_all allows nothing; and Enforcing is reachable only
// through a valid boot or an accepted policy.
func TestNoEventSequenceWidensPermissions(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	classes := []byte{'R', 'W', 'X', 0, 'r', 'Z'}
	modes := []SafeMode{ReadOnly, DenyAll, "", "junk"}
	for run := 0; run < 5000; run++ {
		s := wire.StateBooting
		var last Event = -1
		for step := 0; step < 30; step++ {
			e := allEvents[rng.Intn(len(allEvents))]
			prev := s
			s = Next(s, e)
			if s == wire.StateEnforcing && prev != wire.StateEnforcing && e != Applied && e != BootValid {
				t.Fatalf("reached Enforcing from %s via event %d", prev, e)
			}
			if s == wire.StateEnforcing && prev == wire.StateEnforcing && e == Expired {
				t.Fatalf("Enforcing survived Expired")
			}
			if s == wire.StateSafeMode && prev != wire.StateSafeMode && e != Expired && e != BootExpired {
				t.Fatalf("reached SafeMode from %s via event %d", prev, e)
			}
			last = e
			for _, allowed := range []bool{false, true} {
				for _, c := range classes {
					for _, m := range modes {
						got := Allows(s, allowed, c, m)
						if got && !allowed {
							t.Fatalf("state %s allowed a call the policy denies (last event %d)", s, last)
						}
						switch s {
						case wire.StateEnforcing:
							if got != allowed {
								t.Fatalf("Enforcing must follow the policy exactly")
							}
						case wire.StateSafeMode:
							want := allowed && c == 'R' && m == ReadOnly
							if got != want {
								t.Fatalf("SafeMode mode %q class %q allowed %v: got %v", m, c, allowed, got)
							}
						default:
							if got {
								t.Fatalf("state %s allowed a call", s)
							}
						}
					}
				}
			}
		}
	}
}

func TestSafeModeNeverWiderThanReadOnly(t *testing.T) {
	// deny_all is narrower than read_only for every input.
	for _, allowed := range []bool{false, true} {
		for c := 0; c < 256; c++ {
			if Allows(wire.StateSafeMode, allowed, byte(c), DenyAll) {
				t.Fatalf("deny_all allowed class %d", c)
			}
			if Allows(wire.StateSafeMode, allowed, byte(c), ReadOnly) && !(allowed && c == 'R') {
				t.Fatalf("read_only allowed class %d allowed=%v", c, allowed)
			}
		}
	}
}
