// Package statebreak holds black-box attack tests for the proxy state machine
// (task P-01). Sources: ARCHITECTURE section 4 (diagram, boot rule, "no
// transition ever makes permissions wider"), section 8, M-D33/M-D39, PRD I3, and
// the go doc of the state package.
package statebreak

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"testing"

	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

var allStates = []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode}

var allEvents = []state.Event{state.BootNoPolicy, state.BootTampered, state.BootValid, state.BootExpired, state.Applied, state.Rejected, state.Expired}

var eventName = map[state.Event]string{
	state.BootNoPolicy: "BootNoPolicy", state.BootTampered: "BootTampered", state.BootValid: "BootValid",
	state.BootExpired: "BootExpired", state.Applied: "Applied", state.Rejected: "Rejected", state.Expired: "Expired",
}

// rank is how much a state lets through: nothing < safe mode (R only) < enforcing.
func rank(s wire.ProxyState) int {
	switch s {
	case wire.StateEnforcing:
		return 2
	case wire.StateSafeMode:
		return 1
	default:
		return 0
	}
}

// Independent model of the section 4 diagram. ok=false means "no arrow".
var arrows = map[wire.ProxyState]map[state.Event]wire.ProxyState{
	wire.StateBooting: {
		state.BootNoPolicy: wire.StateDenyAll,
		state.BootTampered: wire.StateTampered,
		state.BootValid:    wire.StateEnforcing,
		state.BootExpired:  wire.StateSafeMode,
	},
	wire.StateDenyAll:   {state.Applied: wire.StateEnforcing},
	wire.StateTampered:  {state.Applied: wire.StateEnforcing},
	wire.StateEnforcing: {state.Applied: wire.StateEnforcing, state.Rejected: wire.StateEnforcing, state.Expired: wire.StateSafeMode},
	wire.StateSafeMode:  {state.Applied: wire.StateEnforcing},
}

func TestEventValuesMatchDocOrder(t *testing.T) {
	// ARCH section 10 proxy/state lists the events with iota in this order.
	want := []state.Event{0, 1, 2, 3, 4, 5, 6}
	for i, e := range allEvents {
		if e != want[i] {
			t.Fatalf("event %s = %d, want %d", eventName[e], e, want[i])
		}
	}
}

func TestNextExactlyTheArrows(t *testing.T) {
	for _, s := range allStates {
		for _, e := range allEvents {
			s, e := s, e
			t.Run(fmt.Sprintf("%s/%s", s, eventName[e]), func(t *testing.T) {
				got := state.Next(s, e)
				want, hasArrow := arrows[s][e]
				if !hasArrow {
					want = s // "an unknown state or event leaves the state unchanged"; no arrow = no move
					// Booting + Applied is not an arrow either; narrower-or-equal is all we insist on.
					if s == wire.StateBooting && e == state.Applied {
						if got != wire.StateBooting && got != wire.StateEnforcing {
							t.Fatalf("Booting+Applied -> %q", got)
						}
						return
					}
				}
				if got != want {
					t.Fatalf("Next(%s, %s) = %q, want %q", s, eventName[e], got, want)
				}
			})
		}
	}
}

func TestI3NoWideningWithoutAValidPolicy(t *testing.T) {
	// The only events that may raise a state's rank: Applied (a verified, persisted
	// policy), and from Booting the boot events that carry a verified stored policy.
	for _, s := range allStates {
		for _, e := range allEvents {
			got := state.Next(s, e)
			if rank(got) > rank(s) {
				ok := e == state.Applied || (s == wire.StateBooting && (e == state.BootValid || e == state.BootExpired))
				if !ok {
					t.Fatalf("I3: Next(%s, %s) = %s widened permissions", s, eventName[e], got)
				}
			}
		}
	}
	// Specific hazards from the doc.
	hazards := []struct {
		s   wire.ProxyState
		e   state.Event
		not wire.ProxyState
		why string
	}{
		{wire.StateDenyAll, state.Expired, wire.StateSafeMode, "no policy cannot expire into safe mode (R-only is wider than deny-all)"},
		{wire.StateTampered, state.Expired, wire.StateSafeMode, "tampered must not relax to safe mode"},
		{wire.StateTampered, state.Rejected, wire.StateEnforcing, "rejected envelope cannot clear tamper"},
		{wire.StateTampered, state.BootValid, wire.StateEnforcing, "boot events after boot change nothing"},
		{wire.StateTampered, state.BootExpired, wire.StateSafeMode, "boot events after boot change nothing"},
		{wire.StateTampered, state.BootNoPolicy, wire.StateDenyAll, "tampered must not relax to deny-all label"},
		{wire.StateDenyAll, state.BootValid, wire.StateEnforcing, "boot events after boot change nothing"},
		{wire.StateDenyAll, state.BootExpired, wire.StateSafeMode, "boot events after boot change nothing"},
		{wire.StateDenyAll, state.Rejected, wire.StateEnforcing, "rejected must not enforce"},
		{wire.StateSafeMode, state.Rejected, wire.StateEnforcing, "rejected must not leave safe mode"},
		{wire.StateSafeMode, state.BootValid, wire.StateEnforcing, "boot events after boot change nothing"},
		{wire.StateSafeMode, state.Expired, wire.StateEnforcing, "expiry cannot widen"},
		{wire.StateEnforcing, state.BootTampered, wire.StateTampered, "boot events after boot change nothing (documented)"},
	}
	for _, h := range hazards {
		if h.e == state.BootTampered || h.e == state.BootNoPolicy {
			// These two are narrowing, so only the "documented as no-op" claim is checked.
			if got := state.Next(h.s, h.e); got != h.s {
				t.Fatalf("%s: Next(%s,%s)=%s, doc says boot events change nothing after boot", h.why, h.s, eventName[h.e], got)
			}
			continue
		}
		if got := state.Next(h.s, h.e); got == h.not {
			t.Fatalf("%s: Next(%s,%s)=%s", h.why, h.s, eventName[h.e], got)
		}
	}
}

func TestBootEventsOnlyMeaningfulInBooting(t *testing.T) {
	// "Boot events are only meaningful in Booting; after boot they change nothing."
	for _, s := range allStates {
		if s == wire.StateBooting {
			continue
		}
		for _, e := range []state.Event{state.BootNoPolicy, state.BootTampered, state.BootValid, state.BootExpired} {
			if got := state.Next(s, e); got != s {
				t.Fatalf("Next(%s, %s) = %s, doc says boot events change nothing after boot", s, eventName[e], got)
			}
		}
	}
}

func TestUnknownEventsAndStatesChangeNothing(t *testing.T) {
	badEvents := []state.Event{-1, 7, 8, 100, math.MaxInt32, math.MinInt32, math.MaxInt64, math.MinInt64}
	for _, s := range allStates {
		for _, e := range badEvents {
			if got := state.Next(s, e); got != s {
				t.Fatalf("Next(%s, unknown event %d) = %s, want unchanged", s, e, got)
			}
		}
	}
	badStates := []wire.ProxyState{"", "bogus", "ENFORCING", "Enforcing", "enforcing ", " enforcing", "enforcing\x00", "safe-mode", "SafeMode", "deny-all", "tampered\n", "enforcing\u200b", "\xff"}
	for _, s := range badStates {
		for _, e := range append(append([]state.Event{}, allEvents...), badEvents...) {
			got := state.Next(s, e)
			if got != s {
				t.Fatalf("Next(%q, %d) = %q, doc says unknown state is unchanged", s, e, got)
			}
		}
		// An unknown state must never allow anything.
		for _, mode := range []state.SafeMode{state.ReadOnly, state.DenyAll, "x"} {
			if state.Allows(s, true, 'R', mode) {
				t.Fatalf("Allows(unknown state %q) = true", s)
			}
		}
	}
}

func TestNextOutputIsAlwaysAValidState(t *testing.T) {
	for _, s := range allStates {
		if !s.Valid() {
			t.Fatalf("wire says %q is not valid", s)
		}
		for _, e := range allEvents {
			if got := state.Next(s, e); !got.Valid() {
				t.Fatalf("Next(%s,%s) = invalid state %q", s, eventName[e], got)
			}
		}
	}
}

func TestRandomEventSequencesNeverWiden(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for iter := 0; iter < 5000; iter++ {
		s := wire.StateBooting
		// "last valid policy rank": what the most recent verified policy would allow.
		cap := 0 // boot has not produced a policy yet
		for i := 0; i < 60; i++ {
			var e state.Event
			if r.Intn(12) == 0 {
				e = state.Event(r.Intn(200) - 50) // garbage events
			} else {
				e = allEvents[r.Intn(len(allEvents))]
			}
			prev := s
			s = state.Next(s, e)
			switch {
			case e == state.Applied && s == wire.StateEnforcing:
				cap = 2 // a newly accepted policy is fully valid
			case prev == wire.StateBooting && e == state.BootValid:
				cap = 2
			case prev == wire.StateBooting && e == state.BootExpired:
				cap = 1
			}
			// Expiry of the policy can only narrow; the state may never exceed the cap.
			if rank(s) > cap {
				t.Fatalf("iter %d step %d: state %s (rank %d) exceeds what the last valid policy allows (cap %d) after event %d", iter, i, s, rank(s), cap, e)
			}
			if e == state.Expired || e == state.Rejected {
				if rank(s) > rank(prev) {
					t.Fatalf("Expired/Rejected widened %s -> %s", prev, s)
				}
			}
			if cap == 2 && s == wire.StateSafeMode {
				cap = 1 // policy expired: until Applied, the cap is R-only
			}
			if s == wire.StateDenyAll || s == wire.StateTampered || s == wire.StateBooting {
				cap = 0
			}
		}
	}
}

func TestTamperedNeverLeavesExceptByApplied(t *testing.T) {
	r := rand.New(rand.NewSource(9))
	for iter := 0; iter < 2000; iter++ {
		s := state.Next(wire.StateBooting, state.BootTampered)
		if s != wire.StateTampered {
			t.Fatalf("BootTampered from Booting -> %q", s)
		}
		for i := 0; i < 50; i++ {
			e := allEvents[r.Intn(len(allEvents))]
			if e == state.Applied {
				continue
			}
			if s = state.Next(s, e); s != wire.StateTampered {
				t.Fatalf("left Tampered via %s -> %s", eventName[e], s)
			}
		}
	}
}

func TestDenyAllNeverLeavesExceptByApplied(t *testing.T) {
	for _, e := range allEvents {
		if e == state.Applied {
			continue
		}
		if got := state.Next(wire.StateDenyAll, e); got != wire.StateDenyAll {
			t.Fatalf("DenyAll + %s -> %s", eventName[e], got)
		}
	}
	if got := state.Next(wire.StateDenyAll, state.Applied); got != wire.StateEnforcing {
		t.Fatalf("DenyAll + Applied -> %s (first valid policy must enforce)", got)
	}
}

// --- Allows ---------------------------------------------------------------

func TestAllowsExhaustiveNeverWider(t *testing.T) {
	modes := []state.SafeMode{state.ReadOnly, state.DenyAll, "", "bogus", "READ_ONLY", "Read_Only", " read_only", "read_only ", "read_only\n", "read-only", "allow_all", "all", "off", "*", "read_only\x00", "deny_all ", "DENY_ALL", "\xff"}
	states := append(append([]wire.ProxyState{}, allStates...), "", "bogus", "ENFORCING", "enforcing ")
	for _, s := range states {
		for _, m := range modes {
			for _, allowed := range []bool{false, true} {
				for c := 0; c < 256; c++ {
					got := state.Allows(s, allowed, byte(c), m)
					if !got {
						continue
					}
					// Derive what is permitted from the doc only.
					switch {
					case s == wire.StateEnforcing && allowed:
					case s == wire.StateSafeMode && m == state.ReadOnly && allowed && c == 'R':
					case s == wire.StateSafeMode && m == "" && allowed && c == 'R':
						// zero-value mode: doc is silent (default is read_only, "unknown counts as deny_all");
						// both are no wider than read_only, so tolerated.
					default:
						t.Fatalf("Allows(%q, allowed=%v, class=%q, mode=%q) = true: wider than the doc allows", s, allowed, rune(c), m)
					}
				}
			}
		}
	}
}

func TestAllowsTruthTable(t *testing.T) {
	cases := []struct {
		s       wire.ProxyState
		allowed bool
		class   byte
		mode    state.SafeMode
		want    bool
	}{
		{wire.StateEnforcing, true, 'R', state.ReadOnly, true},
		{wire.StateEnforcing, true, 'W', state.ReadOnly, true},
		{wire.StateEnforcing, true, 'X', state.DenyAll, true},
		{wire.StateEnforcing, false, 'R', state.ReadOnly, false},
		{wire.StateEnforcing, false, 'X', state.ReadOnly, false},
		{wire.StateEnforcing, true, 0, state.ReadOnly, true}, // class irrelevant when enforcing
		{wire.StateSafeMode, true, 'R', state.ReadOnly, true},
		{wire.StateSafeMode, true, 'W', state.ReadOnly, false},
		{wire.StateSafeMode, true, 'X', state.ReadOnly, false},
		{wire.StateSafeMode, true, 'r', state.ReadOnly, false}, // case-sensitive
		{wire.StateSafeMode, true, 0, state.ReadOnly, false},
		{wire.StateSafeMode, true, 0xff, state.ReadOnly, false},
		{wire.StateSafeMode, false, 'R', state.ReadOnly, false}, // policy denial still wins
		{wire.StateSafeMode, true, 'R', state.DenyAll, false},
		{wire.StateSafeMode, true, 'R', "bogus", false},
		{wire.StateSafeMode, true, 'R', "READ_ONLY", false},
		{wire.StateSafeMode, true, 'R', " read_only", false},
		{wire.StateSafeMode, true, 'R', "read_only\n", false},
		{wire.StateSafeMode, true, 'R', "allow_all", false},
		{wire.StateDenyAll, true, 'R', state.ReadOnly, false},
		{wire.StateTampered, true, 'R', state.ReadOnly, false},
		{wire.StateBooting, true, 'R', state.ReadOnly, false},
		{wire.StateDenyAll, true, 'X', state.ReadOnly, false},
		{wire.StateTampered, true, 'W', state.ReadOnly, false},
	}
	for i, c := range cases {
		if got := state.Allows(c.s, c.allowed, c.class, c.mode); got != c.want {
			t.Fatalf("case %d: Allows(%s, %v, %q, %q) = %v, want %v", i, c.s, c.allowed, rune(c.class), c.mode, got, c.want)
		}
	}
}

func TestParseSafeMode(t *testing.T) {
	good := map[string]state.SafeMode{"": state.ReadOnly, "read_only": state.ReadOnly, "deny_all": state.DenyAll}
	for in, want := range good {
		got, err := state.ParseSafeMode(in)
		if err != nil || got != want {
			t.Fatalf("ParseSafeMode(%q) = %q, %v; want %q, nil", in, got, err, want)
		}
	}
	if state.ReadOnly != "read_only" || state.DenyAll != "deny_all" {
		t.Fatalf("enum values changed: %q %q", state.ReadOnly, state.DenyAll)
	}
	bad := []string{
		"READ_ONLY", "Read_Only", "read_only ", " read_only", "read_only\n", "read_only\x00", "read-only", "readonly",
		"deny_all ", "DENY_ALL", "Deny_All", "deny-all", "denyall", "deny", "allow", "allow_all", "all", "off", "none",
		"*", "true", "false", "0", "1", "null", "read_only,deny_all", "read_only;", "\u200bread_only", "read_onlý",
		"rеad_only", // Cyrillic e
		"\xff", "read_only\r\n", "%72ead_only",
	}
	for _, in := range bad {
		got, err := state.ParseSafeMode(in)
		if err == nil {
			t.Fatalf("ParseSafeMode(%q) accepted as %q: only the enum is allowed (M-D33)", in, got)
		}
		if got == state.ReadOnly {
			t.Fatalf("ParseSafeMode(%q) returned read_only alongside an error: a caller that ignores the error would run wider than configured", in)
		}
		// Even if the caller ignores the error, the returned value must not widen.
		for _, c := range []byte{'R', 'W', 'X'} {
			if state.Allows(wire.StateSafeMode, true, c, got) && got != "" {
				t.Fatalf("ParseSafeMode(%q) error path returned %q which allows class %c in safe mode", in, got, c)
			}
		}
	}
}

func TestConcurrentUse(t *testing.T) {
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			s := wire.StateBooting
			for i := 0; i < 2000; i++ {
				s = state.Next(s, allEvents[(g+i)%len(allEvents)])
				_ = state.Allows(s, true, 'R', state.ReadOnly)
				_, _ = state.ParseSafeMode("deny_all")
			}
		}(g)
	}
	wg.Wait()
}

func FuzzNextAllowsNeverWiden(f *testing.F) {
	f.Add("enforcing", 3, true, byte('R'), "read_only")
	f.Add("", -1, false, byte(0), "")
	f.Fuzz(func(t *testing.T, s string, e int, allowed bool, class byte, mode string) {
		st := wire.ProxyState(s)
		n := state.Next(st, state.Event(e))
		if !st.Valid() && n != st {
			t.Fatalf("unknown state %q moved to %q", s, n)
		}
		if rank(n) > rank(st) && !(e == int(state.Applied) || (st == wire.StateBooting && (e == int(state.BootValid) || e == int(state.BootExpired)))) {
			t.Fatalf("Next(%q,%d) = %q widened", s, e, n)
		}
		if state.Allows(st, allowed, class, state.SafeMode(mode)) {
			if !allowed {
				t.Fatal("allowed despite policy verdict false")
			}
			switch st {
			case wire.StateEnforcing:
			case wire.StateSafeMode:
				if class != 'R' || (state.SafeMode(mode) != state.ReadOnly && mode != "") {
					t.Fatalf("safe mode allowed class %q under mode %q", class, mode)
				}
			default:
				t.Fatalf("state %q allowed a call", s)
			}
		}
	})
}
