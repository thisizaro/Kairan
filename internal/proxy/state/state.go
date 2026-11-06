// Package state is the proxy state machine: Booting, DenyAll, Tampered,
// Enforcing and SafeMode (ARCHITECTURE section 4, section 10 proxy/state).
//
// It is a pure core package: no I/O, no clock. The shell (proxy/agent and
// proxy/store) turns what it sees (a file on disk, a verified envelope, an
// expiry check at effective_now) into an Event and asks Next for the new
// state.
//
// Invariant I3: no transition and no event sequence makes permissions wider
// than the last valid, signed, unexpired policy. Anything unknown (state,
// event, safe mode, call class) resolves to the narrower outcome.
//
// An untrusted clock is not an event. It is reported as clock_untrusted by
// the shell, and expiry already uses effective_now (M-D30).
package state

import (
	"fmt"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// Event is something the shell observed. Boot events are only meaningful in
// Booting; after boot they change nothing.
type Event int

const (
	BootNoPolicy Event = iota // nothing on disk
	BootTampered              // stored envelope failed Verify, or its version is below the apply log's last applied (M-D33)
	BootValid                 // stored envelope verified, not expired
	BootExpired               // stored envelope verified, expired -> SafeMode
	Applied                   // new envelope accepted and persisted
	Rejected                  // new envelope rejected (state unchanged)
	Expired                   // expiry passed with no newer policy
)

// SafeMode says what SafeMode allows. It is an enum; nothing is wider than
// read_only (M-D33, M-D39).
type SafeMode string

const (
	ReadOnly SafeMode = "read_only" // default: only R tools, and only if the policy allows them
	DenyAll  SafeMode = "deny_all"  // every call denied
)

// ParseSafeMode reads the config value. The empty string is the default,
// read_only. Anything else that is not in the enum is an error (the caller
// should refuse to start).
func ParseSafeMode(s string) (SafeMode, error) {
	switch SafeMode(s) {
	case "":
		return ReadOnly, nil
	case ReadOnly:
		return ReadOnly, nil
	case DenyAll:
		return DenyAll, nil
	}
	return "", fmt.Errorf("state: unknown safe mode %q (want read_only or deny_all)", s)
}

// Next returns the state after event e. An unknown state or event leaves the
// state unchanged. The transitions are exactly the arrows of section 4.
func Next(s wire.ProxyState, e Event) wire.ProxyState {
	switch s {
	case wire.StateBooting:
		switch e {
		case BootNoPolicy:
			return wire.StateDenyAll
		case BootTampered:
			return wire.StateTampered
		case BootValid:
			return wire.StateEnforcing
		case BootExpired:
			return wire.StateSafeMode
		}
	case wire.StateDenyAll, wire.StateTampered:
		if e == Applied {
			return wire.StateEnforcing
		}
	case wire.StateEnforcing:
		switch e {
		case Applied:
			return wire.StateEnforcing
		case Expired:
			return wire.StateSafeMode
		}
	case wire.StateSafeMode:
		if e == Applied {
			return wire.StateEnforcing
		}
	}
	return s
}

// Allows says whether a call may go ahead, given the state, the policy's
// verdict (allowed) and the matched tool class ('R', 'W' or 'X'), and the
// safe mode.
//
//	Enforcing:           allowed
//	SafeMode read_only:  allowed && class == 'R'
//	SafeMode deny_all:   false
//	anything else:       false
//
// An unknown safe mode counts as deny_all.
//
// Allows takes the two Decision fields it reads (decision P-D1); use
// AllowsDecision when you hold a policy.Decision.
func Allows(s wire.ProxyState, allowed bool, class byte, mode SafeMode) bool {
	switch s {
	case wire.StateEnforcing:
		return allowed
	case wire.StateSafeMode:
		return mode == ReadOnly && allowed && class == 'R'
	}
	return false
}

// AllowsDecision is Allows over a policy.Decision, the signature the
// architecture drafts (Go has no overloading, so it has its own name).
func AllowsDecision(s wire.ProxyState, d policy.Decision, mode SafeMode) bool {
	return Allows(s, d.Allowed, byte(d.Class), mode)
}
