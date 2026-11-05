package store

import (
	"errors"
	"fmt"
	"time"

	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

// Checked is what a successful re-verification of the stored envelope gives
// back. It is a small projection of trust.Verified, so this package does not
// import trust or policy: the real wiring (P-05, P-07) wraps trust.Verify.
type Checked struct {
	Version uint64    // policy version
	Hash    wire.Hash // payload hash
	Expires time.Time // policy expires_at
}

// Verifier re-checks an envelope's signatures, threshold, tenant and format
// against the proxy's local root. It must not check version or expiry (it is
// trust.Verify). A non-nil error means the envelope is not trusted.
type Verifier func(env wire.Envelope) (Checked, error)

// Stored is the outcome of looking at the policy file and re-verifying it.
type Stored struct {
	Found   bool    // a file exists
	Err     error   // Load or verification failed; the file must not be enforced
	Checked Checked // valid only if Found and Err == nil
}

// Inspect loads the stored envelope and re-verifies it. It never returns a
// value that can be enforced unless verification passed: any Load or verify
// error ends up in Stored.Err. The verified envelope is returned so the
// caller can install it.
func Inspect(s *Store, verify Verifier) (Stored, wire.Envelope) {
	env, found, err := s.Load()
	if err != nil {
		return Stored{Found: found, Err: err}, wire.Envelope{}
	}
	if !found {
		return Stored{}, wire.Envelope{}
	}
	if verify == nil {
		return Stored{Found: true, Err: errors.New("store: no verifier")}, wire.Envelope{}
	}
	c, err := verify(env)
	if err != nil {
		return Stored{Found: true, Err: err}, wire.Envelope{}
	}
	return Stored{Found: true, Checked: c}, env
}

// LogView is what boot needs from the apply log. The caller fills it from
// applylog.Open (OpenErr), Log.Head and Log.LastApplied.
type LogView struct {
	OpenErr     error     // applylog.Open failed (chain broken, truncated last line, ...)
	Seq         uint64    // Head seq; 0 = empty log
	AppliedVer  uint64    // LastApplied version; 0 = nothing applied
	AppliedHash wire.Hash // LastApplied payload hash
}

// BootDecision is the result of DecideBoot.
type BootDecision struct {
	Event state.Event
	// Repair is true if the caller must append a repair entry (applied,
	// To = stored version, Hash = stored hash) before going on: the stored
	// policy is newer than the log because a crash fell between Save and
	// Append (M-D33). It is only ever true with BootValid or BootExpired.
	Repair bool
	// Reason is a short fixed phrase for the operator log. It never holds
	// file content.
	Reason string
}

// DecideBoot is the boot rule of ARCHITECTURE section 4 (M-D33) as pure
// logic. now is effective_now (M-D30). Nothing here can make the proxy trust
// more than a verified, non-stale file:
//
//   - apply log does not open (including a truncated last line): Tampered.
//     There is no auto-repair; an operator acts.
//   - file exists but cannot be loaded or fails verification: Tampered.
//   - no file and nothing was ever applied: BootNoPolicy (deny-all).
//   - no file but the log says a policy was applied: Tampered.
//   - stored version below the log's last applied: Tampered (an older valid
//     policy was put back).
//   - same version as the log's last applied but a different payload hash:
//     Tampered.
//   - stored version above the log's last applied: accept, with Repair.
//   - then BootExpired if now is at or after the expiry, else BootValid.
func DecideBoot(st Stored, lg LogView, now time.Time) BootDecision {
	tampered := func(why string) BootDecision {
		return BootDecision{Event: state.BootTampered, Reason: why}
	}
	switch {
	case lg.OpenErr != nil:
		return tampered("apply log failed verification")
	case st.Err != nil:
		return tampered("stored policy failed to load or verify")
	case !st.Found:
		if lg.AppliedVer > 0 {
			return tampered("stored policy missing but the apply log has applied versions")
		}
		return BootDecision{Event: state.BootNoPolicy, Reason: "no stored policy"}
	}

	c := st.Checked
	var repair bool
	switch {
	case c.Version == 0:
		return tampered("stored policy has no version")
	case c.Version < lg.AppliedVer:
		return tampered(fmt.Sprintf("stored version %d is below the apply log's %d", c.Version, lg.AppliedVer))
	case c.Version == lg.AppliedVer:
		if c.Hash != lg.AppliedHash {
			return tampered("stored policy differs from the one the apply log recorded")
		}
	default:
		repair = true
	}

	if !now.Before(c.Expires) {
		return BootDecision{Event: state.BootExpired, Repair: repair, Reason: "stored policy expired"}
	}
	return BootDecision{Event: state.BootValid, Repair: repair, Reason: "stored policy valid"}
}
