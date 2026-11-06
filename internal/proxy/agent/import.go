package agent

import (
	"errors"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// Imported describes a bundle that Import applied.
type Imported struct {
	Version  uint64    // the version now in force
	Previous uint64    // the highest version applied before it (0 if none)
	Hash     wire.Hash // hash of the signed payload
}

// ImportError is a rejected bundle. Code is the same wire error code the
// control plane path would report, and the rejection is in the apply log.
type ImportError struct{ Code wire.ErrorCode }

func (e *ImportError) Error() string { return "agent: bundle rejected: " + string(e.Code) }

// Import applies an offline bundle (PRD J3, P-11): one JSON-encoded envelope,
// read with the strict decoder (trust.DecodeEnvelope) and then put through
// exactly the checks and steps of an envelope from the control plane:
// trust.Accept (threshold of distinct trusted signatures, tenant, version
// above the floor, not expired at effective_now), store.Save, applylog.Append,
// then the Holder swap. A rejection (including a file that is not an
// envelope) keeps the policy in force, is counted, and is written to the apply
// log; the returned error is an *ImportError with the code. Boot must have
// been called, and Run need not be. Import does not save the clock guard's
// high-water mark; the caller does that when it is done.
func (a *Agent) Import(data []byte) (Imported, error) {
	a.mu.Lock()
	booted := a.booted
	a.mu.Unlock()
	if !booted {
		return Imported{}, errors.New("agent: Import before Boot")
	}
	from := a.lastApplied()
	env, err := trust.DecodeEnvelope(data)
	if err != nil {
		a.reject(wire.ErrMalformed, 0, "", from)
		return Imported{}, &ImportError{Code: wire.ErrMalformed}
	}
	if !a.apply(env, 0) {
		a.mu.Lock()
		defer a.mu.Unlock()
		code := wire.ErrMalformed
		if a.lastErr != nil {
			code = a.lastErr.Code
		}
		return Imported{}, &ImportError{Code: code}
	}
	s := a.Snapshot()
	return Imported{Version: s.AppliedVersion, Previous: from, Hash: s.PolicyHash}, nil
}
