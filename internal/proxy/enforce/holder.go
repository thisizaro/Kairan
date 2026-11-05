package enforce

import (
	"sync/atomic"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// Active is the policy the proxy enforces, with the hash it was verified
// under and the proxy state it belongs to. An Active is immutable once
// stored: to change anything, build a new one and Store it. One request reads
// one Active, so its decision, its version and its hash always come from the
// same policy (I3, I5).
type Active struct {
	Policy *policy.Policy // nil = no policy: every call is denied
	Hash   wire.Hash
	State  wire.ProxyState
}

// Holder is the atomic swap point between the agent loop (which stores a new
// Active after trust.Accept, Save and Append) and the request handlers.
type Holder struct {
	p atomic.Pointer[Active]
}

// Load returns the current Active, or nil before the first Store. A nil
// Active means DenyAll with no policy.
func (h *Holder) Load() *Active { return h.p.Load() }

// Store replaces the current Active. Requests already running keep the one
// they loaded.
func (h *Holder) Store(a *Active) { h.p.Store(a) }
