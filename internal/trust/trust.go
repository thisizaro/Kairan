package trust

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// MaxSkew is the largest expiry tolerance Accept allows (M-D33).
const MaxSkew = 5 * time.Minute

var (
	// ErrBadRoot means the trust root is below the floor: threshold under 2,
	// fewer keys than the threshold, a key stored under the wrong ID, a key of
	// the wrong size, or a bad tenant. It is a Go error, not a wire code
	// (M-D39). It is never a pass: no policy is accepted from such a root.
	ErrBadRoot = errors.New("trust: bad trust root")
	// ErrBadSkew means Accept was given a skew outside [0, MaxSkew].
	ErrBadSkew = errors.New("trust: bad skew")
	// ErrRejected wraps every envelope rejection. The wire.ErrorCode returned
	// with it says why. Messages are fixed text and never echo envelope data.
	ErrRejected = errors.New("trust: envelope rejected")
)

// Root is the proxy's trust root. It comes from local config only, never from
// the control plane.
type Root struct {
	Tenant    wire.ID
	Keys      map[wire.Hash]ed25519.PublicKey // key ID -> key
	Threshold int                             // >= 2 and <= len(Keys), else ErrBadRoot
}

// check enforces the floor. A map entry whose key does not hash to its ID is
// rejected: otherwise one key stored under two IDs could count as two signers.
func (r Root) check() error {
	if !r.Tenant.Valid() || r.Threshold < 2 || len(r.Keys) < r.Threshold {
		return ErrBadRoot
	}
	for id, key := range r.Keys {
		if len(key) != ed25519.PublicKeySize || KeyID(key) != id {
			return ErrBadRoot
		}
	}
	return nil
}

// Verified is a policy that passed Verify or Accept.
type Verified struct {
	Policy  *policy.Policy
	Hash    wire.Hash   // SHA-256 of the exact payload bytes
	Signers []wire.Hash // distinct trusted key IDs with a valid signature, sorted
}

func reject(code wire.ErrorCode, reason string) (Verified, wire.ErrorCode, error) {
	return Verified{}, code, fmt.Errorf("%w: %s", ErrRejected, reason)
}

// Verify checks, in order: the root floor (ErrBadRoot), payload type
// (payload_type), shape (malformed), at least root.Threshold valid signatures
// from distinct trusted keys (threshold_not_met), strict policy parse
// (malformed) and tenant (wrong_tenant). It does not look at version or
// expiry; the proxy uses it at boot to re-check the stored envelope.
//
// On success the code is "" and the error nil. On rejection the Verified is
// the zero value. ErrBadRoot comes with an empty code.
func Verify(env wire.Envelope, root Root) (Verified, wire.ErrorCode, error) {
	if err := root.check(); err != nil {
		return Verified{}, "", err
	}
	if env.PayloadType != wire.PayloadTypePolicy {
		return reject(wire.ErrPayloadType, "payload type")
	}
	if env.ValidateShape() != nil {
		return reject(wire.ErrMalformed, "envelope shape")
	}
	signers := validSigners(env, root.Keys)
	if len(signers) < root.Threshold {
		return reject(wire.ErrThreshold, "too few valid signatures from distinct trusted keys")
	}
	pol, err := policy.Parse(env.Payload)
	if err != nil {
		return reject(wire.ErrMalformed, "policy")
	}
	if pol.Tenant != root.Tenant {
		return reject(wire.ErrWrongTenant, "tenant")
	}
	sum := sha256.Sum256(env.Payload)
	return Verified{Policy: pol, Hash: wire.Hash(hex.EncodeToString(sum[:])), Signers: signers}, "", nil
}

// Accept is Verify plus replay and expiry protection, for new envelopes from
// the control plane or an offline bundle: the policy version must be greater
// than have (I2), then the policy must not be expired at now. Expiry is
// exclusive and tolerates skew: expired when now >= expires_at + skew.
// skew must be within [0, MaxSkew], else ErrBadSkew. The proxy passes
// effective_now as now (M-D30); this package never reads a clock.
func Accept(env wire.Envelope, root Root, have uint64, now time.Time, skew time.Duration) (Verified, wire.ErrorCode, error) {
	if skew < 0 || skew > MaxSkew {
		return Verified{}, "", ErrBadSkew
	}
	v, code, err := Verify(env, root)
	if err != nil {
		return v, code, err
	}
	if v.Policy.Version <= have {
		return reject(wire.ErrNotNewer, "version")
	}
	if !now.Before(v.Policy.ExpiresAt.Add(skew)) {
		return reject(wire.ErrExpired, "expired")
	}
	return v, "", nil
}
