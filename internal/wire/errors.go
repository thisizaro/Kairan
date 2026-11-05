package wire

// ErrorCode is the only way errors cross the wire: a fixed code, never text,
// so an error can't smuggle request data (I4).
type ErrorCode string

// Request errors returned by kairan-cp in an ErrorResponse.
const (
	ErrBadRequest   ErrorCode = "bad_request"  // 400
	ErrUnauthorized ErrorCode = "unauthorized" // 401: missing or wrong token
	ErrForbidden    ErrorCode = "forbidden"    // 403: token valid, but not for this proxy or tenant
	ErrNotFound     ErrorCode = "not_found"    // 404
	ErrConflict     ErrorCode = "conflict"     // 409: e.g. publishing a version that already exists
	ErrTooLarge     ErrorCode = "too_large"    // 413
	ErrInternal     ErrorCode = "internal"     // 500
)

// Envelope rejection and apply-failure reasons, used by the control plane on
// publish and by proxies in ApplyError and RolloutView.Reason.
const (
	ErrMalformed   ErrorCode = "malformed"         // envelope or policy fails strict parsing
	ErrPayloadType ErrorCode = "payload_type"      // not PayloadTypePolicy
	ErrThreshold   ErrorCode = "threshold_not_met" // fewer valid signatures from distinct trusted keys than required
	ErrWrongTenant ErrorCode = "wrong_tenant"
	ErrNotNewer    ErrorCode = "version_not_newer" // rollback/replay protection (I2)
	ErrExpired     ErrorCode = "expired"
	ErrPersist     ErrorCode = "persist_failed" // could not write the policy to disk
	ErrTampered    ErrorCode = "tampered"       // policy on disk failed verification at load
	ErrCanaryLost  ErrorCode = "canary_lost"    // rollout halted: canary stopped reporting
)

func (c ErrorCode) Valid() bool {
	switch c {
	case ErrBadRequest, ErrUnauthorized, ErrForbidden, ErrNotFound, ErrConflict, ErrTooLarge, ErrInternal,
		ErrMalformed, ErrPayloadType, ErrThreshold, ErrWrongTenant, ErrNotNewer, ErrExpired, ErrPersist,
		ErrTampered, ErrCanaryLost:
		return true
	}
	return false
}

// ErrorResponse is the body of every non-2xx response from kairan-cp.
type ErrorResponse struct {
	Code ErrorCode `json:"code"`
}
