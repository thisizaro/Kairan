// Package wire is the JSON contract between kairan-cp, kairan-proxy and kairanctl.
//
// It is the frozen contract (PLAN O-02). Changing a type, a JSON field name, a
// path or a constant here needs a decision entry and the Overseer's approval;
// the golden tests in wire_test.go fail on any accidental change.
//
// Everything a proxy sends to the control plane carries metadata only
// (invariant I4): numbers, booleans and named string types that are validated
// against a fixed pattern or enum. No field can hold tool arguments, results,
// prompts or free text.
//
// Authentication: every request carries "Authorization: Bearer <token>".
// Proxies use their enrollment token; kairanctl uses the admin token. The
// control plane knows each proxy's tenant and group from its enrollment
// registry; proxies never choose their own group.
package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// HTTP paths served by kairan-cp.
const (
	PathPoll     = "/v1/poll"     // GET  proxy:  long-poll for a newer policy (PollRequest as query)
	PathStatus   = "/v1/status"   // POST proxy:  StatusReport -> 204 No Content
	PathPolicies = "/v1/policies" // POST admin:  Envelope -> PublishResponse
	PathRollouts = "/v1/rollouts" // POST admin:  RolloutRequest -> RolloutView; GET ?tenant= -> RolloutView
	PathFleet    = "/v1/fleet"    // GET  admin:  ?tenant= -> FleetView
	PathTimeline = "/v1/timeline" // GET  admin:  ?tenant= -> TimelineView
)

// Headers.
const (
	HeaderAuthorization = "Authorization"
	BearerPrefix        = "Bearer "
	ContentTypeJSON     = "application/json"
)

// Size limits. Both sides enforce them: senders never exceed them, receivers
// reject anything larger (413 too_large).
const (
	MaxEnvelopeBytes     = 256 << 10 // JSON-encoded Envelope, also the publish body
	MaxStatusBytes       = 4 << 10   // JSON-encoded StatusReport
	MaxSmallRequestBytes = 1 << 10   // RolloutRequest and other small admin bodies
	MaxSignatures        = 8
	SignatureSize        = 64 // ed25519.SignatureSize
)

// Timing shared by kairan-proxy and kairan-sim so they behave alike.
const (
	PollHold          = 30 * time.Second // control plane holds a poll this long, then 304
	PollClientTimeout = 45 * time.Second // proxy gives up on one poll after this
	StatusInterval    = 10 * time.Second // periodic status; plus one immediately after every apply attempt
	RetryBackoffMin   = 500 * time.Millisecond
	RetryBackoffMax   = 5 * time.Second // exponential with full jitter between Min and Max
)

// ID names a tenant, proxy or group: 1-63 characters of [a-z0-9-],
// starting with a letter or digit.
type ID string

func (id ID) Valid() bool {
	if len(id) == 0 || len(id) > 63 || id[0] == '-' {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Hash is a lowercase hex SHA-256 (64 characters). A policy hash is the
// SHA-256 of the envelope's exact payload bytes. A key ID is the SHA-256 of
// the raw 32-byte ed25519 public key.
type Hash string

func (h Hash) Valid() bool {
	if len(h) != 64 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var (
	// ErrBodyTooLarge means a body exceeded its limit (HTTP 413, code too_large).
	ErrBodyTooLarge = errors.New("wire: body too large")
	// ErrBodyInvalid means a body was not exactly one JSON value of the
	// expected shape (HTTP 400, code bad_request).
	ErrBodyInvalid = errors.New("wire: body invalid")
	// ErrInvalid means a decoded value failed Validate.
	ErrInvalid = errors.New("wire: invalid value")
)

// Decode reads exactly one JSON value from r into v. It rejects bodies larger
// than limit, unknown fields and trailing data. Errors are bare sentinels and
// never echo the body.
func Decode(r io.Reader, limit int64, v any) error {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return ErrBodyInvalid
	}
	if int64(len(data)) > limit {
		return ErrBodyTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return ErrBodyInvalid
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrBodyInvalid
	}
	return nil
}
