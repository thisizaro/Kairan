package wire

import (
	"fmt"
	"net/url"
	"strconv"
)

// PayloadTypePolicy is the only payload type Kairan signs.
const PayloadTypePolicy = "application/vnd.kairan.policy+json"

// Envelope carries a policy's exact bytes plus signatures (the DSSE idea).
//
// Each signature is ed25519 over the DSSE v1 pre-authentication encoding:
//
//	"DSSEv1" SP len(PayloadType) SP PayloadType SP len(Payload) SP Payload
//
// where len is the byte length in ASCII decimal and SP is one space. Signers
// and verifiers use the Payload bytes as-is; they never re-encode the JSON.
// Verification (2-of-N distinct trusted keys, tenant, version, expiry) is the
// trust package's job; ValidateShape only checks the outline.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     []byte      `json:"payload"` // base64 in JSON
	Signatures  []Signature `json:"signatures"`
}

// Signature is one signer's signature over the envelope.
type Signature struct {
	KeyID Hash   `json:"keyid"` // SHA-256 of the signer's raw ed25519 public key
	Sig   []byte `json:"sig"`   // base64 in JSON, SignatureSize bytes
}

// ValidateShape checks structure only. It does not verify signatures.
func (e Envelope) ValidateShape() error {
	switch {
	case e.PayloadType != PayloadTypePolicy:
		return fmt.Errorf("%w: payload type", ErrInvalid)
	case len(e.Payload) == 0:
		return fmt.Errorf("%w: empty payload", ErrInvalid)
	case len(e.Signatures) == 0 || len(e.Signatures) > MaxSignatures:
		return fmt.Errorf("%w: need 1-%d signatures", ErrInvalid, MaxSignatures)
	}
	for i, s := range e.Signatures {
		if !s.KeyID.Valid() || len(s.Sig) != SignatureSize {
			return fmt.Errorf("%w: signature %d", ErrInvalid, i)
		}
	}
	return nil
}

// Query parameter names for PathPoll.
const (
	QueryTenant = "tenant"
	QueryProxy  = "proxy"
	QueryHave   = "have"
)

// PollRequest asks "is there anything newer than version Have?". It is sent
// as the query string of GET PathPoll. Have is 0 when the proxy has no policy.
//
// The control plane answers 200 with a PollResponse as soon as the proxy's
// desired version is greater than Have, or 304 Not Modified after PollHold.
type PollRequest struct {
	Tenant  ID
	ProxyID ID
	Have    uint64
}

func (p PollRequest) Query() url.Values {
	return url.Values{
		QueryTenant: {string(p.Tenant)},
		QueryProxy:  {string(p.ProxyID)},
		QueryHave:   {strconv.FormatUint(p.Have, 10)},
	}
}

// ParsePollRequest accepts exactly the three parameters, each once.
func ParsePollRequest(q url.Values) (PollRequest, error) {
	if len(q) != 3 {
		return PollRequest{}, fmt.Errorf("%w: want exactly tenant, proxy, have", ErrInvalid)
	}
	one := func(k string) (string, error) {
		v, ok := q[k]
		if !ok || len(v) != 1 {
			return "", fmt.Errorf("%w: %s must appear once", ErrInvalid, k)
		}
		return v[0], nil
	}
	tenant, err := one(QueryTenant)
	if err != nil {
		return PollRequest{}, err
	}
	proxy, err := one(QueryProxy)
	if err != nil {
		return PollRequest{}, err
	}
	haveS, err := one(QueryHave)
	if err != nil {
		return PollRequest{}, err
	}
	have, err := strconv.ParseUint(haveS, 10, 64)
	if err != nil {
		return PollRequest{}, fmt.Errorf("%w: have", ErrInvalid)
	}
	p := PollRequest{Tenant: ID(tenant), ProxyID: ID(proxy), Have: have}
	if !p.Tenant.Valid() || !p.ProxyID.Valid() {
		return PollRequest{}, fmt.Errorf("%w: tenant or proxy id", ErrInvalid)
	}
	return p, nil
}

// PollResponse delivers the envelope a proxy should apply next.
type PollResponse struct {
	// Version is advisory, for logs and metrics. Proxies MUST use the version
	// inside the verified payload, never this field.
	Version  uint64   `json:"version"`
	Envelope Envelope `json:"envelope"`
}

// ProxyState mirrors the proxy state machine in ARCHITECTURE.md.
type ProxyState string

const (
	StateBooting   ProxyState = "booting"
	StateDenyAll   ProxyState = "deny_all"  // no valid policy: every tools/call denied
	StateTampered  ProxyState = "tampered"  // policy on disk failed verification: deny-all
	StateEnforcing ProxyState = "enforcing" // valid, unexpired policy in force
	StateSafeMode  ProxyState = "safe_mode" // policy expired: only R tools allowed
)

func (s ProxyState) Valid() bool {
	switch s {
	case StateBooting, StateDenyAll, StateTampered, StateEnforcing, StateSafeMode:
		return true
	}
	return false
}

// StatusReport is a proxy's heartbeat and ack, POSTed to PathStatus. Proxies
// send one immediately after every apply attempt (success or rejection) and
// otherwise every StatusInterval. Metadata only (I4).
type StatusReport struct {
	Tenant         ID         `json:"tenant"`
	ProxyID        ID         `json:"proxy_id"`
	Seq            uint64     `json:"seq"` // +1 per report within one process; resets on restart
	State          ProxyState `json:"state"`
	AppliedVersion uint64     `json:"applied_version"`       // 0 = no policy
	PolicyHash     Hash       `json:"policy_hash,omitempty"` // set iff AppliedVersion > 0
	// Apply-log anchor (M-D35). LogSeq is the Seq of the last apply-log
	// entry, counting from 1 (so it equals the number of entries); LogHead
	// is that entry's Self hash. Both are 0/"" iff the log is empty. The
	// control plane stores them so evidence can flag a seq or head
	// regression (tail truncation, I6).
	LogSeq        uint64      `json:"log_seq"`
	LogHead       Hash        `json:"log_head,omitempty"`
	LastError     *ApplyError `json:"last_error,omitempty"`
	UptimeSeconds uint64      `json:"uptime_seconds"` // a decrease means the proxy restarted
	Counters      Counters    `json:"counters"`
}

// ApplyError is the latest rejected or failed apply. Codes only, no text.
type ApplyError struct {
	Code    ErrorCode `json:"code"`
	Version uint64    `json:"version,omitempty"` // the version that failed, if known
}

// Counters are totals since the proxy process started.
type Counters struct {
	CallsAllowed      uint64 `json:"calls_allowed"`
	CallsDenied       uint64 `json:"calls_denied"`
	EnvelopesRejected uint64 `json:"envelopes_rejected"`
}

func (s StatusReport) Validate() error {
	switch {
	case !s.Tenant.Valid() || !s.ProxyID.Valid():
		return fmt.Errorf("%w: tenant or proxy id", ErrInvalid)
	case !s.State.Valid():
		return fmt.Errorf("%w: state", ErrInvalid)
	case (s.AppliedVersion == 0) != (s.PolicyHash == ""):
		return fmt.Errorf("%w: applied_version and policy_hash go together", ErrInvalid)
	case s.PolicyHash != "" && !s.PolicyHash.Valid():
		return fmt.Errorf("%w: policy_hash", ErrInvalid)
	case (s.LogSeq == 0) != (s.LogHead == ""):
		return fmt.Errorf("%w: log_seq and log_head go together", ErrInvalid)
	case s.LogHead != "" && !s.LogHead.Valid():
		return fmt.Errorf("%w: log_head", ErrInvalid)
	case (s.State == StateEnforcing || s.State == StateSafeMode) && s.AppliedVersion == 0:
		return fmt.Errorf("%w: %s needs a policy", ErrInvalid, s.State)
	case (s.State == StateDenyAll || s.State == StateTampered) && s.AppliedVersion != 0:
		return fmt.Errorf("%w: %s means no policy in force", ErrInvalid, s.State)
	case s.LastError != nil && !s.LastError.Code.Valid():
		return fmt.Errorf("%w: last_error code", ErrInvalid)
	}
	return nil
}
