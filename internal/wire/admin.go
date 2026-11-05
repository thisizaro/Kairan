package wire

import "fmt"

// Admin API between kairanctl and kairan-cp. Publishing only stores an
// envelope; a rollout makes it the desired version, canary group first.
// Rollback = publish the old content as a new, higher version, then roll out.

// PublishResponse answers POST PathPolicies (body: Envelope).
type PublishResponse struct {
	Tenant     ID     `json:"tenant"`
	Version    uint64 `json:"version"`
	PolicyHash Hash   `json:"policy_hash"`
}

// RolloutRequest starts a rollout of an already published version.
type RolloutRequest struct {
	Tenant             ID     `json:"tenant"`
	Version            uint64 `json:"version"`
	CanaryDwellSeconds uint64 `json:"canary_dwell_seconds,omitempty"` // 0 = control-plane default
}

func (r RolloutRequest) Validate() error {
	if !r.Tenant.Valid() || r.Version == 0 {
		return fmt.Errorf("%w: tenant and version required", ErrInvalid)
	}
	return nil
}

// RolloutPhase mirrors the rollout state machine in ARCHITECTURE.md.
type RolloutPhase string

const (
	PhaseCanary    RolloutPhase = "canary"
	PhasePromoting RolloutPhase = "promoting"
	PhaseHalted    RolloutPhase = "halted"
	PhaseComplete  RolloutPhase = "complete"
)

// RolloutView is the current rollout for a tenant.
type RolloutView struct {
	Tenant  ID           `json:"tenant"`
	Version uint64       `json:"version"`
	Phase   RolloutPhase `json:"phase"`
	Reason  ErrorCode    `json:"reason,omitempty"` // why it halted
}

// Health is the control plane's view of whether a proxy is reporting.
type Health string

const (
	HealthHealthy Health = "healthy"
	HealthStale   Health = "stale"
	HealthLost    Health = "lost"
)

// ProxyView is one row of the fleet. Drift = desired - applied when the proxy
// is behind, else 0.
type ProxyView struct {
	ProxyID        ID          `json:"proxy_id"`
	Group          ID          `json:"group"`
	Health         Health      `json:"health"`
	State          ProxyState  `json:"state"`
	DesiredVersion uint64      `json:"desired_version"`
	AppliedVersion uint64      `json:"applied_version"`
	PolicyHash     Hash        `json:"policy_hash,omitempty"`
	Drift          uint64      `json:"drift"`
	LastSeenUnixMs int64       `json:"last_seen_unix_ms"` // control-plane clock
	LastError      *ApplyError `json:"last_error,omitempty"`
}

// FleetView answers GET PathFleet?tenant=. The fleet page and black-box tests
// read the same data.
type FleetView struct {
	Tenant  ID          `json:"tenant"`
	Proxies []ProxyView `json:"proxies"`
}

// TimelineEntry says proxy P reported version V (hash H) from first to last
// seen, by the control-plane clock. Evidence export joins this with each
// proxy's local apply log.
type TimelineEntry struct {
	ProxyID         ID     `json:"proxy_id"`
	Version         uint64 `json:"version"`
	PolicyHash      Hash   `json:"policy_hash"`
	FirstSeenUnixMs int64  `json:"first_seen_unix_ms"`
	LastSeenUnixMs  int64  `json:"last_seen_unix_ms"`
}

// TimelineView answers GET PathTimeline?tenant=.
type TimelineView struct {
	Tenant  ID              `json:"tenant"`
	Entries []TimelineEntry `json:"entries"`
}
