// Package rollout is the pure rollout state machine (PRD G5, J6):
//
//	Canary -> Promoting -> Complete, or Halted.
//
// A new version first goes to the canary group only. When every canary proxy
// has applied it and stayed healthy for the dwell time, the version goes to
// all groups. A canary apply error or a lost canary halts the rollout, and a
// halted rollout never promotes. Halting freezes every group's desired version
// where it was at that moment (M-D44). Rollback is not a state: the admin
// re-publishes the old content as a new, higher version and starts a new
// rollout, so no group's desired version is ever lowered.
//
// The package does no I/O and never reads the clock; the caller passes "now"
// (ARCHITECTURE R2, R3).
package rollout

import (
	"sort"
	"time"

	"kairan/internal/wire"
)

// CanaryGroup is the group that receives a version first. Group membership
// comes from the enrollment registry (M-D4, M-D26).
const CanaryGroup wire.ID = "canary"

// PromoteErrorPercent is the share of non-canary proxies that may fail to
// apply the new version while promoting. A higher share halts the rollout.
// 20 means 1 of 5 may fail, 2 of 5 may not.
const PromoteErrorPercent = 20

// MaxDwell caps the canary dwell time, so a huge request value cannot overflow
// or park a rollout for years.
const MaxDwell = 7 * 24 * time.Hour

// Rollout is the state of one rollout of Version for one tenant.
type Rollout struct {
	Tenant   wire.ID
	Version  uint64
	Previous uint64            // desired version before this rollout
	Phase    wire.RolloutPhase //
	Reason   wire.ErrorCode    // set when Halted
	Dwell    time.Duration     // canary must stay healthy this long
	CanaryOK time.Time         // when every canary proxy first acked Version; zero until then
	// Promoted is set when the rollout halts because of promotion errors:
	// every group had already been moved to Version, so Halted keeps them
	// there (M-D44). A malformed rollout (wrong tenant, bad version) halts
	// without it: it never raises a group.
	Promoted bool
	// Rejected is set when the rollout was malformed from the start (a bad
	// request from Start, or a canary-phase rollout that does not match the
	// fleet's tenant or its previous version). A rejected rollout raised
	// nothing: every group, the canary group included, stays at Previous
	// (Q-D7). It is always Halted.
	Rejected bool
}

// Start begins a rollout in the Canary phase. A request that cannot be a
// rollout (invalid, or Version not above previous) comes back already Halted
// with the reason and Rejected set, so no group is raised, the canary group
// included (Q-D7). A zero dwell in the request means
// defaultDwell.
func Start(req wire.RolloutRequest, previous uint64, now time.Time, defaultDwell time.Duration) Rollout {
	dwell := defaultDwell
	if req.CanaryDwellSeconds > 0 {
		if req.CanaryDwellSeconds >= uint64(MaxDwell/time.Second) {
			dwell = MaxDwell
		} else {
			dwell = time.Duration(req.CanaryDwellSeconds) * time.Second
		}
	}
	if dwell < 0 {
		dwell = 0
	}
	if dwell > MaxDwell {
		dwell = MaxDwell
	}
	r := Rollout{
		Tenant:   req.Tenant,
		Version:  req.Version,
		Previous: previous,
		Phase:    wire.PhaseCanary,
		Dwell:    dwell,
	}
	switch {
	case req.Validate() != nil:
		r.Rejected = true
		return halt(r, wire.ErrBadRequest)
	case req.Version <= previous:
		r.Rejected = true
		return halt(r, wire.ErrNotNewer)
	}
	return r
}

// Step advances the rollout given the current fleet and returns the next state
// plus the desired version for every group present in the fleet view.
//
//   - Canary: the canary group is desired Version, everyone else Previous.
//     Halts when a canary failed to apply Version, is tampered, or is lost.
//     Promotes once every canary proxy has applied Version, is healthy and
//     enforcing, and has stayed so for Dwell. With no canary proxies it waits.
//   - Promoting: every group is desired Version. Halts when the share of
//     non-canary proxies that failed to apply it exceeds PromoteErrorPercent.
//     Completes when every proxy that is not lost has applied Version.
//   - Halted: every group keeps the version it had when the rollout halted
//     (M-D44). Halted in Canary: canary at Version, others at Previous. Halted
//     in Promoting: every group at Version. Terminal.
//   - Complete: every group at Version. Terminal.
//
// No group is ever desired less than Previous. Step does not modify its inputs.
func Step(r Rollout, fleet wire.FleetView, now time.Time) (Rollout, map[wire.ID]uint64) {
	if r.Phase == wire.PhaseCanary || r.Phase == wire.PhasePromoting {
		reason := wire.ErrorCode("")
		switch {
		case fleet.Tenant != r.Tenant:
			reason = wire.ErrWrongTenant
		case r.Version == 0 || r.Version <= r.Previous:
			reason = wire.ErrNotNewer
		}
		if reason != "" {
			// In Canary nothing legitimate has been raised yet: a rollout for
			// the wrong tenant must not raise the canary group (Q-D7).
			r.Rejected = r.Rejected || r.Phase == wire.PhaseCanary
			r = halt(r, reason)
		}
	}
	switch r.Phase {
	case wire.PhaseCanary:
		r = stepCanary(r, fleet, now)
	case wire.PhasePromoting:
		r = stepPromoting(r, fleet)
	case wire.PhaseHalted, wire.PhaseComplete:
		// terminal
	default:
		r = halt(r, wire.ErrInternal)
	}
	return r, desired(r, fleet)
}

func halt(r Rollout, reason wire.ErrorCode) Rollout {
	r.Phase = wire.PhaseHalted
	r.Reason = reason
	return r
}

func stepCanary(r Rollout, fleet wire.FleetView, now time.Time) Rollout {
	var canaries []wire.ProxyView
	for _, p := range fleet.Proxies {
		if p.Group == CanaryGroup {
			canaries = append(canaries, p)
		}
	}
	// Failures first: an apply error or tampering is more specific than loss.
	for _, p := range sortedByID(canaries) {
		if applyFailed(p, r.Version) {
			return halt(r, p.LastError.Code)
		}
		if p.State == wire.StateTampered {
			return halt(r, wire.ErrTampered)
		}
	}
	for _, p := range canaries {
		if p.Health == wire.HealthLost {
			return halt(r, wire.ErrCanaryLost)
		}
	}
	allOK := len(canaries) > 0
	for _, p := range canaries {
		if p.AppliedVersion < r.Version || p.Health != wire.HealthHealthy || p.State != wire.StateEnforcing {
			allOK = false
			break
		}
	}
	if !allOK {
		r.CanaryOK = time.Time{} // the dwell must be continuous
		return r
	}
	if r.CanaryOK.IsZero() {
		r.CanaryOK = now
	}
	if now.Sub(r.CanaryOK) >= r.Dwell {
		r.Phase = wire.PhasePromoting
	}
	return r
}

func stepPromoting(r Rollout, fleet wire.FleetView) Rollout {
	var main []wire.ProxyView
	for _, p := range fleet.Proxies {
		if p.Group != CanaryGroup {
			main = append(main, p)
		}
	}
	failed := 0
	var first *wire.ProxyView
	for _, p := range sortedByID(main) {
		if applyFailed(p, r.Version) {
			failed++
			if first == nil {
				p := p
				first = &p
			}
		}
	}
	if first != nil && failed*100 > PromoteErrorPercent*len(main) {
		r.Promoted = true // every group is already at Version; keep it there (M-D44)
		return halt(r, first.LastError.Code)
	}
	reachable := 0
	for _, p := range fleet.Proxies {
		if p.Health == wire.HealthLost {
			continue // a lost proxy cannot ack; the fleet view still shows its drift
		}
		if p.AppliedVersion < r.Version {
			return r
		}
		reachable++
	}
	if reachable > 0 {
		r.Phase = wire.PhaseComplete
	}
	return r
}

// applyFailed reports whether p rejected or failed to apply exactly this
// version and has not applied it since. Errors for other versions, or without
// a version, cannot be tied to this rollout and are ignored.
func applyFailed(p wire.ProxyView, version uint64) bool {
	return p.LastError != nil && p.LastError.Version == version && p.AppliedVersion < version
}

func sortedByID(ps []wire.ProxyView) []wire.ProxyView {
	out := append([]wire.ProxyView(nil), ps...)
	sort.Slice(out, func(i, j int) bool { return out[i].ProxyID < out[j].ProxyID })
	return out
}

// DesiredFor is the version a group should run under r: the canary group gets
// the new version at once, other groups only once promoting or complete. A
// halted rollout keeps what each group had when it halted: Version for all
// groups if it halted while promoting, else Previous for non-canary groups. Never
// below Previous. A Rejected rollout raised nothing: every group stays at
// Previous. Step uses it for every group; the fleet page uses it to show
// the desired version without stepping the rollout.
func DesiredFor(r Rollout, group wire.ID) uint64 {
	canary := max(r.Version, r.Previous)
	if r.Rejected {
		return r.Previous
	}
	if group == CanaryGroup || r.Phase == wire.PhasePromoting || r.Phase == wire.PhaseComplete ||
		(r.Phase == wire.PhaseHalted && r.Promoted) {
		return canary
	}
	return r.Previous
}

// desired computes the version each group in the view should run.
func desired(r Rollout, fleet wire.FleetView) map[wire.ID]uint64 {
	out := make(map[wire.ID]uint64)
	for _, p := range fleet.Proxies {
		out[p.Group] = DesiredFor(r, p.Group)
	}
	return out
}
