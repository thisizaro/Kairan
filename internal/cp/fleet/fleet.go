// Package fleet is the control plane's pure view of the fleet: it classifies
// each proxy as healthy, stale or lost, computes version drift, and builds the
// sorted fleet view (PRD G2). It does no I/O and never reads the clock; the
// caller passes "now" (ARCHITECTURE R2, R3).
package fleet

import (
	"sort"
	"time"

	"kairan/internal/wire"
)

// Default thresholds: a proxy that has sent nothing for 30s is stale, for 2m is lost.
const (
	DefaultStale = 30 * time.Second
	DefaultLost  = 2 * time.Minute
)

// Thresholds are the silence durations at which a proxy turns stale or lost.
// Both bounds are inclusive: silence of exactly Stale is already stale.
type Thresholds struct{ Stale, Lost time.Duration }

// DefaultThresholds returns the PRD defaults (stale 30s, lost 2m).
func DefaultThresholds() Thresholds { return Thresholds{Stale: DefaultStale, Lost: DefaultLost} }

// normalize replaces non-positive values by the defaults and raises Lost to
// Stale, so a proxy is never lost before it is stale.
func (th Thresholds) normalize() Thresholds {
	if th.Stale <= 0 {
		th.Stale = DefaultStale
	}
	if th.Lost <= 0 {
		th.Lost = DefaultLost
	}
	if th.Lost < th.Stale {
		th.Lost = th.Stale
	}
	return th
}

// Last is the most recent StatusReport of a proxy plus where it belongs.
// Group comes from the enrollment registry, never from the proxy (M-D4, M-D26).
// SeenAt is the control plane's clock at receipt; zero means never seen.
type Last struct {
	Group  wire.ID
	Report wire.StatusReport
	SeenAt time.Time
}

// Health classifies a proxy by how long ago the control plane last heard from
// it. Never seen (zero seenAt) is lost. A seenAt in the future (clock stepped
// back) counts as just seen.
func Health(seenAt, now time.Time, th Thresholds) wire.Health {
	if seenAt.IsZero() {
		return wire.HealthLost
	}
	th = th.normalize()
	age := now.Sub(seenAt)
	switch {
	case age >= th.Lost:
		return wire.HealthLost
	case age >= th.Stale:
		return wire.HealthStale
	default:
		return wire.HealthHealthy
	}
}

// Desired is the policy a group should be running. Hash may be empty if the
// caller does not know it; then only versions are compared.
type Desired struct {
	Version uint64
	Hash    wire.Hash
}

// DriftKind says how a proxy's applied policy relates to the desired one.
type DriftKind string

const (
	DriftNone         DriftKind = "none"          // applied matches desired
	DriftBehind       DriftKind = "behind"        // applied version is lower (or no policy yet)
	DriftAhead        DriftKind = "ahead"         // applied version is higher than desired
	DriftHashMismatch DriftKind = "hash_mismatch" // same version, different content: should never happen
)

// Classify compares desired and applied. The returned count is how many
// versions the proxy is behind; it is 0 unless the kind is DriftBehind.
func Classify(want Desired, applied uint64, appliedHash wire.Hash) (DriftKind, uint64) {
	switch {
	case applied < want.Version:
		return DriftBehind, want.Version - applied
	case applied > want.Version:
		return DriftAhead, 0
	case want.Version > 0 && want.Hash != "" && appliedHash != want.Hash:
		return DriftHashMismatch, 0
	default:
		return DriftNone, 0
	}
}

// View builds the fleet view for one tenant. desired maps group to the
// version that group should run; a group without an entry has nothing
// desired. Reports from other tenants are skipped. Rows are sorted by drift
// (largest first), then health (lost, stale, healthy), then proxy ID. State,
// last error and applied hash are passed through, so Tampered, SafeMode and
// the last apply error stay visible. The input is not modified.
func View(tenant wire.ID, desired map[wire.ID]uint64, proxies []Last, now time.Time, th Thresholds) wire.FleetView {
	rows := make([]wire.ProxyView, 0, len(proxies))
	for _, p := range proxies {
		r := p.Report
		if r.Tenant != tenant {
			continue
		}
		want := desired[p.Group]
		_, drift := Classify(Desired{Version: want}, r.AppliedVersion, r.PolicyHash)
		row := wire.ProxyView{
			ProxyID:        r.ProxyID,
			Group:          p.Group,
			Health:         Health(p.SeenAt, now, th),
			State:          r.State,
			DesiredVersion: want,
			AppliedVersion: r.AppliedVersion,
			PolicyHash:     r.PolicyHash,
			Drift:          drift,
		}
		if !p.SeenAt.IsZero() {
			row.LastSeenUnixMs = p.SeenAt.UnixMilli()
		}
		if r.LastError != nil {
			e := *r.LastError
			row.LastError = &e
		}
		rows = append(rows, row)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Drift != b.Drift {
			return a.Drift > b.Drift
		}
		if ra, rb := healthRank(a.Health), healthRank(b.Health); ra != rb {
			return ra < rb
		}
		return a.ProxyID < b.ProxyID
	})
	return wire.FleetView{Tenant: tenant, Proxies: rows}
}

func healthRank(h wire.Health) int {
	switch h {
	case wire.HealthLost:
		return 0
	case wire.HealthStale:
		return 1
	default:
		return 2
	}
}
