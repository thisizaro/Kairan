package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"time"

	"kairan/internal/policy"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/state"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// setPolicyLocked makes p the policy in force in state st and tells the
// handlers. The caller holds a.mu.
func (a *Agent) setPolicyLocked(p *policy.Policy, hash wire.Hash, st wire.ProxyState) {
	act := &enforce.Active{Policy: p, Hash: hash, State: st}
	a.hold.Store(act)
	a.view = &enforceView{active: act, version: p.Version, expires: p.ExpiresAt.Add(a.cfg.Skew)}
	a.st8 = st
}

// appliedVersionLocked is the version in force, 0 if none.
func (a *Agent) appliedVersionLocked() uint64 {
	if a.view == nil {
		return 0
	}
	return a.view.version
}

// floorLocked is the highest version this proxy has ever applied: the larger
// of the version in force and the apply log's last applied (I2 across
// restarts). A new envelope must beat it, and it is the "have" of a poll.
func (a *Agent) floorLocked() uint64 {
	f := a.appliedVersionLocked()
	if al := a.alog(); al != nil {
		if v, _ := al.LastApplied(); v > f {
			f = v
		}
	} else {
		f = max(f, a.brokenFloor)
	}
	return f
}

// lastApplied is the highest applied version for the "from" field of log
// entries and results: the log's, or the floor of a broken log.
func (a *Agent) lastApplied() uint64 {
	if al := a.alog(); al != nil {
		v, _ := al.LastApplied()
		return v
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.brokenFloor
}

func payloadHash(p []byte) wire.Hash {
	if len(p) == 0 {
		return ""
	}
	sum := sha256.Sum256(p)
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// apply judges one envelope from the control plane and, if it passes,
// installs it. The order is fixed (M-D33): trust.Accept (signatures,
// threshold, tenant, version beats the floor, not expired at effective_now),
// store.Save, applylog.Append, then the Holder swap. A failure at any step
// keeps the policy in force (I3). It reports whether the envelope was
// applied. advisory is the version the control plane claimed; it is used only
// for logs and the failed-version field of a rejection (the wire says never
// to trust it for enforcement).
func (a *Agent) apply(env wire.Envelope, advisory uint64) bool {
	now := a.cfg.Guard.Now()
	a.mu.Lock()
	floor := a.floorLocked()
	a.mu.Unlock()
	from := a.lastApplied()

	v, code, err := trust.Accept(env, a.cfg.Root, floor, now, a.cfg.Skew)
	if err != nil {
		if code == "" {
			code = wire.ErrMalformed // ErrBadRoot or ErrBadSkew cannot pass Validate; never a pass
		}
		a.reject(code, advisory, payloadHash(env.Payload), from)
		return false
	}
	ver, hash := v.Policy.Version, v.Hash
	al := a.alog()
	if al == nil {
		// The apply log is broken. A newer valid policy is the way out
		// (ARCHITECTURE section 4): keep the broken file, start a new chain.
		// Without a known log path nothing can be applied.
		var ok bool
		if al, ok = a.resetLog(ver, floor); !ok {
			a.reject(wire.ErrPersist, ver, hash, from)
			return false
		}
		from = a.lastApplied()
	}
	if err := a.st.Save(env); err != nil {
		say(a.log, slog.LevelError, evSaveFailed, "version", ver, "err", err)
		a.reject(wire.ErrPersist, ver, hash, from)
		return false
	}
	if _, err := al.Append(applylog.Entry{From: from, To: ver, Hash: hash}); err != nil {
		// The file on disk is now newer than the log; the next boot repairs
		// that. Until then the old policy stays in force.
		say(a.log, slog.LevelError, evLogAppend, "version", ver, "err", err)
		a.reject(wire.ErrPersist, ver, hash, from)
		return false
	}

	a.cfg.Guard.MarkApplied()
	a.mu.Lock()
	next := state.Next(a.st8, state.Applied)
	a.setPolicyLocked(v.Policy, hash, next)
	a.lastErr = nil
	if a.resetNote { // the control plane must see that the log was replaced
		a.lastErr = &wire.ApplyError{Code: wire.ErrTampered, Version: ver}
		a.resetNote = false
	}
	a.lastRej = rejKey{}
	a.failures = 0
	a.mu.Unlock()
	a.stats.Inc(MetricApplyOK)
	say(a.log, slog.LevelInfo, evApplied, "version", ver, "state", string(next))
	a.wake(a.wakeEx)
	a.wake(a.kick)
	return true
}

// reject records a failed apply: the counter, the error shown in the next
// status report, and an apply-log entry (unless it repeats the previous
// rejection exactly, so a control plane that resends one bad envelope cannot
// fill the disk). The policy in force does not change.
func (a *Agent) reject(code wire.ErrorCode, to uint64, hash wire.Hash, from uint64) {
	a.stats.Inc(MetricApplyRejected)
	key := rejKey{to: to, hash: hash, code: code, set: true}
	a.mu.Lock()
	a.lastErr = &wire.ApplyError{Code: code, Version: to}
	dup := a.lastRej == key
	a.lastRej = key
	a.failures++
	a.mu.Unlock()
	say(a.log, slog.LevelWarn, evRejected, "code", string(code), "version", to)
	if al := a.alog(); !dup && al != nil {
		if _, err := al.Append(applylog.Entry{From: from, To: to, Hash: hash, Result: code}); err != nil {
			say(a.log, slog.LevelError, evRejectLost, "err", err)
		}
	}
	a.wake(a.kick)
}

// wake sends on a one-slot channel without blocking.
func (a *Agent) wake(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

// checkExpiry moves Enforcing to SafeMode once effective_now reaches the
// policy's expires_at plus skew (M-D30). The policy stays loaded: SafeMode
// still allows R tools the policy grants, and a newer policy lifts it.
func (a *Agent) checkExpiry() {
	now := a.cfg.Guard.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st8 != wire.StateEnforcing || a.view == nil || now.Before(a.view.expires) {
		return
	}
	next := state.Next(a.st8, state.Expired)
	act := &enforce.Active{Policy: a.view.active.Policy, Hash: a.view.active.Hash, State: next}
	a.hold.Store(act)
	a.view.active = act
	a.st8 = next
	a.stats.Inc(MetricExpired)
	say(a.log, slog.LevelWarn, evExpired, "version", a.view.version)
	a.wake(a.kick)
}

// untilExpiry is how long (effective_now) until the policy in force expires;
// ok is false if nothing can expire (no policy, or already in SafeMode).
func (a *Agent) untilExpiry() (d time.Duration, ok bool) {
	now := a.cfg.Guard.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.st8 != wire.StateEnforcing || a.view == nil {
		return 0, false
	}
	return max(a.view.expires.Sub(now), 0), true
}

// Snapshot is what the local metrics listener (P-09) publishes about the
// agent.
type Snapshot struct {
	State               wire.ProxyState
	AppliedVersion      uint64
	PolicyHash          wire.Hash // hash of the policy in force, "" if none
	LogSeq              uint64    // apply-log anchor, as in the status report
	LogHead             wire.Hash
	ClockUntrusted      bool
	ClockUntrustedCount uint64
}

// Snapshot returns the agent's current state for the local self view and
// metrics. It carries wire types only (I4).
func (a *Agent) Snapshot() Snapshot {
	un, n := a.cfg.Guard.Untrusted(), a.cfg.Guard.UntrustedCount()
	var seq uint64
	var head wire.Hash
	if al := a.alog(); al != nil {
		seq, head = al.Head()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s := Snapshot{State: a.st8, AppliedVersion: a.appliedVersionLocked(), LogSeq: seq, LogHead: head, ClockUntrusted: un, ClockUntrustedCount: n}
	if a.view != nil {
		s.PolicyHash = a.view.active.Hash
	}
	return s
}

// resetLog replaces the broken apply log (P-13, M-D64). The caller has
// already seen the new policy pass trust.Accept against floor. The broken file
// is renamed to <LogPath>.broken-<n>, never deleted, and a new chain starts
// with a reset entry that records the old head, so Save and Append can go on.
// It reports false (and the caller rejects with persist_failed) if the agent
// has no log path or the reset fails; the policy in force does not change.
func (a *Agent) resetLog(version, floor uint64) (*applylog.Log, bool) {
	if a.cfg.LogPath == "" {
		return nil, false
	}
	nl, ent, err := applylog.Reset(a.cfg.LogPath, a.clk, floor)
	if err != nil {
		say(a.log, slog.LevelError, evResetFailed, "version", version, "err", err)
		return nil, false
	}
	a.al.Store(nl)
	a.mu.Lock()
	a.resetNote = true
	a.mu.Unlock()
	a.stats.Inc(MetricLogReset)
	say(a.log, slog.LevelWarn, evLogReset, "version", version, "kept", ent.Reset.File,
		"old_seq", ent.Reset.Seq, "reason", ent.Reset.Reason)
	return nl, true
}
