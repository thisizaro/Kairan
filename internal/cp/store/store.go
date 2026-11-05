// Package store keeps the control plane's state in plain JSON files: signed
// envelopes, rollouts, the last status of each proxy and the timeline of
// versions each proxy reported.
//
// Layout under the state directory:
//
//	envelopes/<tenant>/<version, 20 digits>.json   one per published version, never rewritten
//	rollouts/<tenant>.json                         the current rollout
//	fleet/<tenant>/<proxy>.json                    last status plus that proxy's timeline
//
// Every write goes to a temp file in the same directory, is fsynced, renamed
// over the target, and the directory is fsynced (a crash leaves either the old
// file or the new one). Temp files left by a crash are ignored and removed on
// open. A file that does not decode strictly, or does not match its own name,
// fails OpenFiles with ErrCorrupt: the store never starts silently empty.
// Only regular files are state: a FIFO, a link or any other file type where a
// state file or directory belongs is ErrCorrupt too, and OpenFiles never
// waits on one (it opens without blocking and checks the open file).
//
// A proxy's timeline gets a new entry when the version or hash changes, and
// also when its apply-log anchor goes backwards: a lower log_seq, or the same
// log_seq with another log_head. A regression is its own period, so the
// higher anchor stays on record and evidence sees it before the lower one.
//
// A proxy's timeline holds at most MaxTimeline entries (Q-D21): without a cap,
// a proxy that keeps reporting a moving apply-log anchor would grow the
// control plane's state without bound. When it is full the oldest entry is
// dropped, the number dropped is kept (it survives a restart) and is available
// from DropReporter, and DropNotifier tells the caller as it happens (the API
// counts kairan_cp_timeline_dropped_total{tenant}). A state file with more
// entries than the cap is cut to the newest MaxTimeline when it is opened.
//
// Only metadata is stored (I4): the signed envelopes an admin published, and
// the fields of a StatusReport. Nothing is read from a proxy's call data.
package store

import (
	"errors"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/wire"
)

var (
	// ErrConflict means the tenant already has an envelope with that version.
	ErrConflict = errors.New("store: version already exists")
	// ErrNotFound means there is no such envelope.
	ErrNotFound = errors.New("store: not found")
	// ErrCorrupt means a stored file is damaged or does not match its name.
	// The message names the file, never its content.
	ErrCorrupt = errors.New("store: corrupt state file")
)

// MaxTimeline is the most timeline entries kept for one proxy (Q-D21).
const MaxTimeline = 256

// DropNotifier is implemented by stores that cap the timeline (OpenFiles does).
// OnTimelineDrop sets the function called, with the store's lock held (so it
// must be brief and must not call the store), each time RecordStatus drops
// n oldest entries of a proxy in tenant. Set it before the store is used.
type DropNotifier interface {
	OnTimelineDrop(fn func(tenant wire.ID, n int))
}

// DropReporter is implemented by stores that cap the timeline (OpenFiles
// does). TimelineDropped returns, for each of the tenant's proxies that has
// lost entries, how many earlier timeline entries were dropped; proxies that
// lost none are not in the map.
type DropReporter interface {
	TimelineDropped(tenant wire.ID) (map[wire.ID]uint64, error)
}

// EnvelopeMeta is what the store needs to know about a published envelope. The
// caller (the publish handler) fills it from trust.Verified after the
// signature sanity check; the store does not depend on the trust package.
type EnvelopeMeta struct {
	Tenant  wire.ID
	Version uint64
	Hash    wire.Hash // SHA-256 of the envelope payload; checked against the payload
}

// Store is safe for concurrent use. Values going in and out are copies.
type Store interface {
	// PutEnvelope stores an envelope. ErrConflict if the tenant already has
	// that version; wire.ErrInvalid if the shape, tenant, version or hash is wrong.
	PutEnvelope(env wire.Envelope, m EnvelopeMeta) error
	// Envelope returns a stored envelope, or ErrNotFound.
	Envelope(tenant wire.ID, version uint64) (wire.Envelope, error)
	// PutRollout replaces the tenant's current rollout.
	PutRollout(r rollout.Rollout) error
	Rollout(tenant wire.ID) (rollout.Rollout, bool, error)
	// RecordStatus makes l the proxy's last status and extends its timeline.
	RecordStatus(l fleet.Last) error
	// Fleet returns the last status of each of the tenant's proxies, sorted by proxy ID.
	Fleet(tenant wire.ID) ([]fleet.Last, error)
	// Timeline returns the tenant's entries sorted by proxy ID, then in the order seen.
	Timeline(tenant wire.ID) ([]wire.TimelineEntry, error)
}
