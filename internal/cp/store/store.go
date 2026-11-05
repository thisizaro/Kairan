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
