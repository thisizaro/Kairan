package applylog

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

// ErrNotBroken: Reset was asked to replace a log that verifies.
var ErrNotBroken = errors.New("applylog: log is not broken")

// Reasons a reset records (ResetInfo.Reason). They name the first failure
// Verify found in the old file.
const (
	ReasonChainBroken = "chain_broken" // an edited, deleted, reordered or duplicated entry
	ReasonMalformed   = "malformed"    // a line that is not a canonical entry
	ReasonTruncated   = "truncated"    // the last line has no newline
	ReasonUnreadable  = "unreadable"   // any other failure reading the file
)

// ResetInfo is the extra content of a reset entry: where the broken log went
// and what was still verifiable in it. The zero value means "not a reset".
type ResetInfo struct {
	Seq    uint64 // the broken log's last verifiable seq (0 if none); Entry.Hash is its head
	File   string // base name of the kept file: <log name>.broken-<n>
	Reason string // one of the Reason constants
}

// IsZero reports whether r is the zero value.
func (r ResetInfo) IsZero() bool { return r == ResetInfo{} }

// maxBrokenN bounds the number in a broken file's name.
const maxBrokenN = 999999

// valid is the strict check Decode applies.
func (r ResetInfo) valid() bool {
	switch r.Reason {
	case ReasonChainBroken, ReasonMalformed, ReasonTruncated, ReasonUnreadable:
	default:
		return false
	}
	base, n, ok := strings.Cut(r.File, ".broken-")
	if !ok || base == "" || n == "" || n[0] == '0' || len(n) > 6 {
		return false
	}
	for _, c := range base {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	if strings.HasPrefix(base, ".") && strings.Trim(base, ".") == "" {
		return false
	}
	v, err := strconv.Atoi(n)
	return err == nil && v >= 1 && v <= maxBrokenN && strconv.Itoa(v) == n
}

// Prefix is what can be trusted of a log file up to its first bad line.
type Prefix struct {
	Seq            uint64    // last good entry's seq, 0 if none
	Head           wire.Hash // its Self, "" if none
	AppliedVersion uint64    // the floor: highest version applied in the good part (a reset's floor counts)
	AppliedHash    wire.Hash
	Err            error // nil if the whole file verifies, else the Verify error
}

// Inspect reads the log at path and reports what verifies. A damaged file is
// not an error here: it is Prefix.Err. The returned error is only for a file
// that cannot be read at all.
func Inspect(path string) (Prefix, error) {
	f, err := os.Open(path)
	if err != nil {
		return Prefix{}, fmt.Errorf("applylog: inspect: %w", err)
	}
	defer f.Close()
	var t tally
	last, _, _, serr := scan(f, t.add)
	return Prefix{Seq: last.Seq, Head: last.Self, AppliedVersion: t.version, AppliedHash: t.hash, Err: serr}, nil
}

func reasonFor(err error) string {
	switch {
	case errors.Is(err, ErrTruncated):
		return ReasonTruncated
	case errors.Is(err, ErrChain):
		return ReasonChainBroken
	case errors.Is(err, ErrMalformed):
		return ReasonMalformed
	}
	return ReasonUnreadable
}

// Reset replaces the broken log at path with a new chain, keeping the broken
// file as evidence (Q-D30, M-D64).
//
// The broken file is never deleted, truncated or overwritten: it becomes
// <path>.broken-<n> (the smallest n not yet used, so two resets give broken-1
// and broken-2). The new chain's first entry is a reset entry: Seq 1, Result
// tampered, Hash the old file's last verifiable head, From the floor (the
// larger of floor and the highest version applied in the verifiable part),
// and ResetInfo with the old last seq, the kept file's name and the reason.
// The new chain's Prev is empty again, so a control plane sees the anchor go
// backwards; that is intended (M-D48).
//
// It returns ErrNotBroken, touching nothing, if the log verifies. The caller
// holds the data directory lock. The order of steps leaves no moment with
// neither file: the new chain is written and synced under a temporary name,
// the broken file is hard-linked to its new name, and only then is the
// temporary file renamed over path. A crash before the rename leaves path
// broken (still Tampered) and the next Reset reuses the same kept file; a
// crash after it leaves a log that holds only the reset entry, which
// ResetPending reports.
func Reset(path string, clk clock.Clock, floor uint64) (*Log, Entry, error) {
	if clk == nil {
		return nil, Entry{}, errors.New("applylog: nil clock")
	}
	pre, err := Inspect(path)
	if err != nil {
		return nil, Entry{}, err
	}
	if pre.Err == nil {
		return nil, Entry{}, ErrNotBroken
	}
	dir := filepath.Dir(path)
	cur, err := os.Lstat(path)
	if err != nil {
		return nil, Entry{}, fmt.Errorf("applylog: reset: %w", err)
	}
	if !cur.Mode().IsRegular() {
		return nil, Entry{}, errors.New("applylog: reset: the log is not a regular file")
	}
	name, existing, err := brokenName(path, cur)
	if err != nil {
		return nil, Entry{}, err
	}

	e := Entry{
		Seq: 1, Time: clk.Now().UTC(),
		From: max(floor, pre.AppliedVersion), Hash: pre.Head, Result: wire.ErrTampered,
		Reset: ResetInfo{Seq: pre.Seq, File: filepath.Base(name), Reason: reasonFor(pre.Err)},
	}
	e.Self = computeSelf(e)
	data := append(Encode(e), '\n')
	if _, err := Decode(data[:len(data)-1]); err != nil {
		return nil, Entry{}, fmt.Errorf("applylog: reset entry cannot be encoded: %w", err)
	}

	tmp := path + ".reset-tmp"
	if err := writeSynced(tmp, data); err != nil {
		return nil, Entry{}, err
	}
	if !existing {
		if err := os.Link(path, name); err != nil {
			os.Remove(tmp)
			return nil, Entry{}, fmt.Errorf("applylog: keep broken log: %w", err)
		}
		if err := syncDir(dir); err != nil {
			return nil, Entry{}, err
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, Entry{}, fmt.Errorf("applylog: reset: %w", err)
	}
	if err := syncDir(dir); err != nil {
		return nil, Entry{}, err
	}
	l, err := Open(path, clk)
	if err != nil {
		return nil, Entry{}, err
	}
	return l, e, nil
}

// brokenName picks the kept file's name: the broken file's own existing link
// if a crashed reset already made one, else the first unused number.
func brokenName(path string, cur os.FileInfo) (name string, existing bool, err error) {
	for n := 1; n <= maxBrokenN; n++ {
		name = path + ".broken-" + strconv.Itoa(n)
		st, err := os.Lstat(name)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return name, false, nil
		case err != nil:
			return "", false, fmt.Errorf("applylog: reset: %w", err)
		case os.SameFile(st, cur):
			return name, true, nil
		}
	}
	return "", false, errors.New("applylog: reset: too many broken logs kept")
}

// writeSynced writes a new file (replacing a leftover temporary one) and
// fsyncs it.
func writeSynced(path string, data []byte) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("applylog: reset: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("applylog: reset: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("applylog: reset: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(path)
		return fmt.Errorf("applylog: reset: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return fmt.Errorf("applylog: reset: %w", err)
	}
	return nil
}
