package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

// Clock rollback bound (PLAN P-10, decision M-D30, THREATS #12).
//
// Every proxy expiry check uses effective_now, never the raw wall clock:
//
//	effective_now = max(wall now, high-water, anchor wall + (Mono() - anchor mono))
//
// The anchor is the proxy's own last observation of effective_now, paired with
// the monotonic reading taken at that moment. The first anchor is taken when
// the guard opens (boot), and it is refreshed on every observation and at
// every apply (MarkApplied). So setting the wall clock back, by an operator,
// by NTP or by an attacker who can step the clock, cannot make a policy live
// longer: effective_now keeps advancing at monotonic speed from the last
// value it reached. Within one process lifetime that needs no disk. Across a
// restart the persisted high-water mark does the same job.
//
// High-water persistence. The mark is a single line, an RFC 3339 UTC time,
// in <data dir>/highwater (mode 0600). Save writes a temp file in the same
// directory, fsyncs it, renames it over the old file and fsyncs the
// directory, so a crash leaves the old or the new value, never a mix. The mark
// only ever moves forward: in memory, and on disk. Before writing, Save re-reads
// the file under a process-wide lock and keeps the maximum, so a second guard
// (or a stale one) with a lower mark never lowers a higher file; an unchanged
// or lower value is not written. Across processes the re-read and the atomic
// rename narrow the window but do not close it (no file lock; one proxy owns
// one data directory). Run saves every HighWaterInterval (60s) and once more
// when its context ends.
//
// Hostile or odd file. The file is read only if it is a regular file: it is
// opened non-blocking without following symlinks and its type is checked on
// the open descriptor. A FIFO, device, directory or symlink at the path counts
// as corrupt (ErrHighWaterCorrupt, usable guard) and never blocks; the next
// Save replaces it. Save clamps the mark to 9999-12-31T23:59:59.999999999Z (it
// does not return an error), so the file it writes is always one its own loader
// accepts. EffectiveNow and every guard method return UTC times without a Go
// monotonic reading, whatever the caller passed in.
//
// Untrusted clock. When the wall clock is more than UntrustedMargin (5m)
// behind effective_now the guard reports wire.ErrClockUntrusted through
// LastError and counts the episode (UntrustedCount). It is not a state of its
// own (M-D30): expiry already uses effective_now, so nothing else changes.
// The count is edge-triggered: one increment per episode, not per check.
//
// Metric names for the P-09 listener to publish (M-D39: the owner's choice):
//
//	kairan_proxy_clock_untrusted        gauge, 1 while the wall clock is untrusted
//	kairan_proxy_clock_untrusted_total  counter, episodes since process start
//
// Known limit (LIMITATIONS): a bad forward jump that was persisted keeps
// effective_now ahead of true time, so policies look expired early. The
// operator recovers by deleting the high-water file and restarting. A root
// attacker on the proxy host can delete the file too, and is out of scope.

const (
	// HighWaterFile is the file name inside the proxy data directory.
	HighWaterFile = "highwater"
	// HighWaterInterval is the longest the persister waits between saves.
	HighWaterInterval = 60 * time.Second
	// UntrustedMargin is how far wall time may lag effective_now before the
	// clock is reported as untrusted.
	UntrustedMargin = 5 * time.Minute

	maxHighWaterBytes = 64
	hwTempPrefix      = ".highwater-"
	hwTempSuffix      = ".tmp"
)

// maxHighWater is the largest mark Save will write: the last nanosecond that
// RFC 3339 can print with a four-digit year, which parseHighWater accepts.
var maxHighWater = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)

// fileMu serialises the read-compare-write in Save across every guard in this
// process. Guards in other processes are covered by the re-read and the atomic
// rename only (see the package comment).
var fileMu sync.Mutex

// ErrHighWaterCorrupt means the high-water file exists but is not exactly one
// canonical UTC timestamp line. OpenClockGuard still returns a usable guard
// (high-water unknown, so effective_now follows the wall clock); the caller
// should log it. The next successful Save repairs the file.
var ErrHighWaterCorrupt = errors.New("agent: high-water file is corrupt")

// Anchor pairs a wall time with the monotonic reading taken at the same moment.
type Anchor struct {
	Wall time.Time
	Mono time.Duration
}

// EffectiveNow is max(wall now, highWater, a.Wall + (Mono() - a.Mono)). A zero
// highWater or an Anchor with a zero Wall is ignored. The result never carries
// a Go monotonic reading, so comparing it with other times uses wall time only.
func EffectiveNow(clk clock.Clock, a Anchor, highWater time.Time) time.Time {
	return effective(strip(clk.Now()), clk.Mono(), a, highWater)
}

func effective(wall time.Time, mono time.Duration, a Anchor, highWater time.Time) time.Time {
	eff := wall
	if !highWater.IsZero() && highWater.After(eff) {
		eff = highWater
	}
	if !a.Wall.IsZero() {
		if t := a.Wall.Add(mono - a.Mono); t.After(eff) {
			eff = t
		}
	}
	return strip(eff)
}

// strip drops the zone and, importantly, Go's monotonic reading: Before, After
// and Sub use the monotonic reading when both values have one, which would
// hide a wall-clock step from every comparison here.
func strip(t time.Time) time.Time { return t.Round(0).UTC() }

// ClockGuard owns effective_now and the persisted high-water mark. It is safe
// for concurrent use.
type ClockGuard struct {
	clk  clock.Clock
	path string
	dir  string

	mu        sync.Mutex
	anchor    Anchor // Wall is the high-water mark: the highest effective_now seen
	saved     time.Time
	untrusted bool
	episodes  uint64
	saveErr   error
	log       *slog.Logger         // logs a change of the untrusted flag; may be nil
	syncFn    func(*os.File) error // fsync; replaced in tests
}

// OpenClockGuard loads the high-water file from dir (created with mode 0700
// if absent) and anchors effective_now at max(wall now, high-water). A missing
// file is a first boot, not an error. A corrupt file returns the usable guard
// together with ErrHighWaterCorrupt. Any other failure returns a nil guard.
func OpenClockGuard(clk clock.Clock, dir string) (*ClockGuard, error) {
	if dir == "" {
		return nil, errors.New("agent: clock guard: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("agent: clock guard: %w", err)
	}
	g := &ClockGuard{clk: clk, dir: dir, path: filepath.Join(dir, HighWaterFile), syncFn: (*os.File).Sync}
	removeStaleTemps(dir)

	var hw time.Time
	var openErr error
	b, err := readSmall(g.path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case errors.Is(err, errTooBig), errors.Is(err, errNotRegular):
		openErr = ErrHighWaterCorrupt
	case err != nil:
		return nil, fmt.Errorf("agent: clock guard: %w", err)
	default:
		if hw, err = parseHighWater(b); err != nil {
			hw, openErr = time.Time{}, ErrHighWaterCorrupt
		} else {
			g.saved = hw
		}
	}

	g.mu.Lock()
	g.anchor = Anchor{Wall: hw, Mono: clk.Mono()}
	g.observeLocked()
	g.mu.Unlock()
	return g, openErr
}

// Path is the high-water file.
func (g *ClockGuard) Path() string { return g.path }

// Now returns effective_now and advances the high-water mark to it.
func (g *ClockGuard) Now() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.observeLocked()
}

// MarkApplied records the moment a policy was applied (or re-verified at
// boot): effective_now and the monotonic reading become the anchor. Expiry of
// that policy is then bounded by monotonic time since this call.
func (g *ClockGuard) MarkApplied() Anchor {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observeLocked()
	return g.anchor
}

// HighWater is the highest effective_now observed so far.
func (g *ClockGuard) HighWater() time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.anchor.Wall
}

// Untrusted reports whether the wall clock is more than UntrustedMargin behind
// effective_now right now.
func (g *ClockGuard) Untrusted() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observeLocked()
	return g.untrusted
}

// LastError is &ApplyError{Code: ErrClockUntrusted} while the clock is
// untrusted, else nil. The agent merges it into the status report.
func (g *ClockGuard) LastError() *wire.ApplyError {
	if g.Untrusted() {
		return &wire.ApplyError{Code: wire.ErrClockUntrusted}
	}
	return nil
}

// UntrustedCount is the number of untrusted-clock episodes since open.
func (g *ClockGuard) UntrustedCount() uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.episodes
}

// SaveErr is the error of the most recent Save, nil if it succeeded.
func (g *ClockGuard) SaveErr() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.saveErr
}

// observeLocked reads both clocks once, folds them into the anchor, updates
// the untrusted flag and returns effective_now. The caller holds g.mu.
func (g *ClockGuard) observeLocked() time.Time {
	wall, mono := strip(g.clk.Now()), g.clk.Mono()
	eff := effective(wall, mono, g.anchor, time.Time{})
	g.anchor = Anchor{Wall: eff, Mono: mono}
	u := wall.Before(eff.Add(-UntrustedMargin))
	if u && !g.untrusted {
		g.episodes++
	}
	if g.log != nil && u != g.untrusted {
		if u {
			say(g.log, slog.LevelWarn, evClockUntrusted)
		} else {
			say(g.log, slog.LevelInfo, evClockTrusted)
		}
	}
	g.untrusted = u
	return eff
}

// Save persists the high-water mark if it is higher than what is on disk.
func (g *ClockGuard) Save() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.observeLocked()
	g.saveErr = g.saveLocked()
	return g.saveErr
}

func (g *ClockGuard) saveLocked() (err error) {
	hw := g.anchor.Wall
	if hw.After(maxHighWater) {
		hw = maxHighWater // the loader rejects anything it cannot parse back
	}
	if !hw.After(g.saved) {
		return nil // never move backwards, never rewrite an equal value
	}
	// Other guards (another process, a second guard on the same directory)
	// may have written a higher mark since this one last looked. Compare with
	// the file as it is now, under a lock, and keep the maximum.
	fileMu.Lock()
	defer fileMu.Unlock()
	if b, rerr := readSmall(g.path); rerr == nil {
		if cur, perr := parseHighWater(b); perr == nil && !hw.After(cur) {
			g.saved = cur
			return nil
		}
	}
	f, err := os.CreateTemp(g.dir, hwTempPrefix+"*"+hwTempSuffix) // mode 0600
	if err != nil {
		return fmt.Errorf("agent: save high-water: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return fmt.Errorf("agent: save high-water: %w", err)
	}
	if _, err = f.Write(formatHighWater(hw)); err != nil {
		return fmt.Errorf("agent: save high-water: write: %w", err)
	}
	if err = g.syncFn(f); err != nil {
		return fmt.Errorf("agent: save high-water: sync: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("agent: save high-water: close: %w", err)
	}
	if err = os.Rename(tmp, g.path); err != nil {
		return fmt.Errorf("agent: save high-water: rename: %w", err)
	}
	g.saved = hw
	d, derr := os.Open(g.dir)
	if derr != nil {
		return fmt.Errorf("agent: save high-water: sync dir: %w", derr)
	}
	defer d.Close()
	if serr := g.syncFn(d); serr != nil {
		return fmt.Errorf("agent: save high-water: sync dir: %w", serr)
	}
	return nil
}

// SetLog gives the guard a logger for the changes of the untrusted flag: a
// warning when the clock becomes untrusted and an info line when it is trusted
// again (one line per change, never a time or a path). A nil logger is silent.
func (g *ClockGuard) SetLog(log *slog.Logger) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.log = log
}

// Run saves the high-water mark every HighWaterInterval of monotonic time (and looks at the clock) and
// once more when ctx ends, whose error (if any) it returns. Failed periodic
// saves are logged (log may be nil) and kept in SaveErr; the next tick retries.
func (g *ClockGuard) Run(ctx context.Context, log *slog.Logger) error {
	for {
		select {
		case <-ctx.Done():
			return g.Save()
		case <-g.clk.After(HighWaterInterval):
			if err := g.Save(); err != nil && log != nil {
				say(log, slog.LevelError, evClockSave, "err", err)
			}
			g.Untrusted() // look, so a change is logged even if nothing else asks
		}
	}
}

func removeStaleTemps(dir string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		n := e.Name()
		if len(n) > len(hwTempPrefix)+len(hwTempSuffix) && n[:len(hwTempPrefix)] == hwTempPrefix &&
			n[len(n)-len(hwTempSuffix):] == hwTempSuffix {
			os.Remove(filepath.Join(dir, n))
		}
	}
}

var errTooBig = ErrTooLarge

var errNotRegular = ErrNotRegular

// readSmall reads the file at path only if it is a regular file. The open is
// non-blocking and does not follow a symlink, so a FIFO or device placed at
// the path cannot hang the proxy at boot; the type is then checked on the open
// descriptor, which closes the window between a check and the open.
func readSmall(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, errNotRegular
		}
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, errNotRegular
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHighWaterBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxHighWaterBytes {
		return nil, errTooBig
	}
	return b, nil
}

// formatHighWater is the canonical file content.
func formatHighWater(t time.Time) []byte {
	return []byte(t.UTC().Format(time.RFC3339Nano) + "\n")
}

// parseHighWater accepts only what formatHighWater writes.
func parseHighWater(b []byte) (time.Time, error) {
	if len(b) == 0 || len(b) > maxHighWaterBytes {
		return time.Time{}, ErrHighWaterCorrupt
	}
	t, err := time.Parse(time.RFC3339Nano, string(b[:len(b)-1]))
	if err != nil || t.IsZero() {
		return time.Time{}, ErrHighWaterCorrupt
	}
	t = t.UTC()
	if string(formatHighWater(t)) != string(b) {
		return time.Time{}, ErrHighWaterCorrupt
	}
	return t, nil
}
