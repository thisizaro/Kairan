// Package store is the proxy's atomic persistence of the last good policy
// envelope (ARCHITECTURE section 10, proxy/store).
//
// The file holds the exact envelope the proxy accepted, as JSON. The signed
// payload bytes are never re-encoded. Save writes a temp file in the same
// directory (mode 0600), fsyncs it, renames it over the current file and
// fsyncs the directory, so a crash leaves either the old file or the new one,
// never a mix.
//
// # Temp files (Q-D22)
//
// Save writes to a file named ".policy-<digits>.tmp" in the store directory:
// the fixed prefix ".policy-", a random decimal string chosen by
// os.CreateTemp, and the fixed suffix ".tmp". A crash between create and
// rename can leave such a file behind. A leftover is never loaded: Load only
// reads "policy.json".
//
// Open removes every directory entry whose name starts with ".policy-" and
// ends with ".tmp" (whatever is in between), using os.Remove. It removes
// nothing else: not "policy.json", not other files. An entry that is already
// gone is fine. If a removal fails (for example a non-empty directory with
// such a name, or no permission), Open returns that error and the proxy does
// not start from this directory. Save also removes its own temp file on any
// error, so a failed Save leaves none.
//
// Load is strict. A file that is missing is "not found". A file that exists
// but is not exactly one well-formed envelope (garbage, trailing data,
// unknown fields, too large, wrong shape, not a regular file) is ErrCorrupt.
// Load does not check signatures: the caller re-verifies the envelope with
// trust.Verify at boot (invariant I3) and decides the boot event with
// DecideBoot. A stored file that fails any of this is never enforced.
//
// On apply the caller runs Save, then applylog.Append (M-D33).
package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"kairan/internal/wire"
)

const (
	fileName   = "policy.json"
	tempPrefix = ".policy-"
	tempSuffix = ".tmp"
)

// ErrCorrupt means the stored file exists but is not a well-formed envelope.
// Callers map it, and any other Load error, to Tampered.
var ErrCorrupt = errors.New("store: stored policy is corrupt")

// Store persists one envelope in a directory. It is safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	dir  string
	sync func(*os.File) error // fsync; replaced in tests
}

// Open prepares dir (created with mode 0700 if absent) and removes temp
// files left behind by a crash during Save. It does not read the policy.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("store: empty directory")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	if !fi.IsDir() {
		return nil, errors.New("store: not a directory")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	for _, e := range ents {
		n := e.Name()
		if strings.HasPrefix(n, tempPrefix) && strings.HasSuffix(n, tempSuffix) {
			if err := os.Remove(filepath.Join(dir, n)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("store: remove stale temp: %w", err)
			}
		}
	}
	return &Store{dir: dir, sync: (*os.File).Sync}, nil
}

// Path is the file Save writes and Load reads.
func (s *Store) Path() string { return filepath.Join(s.dir, fileName) }

// Save atomically replaces the stored envelope. The envelope must pass
// ValidateShape and encode within wire.MaxEnvelopeBytes. On any error the
// previous file is untouched and no temp file is left.
func (s *Store) Save(env wire.Envelope) (err error) {
	if err := env.ValidateShape(); err != nil {
		return fmt.Errorf("store: save: %w", err)
	}
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("store: save: %w", err)
	}
	if len(data) > wire.MaxEnvelopeBytes {
		return fmt.Errorf("store: save: %w", wire.ErrBodyTooLarge)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := os.CreateTemp(s.dir, tempPrefix+"*"+tempSuffix) // mode 0600
	if err != nil {
		return fmt.Errorf("store: save: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err = f.Chmod(0o600); err != nil {
		return fmt.Errorf("store: save: %w", err)
	}
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("store: save: write: %w", err)
	}
	if err = s.sync(f); err != nil {
		return fmt.Errorf("store: save: sync: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("store: save: close: %w", err)
	}
	if err = os.Rename(tmp, s.Path()); err != nil {
		return fmt.Errorf("store: save: rename: %w", err)
	}
	// The rename has happened; a directory sync failure is still an error
	// (the new file may not survive a crash), but the temp name is gone.
	d, derr := os.Open(s.dir)
	if derr != nil {
		return fmt.Errorf("store: save: sync dir: %w", derr)
	}
	defer d.Close()
	if serr := s.sync(d); serr != nil {
		return fmt.Errorf("store: save: sync dir: %w", serr)
	}
	return nil
}

// Load reads the stored envelope. found is false, with a nil error, only if
// there is no file. A file that exists but is not a well-formed envelope
// gives an error wrapping ErrCorrupt. Any other error is an I/O failure. In
// every error case the caller must treat the policy as untrusted (Tampered),
// never as "no policy".
func (s *Store) Load() (env wire.Envelope, found bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	fi, err := os.Lstat(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return wire.Envelope{}, false, nil
	}
	if err != nil {
		return wire.Envelope{}, false, fmt.Errorf("store: load: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return wire.Envelope{}, true, fmt.Errorf("%w: not a regular file", ErrCorrupt)
	}
	f, err := os.Open(s.Path())
	if err != nil {
		return wire.Envelope{}, false, fmt.Errorf("store: load: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, wire.MaxEnvelopeBytes+1))
	if err != nil {
		return wire.Envelope{}, false, fmt.Errorf("store: load: %w", err)
	}
	env, err = decode(data)
	if err != nil {
		return wire.Envelope{}, true, err
	}
	return env, true, nil
}

// decode parses stored bytes strictly: one envelope, no unknown fields, no
// trailing data, valid shape. Errors wrap ErrCorrupt and never echo content.
func decode(data []byte) (wire.Envelope, error) {
	var env wire.Envelope
	if err := wire.Decode(bytes.NewReader(data), wire.MaxEnvelopeBytes, &env); err != nil {
		return wire.Envelope{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if err := env.ValidateShape(); err != nil {
		return wire.Envelope{}, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	return env, nil
}
