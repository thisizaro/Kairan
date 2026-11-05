package declog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"kairan/internal/policy"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

// Metric names for Options.Metrics (enforce.Metrics.Inc).
const (
	MetricWriteErrors  = "declog_write_errors"  // a record was not stored
	MetricRotateErrors = "declog_rotate_errors" // a rotation failed
)

// Defaults and bounds.
const (
	DefaultMaxBytes = 10 << 20
	DefaultKeep     = 5
	maxRoleLen      = 256
	maxLineLen      = 2048 // a real line is about 250 bytes
)

// Options configures Open.
type Options struct {
	MaxBytes int64           // rotate before a line would push the file past this; 0 = DefaultMaxBytes
	Keep     int             // rotated files kept (.1 to .Keep); 0 = DefaultKeep
	Sync     bool            // fsync after every line (slower, survives a crash)
	Metrics  enforce.Metrics // may be nil
}

// Log is a file-backed enforce.DecisionLog. It is safe for concurrent use.
type Log struct {
	mu     sync.Mutex
	m      enforce.Metrics
	closed bool

	w io.Writer // writer mode (New): no rotation, no repair

	f    *os.File // file mode (Open); nil after a failed rotation, reopened on the next Record
	path string
	max  int64
	keep int
	sync bool
	size int64
}

var _ enforce.DecisionLog = (*Log)(nil)

// line is the on-disk shape; field order is the key order on disk. Only
// bounded kinds may appear here (a test enforces it).
type line struct {
	Time    string `json:"time"`
	Role    string `json:"role"`
	Tool    string `json:"tool"`
	Allowed bool   `json:"allowed"`
	Class   string `json:"class"`
	Version uint64 `json:"version"`
	Hash    string `json:"hash"`
	State   string `json:"state"`
}

// New returns a Log that writes lines to w, with no rotation. Its errors
// become Record errors.
func New(w io.Writer, m enforce.Metrics) *Log { return &Log{w: w, m: m} }

// Open opens (creating if needed) the log at path for appending, mode 0600.
func Open(path string, o Options) (*Log, error) {
	l := &Log{path: path, max: o.MaxBytes, keep: o.Keep, sync: o.Sync, m: o.Metrics}
	if l.max <= 0 {
		l.max = DefaultMaxBytes
	}
	if l.keep <= 0 {
		l.keep = DefaultKeep
	}
	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) inc(name string) {
	if l.m != nil {
		l.m.Inc(name)
	}
}

// openFile opens l.path for append and starts a fresh line if a crash left
// the last one without its newline.
func (l *Log) openFile() error {
	f, err := os.OpenFile(l.path, os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return fmt.Errorf("declog: open: %w", err)
	}
	fail := func(err error) error { f.Close(); return fmt.Errorf("declog: open: %w", err) }
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !st.Mode().IsRegular() {
		return fail(errors.New("not a regular file"))
	}
	if st.Mode().Perm() != 0o600 {
		if err := f.Chmod(0o600); err != nil {
			return fail(err)
		}
	}
	size := st.Size()
	if size > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], size-1); err != nil {
			return fail(err)
		}
		if last[0] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				return fail(err)
			}
			size++
		}
	}
	l.f, l.size = f, size
	return nil
}

type rotateError struct{ err error }

func (e *rotateError) Error() string { return "declog: rotate: " + e.err.Error() }
func (e *rotateError) Unwrap() error { return e.err }

// Record stores one decision. A nil error means the whole line was handed to
// the file; any error means it was not stored and the caller must deny.
func (l *Log) Record(r enforce.Record) error {
	b, err := encode(r)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err == nil {
		err = l.write(b)
	}
	if err != nil {
		var re *rotateError
		if !errors.As(err, &re) {
			l.inc(MetricWriteErrors)
		}
	}
	return err
}

func (l *Log) write(b []byte) error {
	if l.closed {
		return errors.New("declog: closed")
	}
	if l.w != nil {
		n, err := l.w.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		if err != nil {
			return fmt.Errorf("declog: write: %w", err)
		}
		return nil
	}
	if l.f == nil {
		if err := l.openFile(); err != nil {
			return err
		}
	}
	if l.size > 0 && l.size+int64(len(b)) > l.max {
		if err := l.rotate(); err != nil {
			l.inc(MetricRotateErrors)
			return &rotateError{err}
		}
	}
	n, err := l.f.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		// Cut off whatever part of the line got in. If even that fails, drop
		// the handle: the next Record reopens and starts a fresh line.
		if terr := l.f.Truncate(l.size); terr != nil {
			l.f.Close()
			l.f = nil
		}
		return fmt.Errorf("declog: write: %w", err)
	}
	l.size += int64(n)
	if l.sync {
		if err := l.f.Sync(); err != nil {
			return fmt.Errorf("declog: sync: %w", err)
		}
	}
	return nil
}

// rotate shifts path.N-1 to path.N ... path to path.1 and opens a new file.
// On any error the current file is intact (the next Record reopens it and
// tries again).
func (l *Log) rotate() error {
	cerr := l.f.Close()
	l.f = nil
	if cerr != nil {
		return cerr
	}
	name := func(i int) string { return l.path + "." + strconv.Itoa(i) }
	if err := os.Remove(name(l.keep)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := l.keep - 1; i >= 1; i-- {
		if err := os.Rename(name(i), name(i+1)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if err := os.Rename(l.path, name(1)); err != nil {
		return err
	}
	return l.openFile()
}

// Close flushes and closes the file. Later Records fail.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.f == nil {
		return nil
	}
	err := l.f.Sync()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// validate says whether r fits the schema: nothing in it can be free text.
func validate(r enforce.Record) error {
	switch {
	case r.Time.Year() < 0 || r.Time.Year() > 9999:
		return errors.New("declog: time out of range")
	case len(r.Role) > maxRoleLen || !utf8.ValidString(r.Role):
		return errors.New("declog: bad role")
	case !validTool(r.Tool):
		return errors.New("declog: bad tool name")
	case r.Class != 0 && r.Class != policy.ClassR && r.Class != policy.ClassW && r.Class != policy.ClassX:
		return errors.New("declog: bad class")
	case r.Hash != "" && !r.Hash.Valid():
		return errors.New("declog: bad hash")
	case !r.State.Valid():
		return errors.New("declog: bad state")
	}
	return nil
}

// validTool: "", "tools/list", or 1-128 of [A-Za-z0-9_.-].
func validTool(s string) bool {
	if s == "" || s == "tools/list" {
		return true
	}
	if len(s) > policy.MaxToolNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

func encode(r enforce.Record) ([]byte, error) {
	if err := validate(r); err != nil {
		return nil, err
	}
	l := line{
		Time:    r.Time.UTC().Format(time.RFC3339Nano),
		Role:    r.Role,
		Tool:    r.Tool,
		Allowed: r.Allowed,
		Version: r.Version,
		Hash:    string(r.Hash),
		State:   string(r.State),
	}
	if r.Class != 0 {
		l.Class = string(rune(r.Class))
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(l); err != nil { // Encode ends the line with "\n"
		return nil, err
	}
	if buf.Len() > maxLineLen {
		return nil, errors.New("declog: line too long")
	}
	return buf.Bytes(), nil
}

// Decode reads one line as written by Record (a trailing newline is
// optional). It is strict: exactly the eight fields, each once, in lowercase,
// a UTC time, and values that pass the same checks Record applies.
func Decode(b []byte) (enforce.Record, error) {
	bad := func(why string) (enforce.Record, error) {
		return enforce.Record{}, errors.New("declog: malformed line: " + why)
	}
	b = bytes.TrimSuffix(b, []byte("\n"))
	if len(b) > maxLineLen {
		return bad("too long")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return bad("not an object")
	}
	var l line
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		key, ok := tok.(string)
		if err != nil || !ok {
			return bad("bad key")
		}
		if seen[key] {
			return bad("duplicate key")
		}
		seen[key] = true
		var dst any
		switch key {
		case "time":
			dst = &l.Time
		case "role":
			dst = &l.Role
		case "tool":
			dst = &l.Tool
		case "allowed":
			dst = &l.Allowed
		case "class":
			dst = &l.Class
		case "version":
			dst = &l.Version
		case "hash":
			dst = &l.Hash
		case "state":
			dst = &l.State
		default:
			return bad("unknown key")
		}
		if err := dec.Decode(dst); err != nil {
			return bad("bad value for " + key)
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return bad("unterminated")
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad("trailing data")
	}
	if len(seen) != 8 {
		return bad("missing field")
	}
	ts, err := time.Parse(time.RFC3339Nano, l.Time)
	if err != nil || l.Time[len(l.Time)-1] != 'Z' {
		return bad("time")
	}
	r := enforce.Record{
		Time:    ts.UTC(),
		Role:    l.Role,
		Tool:    l.Tool,
		Allowed: l.Allowed,
		Version: l.Version,
		Hash:    wire.Hash(l.Hash),
		State:   wire.ProxyState(l.State),
	}
	switch len(l.Class) {
	case 0:
	case 1:
		r.Class = policy.Class(l.Class[0])
	default:
		return bad("class")
	}
	if err := validate(r); err != nil {
		return enforce.Record{}, err
	}
	return r, nil
}
