// Package applylog is the proxy's append-only, hash-chained log of apply
// attempts, and its verifier (invariant I6; ARCHITECTURE section 10).
//
// File format: one JSON object per line, in a single canonical form (fixed
// key order, UTC RFC 3339 time, no spaces). Decode accepts only that form, so
// every entry has exactly one byte representation.
//
// Chain: Seq starts at 1 and grows by 1 (M-D39). Prev is the previous
// entry's Self ("" for the first). Self is the SHA-256, in lowercase hex, of
// the entry's canonical fields plus Prev. Verify detects an edited field, a
// deleted entry, a reordered or duplicated entry, a garbage line and a torn
// last line.
//
// What Verify cannot see: an attacker who cuts whole lines off the end, or
// who edits the last entry and recomputes its Self, leaves a valid shorter or
// altered chain. That is closed by the anchor, not by this file: every status
// report carries log_seq and log_head (Head), the control plane stores them,
// and kairanctl evidence flags a regression (M-D35).
//
// A Log has one writer. It remembers the file size it wrote and refuses to
// append if the file changed behind its back. Each Append is one write of a
// whole line to an O_APPEND file followed by fsync; if the write fails the
// partial line is cut off again before the error is returned.
//
// Open refuses a log that fails Verify, including one whose last line lacks
// its newline (ErrTruncated). The caller treats that as tampering; Open does
// not repair the file.
//
// # Reset: leaving a broken log (P-13, M-D64)
//
// A log that fails Verify is never edited, truncated or deleted. When a newer
// valid policy arrives, the proxy calls Reset. The broken file stays as
// evidence under <log>.broken-<n> (n is the smallest number not in use, so two
// resets give broken-1 and broken-2; a hard link makes the new name before the
// old name is replaced, so there is never a moment without the evidence), and
// a new chain starts at Seq 1 with Prev "". Its first line is the reset entry:
//
//	{"seq":1,"time":"...","from":F,"to":0,"hash":"H","result":"tampered",
//	 "reset":{"seq":S,"file":"apply.log.broken-N","reason":"R"},"prev":"","self":"..."}
//
// from (F) is the floor: the larger of the highest version applied in the
// verifiable part of the broken file and the version the caller knows (the
// stored policy), carried over so that a version already applied is never
// accepted again (I2). hash (H) is the Self of the broken file's last
// verifiable entry (its head) and reset.seq (S) its seq; both are empty or 0
// when not even the first line verified. reset.file is the base name of the
// kept file. reset.reason is one of chain_broken, malformed, truncated or
// unreadable: the first failure Verify found. Decode accepts the reset key
// only on a Seq 1 entry with Result "tampered", To 0 and a file name of the
// form <name>.broken-<n>; the reset fields are part of Self, and no other
// entry has the key, so every older log hashes exactly as before.
//
// LastApplied on a chain with no applied entry yet returns the floor and no
// hash. ResetPending is true until the first applied entry (a rejection does
// not end it): boot treats a pending reset as Tampered, so a crash between the
// reset and the first apply still fails closed. The control plane sees the
// anchor (log_seq, log_head) go backwards; that is intended (M-D48). The old
// chain can be verified only by hand, on the kept file, up to its first bad
// line. The caller holds the data directory lock around Reset.
package applylog

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

// Errors. Verify, Read, Decode and Open wrap these; use errors.Is.
var (
	// ErrMalformed: a line is not a canonical entry.
	ErrMalformed = errors.New("applylog: malformed entry")
	// ErrChain: the entry is well-formed but breaks the chain (wrong seq,
	// wrong prev, or a Self that does not match its fields).
	ErrChain = errors.New("applylog: chain broken")
	// ErrTruncated: the log ends in a line with no newline.
	ErrTruncated = errors.New("applylog: truncated last line")
	// ErrChanged: the file is not the size this Log last wrote.
	ErrChanged = errors.New("applylog: file changed since last append")
)

// maxLine is the longest line Verify accepts, newline included. A real entry
// is about 350 bytes.
const maxLine = 4096

// Entry is one apply attempt.
type Entry struct {
	Seq    uint64         // 1, 2, 3 ...; filled by Append
	Time   time.Time      // when it was logged, from the Log's clock; filled by Append
	From   uint64         // version before
	To     uint64         // version offered
	Hash   wire.Hash      // payload hash offered ("" if there was no usable payload)
	Result wire.ErrorCode // "" = applied
	Prev   wire.Hash      // Self of the previous entry ("" for the first); filled by Append
	Self   wire.Hash      // SHA-256 over this entry's canonical fields + Prev; filled by Append
	// Reset is set only on the first entry of a chain that replaced a broken
	// log (see Reset). The zero value means this is an ordinary entry.
	Reset ResetInfo
}

// line is the on-disk shape. Field order here is the key order on disk.
type line struct {
	Seq    uint64         `json:"seq"`
	Time   string         `json:"time"`
	From   uint64         `json:"from"`
	To     uint64         `json:"to"`
	Hash   wire.Hash      `json:"hash"`
	Result wire.ErrorCode `json:"result"`
	Reset  *resetLine     `json:"reset,omitempty"`
	Prev   wire.Hash      `json:"prev"`
	Self   wire.Hash      `json:"self"`
}

type resetLine struct {
	Seq    uint64 `json:"seq"`
	File   string `json:"file"`
	Reason string `json:"reason"`
}

// fmtTime is the one time format: UTC, with trailing zeros of the fraction
// dropped.
const fmtTime = time.RFC3339Nano

// Encode returns the canonical line for e, without the trailing newline.
func Encode(e Entry) []byte {
	l := line{
		Seq: e.Seq, Time: e.Time.UTC().Format(fmtTime), From: e.From, To: e.To,
		Hash: e.Hash, Result: e.Result, Prev: e.Prev, Self: e.Self,
	}
	if !e.Reset.IsZero() {
		l.Reset = &resetLine{Seq: e.Reset.Seq, File: e.Reset.File, Reason: e.Reset.Reason}
	}
	b, err := json.Marshal(l)
	if err != nil { // cannot happen: only strings and integers
		panic("applylog: " + err.Error())
	}
	return b
}

// Decode parses one line (without its newline). It accepts only the exact
// bytes Encode produces for a well-formed entry, so it returns ErrMalformed
// for case-variant, duplicate, reordered or unknown keys, extra whitespace,
// non-UTC times, bad hashes, an unknown result code, Seq 0, or a Prev that is
// set on the first entry or missing on a later one. It does not check Self.
func Decode(data []byte) (Entry, error) {
	var l line
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&l); err != nil {
		return Entry{}, ErrMalformed
	}
	t, err := time.Parse(fmtTime, l.Time)
	if err != nil {
		return Entry{}, ErrMalformed
	}
	e := Entry{Seq: l.Seq, Time: t.UTC(), From: l.From, To: l.To, Hash: l.Hash, Result: l.Result, Prev: l.Prev, Self: l.Self}
	if l.Reset != nil {
		if l.Reset.File == "" { // "reset":{} is not the absence of a reset
			return Entry{}, ErrMalformed
		}
		e.Reset = ResetInfo{Seq: l.Reset.Seq, File: l.Reset.File, Reason: l.Reset.Reason}
	}
	if err := check(e); err != nil {
		return Entry{}, err
	}
	if !bytes.Equal(Encode(e), data) {
		return Entry{}, ErrMalformed
	}
	return e, nil
}

// check validates the fields that do not depend on the chain.
func check(e Entry) error {
	switch {
	case e.Seq == 0:
		return ErrMalformed
	case e.Hash != "" && !e.Hash.Valid():
		return ErrMalformed
	case e.Result != "" && !e.Result.Valid():
		return ErrMalformed
	case (e.Seq == 1) != (e.Prev == ""):
		return ErrMalformed
	case e.Prev != "" && !e.Prev.Valid():
		return ErrMalformed
	case !e.Self.Valid():
		return ErrMalformed
	case !e.Reset.IsZero():
		if e.Seq != 1 || e.Result != wire.ErrTampered || e.To != 0 || !e.Reset.valid() ||
			(e.Reset.Seq == 0) != (e.Hash == "") {
			return ErrMalformed
		}
	}
	return nil
}

// computeSelf is the hash that links an entry into the chain.
func computeSelf(e Entry) wire.Hash {
	var b bytes.Buffer
	b.WriteString("kairan/applylog/v1\n")
	for _, f := range []string{
		strconv.FormatUint(e.Seq, 10),
		e.Time.UTC().Format(fmtTime),
		strconv.FormatUint(e.From, 10),
		strconv.FormatUint(e.To, 10),
		string(e.Hash),
		string(e.Result),
		string(e.Prev),
	} {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	if !e.Reset.IsZero() { // only reset entries; every other entry hashes as before
		for _, f := range []string{"reset", strconv.FormatUint(e.Reset.Seq, 10), e.Reset.File, e.Reset.Reason} {
			b.WriteString(f)
			b.WriteByte('\n')
		}
	}
	sum := sha256.Sum256(b.Bytes())
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// scan reads and checks the chain, calling fn for each good entry. On error
// it returns what it verified so far. consumed counts the bytes of good lines.
func scan(r io.Reader, fn func(Entry)) (last Entry, n int, consumed int64, err error) {
	br := bufio.NewReaderSize(r, maxLine)
	for {
		raw, rerr := br.ReadSlice('\n')
		switch {
		case rerr == io.EOF && len(raw) == 0:
			return last, n, consumed, nil
		case rerr == io.EOF:
			return last, n, consumed, fmt.Errorf("%w: after entry %d", ErrTruncated, n)
		case rerr == bufio.ErrBufferFull:
			return last, n, consumed, fmt.Errorf("%w: line %d too long", ErrMalformed, n+1)
		case rerr != nil:
			return last, n, consumed, fmt.Errorf("applylog: read: %w", rerr)
		}
		e, derr := Decode(raw[:len(raw)-1])
		if derr != nil {
			return last, n, consumed, fmt.Errorf("%w: line %d", derr, n+1)
		}
		if e.Seq != last.Seq+1 || e.Prev != last.Self || e.Self != computeSelf(e) {
			return last, n, consumed, fmt.Errorf("%w: line %d", ErrChain, n+1)
		}
		last = e
		n++
		consumed += int64(len(raw))
		if fn != nil {
			fn(e)
		}
	}
}

// Verify checks the whole chain. It returns the last good entry and how many
// entries verified. On error those describe the log up to the first bad
// line. An empty log is valid: zero Entry, 0, nil. Used by kairanctl too.
func Verify(r io.Reader) (last Entry, n int, err error) {
	last, n, _, err = scan(r, nil)
	return last, n, err
}

// Read verifies the chain and returns every entry. On error it returns the
// good entries so far and the error.
func Read(r io.Reader) ([]Entry, error) {
	var all []Entry
	_, _, _, err := scan(r, func(e Entry) { all = append(all, e) })
	return all, err
}

// Log is an open apply log. It is safe for concurrent use.
type Log struct {
	mu    sync.Mutex
	f     *os.File
	clk   clock.Clock
	last  Entry // zero if empty
	size  int64 // bytes in the file after the last good append
	tally tally
}

// tally folds the entries of a log into what the proxy needs from it: the
// newest applied version and hash, and whether a reset is still waiting for
// its first apply.
type tally struct {
	version uint64
	hash    wire.Hash
	pending bool
}

func (t *tally) add(e Entry) {
	switch {
	case !e.Reset.IsZero():
		// A reset keeps the floor of the log it replaced, with no hash, and
		// stays pending until a policy is applied on the new chain.
		t.version, t.hash, t.pending = e.From, "", true
	case e.Result == "":
		t.version, t.hash, t.pending = e.To, e.Hash, false
	}
}

// Open opens (creating if absent, mode 0600) the log at path and verifies
// the existing chain first. A log that fails verification is not opened; the
// error wraps ErrMalformed, ErrChain or ErrTruncated. clk supplies the time
// of each entry.
func Open(path string, clk clock.Clock) (*Log, error) {
	if clk == nil {
		return nil, errors.New("applylog: nil clock")
	}
	_, statErr := os.Stat(path)
	created := errors.Is(statErr, os.ErrNotExist)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("applylog: open: %w", err)
	}
	l := &Log{f: f, clk: clk}
	last, _, consumed, err := scan(f, l.tally.add)
	if err != nil {
		f.Close()
		return nil, err
	}
	l.last, l.size = last, consumed
	if created {
		if err := syncDir(filepath.Dir(path)); err != nil {
			f.Close()
			return nil, err
		}
	}
	return l, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("applylog: sync dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("applylog: sync dir: %w", err)
	}
	return nil
}

// Append logs e. It fills Seq, Time (from the clock), Prev and Self, writes
// one line, fsyncs, and returns the finished entry. On any error the log is
// as before. From, To, Hash and Result come from the caller; Hash must be
// empty or a valid hash and Result empty or a known error code.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return Entry{}, errors.New("applylog: closed")
	}
	if e.Hash != "" && !e.Hash.Valid() {
		return Entry{}, fmt.Errorf("applylog: bad hash")
	}
	if e.Result != "" && !e.Result.Valid() {
		return Entry{}, fmt.Errorf("applylog: bad result code")
	}
	st, err := l.f.Stat()
	if err != nil {
		return Entry{}, fmt.Errorf("applylog: stat: %w", err)
	}
	if st.Size() != l.size {
		return Entry{}, ErrChanged
	}
	e.Seq = l.last.Seq + 1
	e.Time = l.clk.Now().UTC()
	e.Prev = l.last.Self
	e.Self = computeSelf(e)
	data := append(Encode(e), '\n')
	// Never write a line that Open would refuse (for example a year past 9999).
	if _, err := Decode(data[:len(data)-1]); err != nil {
		return Entry{}, fmt.Errorf("applylog: entry cannot be encoded: %w", err)
	}
	if _, err := l.f.Write(data); err != nil {
		l.rollback()
		return Entry{}, fmt.Errorf("applylog: write: %w", err)
	}
	if err := l.f.Sync(); err != nil {
		l.rollback()
		return Entry{}, fmt.Errorf("applylog: sync: %w", err)
	}
	l.last = e
	l.size += int64(len(data))
	l.tally.add(e)
	return e, nil
}

// rollback cuts off whatever a failed write left, back to the last good size.
// If that fails too, the next Append sees a size mismatch and refuses.
func (l *Log) rollback() {
	if l.f.Truncate(l.size) == nil {
		_ = l.f.Sync()
	}
}

// Head is the anchor for status reports: the last entry's Seq and Self.
// An empty log gives 0 and "" (M-D39).
func (l *Log) Head() (seq uint64, head wire.Hash) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.last.Seq, l.last.Self
}

// LastApplied is the version and payload hash of the newest entry whose
// Result is "" (applied, including repair entries). It is 0 and "" if
// nothing was ever applied. It is the source of the highest applied version
// across restarts (I2). On a chain that starts with a reset entry and has no
// applied entry yet, the version is the floor the reset carried over from the
// broken log and the hash is "".
func (l *Log) LastApplied() (version uint64, hash wire.Hash) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tally.version, l.tally.hash
}

// ResetPending reports whether the chain starts with a reset entry and no
// policy has been applied since. Boot treats that as Tampered: the log
// cannot vouch for the policy on disk until a new one is applied.
func (l *Log) ResetPending() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tally.pending
}

// Close closes the file. Later Appends fail.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
