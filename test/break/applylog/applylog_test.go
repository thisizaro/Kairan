// Package applylogbreak holds black-box attack tests for the proxy apply log
// (task P-04). Sources: ARCHITECTURE section 4 boot rule, section 8, the
// applylog LLD (hash chain, seq from 1, Head/LastApplied), M-D33/M-D35/M-D39,
// PRD I2/I6, and the go doc of the applylog package.
package applylogbreak

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"testing/iotest"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

var start = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func hx(i int) wire.Hash { return wire.Hash(fmt.Sprintf("%064x", i)) }

// entry i: applied for odd i, a rejection for every fourth.
func entryN(i int) applylog.Entry {
	e := applylog.Entry{From: uint64(i - 1), To: uint64(i), Hash: hx(i)}
	if i%4 == 0 {
		e.Result = wire.ErrNotNewer
	}
	return e
}

func newLog(t *testing.T) (*applylog.Log, string, *clock.Fake) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "apply.log")
	clk := clock.NewFake(start)
	l, err := applylog.Open(p, clk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, p, clk
}

// build writes n entries and returns the raw file bytes and the finished entries.
func build(t *testing.T, n int) ([]byte, []applylog.Entry) {
	t.Helper()
	l, p, clk := newLog(t)
	var es []applylog.Entry
	for i := 1; i <= n; i++ {
		clk.Advance(time.Second)
		e, err := l.Append(entryN(i))
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		es = append(es, e)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b, es
}

func lines(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	parts := bytes.SplitAfter(b, []byte("\n"))
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	return parts
}

func join(ls ...[]byte) []byte { return bytes.Join(ls, nil) }

func isChainErr(err error) bool {
	return errors.Is(err, applylog.ErrMalformed) || errors.Is(err, applylog.ErrChain) || errors.Is(err, applylog.ErrTruncated)
}

func mustFailVerify(t *testing.T, why string, b []byte) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s: PANIC %v", why, r)
		}
	}()
	_, _, err := applylog.Verify(bytes.NewReader(b))
	if err == nil {
		t.Fatalf("%s: Verify accepted tampered log", why)
	}
	if !isChainErr(err) {
		t.Fatalf("%s: Verify error %v wraps none of ErrMalformed/ErrChain/ErrTruncated", why, err)
	}
	if _, rerr := applylog.Read(bytes.NewReader(b)); rerr == nil {
		t.Fatalf("%s: Read accepted what Verify rejected", why)
	}
}

func mustOpenFail(t *testing.T, why string, b []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "apply.log")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := applylog.Open(p, clock.NewFake(start))
	if err == nil {
		_ = l.Close()
		t.Fatalf("%s: Open accepted a log that fails Verify", why)
	}
	if !isChainErr(err) {
		t.Fatalf("%s: Open error %v wraps none of the chain errors", why, err)
	}
	if l != nil {
		t.Fatalf("%s: Open returned a Log together with an error", why)
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(after, b) {
		t.Fatalf("%s: Open modified the file of a log it refused (doc: it does not repair)", why)
	}
}

// --- Happy path and shape ------------------------------------------------

func TestChainShape(t *testing.T) {
	b, es := build(t, 9)
	if len(es) != 9 {
		t.Fatal("setup")
	}
	var prev wire.Hash
	seen := map[wire.Hash]bool{}
	for i, e := range es {
		if e.Seq != uint64(i+1) {
			t.Fatalf("entry %d has Seq %d (starts at 1, +1 each)", i, e.Seq)
		}
		if e.Prev != prev {
			t.Fatalf("entry %d Prev=%q want %q", e.Seq, e.Prev, prev)
		}
		if !e.Self.Valid() {
			t.Fatalf("entry %d Self %q is not a valid hash", e.Seq, e.Self)
		}
		if seen[e.Self] {
			t.Fatalf("entry %d Self repeats", e.Seq)
		}
		seen[e.Self] = true
		if e.From != entryN(i+1).From || e.To != entryN(i+1).To || e.Hash != entryN(i+1).Hash || e.Result != entryN(i+1).Result {
			t.Fatalf("Append changed caller-owned fields: %+v", e)
		}
		if !e.Time.Equal(start.Add(time.Duration(i+1) * time.Second)) {
			t.Fatalf("entry %d Time %v not from the clock", e.Seq, e.Time)
		}
		prev = e.Self
	}
	if es[0].Prev != "" {
		t.Fatalf("first Prev = %q, want empty", es[0].Prev)
	}
	last, n, err := applylog.Verify(bytes.NewReader(b))
	if err != nil || n != 9 || last != es[8] {
		t.Fatalf("Verify = %+v, %d, %v; want last entry, 9, nil", last, n, err)
	}
	got, err := applylog.Read(bytes.NewReader(b))
	if err != nil || len(got) != 9 {
		t.Fatalf("Read: %v len %d", err, len(got))
	}
	for i := range got {
		if got[i] != es[i] {
			t.Fatalf("Read entry %d differs from what Append returned: %+v vs %+v", i, got[i], es[i])
		}
	}
	// One canonical byte form: re-encoding gives back the file exactly.
	var re []byte
	for _, e := range got {
		re = append(re, applylog.Encode(e)...)
		re = append(re, '\n')
	}
	if !bytes.Equal(re, b) {
		t.Fatalf("re-encoded log differs from file:\n%s\nvs\n%s", re, b)
	}
}

func TestEmptyLog(t *testing.T) {
	l, p, _ := newLog(t)
	if s, h := l.Head(); s != 0 || h != "" {
		t.Fatalf("empty Head = %d, %q; want 0, empty (M-D39)", s, h)
	}
	if v, h := l.LastApplied(); v != 0 || h != "" {
		t.Fatalf("empty LastApplied = %d, %q", v, h)
	}
	last, n, err := applylog.Verify(bytes.NewReader(nil))
	if err != nil || n != 0 || last != (applylog.Entry{}) {
		t.Fatalf("Verify(empty) = %+v %d %v", last, n, err)
	}
	if es, err := applylog.Read(bytes.NewReader(nil)); err != nil || len(es) != 0 {
		t.Fatalf("Read(empty) = %v %v", es, err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("Open must create the file: %v", err)
	}
	if st.Size() != 0 {
		t.Fatalf("new log not empty: %d bytes", st.Size())
	}
}

func TestFileModeIs0600EvenWithUmask0(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)
	l, p, _ := newLog(t)
	if _, err := l.Append(entryN(1)); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("log mode = %o, doc says created with 0600", st.Mode().Perm())
	}
	// Also after reopen-and-append.
	_ = l.Close()
	l2, err := applylog.Open(p, clock.NewFake(start))
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if _, err := l2.Append(entryN(2)); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode changed after reopen: %o", st.Mode().Perm())
	}
}

func TestReopenKeepsChainAndAnchors(t *testing.T) {
	l, p, clk := newLog(t)
	var last applylog.Entry
	for i := 1; i <= 6; i++ {
		clk.Advance(time.Second)
		e, err := l.Append(entryN(i))
		if err != nil {
			t.Fatal(err)
		}
		last = e
	}
	seq, head := l.Head()
	if seq != 6 || head != last.Self {
		t.Fatalf("Head = %d,%q; want 6,%q", seq, head, last.Self)
	}
	v, h := l.LastApplied() // entries 4 was a rejection; 6 is applied
	if v != 6 || h != hx(6) {
		t.Fatalf("LastApplied = %d,%q", v, h)
	}
	_ = l.Close()
	l2, err := applylog.Open(p, clk)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l2.Close()
	if s2, h2 := l2.Head(); s2 != seq || h2 != head {
		t.Fatalf("Head after reopen = %d,%q", s2, h2)
	}
	if v2, hh2 := l2.LastApplied(); v2 != 6 || hh2 != hx(6) {
		t.Fatalf("LastApplied after reopen = %d,%q", v2, hh2)
	}
	clk.Advance(time.Second)
	e7, err := l2.Append(entryN(7))
	if err != nil || e7.Seq != 7 || e7.Prev != last.Self {
		t.Fatalf("append after reopen: %+v %v", e7, err)
	}
	b, _ := os.ReadFile(p)
	if _, n, err := applylog.Verify(bytes.NewReader(b)); err != nil || n != 7 {
		t.Fatalf("verify after reopen+append: %d %v", n, err)
	}
}

func TestLastAppliedSkipsRejections(t *testing.T) {
	l, _, clk := newLog(t)
	app := func(from, to uint64, h wire.Hash, res wire.ErrorCode) {
		clk.Advance(time.Second)
		if _, err := l.Append(applylog.Entry{From: from, To: to, Hash: h, Result: res}); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	app(0, 1, hx(1), "")
	if v, h := l.LastApplied(); v != 1 || h != hx(1) {
		t.Fatalf("LastApplied = %d %q", v, h)
	}
	for _, code := range []wire.ErrorCode{wire.ErrThreshold, wire.ErrNotNewer, wire.ErrExpired, wire.ErrMalformed, wire.ErrWrongTenant, wire.ErrPersist, wire.ErrTampered, wire.ErrClockUntrusted, wire.ErrPayloadType} {
		app(1, 9, hx(9), code)
		if v, h := l.LastApplied(); v != 1 || h != hx(1) {
			t.Fatalf("a %q rejection moved LastApplied to %d %q (I2: rejected offers never count)", code, v, h)
		}
	}
	// Rejection with empty hash ("no usable payload") is allowed.
	app(1, 0, "", wire.ErrMalformed)
	app(1, 2, hx(2), "")
	if v, h := l.LastApplied(); v != 2 || h != hx(2) {
		t.Fatalf("LastApplied = %d %q", v, h)
	}
	if s, _ := l.Head(); s != 12 {
		t.Fatalf("Head seq = %d, want 12", s)
	}
}

// --- Self commits to every field ----------------------------------------

func selfOf(t *testing.T, mutate func(*applylog.Entry), clkStart time.Time) wire.Hash {
	t.Helper()
	p := filepath.Join(t.TempDir(), "l")
	l, err := applylog.Open(p, clock.NewFake(clkStart))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e := applylog.Entry{From: 5, To: 7, Hash: hx(7), Result: ""}
	mutate(&e)
	got, err := l.Append(e)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	return got.Self
}

func TestSelfCommitsToEveryField(t *testing.T) {
	base := selfOf(t, func(*applylog.Entry) {}, start)
	variants := map[string]wire.Hash{
		"From":       selfOf(t, func(e *applylog.Entry) { e.From = 6 }, start),
		"To":         selfOf(t, func(e *applylog.Entry) { e.To = 8 }, start),
		"Hash":       selfOf(t, func(e *applylog.Entry) { e.Hash = hx(8) }, start),
		"Result":     selfOf(t, func(e *applylog.Entry) { e.Result = wire.ErrExpired }, start),
		"Time":       selfOf(t, func(*applylog.Entry) {}, start.Add(time.Second)),
		"Time-1ns":   selfOf(t, func(*applylog.Entry) {}, start.Add(time.Nanosecond)),
		"Hash-empty": selfOf(t, func(e *applylog.Entry) { e.Hash = "" }, start),
	}
	for name, h := range variants {
		if h == base {
			t.Fatalf("changing %s did not change Self: the field is not covered by the hash (I6)", name)
		}
	}
	// Field boundary ambiguity: concatenating decimals must not collide.
	pairs := [][2]uint64{{1, 23}, {12, 3}, {123, 0}, {0, 123}, {1, 2}, {12, 0}}
	seen := map[wire.Hash][2]uint64{}
	for _, pr := range pairs {
		pr := pr
		h := selfOf(t, func(e *applylog.Entry) { e.From, e.To = pr[0], pr[1] }, start)
		if o, dup := seen[h]; dup {
			t.Fatalf("(From,To)=%v and %v collide: canonical fields are ambiguous", pr, o)
		}
		seen[h] = pr
	}
	// Hash vs Result positions.
	a := selfOf(t, func(e *applylog.Entry) { e.Hash, e.Result = "", wire.ErrExpired }, start)
	b := selfOf(t, func(e *applylog.Entry) { e.Hash, e.Result = hx(1), "" }, start)
	if a == b {
		t.Fatal("Hash/Result swap collides")
	}
	// Self covers Prev: identical second entries after different first entries differ.
	two := func(first uint64) wire.Hash {
		p := filepath.Join(t.TempDir(), "l")
		l, _ := applylog.Open(p, clock.NewFake(start))
		defer l.Close()
		_, _ = l.Append(applylog.Entry{From: 0, To: first, Hash: hx(int(first))})
		e2, err := l.Append(applylog.Entry{From: first, To: 100, Hash: hx(100)})
		if err != nil {
			t.Fatal(err)
		}
		return e2.Self
	}
	// From differs too, so compare with From fixed:
	p1 := filepath.Join(t.TempDir(), "l1")
	p2 := filepath.Join(t.TempDir(), "l2")
	l1, _ := applylog.Open(p1, clock.NewFake(start))
	l2, _ := applylog.Open(p2, clock.NewFake(start))
	defer l1.Close()
	defer l2.Close()
	_, _ = l1.Append(applylog.Entry{From: 0, To: 1, Hash: hx(1)})
	_, _ = l2.Append(applylog.Entry{From: 0, To: 2, Hash: hx(2)})
	x1, _ := l1.Append(applylog.Entry{From: 1, To: 9, Hash: hx(9)})
	x2, _ := l2.Append(applylog.Entry{From: 1, To: 9, Hash: hx(9)})
	if x1.Self == x2.Self {
		t.Fatal("Self does not cover Prev: same entry on different histories hashes equal")
	}
	_ = two
}

// --- Tamper detection (I6) ----------------------------------------------

func TestEverySingleByteEditDetected(t *testing.T) {
	b, _ := build(t, 5)
	n := 0
	for i := 0; i < len(b); i++ {
		for _, xor := range []byte{0x01, 0x20, 0x80, 0xff} {
			c := append([]byte(nil), b...)
			c[i] ^= xor
			if bytes.Equal(c, b) {
				continue
			}
			mustFailVerify(t, fmt.Sprintf("byte %d ^ %#x", i, xor), c)
			n++
		}
	}
	t.Logf("%d single-byte mutations all rejected", n)
}

func TestEveryByteSubstitutionAtFieldsDetected(t *testing.T) {
	b, _ := build(t, 4)
	for i := 0; i < len(b); i++ {
		for _, ch := range []byte{'0', '1', '9', 'f', 'x', '"', ' ', '\n', 0} {
			if b[i] == ch {
				continue
			}
			c := append([]byte(nil), b...)
			c[i] = ch
			mustFailVerify(t, fmt.Sprintf("byte %d -> %q", i, ch), c)
		}
	}
}

func TestEveryByteInsertionAndDeletionDetected(t *testing.T) {
	b, _ := build(t, 4)
	for i := 0; i <= len(b); i++ {
		ins := append(append(append([]byte(nil), b[:i]...), ' '), b[i:]...)
		mustFailVerify(t, fmt.Sprintf("insert space at %d", i), ins)
		if i < len(b) {
			del := append(append([]byte(nil), b[:i]...), b[i+1:]...)
			mustFailVerify(t, fmt.Sprintf("delete byte %d", i), del)
		}
	}
}

func TestDeleteEntry(t *testing.T) {
	b, es := build(t, 6)
	ls := lines(b)
	for i := range ls {
		var rest [][]byte
		rest = append(rest, ls[:i]...)
		rest = append(rest, ls[i+1:]...)
		c := join(rest...)
		if i == len(ls)-1 {
			// Documented blind spot: whole lines cut off the end leave a valid shorter chain.
			last, n, err := applylog.Verify(bytes.NewReader(c))
			if err != nil || n != 5 {
				t.Fatalf("tail cut at a line boundary: %v n=%d", err, n)
			}
			// ...which is exactly what the anchor (Head) must expose: seq regressed.
			if last.Seq >= es[5].Seq || last.Self == es[5].Self {
				t.Fatalf("anchor of the shortened log does not differ: %+v", last)
			}
			continue
		}
		mustFailVerify(t, fmt.Sprintf("delete entry %d", i+1), c)
		mustOpenFail(t, fmt.Sprintf("delete entry %d", i+1), c)
	}
}

func TestReorderEntries(t *testing.T) {
	b, _ := build(t, 6)
	ls := lines(b)
	for i := 0; i < len(ls); i++ {
		for j := i + 1; j < len(ls); j++ {
			c := make([][]byte, len(ls))
			copy(c, ls)
			c[i], c[j] = c[j], c[i]
			mustFailVerify(t, fmt.Sprintf("swap %d,%d", i+1, j+1), join(c...))
		}
	}
	// Reversed, rotated.
	rev := make([][]byte, len(ls))
	for i := range ls {
		rev[len(ls)-1-i] = ls[i]
	}
	mustFailVerify(t, "reversed", join(rev...))
	mustFailVerify(t, "rotated", join(append(append([][]byte{}, ls[1:]...), ls[0])...))
}

func TestDuplicateAndReplay(t *testing.T) {
	b, _ := build(t, 5)
	ls := lines(b)
	for i := range ls {
		var c [][]byte
		c = append(c, ls[:i+1]...)
		c = append(c, ls[i])
		c = append(c, ls[i+1:]...)
		mustFailVerify(t, fmt.Sprintf("duplicate entry %d in place", i+1), join(c...))
	}
	mustFailVerify(t, "whole log replayed after itself", join(b, b))
	mustFailVerify(t, "first entry replayed at end", join(b, ls[0]))
	mustFailVerify(t, "last entry replayed at end", join(b, ls[len(ls)-1]))
	mustFailVerify(t, "first entry only twice", join(ls[0], ls[0]))
}

func TestSpliceTwoValidLogs(t *testing.T) {
	a, _ := build(t, 6)
	// A second, different valid log: same shape, different history from entry 1.
	l, p, clk := newLog(t)
	for i := 1; i <= 6; i++ {
		clk.Advance(2 * time.Second)
		e := entryN(i)
		e.To += 100
		if _, err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	if bytes.Equal(a, b) {
		t.Fatal("setup: logs identical")
	}
	if _, _, err := applylog.Verify(bytes.NewReader(b)); err != nil {
		t.Fatalf("setup: second log invalid: %v", err)
	}
	la, lb := lines(a), lines(b)
	for k := 1; k < 6; k++ {
		mustFailVerify(t, fmt.Sprintf("A[:%d]+B[%d:]", k, k), join(append(append([][]byte{}, la[:k]...), lb[k:]...)...))
		mustFailVerify(t, fmt.Sprintf("B[:%d]+A[%d:]", k, k), join(append(append([][]byte{}, lb[:k]...), la[k:]...)...))
	}
	mustFailVerify(t, "A then B", join(a, b))
	mustFailVerify(t, "interleaved", join(la[0], lb[1], la[2], lb[3]))
	// Two logs with a shared first entry (fork): each branch valid alone, the concatenation is not.
	fork := func(extra uint64) []byte {
		l, p, _ := newLog(t)
		_, _ = l.Append(applylog.Entry{From: 0, To: 1, Hash: hx(1)})
		_, _ = l.Append(applylog.Entry{From: 1, To: extra, Hash: hx(int(extra))})
		bb, _ := os.ReadFile(p)
		return bb
	}
	f1, f2 := fork(2), fork(3)
	lf1, lf2 := lines(f1), lines(f2)
	if !bytes.Equal(lf1[0], lf2[0]) {
		t.Fatal("setup: forks should share entry 1")
	}
	mustFailVerify(t, "fork branches concatenated", join(lf1[0], lf1[1], lf2[1]))
}

func TestTruncatedTail(t *testing.T) {
	b, es := build(t, 4)
	ls := lines(b)
	lastLen := len(ls[len(ls)-1])
	body := len(b) - lastLen
	// Cut inside the last line at every offset, including losing only the newline.
	for cut := body + 1; cut < len(b); cut++ {
		c := b[:cut]
		_, _, err := applylog.Verify(bytes.NewReader(c))
		if err == nil {
			t.Fatalf("cut at %d (inside last line) verified", cut)
		}
		if cut == len(b)-1 && !errors.Is(err, applylog.ErrTruncated) {
			t.Fatalf("missing final newline should be ErrTruncated, got %v", err)
		}
		mustOpenFail(t, fmt.Sprintf("torn tail cut=%d", cut), c)
		// Verify reports the good prefix.
		last, n, _ := applylog.Verify(bytes.NewReader(c))
		if n != 3 || last != es[2] {
			t.Fatalf("cut %d: Verify prefix = %+v n=%d, want entry 3 / 3", cut, last, n)
		}
		got, rerr := applylog.Read(bytes.NewReader(c))
		if rerr == nil || len(got) != 3 {
			t.Fatalf("cut %d: Read = %d entries, err %v; want 3 good entries and an error", cut, len(got), rerr)
		}
	}
	// A line with the right bytes but a partial last write of a *second* log tail.
	mustOpenFail(t, "partial JSON after good log", join(b, []byte(`{"seq":5,"time":"2026-`)))
	mustOpenFail(t, "single NUL after good log", join(b, []byte{0}))
	mustOpenFail(t, "blank line after good log", join(b, []byte("\n")))
	mustOpenFail(t, "CRLF endings", bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n")))
	mustOpenFail(t, "BOM prefix", join([]byte("\xef\xbb\xbf"), b))
	mustOpenFail(t, "leading blank line", join([]byte("\n"), b))
	mustOpenFail(t, "only a newline", []byte("\n"))
	mustOpenFail(t, "only garbage", []byte("hello\n"))
	mustOpenFail(t, "garbage without newline", []byte("hello"))
	mustOpenFail(t, "spaces", []byte("   \n"))
	mustOpenFail(t, "json null", []byte("null\n"))
	mustOpenFail(t, "json array", []byte("[]\n"))
	mustOpenFail(t, "empty object", []byte("{}\n"))
	// Cut at a line boundary is a valid shorter log (documented blind spot).
	if _, n, err := applylog.Verify(bytes.NewReader(b[:body])); err != nil || n != 3 {
		t.Fatalf("clean cut at boundary: n=%d err=%v", n, err)
	}
	// Cut to zero is a valid empty log.
	if _, n, err := applylog.Verify(bytes.NewReader(nil)); err != nil || n != 0 {
		t.Fatal("empty")
	}
}

func TestOpenRefusesAndDoesNotRepair(t *testing.T) {
	b, _ := build(t, 3)
	ls := lines(b)
	bad := append([]byte(nil), ls[1]...)
	bad[12] ^= 1
	mustOpenFail(t, "edited middle entry", join(ls[0], bad, ls[2]))
	mustOpenFail(t, "missing newline on last", b[:len(b)-1])
}

// --- Decode strictness: one byte form per entry ---------------------------

func firstLines(t *testing.T) (l1, l2 string) {
	t.Helper()
	b, _ := build(t, 2)
	ls := lines(b)
	return strings.TrimSuffix(string(ls[0]), "\n"), strings.TrimSuffix(string(ls[1]), "\n")
}

func TestDecodeRoundTripAndStrictness(t *testing.T) {
	l1, l2 := firstLines(t)
	for name, l := range map[string]string{"first": l1, "second": l2} {
		e, err := applylog.Decode([]byte(l))
		if err != nil {
			t.Fatalf("Decode(%s) of Encode output: %v", name, err)
		}
		if got := string(applylog.Encode(e)); got != l {
			t.Fatalf("%s: Encode(Decode(line)) != line:\n%s\n%s", name, got, l)
		}
	}
	if l1 != strings.TrimSpace(l1) || strings.ContainsAny(l1, " \t\n") && false {
		t.Fatal("canonical line has stray whitespace")
	}
	bad := map[string]string{
		"empty":              "",
		"space-after-colon":  strings.Replace(l1, `"seq":`, `"seq": `, 1),
		"space-before-colon": strings.Replace(l1, `"seq":`, `"seq" :`, 1),
		"space-after-comma":  strings.Replace(l1, `,"time"`, `, "time"`, 1),
		"leading-space":      " " + l1,
		"trailing-space":     l1 + " ",
		"trailing-newline":   l1 + "\n",
		"tab":                strings.Replace(l1, `"seq":`, "\"seq\":\t", 1),
		"case-Seq":           strings.Replace(l1, `"seq"`, `"Seq"`, 1),
		"case-SELF":          strings.Replace(l1, `"self"`, `"SELF"`, 1),
		"case-to":            strings.Replace(l1, `"to"`, `"To"`, 1),
		"dup-seq":            strings.TrimSuffix(l1, "}") + `,"seq":1}`,
		"dup-self":           strings.TrimSuffix(l1, "}") + `,"self":"` + strings.Repeat("a", 64) + `"}`,
		"unknown-key":        strings.TrimSuffix(l1, "}") + `,"extra":1}`,
		"unknown-key-nested": strings.TrimSuffix(l1, "}") + `,"x":{"seq":1}}`,
		"missing-self":       strings.Replace(l1, `,"self":"`, `,"selfx":"`, 1),
		"reordered":          reorderTwo(l1),
		"seq-zero":           strings.Replace(l1, `"seq":1`, `"seq":0`, 1),
		"seq-string":         strings.Replace(l1, `"seq":1`, `"seq":"1"`, 1),
		"seq-float":          strings.Replace(l1, `"seq":1`, `"seq":1.0`, 1),
		"seq-exp":            strings.Replace(l1, `"seq":1`, `"seq":1e0`, 1),
		"seq-leading-zero":   strings.Replace(l1, `"seq":1`, `"seq":01`, 1),
		"seq-plus":           strings.Replace(l1, `"seq":1`, `"seq":+1`, 1),
		"seq-negative":       strings.Replace(l1, `"seq":1`, `"seq":-1`, 1),
		"seq-overflow":       strings.Replace(l1, `"seq":1`, `"seq":18446744073709551616`, 1),
		"from-overflow":      strings.Replace(l1, `"from":0`, `"from":18446744073709551616`, 1),
		"to-negative":        strings.Replace(l1, `"to":1`, `"to":-1`, 1),
		"time-offset":        strings.Replace(l1, `Z"`, `+00:00"`, 1),
		"time-jst":           strings.Replace(l1, `T12:00:01Z`, `T21:00:01+09:00`, 1),
		"time-no-zone":       strings.Replace(l1, `Z"`, `"`, 1),
		"time-lowercase-z":   strings.Replace(l1, `Z"`, `z"`, 1),
		"time-space":         strings.Replace(l1, `T12`, ` 12`, 1),
		"time-date-only":     strings.Replace(l1, `T12:00:01Z`, ``, 1),
		"time-null":          strings.Replace(l1, `"time":"2026-11-05T12:00:01Z"`, `"time":null`, 1),
		"time-unix":          strings.Replace(l1, `"time":"2026-11-05T12:00:01Z"`, `"time":1793880001`, 1),
		"self-upper":         strings.Replace(l1, `"self":"`+selfIn(l1)+`"`, `"self":"`+strings.ToUpper(selfIn(l1))+`"`, 1),
		"self-short":         strings.Replace(l1, selfIn(l1), selfIn(l1)[:63], 1),
		"self-long":          strings.Replace(l1, selfIn(l1), selfIn(l1)+"0", 1),
		"self-nonhex":        strings.Replace(l1, selfIn(l1), "g"+selfIn(l1)[1:], 1),
		"hash-upper":         strings.Replace(l1, `"hash":"`+string(hx(1))+`"`, `"hash":"`+strings.Repeat("A", 64)+`"`, 1),
		"hash-short":         strings.Replace(l1, `"hash":"`+string(hx(1))+`"`, `"hash":"abc"`, 1),
		"hash-null":          strings.Replace(l1, `"hash":"`+string(hx(1))+`"`, `"hash":null`, 1),
		"result-unknown":     strings.Replace(l1, `"result":""`, `"result":"bogus"`, 1),
		"result-upper":       strings.Replace(l1, `"result":""`, `"result":"EXPIRED"`, 1),
		"result-null":        strings.Replace(l1, `"result":""`, `"result":null`, 1),
		"result-number":      strings.Replace(l1, `"result":""`, `"result":0`, 1),
		"first-with-prev":    strings.Replace(l1, `"prev":""`, `"prev":"`+string(hx(5))+`"`, 1),
		"later-without-prev": strings.Replace(l2, `"prev":"`+prevIn(l2)+`"`, `"prev":""`, 1),
		"seq1-with-l2-prev":  strings.Replace(l2, `"seq":2`, `"seq":1`, 1),
		"seq2-without-prev":  strings.Replace(l1, `"seq":1`, `"seq":2`, 1),
		"prev-bad-hash":      strings.Replace(l2, prevIn(l2), prevIn(l2)[:60], 1),
		"nul-byte":           l1 + "\x00",
		"bom":                "\xef\xbb\xbf" + l1,
		"not-json":           "seq=1",
		"json-array":         "[" + l1 + "]",
		"two-objects":        l1 + l1,
		"truncated":          l1[:len(l1)-1],
	}
	for name, in := range bad {
		if in == l1 || in == l2 {
			t.Fatalf("case %s: mutation was a no-op (test bug)", name)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s: Decode panicked: %v", name, r)
				}
			}()
			e, err := applylog.Decode([]byte(in))
			if err == nil {
				t.Errorf("%s: Decode accepted non-canonical line %q (-> %+v)", name, in, e)
				return
			}
			if !errors.Is(err, applylog.ErrMalformed) {
				t.Errorf("%s: error %v does not wrap ErrMalformed", name, err)
			}
		}()
	}
}

func selfIn(l string) string {
	i := strings.Index(l, `"self":"`) + len(`"self":"`)
	return l[i : i+64]
}

func prevIn(l string) string {
	i := strings.Index(l, `"prev":"`) + len(`"prev":"`)
	return l[i : i+64]
}

func reorderTwo(l string) string {
	// swap the "from" and "to" members
	return strings.Replace(strings.Replace(strings.Replace(l, `"from":`, `"@@":`, 1), `"to":`, `"from":`, 1), `"@@":`, `"to":`, 1)
}

// Decode with extreme but valid numbers round-trips exactly.
func TestExtremeValuesRoundTrip(t *testing.T) {
	l, p, clk := newLog(t)
	clk.Set(time.Date(2026, 11, 5, 12, 0, 0, 999999999, time.UTC))
	max := ^uint64(0)
	e, err := l.Append(applylog.Entry{From: max, To: max, Hash: hx(1)})
	if err != nil {
		t.Fatalf("append extreme: %v", err)
	}
	b, _ := os.ReadFile(p)
	got, err := applylog.Read(bytes.NewReader(b))
	if err != nil || len(got) != 1 || got[0] != e {
		t.Fatalf("round trip of max versions / ns time: %+v vs %+v err=%v", got, e, err)
	}
	if v, _ := l.LastApplied(); v != max {
		t.Fatalf("LastApplied = %d", v)
	}
}

// --- Append contract ------------------------------------------------------

func TestAppendIgnoresCallerOwnedFields(t *testing.T) {
	l, p, clk := newLog(t)
	clk.Advance(time.Second)
	e, err := l.Append(applylog.Entry{
		Seq: 99, Time: time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC), From: 1, To: 2, Hash: hx(2),
		Prev: hx(77), Self: hx(88),
	})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if e.Seq != 1 || e.Prev != "" || e.Self == hx(88) || !e.Time.Equal(start.Add(time.Second)) {
		t.Fatalf("Append trusted caller-supplied Seq/Prev/Self/Time: %+v", e)
	}
	b, _ := os.ReadFile(p)
	if _, n, err := applylog.Verify(bytes.NewReader(b)); err != nil || n != 1 {
		t.Fatalf("verify: %v %d", err, n)
	}
}

func TestAppendRejectsBadInputAndLeavesLogAsBefore(t *testing.T) {
	l, p, clk := newLog(t)
	clk.Advance(time.Second)
	if _, err := l.Append(entryN(1)); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p)
	seq0, head0 := l.Head()
	v0, h0 := l.LastApplied()
	bad := map[string]applylog.Entry{
		"hash-upper":     {From: 1, To: 2, Hash: wire.Hash(strings.ToUpper(string(hx(0xabc))))},
		"hash-short":     {From: 1, To: 2, Hash: "abc"},
		"hash-long":      {From: 1, To: 2, Hash: hx(1) + "0"},
		"hash-nonhex":    {From: 1, To: 2, Hash: wire.Hash(strings.Repeat("g", 64))},
		"hash-space":     {From: 1, To: 2, Hash: wire.Hash(" " + strings.Repeat("a", 63))},
		"hash-newline":   {From: 1, To: 2, Hash: wire.Hash("\n" + strings.Repeat("a", 63))},
		"hash-quote":     {From: 1, To: 2, Hash: wire.Hash(`"` + strings.Repeat("a", 63))},
		"result-unknown": {From: 1, To: 2, Hash: hx(2), Result: "bogus"},
		"result-upper":   {From: 1, To: 2, Hash: hx(2), Result: "EXPIRED"},
		"result-newline": {From: 1, To: 2, Hash: hx(2), Result: "expired\n"},
		"result-quote":   {From: 1, To: 2, Hash: hx(2), Result: `a","self":"x`},
		"result-nul":     {From: 1, To: 2, Hash: hx(2), Result: "expired\x00"},
	}
	for name, e := range bad {
		if _, err := l.Append(e); err == nil {
			t.Errorf("%s: Append accepted %+v", name, e)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(after, before) {
			t.Fatalf("%s: failed Append changed the file", name)
		}
		if s, h := l.Head(); s != seq0 || h != head0 {
			t.Fatalf("%s: failed Append moved Head to %d %q", name, s, h)
		}
		if v, h := l.LastApplied(); v != v0 || h != h0 {
			t.Fatalf("%s: failed Append moved LastApplied", name)
		}
	}
	// The log is still usable and contiguous.
	clk.Advance(time.Second)
	e, err := l.Append(entryN(2))
	if err != nil || e.Seq != 2 {
		t.Fatalf("append after failures: %+v %v", e, err)
	}
	b, _ := os.ReadFile(p)
	if _, n, err := applylog.Verify(bytes.NewReader(b)); err != nil || n != 2 {
		t.Fatalf("verify: %v %d", err, n)
	}
}

// Whatever the wall clock says, the file must stay verifiable and re-openable.
func TestHostileClockNeverBricksTheLog(t *testing.T) {
	times := map[string]time.Time{
		"year-10000":    time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		"year-9999-end": time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		"year-0":        time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
		"year-minus-1":  time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC),
		"zero-time":     {},
		"unix-epoch":    time.Unix(0, 0),
		"jst-zone":      time.Date(2026, 11, 5, 21, 0, 0, 123, time.FixedZone("JST", 9*3600)),
		"odd-offset":    time.Date(2026, 11, 5, 21, 0, 0, 0, time.FixedZone("x", 5*3600+1800+7)),
		"far-future-ns": time.Unix(1<<40, 999999999),
		"far-past":      time.Unix(-(1 << 40), 1),
	}
	for name, ts := range times {
		t.Run(name, func(t *testing.T) {
			l, p, clk := newLog(t)
			clk.Set(ts)
			e1, err1 := l.Append(entryN(1))
			// Move to a sane time and continue.
			clk.Set(start)
			_, err2 := l.Append(entryN(2))
			_ = l.Close()
			b, _ := os.ReadFile(p)
			if _, _, verr := applylog.Verify(bytes.NewReader(b)); verr != nil {
				t.Fatalf("Append(clock=%s) err=%v left a log that fails Verify: %v\n%s", name, err1, verr, b)
			}
			l2, oerr := applylog.Open(p, clock.NewFake(start))
			if oerr != nil {
				t.Fatalf("log bricked after clock=%s: Open: %v", name, oerr)
			}
			l2.Close()
			if err1 == nil {
				got, _ := applylog.Read(bytes.NewReader(b))
				if len(got) == 0 || got[0] != e1 {
					t.Fatalf("returned entry differs from what was stored: %+v vs %+v", e1, got)
				}
				if !got[0].Time.Equal(ts) {
					t.Fatalf("stored time %v != clock %v (silent change of the timestamp)", got[0].Time, ts)
				}
			}
			_ = err2
		})
	}
}

func TestAppendedEntryEqualsStoredEntry(t *testing.T) {
	l, p, clk := newLog(t)
	clk.Set(time.Date(2026, 11, 5, 21, 0, 0, 123456789, time.FixedZone("JST", 9*3600)))
	e, err := l.Append(entryN(1))
	if err != nil {
		t.Fatal(err)
	}
	if e.Time.Location() != time.UTC {
		t.Fatalf("returned Time zone = %v, canonical form is UTC", e.Time.Location())
	}
	b, _ := os.ReadFile(p)
	got, err := applylog.Read(bytes.NewReader(b))
	if err != nil || got[0] != e {
		t.Fatalf("stored %+v vs returned %+v (err %v)", got, e, err)
	}
}

func TestExternalChangeRefusesAppend(t *testing.T) {
	for name, mutate := range map[string]func(p string, b []byte){
		"appended-junk": func(p string, b []byte) { _ = os.WriteFile(p, append(b, []byte("junk\n")...), 0o600) },
		"appended-valid-looking": func(p string, b []byte) {
			ls := lines(b)
			_ = os.WriteFile(p, join(b, ls[len(ls)-1]), 0o600)
		},
		"truncated-last-line": func(p string, b []byte) {
			ls := lines(b)
			_ = os.WriteFile(p, join(ls[:len(ls)-1]...), 0o600)
		},
		"emptied":         func(p string, b []byte) { _ = os.WriteFile(p, nil, 0o600) },
		"replaced-longer": func(p string, b []byte) { _ = os.WriteFile(p, append(b, b...), 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			l, p, clk := newLog(t)
			for i := 1; i <= 3; i++ {
				clk.Advance(time.Second)
				if _, err := l.Append(entryN(i)); err != nil {
					t.Fatal(err)
				}
			}
			b, _ := os.ReadFile(p)
			mutate(p, b)
			changed, _ := os.ReadFile(p)
			clk.Advance(time.Second)
			_, err := l.Append(entryN(4))
			if err == nil {
				t.Fatal("Append succeeded on a file changed behind the Log's back")
			}
			if !errors.Is(err, applylog.ErrChanged) {
				t.Fatalf("error %v does not wrap ErrChanged", err)
			}
			after, _ := os.ReadFile(p)
			if !bytes.Equal(after, changed) {
				t.Fatal("refused Append still wrote to the file")
			}
		})
	}
}

// Same-size in-place edits are invisible to the size check, but the edit stays
// detectable by the chain no matter what is appended after it.
func TestInPlaceEditBetweenAppendsStaysDetectable(t *testing.T) {
	l, p, clk := newLog(t)
	for i := 1; i <= 3; i++ {
		clk.Advance(time.Second)
		if _, err := l.Append(entryN(i)); err != nil {
			t.Fatal(err)
		}
	}
	b, _ := os.ReadFile(p)
	ls := lines(b)
	edited := append([]byte(nil), b...)
	off := len(ls[0]) + len(ls[1]) - 8 // inside entry 2's self
	if edited[off] == '0' {
		edited[off] = '1'
	} else {
		edited[off] = '0'
	}
	if err := os.WriteFile(p, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Second)
	_, _ = l.Append(entryN(4)) // may or may not be refused
	final, _ := os.ReadFile(p)
	if _, _, err := applylog.Verify(bytes.NewReader(final)); err == nil {
		t.Fatal("an in-place edit became undetectable after further appends")
	}
}

func TestTwoWritersCannotForkTheChain(t *testing.T) {
	p := filepath.Join(t.TempDir(), "apply.log")
	a, err := applylog.Open(p, clock.NewFake(start))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := applylog.Open(p, clock.NewFake(start))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := a.Append(entryN(1)); err != nil {
		t.Fatal(err)
	}
	_, errB := b.Append(entryN(2))
	if errB == nil {
		// If B was allowed, the file must still be a valid chain.
		data, _ := os.ReadFile(p)
		if _, _, err := applylog.Verify(bytes.NewReader(data)); err != nil {
			t.Fatalf("second writer forked the chain: %v", err)
		}
		return
	}
	if !errors.Is(errB, applylog.ErrChanged) {
		t.Fatalf("second writer error = %v, want ErrChanged", errB)
	}
	data, _ := os.ReadFile(p)
	if _, n, err := applylog.Verify(bytes.NewReader(data)); err != nil || n != 1 {
		t.Fatalf("verify after refused second writer: %d %v", n, err)
	}
}

func TestCloseSemantics(t *testing.T) {
	l, p, _ := newLog(t)
	if _, err := l.Append(entryN(1)); err != nil {
		t.Fatal(err)
	}
	seq, head := l.Head()
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	before, _ := os.ReadFile(p)
	if _, err := l.Append(entryN(2)); err == nil {
		t.Fatal("Append after Close succeeded")
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(before, after) {
		t.Fatal("Append after Close modified the file")
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Close twice panicked: %v", r)
			}
		}()
		_ = l.Close()
	}()
	if s, h := l.Head(); s != seq || h != head {
		t.Fatalf("Head changed after Close: %d %q", s, h)
	}
}

func TestOpenBadPaths(t *testing.T) {
	dir := t.TempDir()
	for name, path := range map[string]string{
		"empty-path":     "",
		"directory":      dir,
		"missing-parent": filepath.Join(dir, "nope", "nope", "apply.log"),
		"nul-in-path":    filepath.Join(dir, "a\x00b"),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panic: %v", r)
				}
			}()
			l, err := applylog.Open(path, clock.NewFake(start))
			if err == nil {
				_ = l.Close()
				t.Fatalf("Open(%q) succeeded", path)
			}
		})
	}
	// A file that is not a log at all.
	p := filepath.Join(dir, "notalog")
	_ = os.WriteFile(p, []byte("this is a text file\nwith two lines\n"), 0o600)
	if l, err := applylog.Open(p, clock.NewFake(start)); err == nil {
		_ = l.Close()
		t.Fatal("Open accepted a text file")
	} else if !errors.Is(err, applylog.ErrMalformed) {
		t.Fatalf("error should wrap ErrMalformed: %v", err)
	}
	// Binary junk, including a huge unterminated line, must be refused without panic or OOM.
	big := bytes.Repeat([]byte("A"), 8<<20)
	mustOpenFail(t, "8MiB unterminated line", big)
	mustOpenFail(t, "8MiB terminated line", append(append([]byte(nil), big...), '\n'))
	mustOpenFail(t, "random bytes", bytes.Repeat([]byte{0xff, 0x00, 0x7b, 0x22}, 1000))
}

// --- Reader behavior of Verify -------------------------------------------

type errAfter struct {
	r   io.Reader
	n   int
	err error
}

func (e *errAfter) Read(p []byte) (int, error) {
	if e.n <= 0 {
		return 0, e.err
	}
	if len(p) > e.n {
		p = p[:e.n]
	}
	n, err := e.r.Read(p)
	e.n -= n
	return n, err
}

func TestVerifyDoesNotMistakeReadErrorForEOF(t *testing.T) {
	b, _ := build(t, 4)
	ls := lines(b)
	boundary := len(ls[0]) + len(ls[1])
	ioErr := errors.New("disk on fire")
	for _, cut := range []int{0, 1, 17, boundary - 1, boundary, boundary + 1, len(b) - 1} {
		_, n, err := applylog.Verify(&errAfter{r: bytes.NewReader(b), n: cut, err: ioErr})
		if err == nil {
			t.Fatalf("read error after %d bytes was swallowed: Verify returned n=%d, nil (a failing disk would look like a valid shorter log)", cut, n)
		}
		if _, rerr := applylog.Read(&errAfter{r: bytes.NewReader(b), n: cut, err: ioErr}); rerr == nil {
			t.Fatalf("Read swallowed a read error after %d bytes", cut)
		}
	}
	// TimeoutReader: second read fails.
	if _, _, err := applylog.Verify(iotest.TimeoutReader(bytes.NewReader(b))); err == nil {
		t.Fatal("timeout read error swallowed")
	}
	// Reading byte by byte, or with data+EOF in one call, gives the same result as a plain reader.
	for name, r := range map[string]io.Reader{
		"one-byte": iotest.OneByteReader(bytes.NewReader(b)),
		"half":     iotest.HalfReader(bytes.NewReader(b)),
		"data-err": iotest.DataErrReader(bytes.NewReader(b)),
	} {
		_, n, err := applylog.Verify(r)
		if err != nil || n != 4 {
			t.Fatalf("%s: Verify = %d, %v", name, n, err)
		}
	}
	// Torn tail is still seen through a chunked reader.
	if _, _, err := applylog.Verify(iotest.OneByteReader(bytes.NewReader(b[:len(b)-3]))); err == nil {
		t.Fatal("chunked reader hid a torn tail")
	}
}

func TestVerifyBigLogFast(t *testing.T) {
	l, p, clk := newLog(t)
	const n = 20000
	for i := 1; i <= n; i++ {
		clk.Advance(time.Millisecond)
		if _, err := l.Append(applylog.Entry{From: uint64(i - 1), To: uint64(i), Hash: hx(i)}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	_ = l.Close()
	b, _ := os.ReadFile(p)
	t0 := time.Now()
	last, got, err := applylog.Verify(bytes.NewReader(b))
	if err != nil || got != n || last.Seq != n {
		t.Fatalf("Verify big: %d %v %+v", got, err, last)
	}
	if d := time.Since(t0); d > 60*time.Second {
		t.Fatalf("Verify of %d entries took %v", n, d)
	}
	// One flipped byte in the middle of a big log is found, and the report says where it stops.
	c := append([]byte(nil), b...)
	c[len(c)/2] ^= 1
	last, got, err = applylog.Verify(bytes.NewReader(c))
	if err == nil {
		t.Fatal("middle edit in a big log verified")
	}
	if got >= n || last.Seq != uint64(got) {
		t.Fatalf("on error, last/n must describe the good prefix: n=%d last.Seq=%d", got, last.Seq)
	}
}

// --- Concurrency ----------------------------------------------------------

func TestConcurrentAppendsAndReads(t *testing.T) {
	l, p, clk := newLog(t)
	const writers, per = 16, 60
	var wg sync.WaitGroup
	var mu sync.Mutex
	bySeq := map[uint64]applylog.Entry{}
	stop := make(chan struct{})
	type obs struct {
		seq  uint64
		head wire.Hash
		v    uint64
	}
	var observed []obs
	var rwg sync.WaitGroup
	for r := 0; r < 4; r++ {
		rwg.Add(1)
		go func() {
			defer rwg.Done()
			var lastSeq uint64
			for {
				select {
				case <-stop:
					return
				default:
				}
				s, h := l.Head()
				v, _ := l.LastApplied()
				if s < lastSeq {
					t.Errorf("Head seq went backwards %d -> %d", lastSeq, s)
					return
				}
				lastSeq = s
				mu.Lock()
				observed = append(observed, obs{s, h, v})
				mu.Unlock()
			}
		}()
	}
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				clk.Advance(time.Millisecond)
				e, err := l.Append(applylog.Entry{From: uint64(w), To: uint64(w*1000 + i + 1), Hash: hx(w*1000 + i + 1)})
				if err != nil {
					t.Errorf("writer %d append %d: %v", w, i, err)
					return
				}
				mu.Lock()
				if _, dup := bySeq[e.Seq]; dup {
					t.Errorf("duplicate Seq %d handed out", e.Seq)
				}
				bySeq[e.Seq] = e
				mu.Unlock()
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	rwg.Wait()
	total := writers * per
	if len(bySeq) != total {
		t.Fatalf("%d distinct entries, want %d", len(bySeq), total)
	}
	b, _ := os.ReadFile(p)
	last, n, err := applylog.Verify(bytes.NewReader(b))
	if err != nil || n != total || last.Seq != uint64(total) {
		t.Fatalf("Verify after concurrent appends: %d %v %+v", n, err, last)
	}
	es, _ := applylog.Read(bytes.NewReader(b))
	for i, e := range es {
		if e != bySeq[uint64(i+1)] {
			t.Fatalf("file entry %d differs from what Append returned", i+1)
		}
	}
	seq, head := l.Head()
	if seq != uint64(total) || head != last.Self {
		t.Fatalf("Head = %d %q; want %d %q", seq, head, total, last.Self)
	}
	if v, h := l.LastApplied(); v != last.To || h != last.Hash {
		t.Fatalf("LastApplied = %d %q; want newest applied entry %d %q", v, h, last.To, last.Hash)
	}
	// Every Head pair observed mid-flight must be a real (seq, self) pair: no torn reads.
	for _, o := range observed {
		if o.seq == 0 {
			if o.head != "" {
				t.Fatalf("Head seq 0 with head %q", o.head)
			}
			continue
		}
		if e, ok := bySeq[o.seq]; !ok || e.Self != o.head {
			t.Fatalf("torn Head read: seq %d head %q (real %q)", o.seq, o.head, e.Self)
		}
	}
}

// --- Fuzz: canonical form -------------------------------------------------

func FuzzVerifyCanonical(f *testing.F) {
	l, p, clk := func() (*applylog.Log, string, *clock.Fake) {
		p := filepath.Join(f.TempDir(), "apply.log")
		clk := clock.NewFake(start)
		l, err := applylog.Open(p, clk)
		if err != nil {
			f.Fatal(err)
		}
		return l, p, clk
	}()
	for i := 1; i <= 4; i++ {
		clk.Advance(time.Second)
		if _, err := l.Append(entryN(i)); err != nil {
			f.Fatal(err)
		}
	}
	_ = l.Close()
	b, _ := os.ReadFile(p)
	f.Add(b)
	f.Add(b[:len(b)-1])
	f.Add([]byte{})
	f.Add([]byte("\n"))
	f.Add(bytes.Join(lines(b)[1:], nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		last, n, err := applylog.Verify(bytes.NewReader(data))
		es, rerr := applylog.Read(bytes.NewReader(data))
		if (err == nil) != (rerr == nil) {
			t.Fatalf("Verify (%v) and Read (%v) disagree", err, rerr)
		}
		if err != nil {
			if !isChainErr(err) {
				t.Fatalf("error %v wraps no chain error", err)
			}
			return
		}
		if n != len(es) {
			t.Fatalf("Verify n=%d, Read %d entries", n, len(es))
		}
		var re []byte
		for _, e := range es {
			re = append(re, applylog.Encode(e)...)
			re = append(re, '\n')
		}
		if !bytes.Equal(re, data) {
			t.Fatalf("accepted a non-canonical encoding of a valid chain:\n got %q\n re  %q", data, re)
		}
		if n > 0 && last != es[n-1] {
			t.Fatalf("last != final entry")
		}
		var prev wire.Hash
		for i, e := range es {
			if e.Seq != uint64(i+1) || e.Prev != prev || !e.Self.Valid() {
				t.Fatalf("accepted a broken chain at %d", i)
			}
			prev = e.Self
		}
	})
}

func FuzzDecode(f *testing.F) {
	b, _ := func() ([]byte, error) {
		l, p, clk := func() (*applylog.Log, string, *clock.Fake) {
			p := filepath.Join(f.TempDir(), "apply.log")
			clk := clock.NewFake(start)
			l, _ := applylog.Open(p, clk)
			return l, p, clk
		}()
		for i := 1; i <= 2; i++ {
			clk.Advance(time.Second)
			_, _ = l.Append(entryN(i))
		}
		_ = l.Close()
		return os.ReadFile(p)
	}()
	for _, l := range lines(b) {
		f.Add(bytes.TrimSuffix(l, []byte("\n")))
	}
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := applylog.Decode(data)
		if err != nil {
			if !errors.Is(err, applylog.ErrMalformed) {
				t.Fatalf("error does not wrap ErrMalformed: %v", err)
			}
			return
		}
		if !bytes.Equal(applylog.Encode(e), data) {
			t.Fatalf("Decode accepted a non-canonical line:\n in  %q\n out %q", data, applylog.Encode(e))
		}
		if e.Seq == 0 {
			t.Fatal("Seq 0 accepted")
		}
	})
}
