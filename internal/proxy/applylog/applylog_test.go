package applylog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

var t0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func h(c byte) wire.Hash { return wire.Hash(strings.Repeat(string(c), 64)) }

func openTemp(t *testing.T) (*Log, *clock.Fake, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apply.log")
	clk := clock.NewFake(t0)
	l, err := Open(path, clk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	return l, clk, path
}

func mustAppend(t *testing.T, l *Log, e Entry) Entry {
	t.Helper()
	got, err := l.Append(e)
	if err != nil {
		t.Fatalf("Append(%+v): %v", e, err)
	}
	return got
}

// fiveEntries builds a log file with five entries and returns its lines.
func fiveEntries(t *testing.T) (path string, lines []string) {
	t.Helper()
	l, clk, path := openTemp(t)
	mustAppend(t, l, Entry{From: 0, To: 1, Hash: h('a')})
	clk.Advance(time.Second)
	mustAppend(t, l, Entry{From: 1, To: 2, Hash: h('b')})
	clk.Advance(time.Second)
	mustAppend(t, l, Entry{From: 2, To: 2, Hash: h('b'), Result: wire.ErrNotNewer})
	clk.Advance(time.Second)
	mustAppend(t, l, Entry{From: 2, To: 3, Hash: h('c')})
	clk.Advance(time.Second)
	mustAppend(t, l, Entry{From: 3, To: 4, Hash: h('d'), Result: wire.ErrThreshold})
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines = strings.SplitAfter(string(data), "\n")
	return path, lines[:len(lines)-1] // drop the empty tail
}

func TestEmptyLog(t *testing.T) {
	l, _, path := openTemp(t)
	if seq, head := l.Head(); seq != 0 || head != "" {
		t.Errorf("Head = %d, %q; want 0, empty (M-D39)", seq, head)
	}
	if v, hash := l.LastApplied(); v != 0 || hash != "" {
		t.Errorf("LastApplied = %d, %q; want 0, empty", v, hash)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600", st.Mode().Perm())
	}
	if _, n, err := Verify(bytes.NewReader(nil)); err != nil || n != 0 {
		t.Errorf("Verify(empty) = %d, %v", n, err)
	}
}

func TestAppendFillsAndChains(t *testing.T) {
	l, clk, _ := openTemp(t)
	e1 := mustAppend(t, l, Entry{Seq: 99, Prev: h('f'), Self: h('e'), Time: time.Unix(5, 0), From: 0, To: 1, Hash: h('a')})
	if e1.Seq != 1 || e1.Prev != "" || !e1.Self.Valid() || !e1.Time.Equal(t0) {
		t.Errorf("first entry not filled by Append: %+v", e1)
	}
	clk.Advance(time.Minute)
	e2 := mustAppend(t, l, Entry{From: 1, To: 2, Hash: h('b')})
	if e2.Seq != 2 || e2.Prev != e1.Self || e2.Self == e1.Self || !e2.Time.Equal(t0.Add(time.Minute)) {
		t.Errorf("second entry wrong: %+v", e2)
	}
	if seq, head := l.Head(); seq != 2 || head != e2.Self {
		t.Errorf("Head = %d, %q", seq, head)
	}
}

func TestLastAppliedIgnoresRejections(t *testing.T) {
	l, _, _ := openTemp(t)
	mustAppend(t, l, Entry{From: 0, To: 1, Hash: h('a')})
	mustAppend(t, l, Entry{From: 1, To: 5, Hash: h('b'), Result: wire.ErrThreshold})
	mustAppend(t, l, Entry{From: 1, To: 1, Hash: h('a'), Result: wire.ErrNotNewer})
	if v, hash := l.LastApplied(); v != 1 || hash != h('a') {
		t.Errorf("LastApplied = %d, %q; want 1, a", v, hash)
	}
	mustAppend(t, l, Entry{From: 1, To: 3, Hash: h('c')})
	if v, hash := l.LastApplied(); v != 3 || hash != h('c') {
		t.Errorf("LastApplied = %d, %q; want 3, c", v, hash)
	}
	// If only rejections exist, nothing was applied.
	l2, _, _ := openTemp(t)
	mustAppend(t, l2, Entry{From: 0, To: 1, Hash: h('a'), Result: wire.ErrMalformed})
	if v, hash := l2.LastApplied(); v != 0 || hash != "" {
		t.Errorf("LastApplied with only rejections = %d, %q", v, hash)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path, _ := fiveEntries(t)
	clk := clock.NewFake(t0.Add(time.Hour))
	l, err := Open(path, clk)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer l.Close()
	if seq, head := l.Head(); seq != 5 || !head.Valid() {
		t.Fatalf("Head after reopen = %d, %q", seq, head)
	}
	if v, hash := l.LastApplied(); v != 3 || hash != h('c') {
		t.Errorf("LastApplied after reopen = %d, %q", v, hash)
	}
	e := mustAppend(t, l, Entry{From: 3, To: 6, Hash: h('e')})
	if e.Seq != 6 {
		t.Errorf("seq = %d, want 6", e.Seq)
	}
	data, _ := os.ReadFile(path)
	last, n, err := Verify(bytes.NewReader(data))
	if err != nil || n != 6 || last.Self != e.Self {
		t.Errorf("Verify after reopen+append = %v, %d, %v", last.Seq, n, err)
	}
}

func TestVerifyReturnsLast(t *testing.T) {
	_, lines := fiveEntries(t)
	last, n, err := Verify(strings.NewReader(strings.Join(lines, "")))
	if err != nil || n != 5 || last.Seq != 5 || last.To != 4 || last.Result != wire.ErrThreshold {
		t.Errorf("Verify = %+v, %d, %v", last, n, err)
	}
	all, err := Read(strings.NewReader(strings.Join(lines, "")))
	if err != nil || len(all) != 5 || all[2].Result != wire.ErrNotNewer {
		t.Errorf("Read = %d entries, %v", len(all), err)
	}
}

// rehash recomputes Self for a line so an attacker's edit looks self-consistent.
func rehash(t *testing.T, line string) string {
	t.Helper()
	e, err := Decode([]byte(strings.TrimSuffix(line, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	e.Self = computeSelf(e)
	return string(Encode(e)) + "\n"
}

func TestVerifyDetectsTampering(t *testing.T) {
	_, lines := fiveEntries(t)
	join := func(ls ...string) string { return strings.Join(ls, "") }
	cp := func() []string { return append([]string(nil), lines...) }

	edit := func(i int, from, to string) []string {
		ls := cp()
		if !strings.Contains(ls[i], from) {
			t.Fatalf("line %d lacks %q: %s", i, from, ls[i])
		}
		ls[i] = strings.Replace(ls[i], from, to, 1)
		return ls
	}
	editRehash := func(i int, from, to string) []string {
		ls := edit(i, from, to)
		ls[i] = rehash(t, ls[i])
		return ls
	}
	del := func(i int) []string { ls := cp(); return append(ls[:i], ls[i+1:]...) }
	swap := func(i, j int) []string { ls := cp(); ls[i], ls[j] = ls[j], ls[i]; return ls }

	tests := []struct {
		name    string
		content string
		want    error
		wantN   int // entries verified before the failure
	}{
		{"edit a field, self stale", join(edit(1, `"to":2`, `"to":9`)...), ErrChain, 1},
		{"edit result field", join(edit(2, `"result":"version_not_newer"`, `"result":""`)...), ErrChain, 2},
		{"edit in the last line", join(edit(4, `"to":4`, `"to":5`)...), ErrChain, 4},
		{"edit and rehash a middle line", join(editRehash(1, `"to":2`, `"to":9`)...), ErrChain, 2},
		{"edit and rehash the first line", join(editRehash(0, `"to":1`, `"to":7`)...), ErrChain, 1},
		{"delete the first line", join(del(0)...), ErrChain, 0},
		{"delete a middle line", join(del(2)...), ErrChain, 2},
		{"delete the second line", join(del(1)...), ErrChain, 1},
		{"swap two lines", join(swap(1, 3)...), ErrChain, 1},
		{"swap last two lines", join(swap(3, 4)...), ErrChain, 3},
		{"duplicate a line", join(append(append(cp()[:3:3], lines[2]), lines[3:]...)...), ErrChain, 3},
		{"replay the whole log twice", join(append(cp(), lines...)...), ErrChain, 5},
		{"truncated last line, no newline", strings.TrimSuffix(join(lines...), "\n"), ErrTruncated, 4},
		{"truncated mid-line", join(lines...)[:len(join(lines...))-20], ErrTruncated, 4},
		{"truncated to half a line only", lines[0][:30], ErrTruncated, 0},
		{"blank line in the middle", join(lines[:2]...) + "\n" + join(lines[2:]...), ErrMalformed, 2},
		{"garbage line", join(lines[:2]...) + "not json\n" + join(lines[2:]...), ErrMalformed, 2},
		{"unknown field", join(edit(0, `"to":1`, `"to":1,"x":1`)...), ErrMalformed, 0},
		{"CRLF line ending", strings.Replace(join(lines...), "\n", "\r\n", 1), ErrMalformed, 0},
		{"NUL byte", join(lines[:1]...) + "\x00\n", ErrMalformed, 1},
		{"overlong line", join(lines[:1]...) + strings.Repeat("x", 100000) + "\n", ErrMalformed, 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, n, err := Verify(strings.NewReader(tc.content))
			if !errors.Is(err, tc.want) {
				t.Fatalf("Verify err = %v, want %v", err, tc.want)
			}
			if n != tc.wantN {
				t.Errorf("verified %d entries before failing, want %d", n, tc.wantN)
			}
			// Open must refuse the same content.
			path := filepath.Join(t.TempDir(), "x.log")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			l, err := Open(path, clock.NewFake(t0))
			if err == nil {
				l.Close()
				t.Fatal("Open accepted a tampered log")
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("Open err = %v, want %v", err, tc.want)
			}
		})
	}
}

// Tail truncation at a line boundary is not detectable from the file alone
// (M-D35): the shorter log is a valid chain. The control plane's anchor
// (log_seq, log_head) catches it. This test documents the limit.
func TestTailTruncationNeedsTheAnchor(t *testing.T) {
	_, lines := fiveEntries(t)
	full, nFull, err := Verify(strings.NewReader(strings.Join(lines, "")))
	if err != nil || nFull != 5 {
		t.Fatal(err)
	}
	short, nShort, err := Verify(strings.NewReader(strings.Join(lines[:3], "")))
	if err != nil || nShort != 3 {
		t.Fatalf("Verify(short) = %d, %v", nShort, err)
	}
	if short.Seq >= full.Seq || short.Self == full.Self {
		t.Error("anchor comparison must see a lower seq and a different head")
	}
}

func TestAppendNotesFileChangedUnderIt(t *testing.T) {
	l, _, path := openTemp(t)
	mustAppend(t, l, Entry{From: 0, To: 1, Hash: h('a')})
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("rogue\n")
	f.Close()
	_, err = l.Append(Entry{From: 1, To: 2, Hash: h('b')})
	if err == nil {
		t.Fatal("Append succeeded on a file changed behind its back")
	}
	if seq, _ := l.Head(); seq != 1 {
		t.Errorf("failed Append moved Head to %d", seq)
	}
}

func TestAppendValidatesEntries(t *testing.T) {
	l, _, _ := openTemp(t)
	bad := []Entry{
		{Hash: "xyz"},
		{Hash: h('A')},
		{Result: "boom"},
		{Result: "ok\nmore"},
	}
	for _, e := range bad {
		if _, err := l.Append(e); err == nil {
			t.Errorf("Append(%+v) accepted", e)
		}
	}
	if seq, head := l.Head(); seq != 0 || head != "" {
		t.Errorf("rejected entries moved Head to %d %q", seq, head)
	}
	// Empty hash is allowed: a rejected envelope may have no usable payload.
	mustAppend(t, l, Entry{From: 1, To: 2, Result: wire.ErrMalformed})
}

func TestAppendAfterClose(t *testing.T) {
	l, _, _ := openTemp(t)
	mustAppend(t, l, Entry{From: 0, To: 1, Hash: h('a')})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Append(Entry{From: 1, To: 2, Hash: h('b')}); err == nil {
		t.Error("Append after Close succeeded")
	}
	if seq, _ := l.Head(); seq != 1 {
		t.Errorf("Head = %d after failed append", seq)
	}
}

func TestOpenErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Open(dir, clock.NewFake(t0)); err == nil {
		t.Error("Open on a directory succeeded")
	}
	if _, err := Open(filepath.Join(dir, "nodir", "x.log"), clock.NewFake(t0)); err == nil {
		t.Error("Open in a missing directory succeeded")
	}
	if _, err := Open(filepath.Join(dir, "x.log"), nil); err == nil {
		t.Error("Open with nil clock succeeded")
	}
}

func TestConcurrentAppends(t *testing.T) {
	l, _, path := openTemp(t)
	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := l.Append(Entry{From: uint64(i), To: uint64(i + 1), Hash: h('a')}); err != nil {
				t.Errorf("Append: %v", err)
			}
		}(i)
	}
	wg.Wait()
	data, _ := os.ReadFile(path)
	last, cnt, err := Verify(bytes.NewReader(data))
	if err != nil || cnt != n || last.Seq != n {
		t.Fatalf("Verify = seq %d, n %d, %v", last.Seq, cnt, err)
	}
	if seq, head := l.Head(); seq != n || head != last.Self {
		t.Errorf("Head = %d %q", seq, head)
	}
}

func TestDecodeStrict(t *testing.T) {
	good := Encode(Entry{Seq: 1, Time: t0, To: 1, Hash: h('a'), Self: h('b')})
	if _, err := Decode(good); err != nil {
		t.Fatalf("Decode(good) = %v", err)
	}
	s := string(good)
	bad := map[string]string{
		"empty":            "",
		"not json":         "{",
		"array":            "[]",
		"trailing data":    s + "{}",
		"trailing space":   s + " ",
		"upper-case key":   strings.Replace(s, `"seq"`, `"Seq"`, 1),
		"key order":        `{"time":"2026-11-05T12:00:00Z","seq":1,` + s[strings.Index(s, `"from"`):],
		"duplicate key":    strings.Replace(s, `"seq":1,`, `"seq":1,"seq":1,`, 1),
		"seq zero":         strings.Replace(s, `"seq":1`, `"seq":0`, 1),
		"seq float":        strings.Replace(s, `"seq":1`, `"seq":1.0`, 1),
		"seq negative":     strings.Replace(s, `"seq":1`, `"seq":-1`, 1),
		"time with offset": strings.Replace(s, `T12:00:00Z`, `T14:00:00+02:00`, 1),
		"time not string":  strings.Replace(s, `"2026-11-05T12:00:00Z"`, `1`, 1),
		"hash short":       strings.Replace(s, strings.Repeat("a", 64), "aa", 1),
		"self missing":     strings.Replace(s, `"self":"`+strings.Repeat("b", 64)+`"`, `"self":""`, 1),
		"prev on first":    strings.Replace(s, `"prev":""`, `"prev":"`+strings.Repeat("c", 64)+`"`, 1),
		"result unknown":   strings.Replace(s, `"result":""`, `"result":"nope"`, 1),
		"escaped key":      strings.Replace(s, `"seq"`, "\"s\\u0065q\"", 1),
	}
	for name, in := range bad {
		if in == s {
			t.Fatalf("%s: mutation did not change the line", name)
		}
		if _, err := Decode([]byte(in)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: Decode err = %v, want ErrMalformed", name, err)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	e := Entry{Seq: 7, Time: time.Date(2026, 1, 2, 3, 4, 5, 123456789, time.FixedZone("x", 3600)),
		From: 3, To: 4, Hash: h('1'), Result: wire.ErrExpired, Prev: h('2'), Self: h('3')}
	got, err := Decode(Encode(e))
	if err != nil {
		t.Fatal(err)
	}
	if !got.Time.Equal(e.Time) || got.Time.Location() != time.UTC {
		t.Errorf("time = %v", got.Time)
	}
	e.Time = got.Time
	if got != e {
		t.Errorf("got %+v want %+v", got, e)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(Encode(Entry{Seq: 1, Time: t0, To: 1, Hash: h('a'), Self: h('b')}))
	f.Add(Encode(Entry{Seq: 2, Time: t0, From: 1, To: 2, Hash: h('a'), Result: wire.ErrThreshold, Prev: h('b'), Self: h('c')}))
	f.Add([]byte(`{"seq":1}`))
	f.Add([]byte(`{"seq":1,"seq":2}`))
	f.Add([]byte(`{"Seq":1,"time":"2026-11-05T12:00:00+02:00"}`))
	f.Add([]byte(`{"seq":18446744073709551616}`))
	f.Add([]byte("\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		e, err := Decode(data)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("error %v does not wrap ErrMalformed", err)
			}
			return
		}
		// Whatever Decode accepts is in canonical form: one byte string per entry.
		if !bytes.Equal(Encode(e), data) {
			t.Fatalf("accepted a non-canonical line:\n in: %q\nout: %q", data, Encode(e))
		}
		if e.Seq == 0 || !e.Self.Valid() {
			t.Fatalf("accepted an invalid entry %+v", e)
		}
	})
}

func FuzzVerify(f *testing.F) {
	e1 := Entry{Seq: 1, Time: t0, To: 1, Hash: h('a')}
	e1.Self = computeSelf(e1)
	l1 := Encode(e1)
	f.Add(append(l1, '\n'))
	e2 := Entry{Seq: 2, Time: t0, From: 1, To: 2, Hash: h('b'), Prev: e1.Self}
	e2.Self = computeSelf(e2)
	f.Add(append(append(append([]byte{}, l1...), '\n'), append(Encode(e2), '\n')...))
	f.Add([]byte{})
	f.Add([]byte("\n"))
	f.Add(l1)
	f.Fuzz(func(t *testing.T, data []byte) {
		last, n, err := Verify(bytes.NewReader(data))
		if err != nil {
			return
		}
		if (n == 0) != (last.Seq == 0) || uint64(n) != last.Seq {
			t.Fatalf("n=%d last.Seq=%d", n, last.Seq)
		}
		if n > 0 && !bytes.HasSuffix(data, []byte("\n")) {
			t.Fatal("accepted a log without a final newline")
		}
	})
}
