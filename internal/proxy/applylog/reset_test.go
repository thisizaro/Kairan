package applylog

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/wire"
)

// breakers damage the five-entry log in the three ways the tests care about.
var breakers = []struct {
	name   string
	damage func(t *testing.T, path string, lines []string)
	reason string
	// good is how many entries still verify after the damage; floor is the
	// highest version applied among them.
	good  int
	floor uint64
}{
	{"edited line", func(t *testing.T, path string, lines []string) {
		lines[3] = strings.Replace(lines[3], `"to":3`, `"to":9`, 1)
		writeLines(t, path, lines)
	}, "chain_broken", 3, 2},
	{"truncated last line", func(t *testing.T, path string, lines []string) {
		last := lines[4]
		lines[4] = last[:len(last)/2]
		writeLines(t, path, lines)
	}, "truncated", 4, 3},
	{"garbage appended", func(t *testing.T, path string, lines []string) {
		writeLines(t, path, append(lines, "not a log line\n"))
	}, "malformed", 5, 3},
}

func writeLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "")), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestResetKeepsEvidenceAndStartsNewChain(t *testing.T) {
	for _, b := range breakers {
		t.Run(b.name, func(t *testing.T) {
			path, lines := fiveEntries(t)
			b.damage(t, path, lines)
			before, _ := os.ReadFile(path)
			if _, err := Open(path, clock.NewFake(t0)); err == nil {
				t.Fatal("the damaged log opened")
			}
			clk := clock.NewFake(t0.Add(time.Hour))
			l, first, err := Reset(path, clk, 0)
			if err != nil {
				t.Fatalf("Reset: %v", err)
			}
			defer l.Close()

			// The broken file is kept, byte for byte.
			kept, err := os.ReadFile(path + ".broken-1")
			if err != nil || !bytes.Equal(kept, before) {
				t.Fatalf("broken-1 missing or changed: %v", err)
			}
			// The new chain verifies and starts with the reset entry.
			f, _ := os.Open(path)
			es, err := Read(f)
			f.Close()
			if err != nil || len(es) != 1 {
				t.Fatalf("new log: %v entries, err %v", len(es), err)
			}
			e := es[0]
			if e != first {
				t.Errorf("returned entry %+v differs from the one on disk %+v", first, e)
			}
			if e.Seq != 1 || e.Prev != "" || e.Result != wire.ErrTampered || e.To != 0 {
				t.Errorf("reset entry shape: %+v", e)
			}
			if e.Reset.File != "apply.log.broken-1" || e.Reset.Reason != b.reason || e.Reset.Seq != uint64(b.good) {
				t.Errorf("reset info %+v, want broken-1, %s, seq %d", e.Reset, b.reason, b.good)
			}
			// It records the old file's last verifiable head and applied floor.
			old, _ := Read(bytes.NewReader(before))
			if len(old) != b.good {
				t.Fatalf("test setup: %d good entries, want %d", len(old), b.good)
			}
			if e.Hash != old[b.good-1].Self {
				t.Errorf("reset hash %s, want old head %s", e.Hash, old[b.good-1].Self)
			}
			wantFloor := b.floor
			if e.From != wantFloor {
				t.Errorf("reset floor %d, want %d", e.From, wantFloor)
			}
			if !e.Time.Equal(clk.Now()) {
				t.Errorf("reset time %v", e.Time)
			}
			// The log works: head is the reset entry, floor is carried, append continues.
			if seq, head := l.Head(); seq != 1 || head != e.Self {
				t.Errorf("Head = %d %s", seq, head)
			}
			if v, h := l.LastApplied(); v != wantFloor || h != "" {
				t.Errorf("LastApplied = %d %q, want floor %d and no hash", v, h, wantFloor)
			}
			if !l.ResetPending() {
				t.Error("ResetPending false before any apply")
			}
			got := mustAppend(t, l, Entry{From: wantFloor, To: wantFloor + 1, Hash: h('e')})
			if got.Seq != 2 || got.Prev != e.Self {
				t.Errorf("append after reset: %+v", got)
			}
			if l.ResetPending() {
				t.Error("ResetPending true after an apply")
			}
			l.Close()
			l2, err := Open(path, clk)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			defer l2.Close()
			if v, _ := l2.LastApplied(); v != wantFloor+1 {
				t.Errorf("reopened LastApplied = %d", v)
			}
		})
	}
}

func TestResetFloorIsTheLargerOfPrefixAndCaller(t *testing.T) {
	path, lines := fiveEntries(t)
	breakers[0].damage(t, path, lines) // prefix floor is 2
	l, first, err := Reset(path, clock.NewFake(t0), 7)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if first.From != 7 {
		t.Errorf("floor %d, want 7", first.From)
	}
}

func TestResetRefusesAGoodLog(t *testing.T) {
	path, _ := fiveEntries(t)
	before, _ := os.ReadFile(path)
	if _, _, err := Reset(path, clock.NewFake(t0), 0); !errors.Is(err, ErrNotBroken) {
		t.Fatalf("err = %v, want ErrNotBroken", err)
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Error("a good log was changed")
	}
	if _, err := os.Stat(path + ".broken-1"); err == nil {
		t.Error("a broken-1 file was made for a good log")
	}
}

func TestTwoResetsKeepBothFiles(t *testing.T) {
	path, lines := fiveEntries(t)
	breakers[0].damage(t, path, lines)
	first, _ := os.ReadFile(path)
	l, _, err := Reset(path, clock.NewFake(t0), 0)
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, l, Entry{From: 2, To: 5, Hash: h('f')})
	l.Close()
	// Break the new log too.
	data, _ := os.ReadFile(path)
	second := append(append([]byte{}, data...), "junk\n"...)
	if err := os.WriteFile(path, second, 0o600); err != nil {
		t.Fatal(err)
	}
	l, e, err := Reset(path, clock.NewFake(t0), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if e.Reset.File != "apply.log.broken-2" {
		t.Errorf("second reset file = %s", e.Reset.File)
	}
	if e.From != 5 {
		t.Errorf("second reset floor %d, want 5 (carried through the first reset)", e.From)
	}
	for name, want := range map[string][]byte{"apply.log.broken-1": first, "apply.log.broken-2": second} {
		got, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s missing or changed (%v)", name, err)
		}
	}
}

// A crash after the broken log was linked aside but before the new log took
// its place leaves the broken log in place: still broken, so still Tampered.
// The next reset reuses the same evidence file.
func TestResetAfterCrashBetweenLinkAndRename(t *testing.T) {
	path, lines := fiveEntries(t)
	breakers[2].damage(t, path, lines)
	if err := os.Link(path, path+".broken-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, clock.NewFake(t0)); err == nil {
		t.Fatal("log opened")
	}
	l, e, err := Reset(path, clock.NewFake(t0), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if e.Reset.File != "apply.log.broken-1" {
		t.Errorf("file = %s, want the existing broken-1 reused", e.Reset.File)
	}
	if _, err := os.Stat(path + ".broken-2"); err == nil {
		t.Error("a duplicate broken-2 was made")
	}
}

func TestResetLeavesNoTempFile(t *testing.T) {
	path, lines := fiveEntries(t)
	breakers[1].damage(t, path, lines)
	// A leftover temp file from an earlier crash is replaced, not an obstacle.
	if err := os.WriteFile(path+".reset-tmp", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _, err := Reset(path, clock.NewFake(t0), 0)
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	if _, err := os.Stat(path + ".reset-tmp"); err == nil {
		t.Error("temp file left behind")
	}
}

func TestResetPendingOnlyUntilAnApply(t *testing.T) {
	path, lines := fiveEntries(t)
	breakers[2].damage(t, path, lines)
	l, _, err := Reset(path, clock.NewFake(t0), 0)
	if err != nil {
		t.Fatal(err)
	}
	// A rejection does not end it.
	mustAppend(t, l, Entry{From: 4, To: 4, Hash: h('a'), Result: wire.ErrNotNewer})
	if !l.ResetPending() {
		t.Error("a rejection ended ResetPending")
	}
	l.Close()
	l, err = Open(path, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if !l.ResetPending() {
		t.Error("ResetPending lost on reopen")
	}
	if fresh, _, _ := openTemp(t); fresh.ResetPending() {
		t.Error("a new empty log is ResetPending")
	}
}

func TestInspect(t *testing.T) {
	path, lines := fiveEntries(t)
	p, err := Inspect(path)
	if err != nil || p.Err != nil || p.Seq != 5 || p.AppliedVersion != 3 || p.AppliedHash != h('c') || p.Head == "" {
		t.Fatalf("good log: %+v %v", p, err)
	}
	breakers[0].damage(t, path, lines)
	p, err = Inspect(path)
	if err != nil || !errors.Is(p.Err, ErrChain) || p.Seq != 3 || p.AppliedVersion != 2 {
		t.Fatalf("edited log: %+v %v", p, err)
	}
	if _, err := Inspect(path + ".missing"); err == nil {
		t.Error("a missing file inspected without error")
	}
}

func TestResetEntryIsStrictlyDecoded(t *testing.T) {
	good := Entry{Seq: 1, Time: t0, From: 3, Hash: h('a'), Result: wire.ErrTampered,
		Reset: ResetInfo{Seq: 5, File: "apply.log.broken-2", Reason: "chain_broken"}}
	good.Self = computeSelf(good)
	if got, err := Decode(Encode(good)); err != nil || got != good {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	bad := map[string]func(e *Entry){
		"not first":        func(e *Entry) { e.Seq, e.Prev = 2, h('b') },
		"no tampered code": func(e *Entry) { e.Result = "" },
		"other code":       func(e *Entry) { e.Result = wire.ErrNotNewer },
		"to set":           func(e *Entry) { e.To = 1 },
		"path in file":     func(e *Entry) { e.Reset.File = "../apply.log.broken-1" },
		"wrong file name":  func(e *Entry) { e.Reset.File = "apply.log" },
		"zero n":           func(e *Entry) { e.Reset.File = "apply.log.broken-0" },
		"leading zero n":   func(e *Entry) { e.Reset.File = "apply.log.broken-01" },
		"huge n":           func(e *Entry) { e.Reset.File = "apply.log.broken-99999999999" },
		"unknown reason":   func(e *Entry) { e.Reset.Reason = "because" },
		"empty reason":     func(e *Entry) { e.Reset.Reason = "" },
		"head without seq": func(e *Entry) { e.Reset.Seq = 0 },
		"seq without head": func(e *Entry) { e.Hash = "" },
		"no file":          func(e *Entry) { e.Reset.File = "" },
	}
	for name, mod := range bad {
		t.Run(name, func(t *testing.T) {
			e := good
			mod(&e)
			e.Self = computeSelf(e)
			if _, err := Decode(Encode(e)); !errors.Is(err, ErrMalformed) {
				t.Errorf("accepted: err = %v", err)
			}
		})
	}
	// A reset with nothing verifiable before it (the first line was bad).
	empty := good
	empty.From, empty.Hash, empty.Reset.Seq = 0, "", 0
	empty.Self = computeSelf(empty)
	if _, err := Decode(Encode(empty)); err != nil {
		t.Errorf("empty-prefix reset refused: %v", err)
	}
	// The reset fields are part of the hash.
	other := good
	other.Reset.File = "apply.log.broken-3"
	if computeSelf(other) == good.Self {
		t.Error("Self ignores the reset fields")
	}
	// An ordinary entry encodes with no reset key at all: old logs stay byte-identical.
	plain := Entry{Seq: 1, Time: t0, To: 1, Hash: h('a'), Self: h('b')}
	if bytes.Contains(Encode(plain), []byte("reset")) {
		t.Error("ordinary entry carries a reset key")
	}
}
