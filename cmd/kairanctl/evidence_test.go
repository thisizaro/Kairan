package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

var (
	hh8  = wire.Hash(strings.Repeat("11", 32))
	hh9  = wire.Hash(strings.Repeat("22", 32))
	hh10 = wire.Hash(strings.Repeat("33", 32))
)

type logSpec struct {
	from, to uint64
	hash     wire.Hash
	result   wire.ErrorCode
}

// mkLog writes a real apply log (one entry per minute from t0) and returns
// its path and entries.
func mkLog(t *testing.T, dir, name string, specs ...logSpec) (string, []applylog.Entry) {
	t.Helper()
	path := filepath.Join(dir, name)
	clk := clock.NewFake(time.UnixMilli(t0))
	l, err := applylog.Open(path, clk)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var out []applylog.Entry
	for _, s := range specs {
		e, err := l.Append(applylog.Entry{From: s.from, To: s.to, Hash: s.hash, Result: s.result})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
		clk.Advance(time.Minute)
	}
	return path, out
}

// goodLog is the log of a proxy that applied v8 then v9.
func goodLog(t *testing.T, dir, name string) (string, []applylog.Entry) {
	return mkLog(t, dir, name, logSpec{0, 8, hh8, ""}, logSpec{8, 9, hh9, ""})
}

func tl(proxy wire.ID, v uint64, h wire.Hash, first, last int64, e *applylog.Entry) wire.TimelineEntry {
	te := wire.TimelineEntry{ProxyID: proxy, Version: v, PolicyHash: h, FirstSeenUnixMs: t0 + first, LastSeenUnixMs: t0 + last}
	if e != nil {
		te.LogSeq, te.LogHead = e.Seq, e.Self
	}
	return te
}

// cleanTimeline matches goodLog for bank-a-p1.
func cleanTimeline(es []applylog.Entry) []wire.TimelineEntry {
	return []wire.TimelineEntry{
		tl("bank-a-p1", 8, hh8, 0, 30_000, &es[0]),
		tl("bank-a-p1", 9, hh9, 60_000, 600_000, &es[1]),
	}
}

func cpWith(t *testing.T, entries []wire.TimelineEntry) *fakeCP {
	cp := newFakeCP(t, false)
	cp.timeline = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, wire.TimelineView{Tenant: wire.ID(tenant), Entries: entries})
	}
	return cp
}

func evid(t *testing.T, cp *fakeCP, extra ...string) (int, string, string) {
	t.Helper()
	args := append([]string{"evidence", "export", "-tenant", "bank-a"}, extra...)
	return cp.admin(t, args...)
}

func TestCrossCheckClean(t *testing.T) {
	dir := t.TempDir()
	path, es := goodLog(t, dir, "p1.log")
	cp := cpWith(t, cleanTimeline(es))
	code, out, errb := evid(t, cp, "-applylog", "bank-a-p1="+path)
	if code != 0 {
		t.Fatalf("exit %d\nout %s\nerr %s", code, out, errb)
	}
	for _, want := range []string{
		"proxy bank-a-p1 enforced version 9",
		"apply log verified",
		"2 entries",
		"no mismatch",
		"2026-11-05 18:01:00 JST (2026-11-05 09:01:00 UTC)", // newest log entry time
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "FLAG") {
		t.Errorf("clean case has a flag:\n%s", out)
	}
}

func TestCrossCheckFlags(t *testing.T) {
	type tc struct {
		name string
		// build returns the log path and the timeline.
		build func(t *testing.T, dir string) (string, []wire.TimelineEntry)
		kind  string // expected in a FLAG line
		text  string // expected somewhere in the output
	}
	cases := []tc{
		{"version not in log", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := goodLog(t, dir, "p1.log")
			tle := cleanTimeline(es)
			tle = append(tle, tl("bank-a-p1", 10, hh10, 700_000, 800_000, &es[1]))
			return p, tle
		}, "version", "version 10"},
		{"same version, other hash", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := goodLog(t, dir, "p1.log")
			tle := cleanTimeline(es)
			tle[1].PolicyHash = hh10
			return p, tle
		}, "version", "hash"},
		{"log newest applied differs from CP latest", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := goodLog(t, dir, "p1.log")
			return p, cleanTimeline(es)[:1]
		}, "version", "newest applied version 9"},
		{"rejected attempt is not an apply", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := mkLog(t, dir, "p1.log", logSpec{0, 8, hh8, ""}, logSpec{8, 9, hh9, wire.ErrNotNewer})
			tle := []wire.TimelineEntry{
				tl("bank-a-p1", 8, hh8, 0, 30_000, &es[0]),
				tl("bank-a-p1", 9, hh9, 60_000, 600_000, &es[1]),
			}
			return p, tle
		}, "version", "version 9"},
		{"truncated tail", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			_, es := goodLog(t, dir, "full.log")
			p, _ := mkLog(t, dir, "p1.log", logSpec{0, 8, hh8, ""}) // same first entry, cut after it
			return p, cleanTimeline(es)
		}, "seq", "ends at seq 1"},
		{"head differs at same seq", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := goodLog(t, dir, "p1.log")
			tle := cleanTimeline(es)
			tle[1].LogHead = hh10
			return p, tle
		}, "head", "seq 2"},
		{"anchor regression in the CP timeline", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := mkLog(t, dir, "p1.log", logSpec{0, 8, hh8, ""}, logSpec{8, 9, hh9, ""},
				logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""})
			tle := []wire.TimelineEntry{
				tl("bank-a-p1", 9, hh9, 0, 30_000, &es[4]),
				tl("bank-a-p1", 9, hh9, 60_000, 600_000, &es[1]),
			}
			return p, tle
		}, "regression", "seq 5"},
		{"edited log", func(t *testing.T, dir string) (string, []wire.TimelineEntry) {
			p, es := goodLog(t, dir, "p1.log")
			b, _ := os.ReadFile(p)
			b = []byte(strings.Replace(string(b), `"to":8`, `"to":7`, 1))
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
			return p, cleanTimeline(es)
		}, "log", "failed verification"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			path, tle := c.build(t, dir)
			cp := cpWith(t, tle)
			code, out, errb := evid(t, cp, "-applylog", "bank-a-p1="+path)
			if code != 1 {
				t.Fatalf("exit %d, want 1\n%s\n%s", code, out, errb)
			}
			if !hasBoth(errb) {
				t.Errorf("exit message is not bilingual: %q", errb)
			}
			var flagLine string
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "FLAG ["+c.kind+"]") {
					flagLine += l + "\n"
				}
			}
			if flagLine == "" {
				t.Fatalf("no FLAG [%s] line\n%s", c.kind, out)
			}
			if !strings.Contains(out, c.text) {
				t.Errorf("output lacks %q\n%s", c.text, out)
			}
			if strings.Contains(out, "no mismatch") {
				t.Errorf("says no mismatch though flagged:\n%s", out)
			}
		})
	}
}

// Q-D15: 7 then 5 is seen by the timeline alone, with or without logs.
func TestAnchorRegressionWithoutLogs(t *testing.T) {
	_, es := mkLog(t, t.TempDir(), "x.log", logSpec{0, 9, hh9, ""}, logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""},
		logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""}, logSpec{9, 9, hh9, ""})
	tle := []wire.TimelineEntry{
		tl("bank-a-p1", 9, hh9, 0, 30_000, &es[6]),        // seq 7
		tl("bank-a-p1", 9, hh9, 60_000, 90_000, &es[4]),   // seq 5
		tl("bank-a-p1", 9, hh9, 120_000, 150_000, &es[5]), // seq 6: still behind the highest seen
	}
	code, out, _ := evid(t, cpWith(t, tle))
	if code != 1 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if n := strings.Count(out, "FLAG [regression]"); n != 2 {
		t.Errorf("want 2 regression flags (seq 5 and seq 6 are both behind 7), got %d\n%s", n, out)
	}
	if !strings.Contains(out, "7") || !strings.Contains(out, "seq 5") || !strings.Contains(out, "2026-11-05 18:01:00 JST (2026-11-05 09:01:00 UTC)") {
		t.Errorf("flag should name both seqs and the time in JST and UTC\n%s", out)
	}
}

func TestAnchorSameSeqOtherHeadWithoutLogs(t *testing.T) {
	_, es := goodLog(t, t.TempDir(), "x.log")
	tle := cleanTimeline(es)
	tle = append(tle, tl("bank-a-p1", 9, hh9, 700_000, 800_000, &es[1]))
	tle[2].LogHead = hh10
	code, out, _ := evid(t, cpWith(t, tle))
	if code != 1 || !strings.Contains(out, "FLAG [head]") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestAnchorDroppedToZero(t *testing.T) {
	_, es := goodLog(t, t.TempDir(), "x.log")
	tle := []wire.TimelineEntry{
		tl("bank-a-p1", 8, hh8, 0, 30_000, &es[1]),
		tl("bank-a-p1", 9, hh9, 60_000, 90_000, nil), // no anchor any more
	}
	code, out, _ := evid(t, cpWith(t, tle))
	if code != 1 || !strings.Contains(out, "FLAG [regression]") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestVersionGoingBackwardsInTimeline(t *testing.T) {
	_, es := goodLog(t, t.TempDir(), "x.log")
	tle := []wire.TimelineEntry{
		tl("bank-a-p1", 9, hh9, 0, 30_000, &es[1]),
		tl("bank-a-p1", 8, hh8, 60_000, 90_000, &es[1]),
	}
	code, out, _ := evid(t, cpWith(t, tle))
	if code != 1 || !strings.Contains(out, "FLAG [version]") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestCrossCheckLogNotInTimelineAndMissingLog(t *testing.T) {
	dir := t.TempDir()
	path, es := goodLog(t, dir, "p1.log")
	tle := append(cleanTimeline(es), tl("bank-a-p2", 9, hh9, 0, 1000, &es[1]))
	cp := cpWith(t, tle)

	// p2 has no log supplied: noted, not a failure.
	code, out, _ := evid(t, cp, "-applylog", "bank-a-p1="+path)
	if code != 0 || !strings.Contains(out, "bank-a-p2: no apply log supplied") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// A log for a proxy the CP never heard of is a flag.
	code, out, _ = evid(t, cp, "-applylog", "bank-a-p1="+path, "-applylog", "bank-a-p7="+path)
	if code != 1 || !strings.Contains(out, "FLAG [log]") || !strings.Contains(out, "bank-a-p7") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// -proxy narrows the check to one proxy.
	code, out, _ = evid(t, cp, "-proxy", "bank-a-p1", "-applylog", "bank-a-p1="+path)
	if code != 0 || strings.Contains(out, "bank-a-p2") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// A log for a proxy outside the filter is a usage error.
	if code, _, e := evid(t, cp, "-proxy", "bank-a-p1", "-applylog", "bank-a-p2="+path); code != 2 || !hasBoth(e) {
		t.Errorf("filtered-out log: exit %d err %q", code, e)
	}
}

func TestCrossCheckEmptyLogAndNoTimeline(t *testing.T) {
	dir := t.TempDir()
	empty, _ := mkLog(t, dir, "empty.log")
	// CP has anchors for an empty log: truncation to zero.
	_, es := goodLog(t, dir, "full.log")
	code, out, _ := evid(t, cpWith(t, cleanTimeline(es)), "-applylog", "bank-a-p1="+empty)
	if code != 1 || !strings.Contains(out, "FLAG [seq]") {
		t.Errorf("exit %d\n%s", code, out)
	}
	// An empty CP timeline with a supplied log: the proxy is unknown to the CP.
	code, out, _ = evid(t, cpWith(t, nil), "-applylog", "bank-a-p1="+empty)
	if code != 1 || !strings.Contains(out, "FLAG [log]") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestCrossCheckDropped(t *testing.T) {
	dir := t.TempDir()
	path, es := goodLog(t, dir, "p1.log")
	withDropped := func(d map[wire.ID]uint64) *fakeCP {
		cp := newFakeCP(t, false)
		cp.timeline = func(w http.ResponseWriter, tenant string) {
			writeJSON(w, 200, wire.TimelineView{Tenant: wire.ID(tenant), Entries: cleanTimeline(es), Dropped: d})
		}
		return cp
	}
	code, out, errb := evid(t, withDropped(map[wire.ID]uint64{"bank-a-p1": 3, "bank-a-p2": 4}), "-applylog", "bank-a-p1="+path)
	if code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, out, errb)
	}
	for _, want := range []string{"WARNING [dropped]", "7 earlier", "proxy bank-a-p1: 3 dropped", "proxy bank-a-p2: 4 dropped"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q\n%s", want, out)
		}
	}
	// Without logs the warning still shows, and the exit code stays 0.
	if code, out, _ := evid(t, withDropped(map[wire.ID]uint64{"bank-a-p1": 1})); code != 0 || !strings.Contains(out, "1 earlier") {
		t.Errorf("no logs: exit %d\n%s", code, out)
	}
	// Absent, empty and zero counts are silent.
	for _, d := range []map[wire.ID]uint64{nil, {}, {"bank-a-p1": 0}} {
		if code, out, _ := evid(t, withDropped(d)); code != 0 || strings.Contains(out, "dropped") {
			t.Errorf("%v: exit %d\n%s", d, code, out)
		}
	}
	// A bare number (the old local guess) and bad proxy IDs are refused.
	for name, raw := range map[string]string{
		"integer":    `3`,
		"bad id":     `{"bad id":1}`,
		"escape id":  `{"p\u001b[2J":1}`,
		"negative":   `{"bank-a-p1":-1}`,
		"fractional": `{"bank-a-p1":1.5}`,
	} {
		t.Run(name, func(t *testing.T) {
			cp := newFakeCP(t, false)
			cp.timeline = func(w http.ResponseWriter, tenant string) {
				writeJSON(w, 200, struct {
					wire.TimelineView
					Dropped rawJSON `json:"dropped"`
				}{wire.TimelineView{Tenant: wire.ID(tenant), Entries: cleanTimeline(es)}, rawJSON(raw)})
			}
			if code, out, e := evid(t, cp); code != 1 || !hasBoth(e) || strings.ContainsRune(out+e, 0x1b) {
				t.Errorf("exit %d out %q err %q", code, out, e)
			}
		})
	}
}

// rawJSON marshals as itself.
type rawJSON string

func (r rawJSON) MarshalJSON() ([]byte, error) { return []byte(r), nil }

func TestApplylogFlagErrors(t *testing.T) {
	dir := t.TempDir()
	path, es := goodLog(t, dir, "p1.log")
	cp := cpWith(t, cleanTimeline(es))
	for name, args := range map[string][]string{
		"no equals":   {"-applylog", path},
		"bad id":      {"-applylog", "P R=" + path},
		"empty path":  {"-applylog", "bank-a-p1="},
		"duplicate":   {"-applylog", "bank-a-p1=" + path, "-applylog", "bank-a-p1=" + path},
		"missing":     {"-applylog", "bank-a-p1=" + filepath.Join(dir, "nope")},
		"a directory": {"-applylog", "bank-a-p1=" + dir},
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errb := evid(t, cp, args...)
			if code == 0 || !hasBoth(errb) {
				t.Errorf("exit %d err %q out %q", code, errb, out)
			}
		})
	}
	// A huge file is refused before it is read.
	big := filepath.Join(dir, "big.log")
	f, _ := os.Create(big)
	_ = f.Truncate(maxApplyLogBytes + 1)
	f.Close()
	if code, _, errb := evid(t, cp, "-applylog", "bank-a-p1="+big); code != 1 || !hasBoth(errb) {
		t.Errorf("big file: exit %d err %q", code, errb)
	}
}

func TestParseLogArg(t *testing.T) {
	for _, c := range []struct {
		in       string
		id, path string
		ok       bool
	}{
		{"bank-a-p1=/tmp/x.log", "bank-a-p1", "/tmp/x.log", true},
		{"bank-a-p1=a=b", "bank-a-p1", "a=b", true},
		{"", "", "", false},
		{"=x", "", "", false},
		{"p1=", "", "", false},
		{"p1", "", "", false},
		{"P R=x", "", "", false},
		{"p1=x\x00y", "", "", false},
	} {
		id, path, ok := parseLogArg(c.in)
		if ok != c.ok || (ok && (string(id) != c.id || path != c.path)) {
			t.Errorf("%q -> %q %q %v", c.in, id, path, ok)
		}
	}
}

func FuzzParseLogArg(f *testing.F) {
	for _, s := range []string{"bank-a-p1=/x", "=", "a=b=c", "p1=\x00", "\xff=\xff"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		id, path, ok := parseLogArg(s)
		if !ok {
			return
		}
		if !id.Valid() || path == "" || !utf8.ValidString(path) || strings.ContainsRune(path, 0) || id+"="+wire.ID(path) != wire.ID(s) {
			t.Errorf("accepted %q as %q %q", s, id, path)
		}
	})
}

func FuzzCheckDropped(f *testing.F) {
	for _, s := range []string{`{"p1":2}`, `{}`, `{"p1":0}`, `{"bad id":1}`, `{"a":18446744073709551615,"b":1}`, `{"a":-1}`, `3`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var m map[wire.ID]uint64
		if json.Unmarshal(b, &m) != nil {
			return
		}
		d, err := checkDropped(m)
		if err != nil {
			return
		}
		var sum uint64
		for id, n := range d.byProxy {
			if !id.Valid() || n == 0 {
				t.Errorf("bad kept entry %q %d", id, n)
			}
			sum += n
		}
		if sum != d.total {
			t.Errorf("total %d != sum %d", d.total, sum)
		}
	})
}

func TestVerifyApplylog(t *testing.T) {
	dir := t.TempDir()
	path, _ := goodLog(t, dir, "p1.log")
	code, out, errb := ctl(t, "", "verify-applylog", "-in", path)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	for _, want := range []string{"apply log verified", "2 entries", "seq 2", "2026-11-05 18:01:00 JST (2026-11-05 09:01:00 UTC)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}

	empty, _ := mkLog(t, dir, "empty.log")
	if code, out, _ := ctl(t, "", "verify-applylog", "-in", empty); code != 0 || !strings.Contains(out, "empty") {
		t.Errorf("empty: exit %d %s", code, out)
	}

	raw, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(raw), "\n")
	bad := map[string]string{
		"edited":       strings.Replace(string(raw), `"to":8`, `"to":7`, 1),
		"line deleted": lines[1],
		"reordered":    lines[1] + lines[0],
		"torn tail":    strings.TrimSuffix(string(raw), "\n"),
		"garbage":      string(raw) + "garbage\n",
	}
	for name, content := range bad {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x.log")
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errb := ctl(t, "", "verify-applylog", "-in", p)
			if code != 1 || !hasBoth(errb) || strings.Contains(out, "verified") {
				t.Errorf("exit %d out %q err %q", code, out, errb)
			}
		})
	}
	for name, args := range map[string][]string{
		"no -in":  {"verify-applylog"},
		"missing": {"verify-applylog", "-in", filepath.Join(dir, "nope")},
		"dir":     {"verify-applylog", "-in", dir},
		"extra":   {"verify-applylog", "-in", path, "x"},
	} {
		if code, _, errb := ctl(t, "", args...); code == 0 || !hasBoth(errb) {
			t.Errorf("%s: exit %d err %q", name, code, errb)
		}
	}
}
