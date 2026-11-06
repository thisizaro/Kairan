package main

// T-09 (Q-D40, M-D71): a real proxy's first report comes from deny-all boot
// with version 0 and an empty policy hash. The control plane records it, and
// evidence export must show it as a "no policy" period instead of refusing
// the whole answer.

import (
	"encoding/json"
	"strings"
	"testing"

	"kairan/internal/wire"
)

// bootTimeline is what a real control plane holds for a proxy that booted
// deny-all and then applied v8 (the first entry of goodLog).
func bootTimeline(es ...wire.TimelineEntry) []wire.TimelineEntry {
	return append([]wire.TimelineEntry{tl("bank-a-p1", 0, "", 0, 5_000, nil)}, es...)
}

func TestEvidenceBootEntryNoLog(t *testing.T) {
	_, es := goodLog(t, t.TempDir(), "x.log")
	cp := cpWith(t, bootTimeline(tl("bank-a-p1", 8, hh8, 10_000, 30_000, &es[0])))
	code, out, errb := evid(t, cp)
	if code != 0 {
		t.Fatalf("exit %d\nout %s\nerr %s", code, out, errb)
	}
	var boot string
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "no policy") {
			boot = l
		}
	}
	for _, want := range []string{
		"proxy bank-a-p1 had no policy (deny-all, version 0)",
		"ポリシーなし",
		"2026-11-05 18:00:00 JST (2026-11-05 09:00:00 UTC)",
		"2026-11-05 18:00:05 JST (2026-11-05 09:00:05 UTC)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q\n%s", want, out)
		}
	}
	if boot == "" || strings.Contains(boot, "enforced version 0") || strings.Contains(boot, "hash") {
		t.Errorf("boot line wrong: %q\n%s", boot, out)
	}
	if !strings.Contains(out, "proxy bank-a-p1 enforced version 8") || strings.Contains(out, "FLAG") {
		t.Errorf("v8 line missing or flagged\n%s", out)
	}
}

func TestEvidenceBootEntryWithLog(t *testing.T) {
	dir := t.TempDir()
	path, es := mkLog(t, dir, "p1.log", logSpec{0, 8, hh8, ""}, logSpec{8, 9, hh9, ""})
	cp := cpWith(t, bootTimeline(
		tl("bank-a-p1", 8, hh8, 10_000, 30_000, &es[0]),
		tl("bank-a-p1", 9, hh9, 60_000, 600_000, &es[1])))
	code, out, errb := evid(t, cp, "-applylog", "bank-a-p1="+path)
	if code != 0 {
		t.Fatalf("exit %d\nout %s\nerr %s", code, out, errb)
	}
	if !strings.Contains(out, "no mismatch") || strings.Contains(out, "FLAG") || !strings.Contains(out, "no policy") {
		t.Errorf("unexpected output\n%s", out)
	}
}

// A boot entry is never compared with the log's versions, even when it is
// the only period or the last one.
func TestEvidenceBootEntryOnly(t *testing.T) {
	dir := t.TempDir()
	empty, _ := mkLog(t, dir, "empty.log")
	cp := cpWith(t, bootTimeline())
	if code, out, errb := evid(t, cp, "-applylog", "bank-a-p1="+empty); code != 0 || strings.Contains(out, "FLAG") {
		t.Errorf("boot only, empty log: exit %d\n%s\n%s", code, out, errb)
	}
	// The proxy has since applied v8, which the control plane has not seen yet:
	// that is the existing "newer apply not reported" finding, in words that do
	// not talk about a "version 0" being enforced.
	full, _ := mkLog(t, dir, "full.log", logSpec{0, 8, hh8, ""})
	code, out, _ := evid(t, cp, "-applylog", "bank-a-p1="+full)
	if code != 1 || !strings.Contains(out, "FLAG [version]") || strings.Contains(out, "has no applied entry for version 0") {
		t.Errorf("boot only, log with v8: exit %d\n%s", code, out)
	}
}

// The anchor of a boot entry is still checked, with the same rules.
func TestEvidenceBootEntryAnchor(t *testing.T) {
	dir := t.TempDir()
	path, es := goodLog(t, dir, "p1.log")
	good := func() []wire.TimelineEntry {
		return []wire.TimelineEntry{
			tl("bank-a-p1", 0, "", 0, 5_000, &es[0]),
			tl("bank-a-p1", 8, hh8, 10_000, 30_000, &es[0]),
			tl("bank-a-p1", 9, hh9, 60_000, 600_000, &es[1]),
		}
	}
	if code, out, errb := evid(t, cpWith(t, good()), "-applylog", "bank-a-p1="+path); code != 0 {
		t.Fatalf("matching anchor on boot entry: exit %d\n%s\n%s", code, out, errb)
	}
	for _, c := range []struct {
		name string
		mut  func(es []wire.TimelineEntry)
		kind string
	}{
		{"wrong head", func(es []wire.TimelineEntry) { es[0].LogHead = hh10 }, "head"},
		{"seq beyond log", func(es []wire.TimelineEntry) { es[0].LogSeq = 7 }, "seq"},
		{"half anchor", func(es []wire.TimelineEntry) { es[0].LogHead = "" }, "anchor"},
	} {
		t.Run(c.name, func(t *testing.T) {
			tle := good()
			c.mut(tle)
			code, out, _ := evid(t, cpWith(t, tle), "-applylog", "bank-a-p1="+path)
			if code != 1 || !strings.Contains(out, "FLAG ["+c.kind+"]") {
				t.Errorf("exit %d, want FLAG [%s]\n%s", code, c.kind, out)
			}
		})
	}
	// Boot entry at seq 2, next period back at seq 1.
	back := good()
	back[0].LogSeq, back[0].LogHead = es[1].Seq, es[1].Self
	back[1].LogSeq, back[1].LogHead = es[0].Seq, es[0].Self
	if code, out, _ := evid(t, cpWith(t, back), "-applylog", "bank-a-p1="+path); code != 1 || !strings.Contains(out, "FLAG [regression]") {
		t.Errorf("anchor regression after boot: exit %d\n%s", code, out)
	}
	// Without a log the timeline-alone checks still see a boot-entry anchor.
	tle := good()
	tle[0].LogHead = ""
	if code, out, _ := evid(t, cpWith(t, tle)); code != 1 || !strings.Contains(out, "FLAG [anchor]") {
		t.Errorf("half anchor, no log: exit %d\n%s", code, out)
	}
}

func TestEvidenceBootEntryBadAnswers(t *testing.T) {
	for name, e := range map[string]wire.TimelineEntry{
		"version 0 with a hash":        tl("bank-a-p1", 0, hh8, 0, 5_000, nil),
		"version 0 with a malformed":   tl("bank-a-p1", 0, "zz", 0, 5_000, nil),
		"version 1 with an empty hash": tl("bank-a-p1", 1, "", 0, 5_000, nil),
		"version 0 time reversed":      tl("bank-a-p1", 0, "", 5_000, 0, nil),
		"version 0 bad head":           func() wire.TimelineEntry { e := tl("bank-a-p1", 0, "", 0, 5_000, nil); e.LogHead = "zz"; return e }(),
	} {
		t.Run(name, func(t *testing.T) {
			code, out, errb := evid(t, cpWith(t, []wire.TimelineEntry{e}))
			if code != 1 || !hasBoth(errb) || strings.Contains(out, "had no policy") {
				t.Errorf("exit %d\nout %s\nerr %s", code, out, errb)
			}
		})
	}
}

// Going back to version 0 after a real version is still a version regression.
func TestEvidenceBootEntryAfterVersionIsFlagged(t *testing.T) {
	tle := []wire.TimelineEntry{
		tl("bank-a-p1", 8, hh8, 0, 5_000, nil),
		tl("bank-a-p1", 0, "", 10_000, 20_000, nil),
	}
	if code, out, _ := evid(t, cpWith(t, tle)); code != 1 || !strings.Contains(out, "FLAG [version]") {
		t.Errorf("exit %d\n%s", code, out)
	}
}

func TestCheckTimelineBootEntry(t *testing.T) {
	e := func(v uint64, h wire.Hash) wire.TimelineEntry { return tl("bank-a-p1", v, h, 0, 1_000, nil) }
	for _, c := range []struct {
		name string
		e    wire.TimelineEntry
		ok   bool
	}{
		{"v0 empty", e(0, ""), true},
		{"v1 hash", e(1, hh8), true},
		{"v0 hash", e(0, hh8), false},
		{"v1 empty", e(1, ""), false},
		{"v0 bad hash", e(0, "zz"), false},
	} {
		got := checkTimeline(wire.TimelineView{Tenant: "bank-a", Entries: []wire.TimelineEntry{c.e}}, "bank-a") == nil
		if got != c.ok {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.ok)
		}
	}
}

// FuzzTimelineDecode runs arbitrary bytes through the same path as the
// command (strict key scan, JSON decode, checkTimeline, crossCheck). It must
// not panic, and whatever is accepted obeys the version/hash rule.
func FuzzTimelineDecode(f *testing.F) {
	h := string(hh9)
	for _, s := range []string{
		`{"tenant":"bank-a","entries":[{"proxy_id":"p1","version":0,"policy_hash":"","first_seen_unix_ms":1793000000000,"last_seen_unix_ms":1793000001000},{"proxy_id":"p1","version":1,"policy_hash":"` + h + `","first_seen_unix_ms":1793000002000,"last_seen_unix_ms":1793000003000,"log_seq":1,"log_head":"` + h + `"}]}`,
		`{"tenant":"bank-a","entries":[{"proxy_id":"p1","version":0,"policy_hash":"` + h + `","first_seen_unix_ms":1793000000000,"last_seen_unix_ms":1793000001000}]}`,
		`{"tenant":"bank-a","entries":[{"proxy_id":"p1","version":1,"policy_hash":"","first_seen_unix_ms":1793000000000,"last_seen_unix_ms":1793000001000}]}`,
		`{"tenant":"bank-a","entries":[{"proxy_id":"p1","version":0,"policy_hash":"","first_seen_unix_ms":1793000000000,"last_seen_unix_ms":1793000001000,"log_seq":3}]}`,
		`{"tenant":"bank-a","entries":[null]}`, `{}`, `[`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if !strictTimelineKeys(b) {
			return
		}
		var v wire.TimelineView
		if json.Unmarshal(b, &v) != nil || checkTimeline(v, string(v.Tenant)) != nil {
			return
		}
		for _, e := range v.Entries {
			if (e.Version == 0) != (e.PolicyHash == "") {
				t.Fatalf("accepted version %d with hash %q", e.Version, e.PolicyHash)
			}
		}
		fs := crossCheck(v.Entries, nil)
		for _, x := range fs {
			if x.en == "" || x.ja == "" {
				t.Fatalf("empty finding %+v", x)
			}
		}
	})
}
