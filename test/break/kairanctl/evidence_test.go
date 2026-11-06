package kairanctlbreak

// Break pass for T-07: kairanctl evidence export -applylog PROXY=FILE, and kairanctl verify-applylog.
// Sources: the kairanctl command doc, ARCHITECTURE (kairanctl LLD, applylog LLD, I6), PRD J5 (JST + UTC),
// decisions M-D35, M-D45, M-D55, T-D7, T-D8 (flag tags, exit codes, Dropped as a WARNING).

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

var (
	hA = wire.Hash(strings.Repeat("a3", 32))
	hB = wire.Hash(strings.Repeat("b5", 32))
	hC = wire.Hash(strings.Repeat("c7", 32))
	hX = wire.Hash(strings.Repeat("ee", 32))
)

// mkLog writes an apply log through the real library and returns its path and the finished entries.
func mkLog(t testing.TB, dir, name string, steps ...applylog.Entry) (string, []applylog.Entry) {
	t.Helper()
	p := filepath.Join(dir, name)
	clk := clock.NewFake(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	l, err := applylog.Open(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	var out []applylog.Entry
	for _, s := range steps {
		clk.Advance(time.Minute)
		e, err := l.Append(s)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	l.Close()
	return p, out
}

func threeEntryLog(t testing.TB, dir, name string) (string, []applylog.Entry) {
	return mkLog(t, dir, name,
		applylog.Entry{From: 0, To: 3, Hash: hA},
		applylog.Entry{From: 3, To: 5, Hash: hB},
		applylog.Entry{From: 5, To: 7, Hash: hC},
	)
}

func te(proxy string, v uint64, h wire.Hash, first, last int64, e *applylog.Entry) wire.TimelineEntry {
	x := wire.TimelineEntry{ProxyID: wire.ID(proxy), Version: v, PolicyHash: h, FirstSeenUnixMs: first, LastSeenUnixMs: last}
	if e != nil {
		x.LogSeq, x.LogHead = e.Seq, e.Self
	}
	return x
}

const t0 = int64(1700000000000)

// evidence runs `evidence export` against a stub serving tl and returns the result and the output file, if any.
func evidence(t *testing.T, tl wire.TimelineView, extra ...string) result {
	t.Helper()
	bin := buildCtl(t)
	if tl.Tenant == "" {
		tl.Tenant = "bank-a"
	}
	cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) {
		if r.URL.Path == wire.PathTimeline {
			jsonReply(w, 200, tl)
			return
		}
		http.NotFound(w, r)
	})
	args := append([]string{"evidence", "export", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext"}, extra...)
	r := runIn(t, bin, t.TempDir(), connEnv(tok), "", args...)
	sane(t, r)
	return r
}

// sane: whatever the verdict, output is never a panic, a token, or terminal control bytes.
func sane(t testing.TB, r result) {
	t.Helper()
	all := r.stdout + r.stderr
	if strings.Contains(all, "panic:") || strings.Contains(all, "goroutine ") {
		t.Errorf("panic in output: %s", clip(all))
	}
	if strings.Contains(all, tok) {
		t.Errorf("admin token in output")
	}
	for _, c := range all {
		if c == 0x1b || (c < 0x20 && c != '\n' && c != '\t' && c != '\r') || c == 0x7f {
			t.Errorf("control character %q in output (terminal injection): %s", c, clip(all))
			break
		}
	}
}

func clip(s string) string {
	if len(s) > 600 {
		return s[:600] + "..."
	}
	return s
}

func flagLines(out string) []string {
	var o []string
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "FLAG") {
			o = append(o, ln)
		}
	}
	return o
}

func hasCJK(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
			return true
		}
	}
	return false
}

// wantFlag requires exit 1 and a FLAG line, with one of the tags if given (T-D7), in English and Japanese.
func wantFlag(t *testing.T, r result, why string, tags ...string) {
	t.Helper()
	if r.code != 1 {
		t.Errorf("%s: exit %d, want 1\n%s%s", why, r.code, r.stdout, r.stderr)
	}
	fl := flagLines(r.stdout)
	if len(fl) == 0 {
		t.Errorf("%s: no FLAG line\n%s%s", why, r.stdout, r.stderr)
		return
	}
	if len(tags) > 0 {
		ok := false
		for _, ln := range fl {
			for _, tg := range tags {
				if strings.Contains(ln, "FLAG ["+tg+"]") {
					ok = true
				}
			}
		}
		if !ok {
			t.Errorf("%s: FLAG lines %q lack a tag among %v (T-D7)", why, fl, tags)
		}
	}
	// The Japanese text of a flag may be on the same or the next line; require some Japanese in the report.
	if !hasCJK(r.stdout) {
		t.Errorf("%s: report has no Japanese (PRD J7)", why)
	}
	if strings.Contains(r.stdout, "no mismatch found") {
		t.Errorf("%s: report says no mismatch although it flags one", why)
	}
}

func wantClean(t *testing.T, r result, why string) {
	t.Helper()
	if r.code != 0 || len(flagLines(r.stdout)) != 0 {
		t.Errorf("%s: exit %d with FLAG lines %q\n%s%s", why, r.code, flagLines(r.stdout), r.stdout, r.stderr)
	}
}

// ---- cross-check: the timeline against a log ----

func TestEvidenceConsistentLogIsClean(t *testing.T) {
	d := t.TempDir()
	p, e := threeEntryLog(t, d, "p1.log")
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{
		te("p-1", 3, hA, t0, t0+3600000, &e[0]),
		te("p-1", 5, hB, t0+3600000, t0+7200000, &e[1]),
		te("p-1", 7, hC, t0+7200000, t0+9000000, &e[2]),
	}}
	r := evidence(t, tl, "-applylog", "p-1="+p)
	wantClean(t, r, "consistent timeline and log")
	// PRD J5: JST and UTC, the claim sentence, labelled as the control plane's record
	for _, want := range []string{"p-1", "enforced version 3", "enforced version 7", string(hA), string(hC), "UTC", "JST", "2023-11-15 07:13:20 JST", "2023-11-14 22:13:20 UTC"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("report lacks %q\n%s", want, r.stdout)
		}
	}
	// the timeline alone (no log) is also clean when its own anchors are consistent
	r = evidence(t, tl)
	wantClean(t, r, "timeline alone")
	// a log for a proxy that the timeline has a prefix of (older timeline than log) is a version flag (T-D7 note),
	// never silent
	old := wire.TimelineView{Entries: tl.Entries[:2]}
	r = evidence(t, old, "-applylog", "p-1="+p)
	wantFlag(t, r, "log newer than the control plane's last report", "version", "seq", "log")
}

func TestEvidenceMismatches(t *testing.T) {
	d := t.TempDir()
	p, e := threeEntryLog(t, d, "p1.log")
	cases := []struct {
		name string
		tl   []wire.TimelineEntry
		tags []string
	}{
		{"timeline version differs from the log's newest applied (I6)", []wire.TimelineEntry{
			te("p-1", 3, hA, t0, t0+1, &e[0]), te("p-1", 5, hB, t0+1, t0+2, &e[1]), te("p-1", 6, hC, t0+2, t0+3, &e[2])}, []string{"version"}},
		{"same version, other hash", []wire.TimelineEntry{
			te("p-1", 3, hA, t0, t0+1, &e[0]), te("p-1", 5, hB, t0+1, t0+2, &e[1]), te("p-1", 7, hX, t0+2, t0+3, &e[2])}, []string{"version"}},
		{"a version the log never applied", []wire.TimelineEntry{
			te("p-1", 3, hA, t0, t0+1, &e[0]), te("p-1", 4, hX, t0+1, t0+2, &e[1]), te("p-1", 7, hC, t0+2, t0+3, &e[2])}, []string{"version"}},
		{"anchor seq beyond the end of the log (truncation)", []wire.TimelineEntry{
			te("p-1", 7, hC, t0, t0+1, &applylog.Entry{Seq: 9, Self: e[2].Self})}, []string{"seq"}},
		{"anchor seq right, head wrong (rewrite)", []wire.TimelineEntry{
			te("p-1", 7, hC, t0, t0+1, &applylog.Entry{Seq: e[2].Seq, Self: hX})}, []string{"head"}},
		{"anchor head is another entry's head", []wire.TimelineEntry{
			te("p-1", 7, hC, t0, t0+1, &applylog.Entry{Seq: e[2].Seq, Self: e[1].Self})}, []string{"head"}},
		{"anchor head right, seq wrong", []wire.TimelineEntry{
			te("p-1", 7, hC, t0, t0+1, &applylog.Entry{Seq: e[1].Seq, Self: e[2].Self})}, []string{"head", "seq"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			wantFlag(t, evidence(t, wire.TimelineView{Entries: c.tl}, "-applylog", "p-1="+p), c.name, c.tags...)
		})
	}
}

// Truncation by an attacker who cuts whole lines: the chain still verifies, only the anchor shows it.
func TestEvidenceTruncatedLogAtEveryLength(t *testing.T) {
	d := t.TempDir()
	full, e := threeEntryLog(t, d, "full.log")
	b, _ := os.ReadFile(full)
	lines := bytes.SplitAfter(b, []byte("\n"))
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{
		te("p-1", 3, hA, t0, t0+1, &e[0]), te("p-1", 5, hB, t0+1, t0+2, &e[1]), te("p-1", 7, hC, t0+2, t0+3, &e[2])}}
	for keep := 0; keep < 3; keep++ {
		t.Run(fmt.Sprintf("keep %d of 3 lines", keep), func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "cut.log")
			os.WriteFile(p, bytes.Join(lines[:keep], nil), 0o600)
			wantFlag(t, evidence(t, tl, "-applylog", "p-1="+p), "log cut to a valid shorter chain", "seq", "version", "log", "head")
		})
	}
}

// Timeline anchors alone: a regression is flagged without any log (M-D35, "7 then 5").
func TestEvidenceTimelineRegressions(t *testing.T) {
	a := func(seq uint64, head wire.Hash) *applylog.Entry { return &applylog.Entry{Seq: seq, Self: head} }
	h1, h2, h3 := wire.Hash(strings.Repeat("11", 32)), wire.Hash(strings.Repeat("22", 32)), wire.Hash(strings.Repeat("33", 32))
	cases := []struct {
		name string
		es   []wire.TimelineEntry
		tags []string
		bad  bool
	}{
		{"7 then 5", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(7, h1)), te("p-1", 4, hB, t0+2, t0+3, a(5, h2))}, []string{"regression"}, true},
		{"5 then 7 then 6", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(5, h1)), te("p-1", 4, hB, t0+2, t0+3, a(7, h2)), te("p-1", 5, hC, t0+4, t0+5, a(6, h3))}, []string{"regression"}, true},
		{"7 then 5 across a version change back and forth", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(7, h1)), te("p-1", 3, hA, t0+2, t0+3, a(5, h1))}, []string{"regression"}, true},
		{"same seq, other head", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(7, h1)), te("p-1", 4, hB, t0+2, t0+3, a(7, h2))}, []string{"head", "regression"}, true},
		{"version going down", []wire.TimelineEntry{te("p-1", 5, hB, t0, t0+1, a(1, h1)), te("p-1", 3, hA, t0+2, t0+3, a(2, h2))}, []string{"version", "regression"}, true},
		{"seq going up with versions going up", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(1, h1)), te("p-1", 4, hB, t0+2, t0+3, a(2, h2)), te("p-1", 5, hC, t0+4, t0+5, a(3, h3))}, nil, false},
		{"same seq, same head (a later report of the same anchor)", []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, a(1, h1)), te("p-1", 3, hA, t0+2, t0+3, a(1, h1))}, nil, false},
		{"a regression of another proxy is not hidden by a good one", []wire.TimelineEntry{
			te("p-2", 3, hA, t0, t0+1, a(1, h1)), te("p-2", 4, hB, t0+2, t0+3, a(2, h2)),
			te("p-1", 3, hA, t0, t0+1, a(7, h1)), te("p-1", 4, hB, t0+2, t0+3, a(5, h2))}, []string{"regression"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := evidence(t, wire.TimelineView{Entries: c.es})
			if c.bad {
				wantFlag(t, r, c.name, c.tags...)
			} else {
				wantClean(t, r, c.name)
			}
		})
	}
}

func TestEvidenceFlagNamesTheBadProxyOnly(t *testing.T) {
	d := t.TempDir()
	p1, e1 := threeEntryLog(t, d, "p1.log")
	p2, e2 := threeEntryLog(t, d, "p2.log")
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{
		te("p-good", 7, hC, t0, t0+1, &e1[2]),
		te("p-bad", 6, hC, t0, t0+1, &e2[2]),
	}}
	r := evidence(t, tl, "-applylog", "p-good="+p1, "-applylog", "p-bad="+p2)
	wantFlag(t, r, "one of two proxies differs")
	var bad, good bool
	for _, ln := range flagLines(r.stdout) {
		bad = bad || strings.Contains(ln, "p-bad")
		good = good || strings.Contains(ln, "p-good")
	}
	if !bad {
		t.Errorf("no FLAG line names p-bad: %q", flagLines(r.stdout))
	}
	if good {
		t.Errorf("a FLAG line names the consistent proxy p-good: %q", flagLines(r.stdout))
	}
	// -proxy narrows the check as well as the report
	r = evidence(t, tl, "-proxy", "p-good", "-applylog", "p-good="+p1)
	wantClean(t, r, "only the good proxy asked for")
	if strings.Contains(r.stdout, "p-bad") {
		t.Errorf("-proxy p-good still shows p-bad\n%s", r.stdout)
	}
}

// A rejected entry is not an apply: claiming a version that the log only rejected is a flag.
func TestEvidenceRejectedEntryIsNotAnApply(t *testing.T) {
	d := t.TempDir()
	p, e := mkLog(t, d, "p.log",
		applylog.Entry{From: 0, To: 3, Hash: hA},
		applylog.Entry{From: 3, To: 5, Hash: hB, Result: wire.ErrBadRequest},
	)
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{
		te("p-1", 3, hA, t0, t0+1, &e[0]),
		te("p-1", 5, hB, t0+1, t0+2, &e[1]),
	}}
	wantFlag(t, evidence(t, tl, "-applylog", "p-1="+p), "control plane says enforced 5, the log says rejected", "version", "log")
	ok := wire.TimelineView{Entries: []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, &e[1])}}
	wantClean(t, evidence(t, ok, "-applylog", "p-1="+p), "rejected entry after the applied one, timeline at v3 with the newest anchor")
}

// ---- the log file itself ----

func TestEvidenceBrokenLogs(t *testing.T) {
	d := t.TempDir()
	good, e := threeEntryLog(t, d, "good.log")
	b, _ := os.ReadFile(good)
	lines := strings.SplitAfter(string(b), "\n")
	lines = lines[:3]
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{
		te("p-1", 3, hA, t0, t0+1, &e[0]), te("p-1", 5, hB, t0+1, t0+2, &e[1]), te("p-1", 7, hC, t0+2, t0+3, &e[2])}}
	edit := strings.Replace(string(b), `"to":5`, `"to":4`, 1)
	if edit == string(b) {
		t.Fatalf("edit did not apply to %q", b)
	}
	cases := map[string]string{
		"field edited":           edit,
		"middle entry deleted":   lines[0] + lines[2],
		"first entry deleted":    lines[1] + lines[2],
		"entries swapped":        lines[0] + lines[2] + lines[1],
		"entry duplicated":       lines[0] + lines[1] + lines[1] + lines[2],
		"garbage line appended":  string(b) + "not json\n",
		"garbage line in middle": lines[0] + "not json\n" + lines[1] + lines[2],
		"torn last line":         string(b)[:len(b)-9],
		"no final newline":       strings.TrimSuffix(string(b), "\n"),
		"CRLF line ends":         strings.ReplaceAll(string(b), "\n", "\r\n"),
		"blank line":             lines[0] + "\n" + lines[1] + lines[2],
		"NUL bytes":              string(b) + "\x00\x00\x00",
		"a JSON array":           "[" + strings.TrimSuffix(string(b), "\n") + "]\n",
		"last entry rewritten with a valid-looking self": strings.Replace(lines[2], string(e[2].Self), string(hX), 1) + "",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "x.log")
			os.WriteFile(p, []byte(content), 0o600)
			r := evidence(t, tl, "-applylog", "p-1="+p)
			wantFlag(t, r, name, "log")
			// and the offline verifier agrees
			v := runIn(t, buildCtl(t), t.TempDir(), nil, "", "verify-applylog", "-in", p)
			sane(t, v)
			if v.code != 1 {
				t.Errorf("verify-applylog on %s: exit %d, want 1\n%s%s", name, v.code, v.stdout, v.stderr)
			}
			if !hasCJK(v.stdout + v.stderr) {
				t.Errorf("verify-applylog failure is not in Japanese too: %s%s", v.stdout, v.stderr)
			}
		})
	}
}

func TestEvidenceApplylogArgumentShapes(t *testing.T) {
	d := t.TempDir()
	p, e := threeEntryLog(t, d, "p.log")
	p2, _ := threeEntryLog(t, d, "q.log")
	tl := wire.TimelineView{Entries: []wire.TimelineEntry{te("p-1", 7, hC, t0, t0+1, &e[2])}}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	big := filepath.Join(d, "big.log")
	if f, err := os.Create(big); err == nil {
		f.Truncate(65 << 20) // over the 64 MiB cap (T-D7), all NULs
		f.Close()
	}
	link := filepath.Join(d, "link.log")
	os.Symlink(p, link)
	empty := filepath.Join(d, "empty.log")
	os.WriteFile(empty, nil, 0o600)
	bad := map[string]string{
		"no equals sign":       "p-1",
		"empty id":             "=" + p,
		"empty file name":      "p-1=",
		"missing file":         "p-1=" + filepath.Join(d, "nope"),
		"directory":            "p-1=" + d,
		"fifo (must not hang)": "p-1=" + fifo,
		"over 64 MiB":          "p-1=" + big,
		"uppercase id":         "P-1=" + p,
		"escape in id":         "p-1\x1b[31m=" + p,
		"newline in id":        "p-1\nFLAG fake=" + p,
		"id with spaces":       "p 1=" + p,
		"id too long":          strings.Repeat("a", 64) + "=" + p,
		"unicode id":           "プロキシ=" + p,
	}
	for name, arg := range bad {
		t.Run(name, func(t *testing.T) {
			r := evidence(t, tl, "-applylog", arg)
			if r.code == 0 {
				t.Errorf("exit 0 for -applylog %q\n%s", arg, r.stdout)
			}
			if r.code != 1 && r.code != 2 {
				t.Errorf("exit %d, want 1 or 2", r.code)
			}
			if strings.Contains(r.stdout, "no mismatch found") {
				t.Errorf("a bad -applylog argument ended in a clean verdict")
			}
			if strings.Contains(r.stdout+r.stderr, "\nFLAG fake") {
				t.Errorf("a hostile id forged a FLAG line")
			}
		})
	}
	t.Run("duplicate proxy id", func(t *testing.T) {
		r := evidence(t, tl, "-applylog", "p-1="+p, "-applylog", "p-1="+p2)
		if r.code == 0 {
			t.Errorf("two logs for one proxy were accepted silently\n%s", r.stdout)
		}
	})
	t.Run("an empty log cannot back a timeline with anchors", func(t *testing.T) {
		wantFlag(t, evidence(t, tl, "-applylog", "p-1="+empty), "empty log")
	})
	t.Run("a log for a proxy the control plane never saw", func(t *testing.T) {
		wantFlag(t, evidence(t, tl, "-applylog", "p-1="+p, "-applylog", "p-9="+p), "unknown proxy log (T-D7)")
	})
	t.Run("a proxy without a supplied log is not an error", func(t *testing.T) {
		two := wire.TimelineView{Entries: []wire.TimelineEntry{te("p-1", 7, hC, t0, t0+1, &e[2]), te("p-2", 7, hC, t0, t0+1, nil)}}
		wantClean(t, evidence(t, two, "-applylog", "p-1="+p), "p-2 has no log")
	})
	t.Run("symlink to a regular file: refused or read, never a crash", func(t *testing.T) {
		r := evidence(t, tl, "-applylog", "p-1="+link)
		if r.code != 0 && r.code != 1 && r.code != 2 {
			t.Errorf("exit %d", r.code)
		}
		if r.code == 0 && len(flagLines(r.stdout)) != 0 {
			t.Errorf("exit 0 with flags")
		}
	})
	t.Run("-out writes the report, flags included, and exit stays 1", func(t *testing.T) {
		out := filepath.Join(t.TempDir(), "report.txt")
		bad := wire.TimelineView{Entries: []wire.TimelineEntry{te("p-1", 6, hC, t0, t0+1, &e[2])}}
		r := evidence(t, bad, "-applylog", "p-1="+p, "-out", out)
		if r.code != 1 {
			t.Errorf("exit %d, want 1", r.code)
		}
		b, err := os.ReadFile(out)
		if err != nil || !strings.Contains(string(b), "FLAG") || !strings.Contains(string(b), "JST") {
			t.Errorf("report file: %v %q", err, clip(string(b)))
		}
		if st, err := os.Stat(out); err == nil && st.Mode().Perm()&0o022 != 0 {
			t.Errorf("report file mode %v is group/world writable", st.Mode().Perm())
		}
	})
}

// ---- Dropped (M-D55, T-D8) ----

func TestEvidenceDropped(t *testing.T) {
	d := t.TempDir()
	p, e := threeEntryLog(t, d, "p.log")
	es := []wire.TimelineEntry{te("p-1", 7, hC, t0, t0+1, &e[2])}
	t.Run("a count is a WARNING, exit 0, number shown, bilingual", func(t *testing.T) {
		r := evidence(t, wire.TimelineView{Entries: es, Dropped: map[wire.ID]uint64{"p-1": 12}}, "-applylog", "p-1="+p)
		if r.code != 0 || len(flagLines(r.stdout)) != 0 {
			t.Errorf("dropped made a verdict: exit %d flags %q", r.code, flagLines(r.stdout))
		}
		if !strings.Contains(r.stdout, "WARNING") || !strings.Contains(r.stdout, "12") || !hasCJK(r.stdout) {
			t.Errorf("no bilingual WARNING with the count\n%s", r.stdout)
		}
		if !strings.Contains(r.stdout, "p-1") {
			t.Errorf("warning does not say which proxy")
		}
	})
	t.Run("a dropped warning does not hide a mismatch", func(t *testing.T) {
		bad := []wire.TimelineEntry{te("p-1", 6, hC, t0, t0+1, &e[2])}
		r := evidence(t, wire.TimelineView{Entries: bad, Dropped: map[wire.ID]uint64{"p-1": 3}}, "-applylog", "p-1="+p)
		wantFlag(t, r, "mismatch with a dropped count")
		if !strings.Contains(r.stdout, "WARNING") {
			t.Errorf("warning lost when a mismatch is present")
		}
	})
	t.Run("zero is left out", func(t *testing.T) {
		r := evidence(t, wire.TimelineView{Entries: es, Dropped: map[wire.ID]uint64{"p-1": 0}}, "-applylog", "p-1="+p)
		if r.code != 0 || strings.Contains(r.stdout, "WARNING") {
			t.Errorf("a zero count produced a warning: exit %d\n%s", r.code, r.stdout)
		}
	})
	t.Run("the largest count prints exactly or is refused", func(t *testing.T) {
		r := evidence(t, wire.TimelineView{Entries: es, Dropped: map[wire.ID]uint64{"p-1": ^uint64(0)}}, "-applylog", "p-1="+p)
		if r.code == 0 && !strings.Contains(r.stdout, "18446744073709551615") {
			t.Errorf("max uint64 printed wrongly\n%s", r.stdout)
		}
	})
	t.Run("dropped for a proxy not in the timeline", func(t *testing.T) {
		r := evidence(t, wire.TimelineView{Entries: es, Dropped: map[wire.ID]uint64{"p-9": 2}}, "-applylog", "p-1="+p)
		if r.code != 0 && r.code != 1 {
			t.Errorf("exit %d", r.code)
		}
	})
	// raw answers that wire.Decode must refuse, before anything is printed (T-D4, T-D8)
	raws := map[string]string{
		"negative":          `{"p-1":-1}`,
		"string":            `{"p-1":"12"}`,
		"float":             `{"p-1":1.5}`,
		"null":              `{"p-1":null}`,
		"bare number":       `12`,
		"array":             `[1,2]`,
		"hostile id":        `{"p-1\u001b[31m":3}`,
		"uppercase id":      `{"P-1":3}`,
		"newline id":        `{"p-1\nFLAG fake":3}`,
		"overflow":          `{"p-1":18446744073709551616}`,
		"duplicate id keys": `{"p-1":1,"p-1":2}`,
		"empty id":          `{"":1}`,
	}
	for name, raw := range raws {
		t.Run("refused: "+name, func(t *testing.T) {
			bin := buildCtl(t)
			body := fmt.Sprintf(`{"tenant":"bank-a","entries":[],"dropped":%s}`, raw)
			cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) {
				w.Header().Set("Content-Type", wire.ContentTypeJSON)
				_, _ = w.Write([]byte(body))
			})
			r := runIn(t, bin, t.TempDir(), connEnv(tok), "", "evidence", "export", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
			sane(t, r)
			if r.code == 0 {
				t.Errorf("exit 0 for dropped=%s\n%s", raw, r.stdout)
			}
			if r.stdout != "" {
				t.Errorf("something was printed before the answer was refused: %q", clip(r.stdout))
			}
		})
	}
}

// ---- hostile data in the timeline (a rogue control plane) ----

func TestEvidenceHostileTimeline(t *testing.T) {
	mk := func(f func(x *wire.TimelineEntry)) wire.TimelineView {
		x := te("p-1", 3, hA, t0, t0+1, nil)
		f(&x)
		return wire.TimelineView{Entries: []wire.TimelineEntry{x}}
	}
	cases := map[string]wire.TimelineView{
		"escape in proxy id":    mk(func(x *wire.TimelineEntry) { x.ProxyID = "p-1\x1b]0;pwn\x07" }),
		"newline in proxy id":   mk(func(x *wire.TimelineEntry) { x.ProxyID = "p-1\nFLAG forged" }),
		"uppercase proxy id":    mk(func(x *wire.TimelineEntry) { x.ProxyID = "P-1" }),
		"empty proxy id":        mk(func(x *wire.TimelineEntry) { x.ProxyID = "" }),
		"hash with escape":      mk(func(x *wire.TimelineEntry) { x.PolicyHash = "\x1b[31m" + hA[4:] }),
		"short hash":            mk(func(x *wire.TimelineEntry) { x.PolicyHash = "abcd" }),
		"head not a hash":       mk(func(x *wire.TimelineEntry) { x.LogSeq, x.LogHead = 1, "\x1b[2J" }),
		"seq without head":      mk(func(x *wire.TimelineEntry) { x.LogSeq, x.LogHead = 1, "" }),
		"head without seq":      mk(func(x *wire.TimelineEntry) { x.LogSeq, x.LogHead = 0, hA }),
		"last before first":     mk(func(x *wire.TimelineEntry) { x.FirstSeenUnixMs, x.LastSeenUnixMs = t0+10, t0 }),
		"negative time":         mk(func(x *wire.TimelineEntry) { x.FirstSeenUnixMs = -1 }),
		"time beyond year 9999": mk(func(x *wire.TimelineEntry) { x.LastSeenUnixMs = 1 << 62 }),
		"tenant of another":     {Tenant: "bank-b", Entries: []wire.TimelineEntry{te("p-1", 3, hA, t0, t0+1, nil)}},
	}
	for name, tl := range cases {
		t.Run(name, func(t *testing.T) {
			bin := buildCtl(t)
			if tl.Tenant == "" {
				tl.Tenant = "bank-a"
			}
			cp := newCP(t, false, func(w http.ResponseWriter, r *http.Request, _ []byte) { jsonReply(w, 200, tl) })
			r := runIn(t, bin, t.TempDir(), connEnv(tok), "", "evidence", "export", "-tenant", "bank-a", "-url", cp.srv.URL, "-allow-plaintext")
			sane(t, r)
			// A half-set anchor (seq without head or the reverse) cannot come from a proxy (M-D39: an empty log
			// is 0 and ""). The docs do not say refuse or flag, so either is accepted; silence is not.
			if name == "seq without head" || name == "head without seq" {
				if r.code != 1 || (r.stdout != "" && len(flagLines(r.stdout)) == 0) {
					t.Errorf("half-set anchor passed silently: exit %d\n%s", r.code, r.stdout)
				}
				return
			}
			if r.code == 0 {
				t.Errorf("exit 0 for a malformed timeline\n%s", r.stdout)
			}
			if r.stdout != "" {
				t.Errorf("printed before refusing: %q", clip(r.stdout))
			}
		})
	}
}

// ---- verify-applylog ----

// The offline verifier must agree with the library on every one-byte change and every prefix of a real log.
func TestVerifyApplylogAgreesWithLibrary(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	p, _ := mkLog(t, d, "base.log",
		applylog.Entry{From: 0, To: 3, Hash: hA},
		applylog.Entry{From: 3, To: 5, Hash: hB, Result: wire.ErrBadRequest},
		applylog.Entry{From: 3, To: 7, Hash: hC},
	)
	b, _ := os.ReadFile(p)
	check := func(name string, content []byte) {
		f := filepath.Join(d, "t.log")
		os.WriteFile(f, content, 0o600)
		_, _, lerr := applylog.Verify(bytes.NewReader(content))
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", f)
		sane(t, r)
		if (lerr == nil) != (r.code == 0) {
			t.Errorf("%s: library error=%v but kairanctl exit %d\n%s%s", name, lerr, r.code, r.stdout, r.stderr)
		}
		if r.code != 0 && r.code != 1 {
			t.Errorf("%s: exit %d, want 0 or 1", name, r.code)
		}
	}
	check("intact", b)
	check("empty", nil)
	for n := 1; n < len(b); n += 3 {
		check(fmt.Sprintf("prefix %d", n), b[:n])
	}
	for i := 0; i < len(b); i += 5 {
		for _, x := range []byte{0x01, 0x20} {
			c := append([]byte(nil), b...)
			c[i] ^= x
			check(fmt.Sprintf("byte %d ^ %#x", i, x), c)
		}
	}
	// whole-line cuts are valid chains: the verifier says so, and says how many entries (so an admin sees the count)
	lines := bytes.SplitAfter(b, []byte("\n"))
	check("two of three lines", bytes.Join(lines[:2], nil))
}

func TestVerifyApplylogOutputAndUsage(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	p, e := threeEntryLog(t, d, "p.log")
	t.Run("valid log: counts, last seq, full head, JST and UTC", func(t *testing.T) {
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", p)
		sane(t, r)
		if r.code != 0 {
			t.Fatalf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
		for _, w := range []string{"3 entries", "seq 3", string(e[2].Self), "JST", "UTC", "2026-01-01 09:03:00 JST", "2026-01-01 00:03:00 UTC"} {
			if !strings.Contains(r.stdout, w) {
				t.Errorf("output lacks %q\n%s", w, r.stdout)
			}
		}
	})
	t.Run("empty log is valid", func(t *testing.T) {
		f := filepath.Join(d, "empty.log")
		os.WriteFile(f, nil, 0o600)
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", f)
		sane(t, r)
		if r.code != 0 || !strings.Contains(r.stdout, "0 entries") {
			t.Errorf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
	})
	t.Run("no -in is a usage error (2)", func(t *testing.T) {
		r := runIn(t, bin, d, nil, "", "verify-applylog")
		sane(t, r)
		if r.code != 2 {
			t.Errorf("exit %d, want 2", r.code)
		}
	})
	t.Run("-in with an empty value is a usage error (2)", func(t *testing.T) {
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", "")
		sane(t, r)
		if r.code != 2 {
			t.Errorf("exit %d, want 2", r.code)
		}
	})
	t.Run("unknown flag is a usage error (2)", func(t *testing.T) {
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", p, "-x")
		sane(t, r)
		if r.code != 2 {
			t.Errorf("exit %d, want 2", r.code)
		}
	})
	t.Run("missing file, directory, fifo", func(t *testing.T) {
		fifo := filepath.Join(d, "ff")
		_ = syscall.Mkfifo(fifo, 0o600)
		for _, f := range []string{filepath.Join(d, "nope"), d, fifo} {
			r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", f)
			sane(t, r)
			if r.code != 1 {
				t.Errorf("%s: exit %d, want 1\n%s%s", f, r.code, r.stdout, r.stderr)
			}
		}
	})
	t.Run("the log is not modified", func(t *testing.T) {
		before, _ := os.ReadFile(p)
		runIn(t, bin, d, nil, "", "verify-applylog", "-in", p)
		after, _ := os.ReadFile(p)
		if !bytes.Equal(before, after) {
			t.Errorf("verify-applylog changed the file")
		}
	})
	t.Run("failure names the problem in English and Japanese and prints no log content", func(t *testing.T) {
		f := filepath.Join(d, "bad.log")
		os.WriteFile(f, []byte("SECRETLINE-xyz\n"), 0o600)
		r := runIn(t, bin, d, nil, "", "verify-applylog", "-in", f)
		sane(t, r)
		if r.code != 1 || !hasCJK(r.stdout+r.stderr) {
			t.Errorf("exit %d\n%s%s", r.code, r.stdout, r.stderr)
		}
		if strings.Contains(r.stdout+r.stderr, "SECRETLINE") {
			t.Errorf("file content echoed in the error (the line is attacker-controlled)")
		}
	})
	t.Run("no network, no token needed", func(t *testing.T) {
		r := runIn(t, bin, d, []string{"KCTL_CP_URL=http://127.0.0.1:1"}, "", "verify-applylog", "-in", p)
		if r.code != 0 {
			t.Errorf("exit %d with an unreachable CP configured\n%s%s", r.code, r.stdout, r.stderr)
		}
	})
}
