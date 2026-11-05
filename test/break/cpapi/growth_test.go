package cpapibreak

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// Ruling Q-D21 (M-D55): the timeline keeps at most 256 entries per proxy; when full the oldest entry
// is dropped, kairan_cp_timeline_dropped_total{tenant} increments, and the timeline response reports
// the dropped count. Under the Q-D15 ruling every backwards log anchor starts a timeline entry, so
// flipping 9, 3, 9, 3 creates one entry per report.

const timelineCap = 256

// flood posts n alternating-anchor reports from one proxy; each one starts a new timeline entry.
// The report's version carries i so each entry is identifiable by its LogSeq-independent order.
func flood(t *testing.T, e *env, proxy string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		r := report("bank-a", proxy, 1, uint64(i+1))
		// a strictly decreasing anchor is a regression on every report, so each one starts an entry
		r.LogSeq, r.LogHead = uint64(100000-i), hashOf([]byte("h"+strconv.Itoa(i)))
		if res := e.status(proxy, r); res.code != 204 {
			t.Fatalf("status %d: %d %s", i, res.code, res.body)
		}
		e.clk.Advance(time.Second)
	}
}

func getTimeline(t *testing.T, e *env, tenant string) (wire.TimelineView, map[string]json.RawMessage) {
	t.Helper()
	r := e.do("GET", wire.PathTimeline+"?tenant="+tenant, adminTok, nil)
	if r.code != 200 {
		t.Fatalf("timeline %d %s", r.code, r.body)
	}
	var tv wire.TimelineView
	if err := json.Unmarshal(r.body, &tv); err != nil {
		t.Fatal(err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(r.body, &raw); err != nil {
		t.Fatal(err)
	}
	return tv, raw
}

// droppedIn reads the per-proxy dropped counts the timeline response reports (M-D56:
// wire.TimelineView.Dropped, map[ID]uint64 `json:"dropped,omitempty"`, omitted when nothing was dropped).
// It decodes the raw key so this file compiles with or without the wire field in the checkout.
func droppedIn(raw map[string]json.RawMessage) (map[string]uint64, bool) {
	v, ok := raw["dropped"]
	if !ok {
		return nil, false
	}
	var m map[string]uint64
	if err := json.Unmarshal(v, &m); err != nil {
		return nil, false
	}
	return m, true
}

func countFor(tv wire.TimelineView, proxy string) int {
	n := 0
	for _, en := range tv.Entries {
		if en.ProxyID == wire.ID(proxy) {
			n++
		}
	}
	return n
}

// Q-D21: at most 256 entries per proxy, the oldest dropped, the count reported and counted in a metric.
func TestTimelineGrowthIsBounded(t *testing.T) {
	e := newEnv(t)
	const posts = timelineCap + 44
	flood(t, e, "p1", posts)
	tv, raw := getTimeline(t, e, "bank-a")
	if got := countFor(tv, "p1"); got != timelineCap {
		t.Fatalf("p1 has %d timeline entries after %d entry-starting reports; Q-D21 caps at exactly %d", got, posts, timelineCap)
	}
	// oldest dropped: the newest report's anchor is the last entry; the first report (seq 9, at t0) is gone.
	var p1 []wire.TimelineEntry
	for _, en := range tv.Entries {
		if en.ProxyID == "p1" {
			p1 = append(p1, en)
		}
	}
	if min := t0.UnixMilli(); p1[0].FirstSeenUnixMs <= min {
		t.Errorf("oldest remaining entry first seen at %d (the very first report): the oldest entries were not the ones dropped", p1[0].FirstSeenUnixMs)
	}
	wantFirst := t0.Add(time.Duration(posts-timelineCap) * time.Second).UnixMilli()
	if p1[0].FirstSeenUnixMs != wantFirst {
		t.Errorf("oldest remaining entry first seen %d, want %d (exactly the %d oldest dropped)", p1[0].FirstSeenUnixMs, wantFirst, posts-timelineCap)
	}
	for i := 1; i < len(p1); i++ {
		if p1[i].FirstSeenUnixMs <= p1[i-1].FirstSeenUnixMs {
			t.Fatalf("timeline not in time order at %d", i)
		}
	}
	want := posts - timelineCap
	if d, ok := droppedIn(raw); !ok {
		t.Errorf("timeline response has no dropped map (keys: %v); Q-D21 and M-D56 require it", keysOf(raw))
	} else if d["p1"] != uint64(want) {
		t.Errorf("timeline dropped[p1] = %d, want %d (map %v)", d["p1"], want, d)
	}
	m := e.metricsText()
	if !metricHasValue(m, "kairan_cp_timeline_dropped_total", `tenant="bank-a"`, want) {
		t.Errorf("kairan_cp_timeline_dropped_total{tenant=\"bank-a\"} %d not found in metrics:\n%s", want, grepLines(m, "timeline"))
	}
}

// Q-D21: exactly at the cap nothing is dropped, and the counter is not present with a nonzero value.
func TestTimelineAtCapDropsNothing(t *testing.T) {
	e := newEnv(t)
	flood(t, e, "p1", timelineCap)
	tv, raw := getTimeline(t, e, "bank-a")
	if got := countFor(tv, "p1"); got != timelineCap {
		t.Fatalf("p1 has %d entries, want %d (nothing dropped at the cap)", got, timelineCap)
	}
	if d, ok := droppedIn(raw); ok && d["p1"] != 0 {
		t.Errorf("dropped[p1] = %d at exactly the cap, want 0 (omitted)", d["p1"])
	}
	for _, ln := range strings.Split(e.metricsText(), "\n") {
		if strings.HasPrefix(ln, "kairan_cp_timeline_dropped_total{") && !strings.HasSuffix(strings.TrimSpace(ln), " 0") {
			t.Errorf("dropped counter nonzero at the cap: %s", ln)
		}
	}
}

// Q-D21: the cap is per proxy; one flooding proxy must not evict another proxy's history, nor another
// tenant's.
func TestTimelineCapIsPerProxy(t *testing.T) {
	e := newEnv(t)
	if res := e.status("p2", report("bank-a", "p2", 1, 1)); res.code != 204 {
		t.Fatalf("p2 status %d", res.code)
	}
	if res := e.status("q1", report("bank-b", "q1", 1, 1)); res.code != 204 {
		t.Fatalf("q1 status %d", res.code)
	}
	flood(t, e, "p1", timelineCap+20)
	tv, _ := getTimeline(t, e, "bank-a")
	if got := countFor(tv, "p2"); got != 1 {
		t.Errorf("p2 has %d entries after p1 flooded; its own entry must survive", got)
	}
	tvb, _ := getTimeline(t, e, "bank-b")
	if got := countFor(tvb, "q1"); got != 1 {
		t.Errorf("bank-b q1 has %d entries after bank-a flood, want 1", got)
	}
	// the metric is labelled per tenant: bank-b is untouched
	for _, ln := range strings.Split(e.metricsText(), "\n") {
		if strings.HasPrefix(ln, "kairan_cp_timeline_dropped_total{") && strings.Contains(ln, `tenant="bank-b"`) && !strings.HasSuffix(strings.TrimSpace(ln), " 0") {
			t.Errorf("bank-b dropped counter moved: %s", ln)
		}
	}
}

func keysOf(m map[string]json.RawMessage) []string {
	var ks []string
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

func grepLines(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func metricHasValue(text, name, label string, want int) bool {
	for _, ln := range strings.Split(text, "\n") {
		if strings.HasPrefix(ln, name+"{") && strings.Contains(ln, label) {
			f := strings.Fields(ln)
			if len(f) >= 2 {
				v, err := strconv.ParseFloat(f[len(f)-1], 64)
				if err == nil && int(v) == want {
					return true
				}
			}
		}
	}
	return false
}
