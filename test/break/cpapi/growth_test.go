package cpapibreak

import (
	"encoding/json"
	"testing"
	"time"

	"kairan/internal/wire"
)

// A single enrolled (authenticated) proxy must not be able to grow the control plane's state without
// bound by alternating its reported log anchor (THREATS: status spoofing and DoS, M-D9). With the
// Q-D15 ruling every backwards anchor starts a timeline entry, so flipping 9, 3, 9, 3 creates one
// entry per report. ARCHITECTURE sets no explicit cap; the most defensible reading is that some bound
// exists, otherwise one compromised proxy fills the disk and the evidence export.
func TestTimelineGrowthIsBounded(t *testing.T) {
	e := newEnv(t)
	const posts = 3000
	for i := 0; i < posts; i++ {
		r := report("bank-a", "p1", 1, uint64(i+1))
		if i%2 == 0 {
			r.LogSeq, r.LogHead = 9, hashOf([]byte("h9"))
		} else {
			r.LogSeq, r.LogHead = 3, hashOf([]byte("h3"))
		}
		if res := e.status("p1", r); res.code != 204 {
			t.Fatalf("status %d: %d %s", i, res.code, res.body)
		}
		e.clk.Advance(time.Second)
	}
	r := e.do("GET", wire.PathTimeline+"?tenant=bank-a", adminTok, nil)
	if r.code != 200 {
		t.Fatalf("%d", r.code)
	}
	var tv wire.TimelineView
	if err := json.Unmarshal(r.body, &tv); err != nil {
		t.Fatal(err)
	}
	t.Logf("timeline entries after %d alternating reports: %d (%d bytes)", posts, len(tv.Entries), len(r.body))
	if len(tv.Entries) >= posts/2 {
		t.Fatalf("one proxy produced %d timeline entries from %d status posts: unbounded growth", len(tv.Entries), posts)
	}
}
