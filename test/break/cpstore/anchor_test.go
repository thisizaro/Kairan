package cpstorebreak

import (
	"testing"
	"time"
)

// M-D35 / I6: tail truncation of the apply log shows as a seq/head regression. The store keeps only the
// latest anchor per period, so the higher value is overwritten by the lower one. Awaiting the ruling
// on where regressions are detected.
func TestTimelineKeepsHighestAnchorSeen(t *testing.T) {
	t.Skip("doc ambiguity: Q-D15")
	_, dir := sandbox(t)
	s := open(t, dir)
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(7)), t0))
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(5), withSeq(2, 10)), t0.Add(10*time.Second)))
	tl, _ := s.Timeline("bank-a")
	if len(tl) != 1 || tl[0].LogSeq < 7 {
		t.Fatalf("the evidence of seq 7 was overwritten by a regression to 5: %+v", tl)
	}
}
