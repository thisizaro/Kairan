package cpstorebreak

import (
	"testing"
	"time"
)

// M-D35 / I6, ruling Q-D15 / M-D48: a log_seq that goes backwards for a proxy starts a new timeline
// entry (a regression is its own period), so evidence sees 7 and then 5.
func TestTimelineKeepsHighestAnchorSeen(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	if err := s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(7)), t0)); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(5), withSeq(2, 10)), t0.Add(10*time.Second))); err != nil {
		t.Fatal(err)
	}
	tl, err := s.Timeline("bank-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 2 || tl[0].LogSeq != 7 || tl[1].LogSeq != 5 {
		t.Fatalf("want two entries with log_seq 7 then 5, got %+v", tl)
	}
	if tl[0].LogHead != hx("head-7") || tl[1].LogHead != hx("head-5") {
		t.Fatalf("heads do not follow the seqs: %+v", tl)
	}
}

// The regression record survives a restart of the store (I6: evidence must not depend on memory).
func TestAnchorRegressionSurvivesReopen(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(7)), t0))
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(5), withSeq(2, 10)), t0.Add(10*time.Second)))
	s2 := open(t, dir)
	tl, err := s2.Timeline("bank-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 2 || tl[0].LogSeq != 7 || tl[1].LogSeq != 5 {
		t.Fatalf("after reopen want log_seq 7 then 5, got %+v", tl)
	}
}

// A normal advance (5 then 7 in the same version) stays one period and keeps the latest anchor.
func TestAnchorAdvanceStaysOnePeriod(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(5)), t0))
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withAnchor(7), withSeq(2, 10)), t0.Add(10*time.Second)))
	tl, _ := s.Timeline("bank-a")
	if len(tl) != 1 || tl[0].LogSeq != 7 {
		t.Fatalf("advance must stay in one entry at seq 7, got %+v", tl)
	}
}
