package cpwebbreak

import (
	"strings"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

// The page on top of the real file store: a halted-after-promoting rollout (M-D44, C-D6) must
// survive the store and still show the promoted desired version for every group.
func TestPageOnRealStoreShowsPromotedHaltedDesired(t *testing.T) {
	st, err := store.OpenFiles(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r := rollout.Rollout{Tenant: "bank-a", Version: 4242, Previous: 41, Phase: wire.PhaseHalted, Reason: wire.ErrThreshold, Promoted: true, Dwell: time.Minute}
	if err := st.PutRollout(r); err != nil {
		t.Fatal(err)
	}
	for _, l := range []fleet.Last{
		lastOf("bank-a", "main-ok", "main", wire.StateEnforcing, 41, now0.Add(-time.Second)),
		lastOf("bank-a", "canary-1", "canary", wire.StateEnforcing, 4242, now0.Add(-time.Second)),
	} {
		if err := st.RecordStatus(l); err != nil {
			t.Fatal(err)
		}
	}
	h, _ := newHandler(st)
	for _, l := range []string{"ja", "en"} {
		resp := get(t, h, "/?tenant=bank-a&lang="+l)
		if resp.code != 200 {
			t.Fatalf("%s: %d", l, resp.code)
		}
		row := rowFor(resp.body, "main-ok")
		if !strings.Contains(visibleText(row), "4242") {
			t.Fatalf("%s: main-ok row does not show desired 4242 after a halt-while-promoting: %s", l, visibleText(row))
		}
	}
	if r := get(t, h, "/?tenant=city-b"); r.code >= 500 {
		t.Fatalf("empty tenant: %d", r.code)
	}
}
