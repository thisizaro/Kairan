package e2e

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// traffic is a pool of agents sending a fixed mix of allowed and forbidden tools/call requests through a set
// of proxies. Every answer is checked against the oracle wantAllowed for the policy version in force.
type traffic struct {
	w        *world
	hc       *http.Client
	targets  []px
	version  uint64
	stop     chan struct{}
	wg       sync.WaitGroup
	total    atomic.Int64
	okAllow  atomic.Int64 // allowed calls that were expected to be allowed
	okDeny   atomic.Int64 // blocked calls that were expected to be blocked
	wrongYes atomic.Int64 // allowed but forbidden: a permission leak (I3)
	wrongNo  atomic.Int64 // blocked but should be allowed
	netErr   atomic.Int64
	mu       sync.Mutex
	samples  []string
}

func (w *world) startTraffic(targets []px, workers int, version uint64) *traffic {
	// no keep-alive, so a restarted proxy never meets a stale connection
	tr := &traffic{w: w, targets: targets, version: version, stop: make(chan struct{}),
		hc: &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}}
	for i := 0; i < workers; i++ {
		tr.wg.Add(1)
		go func(seed int64) {
			defer tr.wg.Done()
			rng := rand.New(rand.NewSource(seed))
			for {
				select {
				case <-tr.stop:
					return
				default:
				}
				p := tr.targets[rng.Intn(len(tr.targets))]
				c := callMix[rng.Intn(len(callMix))]
				res := tr.w.callWith(tr.hc, p, tr.w.keyFor(c.role), c.tool)
				tr.total.Add(1)
				want := wantAllowed(c.role, c.tool, tr.version)
				switch {
				case res.Err != nil:
					tr.netErr.Add(1)
					tr.note(fmt.Sprintf("transport error on %s %s/%s: %v", p.ID, c.role, c.tool, res.Err))
				case res.Allowed && !want:
					tr.wrongYes.Add(1)
					tr.note(fmt.Sprintf("WRONGLY ALLOWED on %s: %s/%s (policy v%d): %.120s", p.ID, c.role, c.tool, tr.version, res.Text))
				case !res.Allowed && want:
					tr.wrongNo.Add(1)
					tr.note(fmt.Sprintf("wrongly blocked on %s: %s/%s (policy v%d): HTTP %d %.120s", p.ID, c.role, c.tool, tr.version, res.HTTP, res.Text))
				case res.Allowed:
					tr.okAllow.Add(1)
				default:
					tr.okDeny.Add(1)
				}
				time.Sleep(time.Millisecond)
			}
		}(int64(i) + time.Now().UnixNano())
	}
	return tr
}

func (tr *traffic) note(s string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.samples) < 8 {
		tr.samples = append(tr.samples, s)
	}
}

// halt stops the agents and returns a snapshot.
func (tr *traffic) halt() {
	close(tr.stop)
	tr.wg.Wait()
}

// check fails the test on any permission leak or (when strict) any blocked-but-allowed call or transport error.
func (tr *traffic) check(t *testing.T, strict bool, minCalls int64) {
	t.Helper()
	t.Logf("traffic: %d calls: %d allowed as expected, %d blocked as expected, %d wrongly allowed, %d wrongly blocked, %d transport errors",
		tr.total.Load(), tr.okAllow.Load(), tr.okDeny.Load(), tr.wrongYes.Load(), tr.wrongNo.Load(), tr.netErr.Load())
	for _, s := range tr.samples {
		t.Logf("  sample: %s", s)
	}
	if tr.wrongYes.Load() != 0 {
		t.Errorf("I3 violated: %d calls were allowed that the policy forbids", tr.wrongYes.Load())
	}
	if strict && tr.wrongNo.Load() != 0 {
		t.Errorf("fail-static violated: %d calls the policy allows were blocked", tr.wrongNo.Load())
	}
	if strict && tr.netErr.Load() != 0 {
		t.Errorf("%d transport errors talking to proxies that should be up", tr.netErr.Load())
	}
	if tr.total.Load() < minCalls {
		t.Errorf("only %d calls were made, wanted at least %d", tr.total.Load(), minCalls)
	}
	if tr.okAllow.Load() == 0 {
		t.Errorf("no allowed call succeeded: the proxies did not keep serving")
	}
}
