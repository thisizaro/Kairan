package main

import (
	"fmt"
	"sync"
	"time"

	"kairan/internal/wire"
)

// M2 (dead proxy detection) and M3 (catch-up after a network cut) share one fault window per run, on
// different proxies of the 10 REAL ones:
//   - M2: three bank-a mains are killed with `docker kill` (SIGKILL); time from the kill to the control
//     plane showing each one stale, then lost.
//   - M3: three city-b mains are cut off the control plane's network (`docker network disconnect`); once they
//     are lost, a new version is published for both tenants, the three are reconnected, and the time from the
//     reconnect to the control plane seeing each of them on the new version is measured.
//
// The cut proxies stay on their customer network, as in scenario S4.
var (
	m2Victims = []string{"bank-a-main-1", "bank-a-main-2", "bank-a-main-3"}
	m3Victims = []string{"city-b-main-1", "city-b-main-2", "city-b-main-3"}
)

func (w *world) benchM2M3() {
	logf("M2/M3 fault windows on REAL proxies: %d runs (each about 3 minutes: the loss threshold is 131 s)", w.o.runs)
	stale := Result{ID: "M2-stale", Metric: "M2", Title: "Dead proxy: time from docker kill to stale (real proxy)", Unit: "s", Judge: "max", Cmp: "<=", Target: 41,
		Notes: "3 proxies killed per run (SIGKILL); a run's value is the slowest of its 3. Polled every 250 ms (resolution +/-0.25 s)."}
	lost := Result{ID: "M2-lost", Metric: "M2", Title: "Dead proxy: time from docker kill to lost (real proxy)", Unit: "s", Judge: "max", Cmp: "<=", Target: 131,
		Notes: "3 proxies killed per run; a run's value is the slowest of its 3. Polled every 250 ms."}
	catch := Result{ID: "M3-catchup", Metric: "M3", Title: "Network cut: time from reconnect to ack of the version published during the cut (real proxy)", Unit: "ms", Judge: "p99", Cmp: "<=", Target: 6000,
		Notes: "3 proxies cut per run, cut until the control plane showed them lost (about 2 minutes), a new version published for both tenants, then reconnected. Sample = the control plane's first sighting of the new version minus the time `docker network connect` returned."}
	for _, tn := range tenants {
		w.cp.syncVersion(tn)
	}
	for i := 1; i <= w.o.runs; i++ {
		w.baseline()
		killIDs := m2Victims
		cutIDs := m3Victims

		// fault: kill three, cut three
		args := []string{"kill"}
		for _, id := range killIDs {
			args = append(args, proxyByID(id).Container)
		}
		mustDocker(args...)
		tKill := time.Now()
		var wg sync.WaitGroup
		for _, id := range cutIDs {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				mustDocker("network", "disconnect", cloudNet, proxyByID(id).Container)
			}(id)
		}
		wg.Wait()
		tCut := time.Now()

		staleAt := map[string]time.Duration{}
		lostAt := map[string]time.Duration{}
		cutLost := map[string]bool{}
		waitFor(200*time.Second, 250*time.Millisecond, "killed and cut proxies to be lost", func() (bool, string) {
			for _, tn := range tenants {
				fv, err := w.cp.fleet(tn)
				if err != nil {
					return false, err.Error()
				}
				now := time.Now()
				for _, r := range fv.Proxies {
					id := string(r.ProxyID)
					for _, k := range killIDs {
						if k != id {
							continue
						}
						if r.Health == wire.HealthStale || r.Health == wire.HealthLost {
							if _, ok := staleAt[id]; !ok {
								staleAt[id] = now.Sub(tKill)
							}
						}
						if r.Health == wire.HealthLost {
							if _, ok := lostAt[id]; !ok {
								lostAt[id] = now.Sub(tKill)
							}
						}
					}
					for _, k := range cutIDs {
						if k == id && r.Health == wire.HealthLost {
							cutLost[id] = true
						}
					}
				}
			}
			ok := len(lostAt) == len(killIDs) && len(cutLost) == len(cutIDs)
			return ok, fmt.Sprintf("killed lost %d/%d, cut lost %d/%d", len(lostAt), len(killIDs), len(cutLost), len(cutIDs))
		})
		_ = tCut

		var staleS, lostS []float64
		for _, id := range killIDs {
			staleS = append(staleS, staleAt[id].Seconds())
			lostS = append(lostS, lostAt[id].Seconds())
		}

		// publish for both tenants while the three are cut (and the three are dead)
		type pub struct {
			tn string
			v  uint64
		}
		var pubs []pub
		for _, tn := range tenants {
			v, _, err := w.release(w.cp, tn, 2)
			if err != nil {
				fatalf("M3 run %d: %v", i, err)
			}
			pubs = append(pubs, pub{tn, v})
		}
		for _, p := range pubs {
			var others []string
			for _, q := range tenantProxies(p.tn) {
				if contains(killIDs, q.ID) || contains(cutIDs, q.ID) {
					continue
				}
				others = append(others, q.ID)
			}
			w.cp.waitAcked(p.tn, p.v, others, 90*time.Second)
		}

		// reconnect the cut proxies together
		for _, id := range cutIDs {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				mustDocker("network", "connect", cloudNet, proxyByID(id).Container)
			}(id)
		}
		wg.Wait()
		tRe := time.Now()
		var cv uint64
		for _, p := range pubs {
			if p.tn == "city-b" {
				cv = p.v
			}
		}
		w.cp.waitAcked("city-b", cv, cutIDs, 60*time.Second)
		fs, err := w.cp.firstSeen("city-b", cv)
		if err != nil {
			fatalf("M3 run %d: %v", i, err)
		}
		var catchS []float64
		for _, id := range cutIDs {
			t, ok := fs[id]
			if !ok {
				fatalf("M3 run %d: no timeline entry for %s v%d", i, id, cv)
			}
			catchS = append(catchS, float64(t-tRe.UnixMilli()))
		}

		// bring the killed proxies back for the next run
		w.baseline()

		stale.Runs = append(stale.Runs, Run{Index: i, N: len(staleS), Stats: map[string]float64{"max": percentile(staleS, 1), "min": percentile(staleS, 0), "p50": percentile(staleS, .5)}, Detail: map[string]any{"samples_s": staleS}})
		lost.Runs = append(lost.Runs, Run{Index: i, N: len(lostS), Stats: map[string]float64{"max": percentile(lostS, 1), "min": percentile(lostS, 0), "p50": percentile(lostS, .5)}, Detail: map[string]any{"samples_s": lostS}})
		catch.Runs = append(catch.Runs, stageRun(i, catchS, nil))
		logf("M2/M3 run %d: stale %v s, lost %v s, catch-up %v ms", i, fmtVals(staleS), fmtVals(lostS), fmtVals(catchS))
	}
	w.o.save(stale)
	w.o.save(lost)
	w.o.save(catch)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
