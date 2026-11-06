package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

const m1Dwell = 5 // canary dwell, seconds; excluded from the main stage

// stageSamples are the ack latencies of one batch of rollouts, in ms.
type stageSamples struct {
	canary, main []float64
	// from the control plane's own log (when the container is known): how long after canary ack + dwell it decided
	// to promote, and how long the mains took to ack after that decision
	promoteDelay, afterPromote []float64
}

var rePromote = regexp.MustCompile(`"time":"([^"]+)".*"msg":"rollout phase changed","tenant":"([^"]+)","version":(\d+),"phase":"promoting"`)

// promoteTimes reads the control plane container's log for "promoting" lines since `since` (unix ms by log time).
func promoteTimes(container string, since time.Time) map[string]int64 {
	out, err := docker("logs", "--since", since.Add(-time.Second).UTC().Format(time.RFC3339Nano), container)
	res := map[string]int64{}
	if err != nil {
		return res
	}
	for _, ln := range strings.Split(out, "\n") {
		m := rePromote.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, m[1])
		if err != nil {
			continue
		}
		res[m[2]+"/"+m[3]] = t.UnixMilli()
	}
	return res
}

// m1Round publishes one new version for each given tenant on cp and returns the per-stage latencies, taken from
// the control plane's own timeline (first time each proxy reported the version, control-plane clock; the host
// and the containers share one kernel clock). Stage 1 = publish -> canary ack. Stage 2 = main ack minus
// (the last canary ack + dwell): the dwell is excluded, as the PRD says.
func (w *world) m1Round(c *cpc, cpContainer string, tenantList []string, canaryOf func(tenant string) []string, mainOf func(tenant string) []string, limit time.Duration) (stageSamples, error) {
	var s stageSamples
	type pub struct {
		tenant string
		v      uint64
		t0     time.Time
	}
	var pubs []pub
	for _, tn := range tenantList {
		v, t0, err := w.release(c, tn, m1Dwell)
		if err != nil {
			return s, err
		}
		pubs = append(pubs, pub{tn, v, t0})
	}
	for _, p := range pubs {
		c.waitAcked(p.tenant, p.v, nil, limit)
	}
	var promoted map[string]int64
	if cpContainer != "" {
		time.Sleep(300 * time.Millisecond) // let the control plane log the end of the rollout
		promoted = promoteTimes(cpContainer, pubs[0].t0)
	}
	for _, p := range pubs {
		fs, err := c.firstSeen(p.tenant, p.v)
		if err != nil {
			return s, err
		}
		var lastCanary int64
		for _, id := range canaryOf(p.tenant) {
			t, ok := fs[id]
			if !ok {
				return s, fmt.Errorf("%s v%d: no timeline entry for canary %s", p.tenant, p.v, id)
			}
			s.canary = append(s.canary, float64(t-p.t0.UnixMilli()))
			if t > lastCanary {
				lastCanary = t
			}
		}
		mainStart := lastCanary + int64(m1Dwell*1000)
		pt, havePT := promoted[fmt.Sprintf("%s/%d", p.tenant, p.v)]
		if havePT {
			s.promoteDelay = append(s.promoteDelay, float64(pt-mainStart))
		}
		for _, id := range mainOf(p.tenant) {
			t, ok := fs[id]
			if !ok {
				return s, fmt.Errorf("%s v%d: no timeline entry for %s", p.tenant, p.v, id)
			}
			s.main = append(s.main, float64(t-mainStart))
			if havePT {
				s.afterPromote = append(s.afterPromote, float64(t-pt))
			}
		}
	}
	return s, nil
}

func realCanary(tenant string) []string {
	var out []string
	for _, p := range tenantProxies(tenant) {
		if p.Group == "canary" {
			out = append(out, p.ID)
		}
	}
	return out
}

func realMain(tenant string) []string {
	var out []string
	for _, p := range tenantProxies(tenant) {
		if p.Group == "main" {
			out = append(out, p.ID)
		}
	}
	return out
}

func stageRun(i int, xs []float64, extra map[string]any) Run {
	st := dist(xs)
	d := map[string]any{"samples_ms": xs}
	for k, v := range extra {
		d[k] = v
	}
	return Run{Index: i, N: len(xs), Stats: st, Detail: d}
}

// M1 with the 10 real proxies of the compose stack.
func (w *world) benchM1Real() {
	logf("M1 propagation, 10 REAL proxies: %d runs x %d rounds, dwell %ds", w.o.runs, w.o.rounds, m1Dwell)
	canary := Result{ID: "M1-real-canary", Metric: "M1", Title: "Propagation, publish to canary ack (10 real proxies)", Unit: "ms", Judge: "p99", Cmp: "<=", Target: 1000,
		Notes: "Per run: 2 tenants x rounds publishes; each sample is publish (host clock) to the canary's first status report with the new version (control-plane clock, same kernel clock)."}
	mainR := Result{ID: "M1-real-main", Metric: "M1", Title: "Propagation, main group ack after the canary dwell (10 real proxies)", Unit: "ms", Judge: "p99", Cmp: "<=", Target: 1000,
		Notes: "Per run: 8 main proxies x rounds. Sample = main ack minus (last canary ack + 5 s dwell); the dwell is excluded as PRD M1 says."}
	delay := Result{ID: "M1-real-main-decision-delay", Metric: "M1", Unit: "ms", Judge: "p99", Cmp: "info",
		Title: "Where the main-stage time goes (10 real proxies), part 1: from the end of the canary dwell to the control plane's decision to promote",
		Notes: "From the control plane's own log line `rollout phase changed ... promoting`, minus (last canary ack + dwell). Informational: it is part of the main-stage number above, split out to show where the time is spent."}
	after := Result{ID: "M1-real-main-apply-after-promote", Metric: "M1", Unit: "ms", Judge: "p99", Cmp: "info",
		Title: "Where the main-stage time goes (10 real proxies), part 2: from the promote decision to each main proxy's ack",
		Notes: "Main ack (control-plane clock) minus the `promoting` log time. Informational."}
	for _, tn := range tenants {
		w.cp.syncVersion(tn)
	}
	for i := 1; i <= w.o.runs; i++ {
		w.baseline()
		var all stageSamples
		for r := 0; r < w.o.rounds; r++ {
			s, err := w.m1Round(w.cp, "kairan-cp", tenants, realCanary, realMain, 90*time.Second)
			if err != nil {
				fatalf("M1 real run %d: %v", i, err)
			}
			all.canary = append(all.canary, s.canary...)
			all.main = append(all.main, s.main...)
			all.promoteDelay = append(all.promoteDelay, s.promoteDelay...)
			all.afterPromote = append(all.afterPromote, s.afterPromote...)
		}
		canary.Runs = append(canary.Runs, stageRun(i, all.canary, nil))
		mainR.Runs = append(mainR.Runs, stageRun(i, all.main, nil))
		delay.Runs = append(delay.Runs, stageRun(i, all.promoteDelay, nil))
		after.Runs = append(after.Runs, stageRun(i, all.afterPromote, nil))
		logf("M1 real run %d: canary p99 %.0f ms (n=%d), main p99 %.0f ms (n=%d)", i, percentile(all.canary, .99), len(all.canary), percentile(all.main, .99), len(all.main))
	}
	w.o.save(canary)
	w.o.save(mainR)
	w.o.save(delay)
	w.o.save(after)
}
