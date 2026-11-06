// Command results writes RESULTS.md from bench/out (PLAN Q-07).
//
//	go run ./bench/results [-in bench/out] [-o RESULTS.md]
//
// It decides pass or fail itself from the raw per-run values written by bench/run: a metric passes only if every
// run is within its target. Spread is min and max over runs. Anything measured with kairan-sim is labelled
// SIMULATED. A missed target is printed as MISS with the same weight as a pass; nothing is dropped.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Result struct {
	ID        string  `json:"id"`
	Metric    string  `json:"metric"`
	Title     string  `json:"title"`
	Simulated bool    `json:"simulated"`
	Unit      string  `json:"unit"`
	Judge     string  `json:"judge"`
	Cmp       string  `json:"cmp"`
	Target    float64 `json:"target"`
	Runs      []Run   `json:"runs"`
	Notes     string  `json:"notes"`
}

type Run struct {
	Index  int                `json:"run"`
	N      int                `json:"n"`
	Stats  map[string]float64 `json:"stats"`
	Detail map[string]any     `json:"detail"`
}

type Env struct {
	Commit   string `json:"commit"`
	Dirty    bool   `json:"dirty"`
	DirtyWhy string `json:"dirty_files"`
	Date     string `json:"date"`
	CPU      string `json:"cpu"`
	Cores    int    `json:"cores"`
	RAMMB    int    `json:"ram_mb"`
	OS       string `json:"os"`
	Docker   string `json:"docker"`
	Go       string `json:"go"`
	Runs     int    `json:"runs"`
	Rounds   int    `json:"rounds"`
}

type ChaosT struct {
	Pass              bool `json:"pass"`
	CallsTotal        int  `json:"calls_total"`
	CallsDuringOutage int  `json:"calls_during_outage"`
	WronglyAllowed    int  `json:"wrongly_allowed"`
	WronglyBlocked    int  `json:"wrongly_blocked"`
	BadPolicies       int  `json:"bad_policies"`
	Applied           int  `json:"applied"`
	CanaryHits        int  `json:"canary_hits"`
	Bytes             int  `json:"bytes_scanned"`
	Artifacts         int  `json:"artifacts"`
	CPRequests        int  `json:"cp_requests_captured"`
}

type Chaos struct {
	Runs []struct {
		Index int               `json:"run"`
		Tests map[string]ChaosT `json:"tests"`
	} `json:"runs"`
}

func median(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n == 0 {
		return math.NaN()
	}
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func minmax(xs []float64) (float64, float64) {
	lo, hi := math.Inf(1), math.Inf(-1)
	for _, x := range xs {
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	return lo, hi
}

func num(x float64) string {
	switch {
	case math.IsNaN(x):
		return "n/a"
	case x == math.Trunc(x) && math.Abs(x) < 1e7:
		return fmt.Sprintf("%.0f", x)
	case math.Abs(x) >= 100:
		return fmt.Sprintf("%.0f", x)
	case math.Abs(x) >= 10:
		return fmt.Sprintf("%.1f", x)
	case math.Abs(x) >= 1:
		return fmt.Sprintf("%.2f", x)
	default:
		return fmt.Sprintf("%.3f", x)
	}
}

func (r Result) vals(stat string) []float64 {
	var v []float64
	for _, run := range r.Runs {
		if x, ok := run.Stats[stat]; ok {
			v = append(v, x)
		}
	}
	return v
}

func (r Result) within(x float64) bool {
	switch r.Cmp {
	case "<=":
		return x <= r.Target
	case "==":
		return x == r.Target
	}
	return true
}

// verdict returns "PASS", "MISS" or "INFO" and the "k of n runs within target" text.
func (r Result) verdict() (string, string) {
	if r.Cmp == "info" {
		return "INFO", "no target"
	}
	v := r.vals(r.Judge)
	ok := 0
	for _, x := range v {
		if r.within(x) {
			ok++
		}
	}
	text := fmt.Sprintf("%d of %d runs within target", ok, len(v))
	if len(v) == 0 {
		return "MISS", "no data"
	}
	if ok == len(v) {
		return "PASS", text
	}
	return "MISS", text
}

func (r Result) targetText() string {
	switch r.Cmp {
	case "<=":
		return fmt.Sprintf("%s <= %s %s", r.Judge, num(r.Target), r.Unit)
	case "==":
		return fmt.Sprintf("%s = %s", r.Judge, num(r.Target))
	}
	return "none (informational)"
}

func (r Result) title() string {
	t := r.Title
	if r.Simulated && !strings.Contains(t, "SIMULATED") {
		t = "SIMULATED: " + t
	}
	return t
}

func main() {
	in := flag.String("in", "bench/out", "bench/run output directory")
	out := flag.String("o", "RESULTS.md", "file to write")
	flag.Parse()

	var env Env
	if b, err := os.ReadFile(filepath.Join(*in, "env.json")); err != nil {
		fmt.Fprintln(os.Stderr, "results: no env.json in", *in, "(run `make bench` first):", err)
		os.Exit(1)
	} else if err := json.Unmarshal(b, &env); err != nil {
		fmt.Fprintln(os.Stderr, "results: env.json:", err)
		os.Exit(1)
	}
	files, _ := filepath.Glob(filepath.Join(*in, "M*.json"))
	var rs []Result
	for _, f := range files {
		var r Result
		b, err := os.ReadFile(f)
		if err == nil {
			err = json.Unmarshal(b, &r)
		}
		if err != nil || r.ID == "" {
			fmt.Fprintln(os.Stderr, "results: skipping unreadable", f, err)
			continue
		}
		rs = append(rs, r)
	}
	if len(rs) == 0 {
		fmt.Fprintln(os.Stderr, "results: no results in", *in)
		os.Exit(1)
	}
	order := func(r Result) string {
		// M1 real, M1 sim100, M1 sim1000, M2, M3, M4, M7
		return r.Metric + "~" + r.ID
	}
	sort.Slice(rs, func(i, j int) bool { return order(rs[i]) < order(rs[j]) })

	var chaos *Chaos
	if b, err := os.ReadFile(filepath.Join(*in, "chaos.json")); err == nil {
		var c Chaos
		if json.Unmarshal(b, &c) == nil {
			chaos = &c
		}
	}

	var sb strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&sb, f, a...) }
	w("# Kairan results\n\n")
	w("Generated by `make results` (`bench/results`) from the raw per-run numbers in `bench/out`, written by `make bench` (`bench/run`). ")
	w("Pass or fail is decided here from those numbers: a metric passes only if **every** run is within its target. ")
	w("A missed target is reported as **MISS**.\n\n")
	if env.Dirty {
		w("> **WARNING: the working tree was dirty when these numbers were measured.** This file is not release evidence; regenerate it from a clean checkout.\n>\n> ```\n")
		for _, l := range strings.Split(strings.TrimSpace(env.DirtyWhy), "\n") {
			w("> %s\n", l)
		}
		w("> ```\n\n")
	}
	minRuns := 0
	for i, r := range rs {
		if i == 0 || len(r.Runs) < minRuns {
			minRuns = len(r.Runs)
		}
	}
	w("## Run\n\n| | |\n|---|---|\n")
	w("| Commit | `%s`%s |\n", env.Commit, map[bool]string{true: " (DIRTY tree)", false: " (clean tree)"}[env.Dirty])
	w("| Date | %s |\n", env.Date)
	w("| CPU | %s |\n", env.CPU)
	w("| Cores | %d (logical, as seen by the host) |\n", env.Cores)
	w("| RAM | %d MB |\n", env.RAMMB)
	w("| OS | %s |\n", env.OS)
	w("| Docker | %s |\n", env.Docker)
	w("| Go | %s |\n", env.Go)
	w("| Runs | %d requested per metric; the fewest runs any row below has: %d |\n", env.Runs, minRuns)
	w("| Rollouts per run (propagation) | %d |\n\n", env.Rounds)
	w("All containers run on one Docker Desktop VM on this one machine, so network numbers are loopback/bridge numbers, not a datacenter's. ")
	w("Rows marked **SIMULATED** used `kairan-sim` (no signature checks, no enforcement) against the real control plane; they say nothing about a real proxy.\n\n")

	w("## Summary\n\n")
	w("Median and spread are over runs of the judged statistic (one value per run); spread is min to max.\n\n")
	w("| Metric | What | Target | Median | Spread (min to max) | Runs | Result |\n|---|---|---|---|---|---|---|\n")
	for _, r := range rs {
		v := r.vals(r.Judge)
		lo, hi := minmax(v)
		verdict, why := r.verdict()
		w("| %s | %s | %s | %s %s | %s to %s | %d | **%s** (%s) |\n", r.Metric, r.title(), r.targetText(), num(median(v)), r.Unit, num(lo), num(hi), len(v), verdict, why)
	}
	// M5, M6, M8 from the chaos scenarios
	chaosRows(&sb, chaos)

	w("\n## Latency detail (median over runs of each run's statistic)\n\n")
	w("| Row | p50 | p95 | p99 | max | samples per run |\n|---|---|---|---|---|---|\n")
	for _, r := range rs {
		if _, ok := r.Runs[0].Stats["p99"]; !ok || (r.Metric != "M1" && r.Metric != "M3") {
			continue
		}
		g := func(s string) string { return num(median(r.vals(s))) }
		w("| %s | %s | %s | %s | %s | %d |\n", r.title(), g("p50"), g("p95"), g("p99"), g("max"), r.Runs[0].N)
	}
	w("\n(milliseconds)\n")

	w("\n## Per-run values of the judged statistic\n\n| Row | per-run values (%s) |\n|---|---|\n", "run 1, 2, ...")
	for _, r := range rs {
		var parts []string
		for _, x := range r.vals(r.Judge) {
			parts = append(parts, num(x))
		}
		w("| %s | %s %s |\n", r.title(), strings.Join(parts, ", "), r.Unit)
	}

	w("\n## Notes per row\n\n")
	for _, r := range rs {
		if r.Notes != "" {
			w("- **%s** (`%s`): %s\n", r.title(), r.ID, r.Notes)
		}
	}
	for _, r := range rs {
		if r.ID == "M7-rss" {
			v, peak := r.vals("rss_hwm_mb"), r.vals("rss_peak_mb")
			_, hi := minmax(v)
			_, hiPeak := minmax(peak)
			w("\n**M7 margin (SIMULATED proxies).** Worst run RSS high-water %s MB against the %s MB limit: %s MB of headroom (%.0f%%); worst sampled peak during the 60 s window %s MB. ",
				num(hi), num(r.Target), num(r.Target-hi), 100*(r.Target-hi)/r.Target, num(hiPeak))
			w("Memory use is within the limit, but the margin is the number to watch when the control plane grows.\n")
		}
	}
	w("\n## Not covered here\n\n")
	w("Only M1, M2, M3, M4 and M7 are measured by `make bench`; M5, M6 and M8 come from the chaos scenarios above (decision M-D66). ")
	w("The k3d run (S11) and the reconnect-storm cap (S13) are not part of this evidence. The 100- and 1,000-proxy rows are simulated. ")
	w("M4's end-to-end latency uses the fake MCP server as the upstream, so it shows the proxy's own overhead, not a real tool server's.\n")

	if err := os.WriteFile(*out, []byte(sb.String()), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "results:", err)
		os.Exit(1)
	}
	fmt.Println("results: wrote", *out)
}

func chaosRows(sb *strings.Builder, c *Chaos) {
	w := func(f string, a ...any) { fmt.Fprintf(sb, f, a...) }
	type row struct{ m, what, target, test string }
	rows := []row{
		{"M5", "Outage correctness (chaos S2: control plane killed mid-traffic)", "0 wrongly allowed", "TestS2ControlPlaneKilledMidTraffic"},
		{"M6", "Bad-policy rejection (chaos S5: unsigned, 1 signature, old version, wrong tenant, expired, corrupted)", "0 applied", "TestS5BadPolicies"},
		{"M8", "Data leakage (chaos S10: canary secrets in captured control-plane traffic)", "0 hits", "TestS10LeakCheck"},
	}
	for _, r := range rows {
		if c == nil || len(c.Runs) == 0 {
			w("| %s | %s | %s | not run | | 0 | **NOT RUN** |\n", r.m, r.what, r.target)
			continue
		}
		pass := 0
		var detail []string
		for _, run := range c.Runs {
			t := run.Tests[r.test]
			ok := t.Pass
			var d string
			switch r.m {
			case "M5":
				ok = ok && t.WronglyAllowed == 0 && t.CallsTotal >= 2000
				d = fmt.Sprintf("%d calls (%d during the outage), %d wrongly allowed, %d wrongly blocked", t.CallsTotal, t.CallsDuringOutage, t.WronglyAllowed, t.WronglyBlocked)
			case "M6":
				ok = ok && t.Applied == 0 && t.BadPolicies > 0
				d = fmt.Sprintf("%d bad policies, %d applied", t.BadPolicies, t.Applied)
			case "M8":
				ok = ok && t.CanaryHits == 0 && t.CPRequests > 0
				d = fmt.Sprintf("%d hits in %d bytes over %d artifacts, %d proxy-to-control-plane requests captured", t.CanaryHits, t.Bytes, t.Artifacts, t.CPRequests)
			}
			if ok {
				pass++
			}
			detail = append(detail, fmt.Sprintf("run %d: scenario %s; %s", run.Index, map[bool]string{true: "passed", false: "FAILED"}[t.Pass], d))
		}
		verdict := "PASS"
		if pass != len(c.Runs) {
			verdict = "MISS"
		}
		w("| %s | %s | %s | %s | n/a (pass/fail) | %d | **%s** (%d of %d runs) |\n", r.m, r.what, r.target, strings.Join(detail, "; "), len(c.Runs), verdict, pass, len(c.Runs))
	}
	w("\nM5, M6 and M8 are pass/fail counts from the chaos scenarios, run %d time(s) here; they are not re-measured by the benchmark loop (decision M-D66).\n", func() int {
		if c == nil {
			return 0
		}
		return len(c.Runs)
	}())
}
