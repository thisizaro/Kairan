package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
)

// Result is one judged number (a "metric line") with one entry per run. bench/results reads these files and
// decides pass or fail itself from the raw per-run values, so a missed target cannot be hidden here.
type Result struct {
	ID        string  `json:"id"`        // e.g. M1-real-canary
	Metric    string  `json:"metric"`    // M1 .. M8
	Title     string  `json:"title"`     // human text
	Simulated bool    `json:"simulated"` // true: proxies were kairan-sim, not real kairan-proxy
	Unit      string  `json:"unit"`
	Judge     string  `json:"judge"`  // the key of Run.Stats that is compared with Target
	Cmp       string  `json:"cmp"`    // "<=" or "=="
	Target    float64 `json:"target"` // in Unit
	Runs      []Run   `json:"runs"`
	Notes     string  `json:"notes,omitempty"`
}

// Run is one repetition of the whole measurement.
type Run struct {
	Index  int                `json:"run"`
	N      int                `json:"n"` // samples behind the stats
	Stats  map[string]float64 `json:"stats"`
	Detail map[string]any     `json:"detail,omitempty"`
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func (o *opts) save(r Result) {
	if err := writeJSON(filepath.Join(o.out, r.ID+".json"), r); err != nil {
		fmt.Fprintln(os.Stderr, "bench: write result:", err)
		os.Exit(1)
	}
	var vals []float64
	for _, run := range r.Runs {
		vals = append(vals, run.Stats[r.Judge])
	}
	fmt.Printf("bench: %-22s %s %s %.4g %s  (runs: %s)\n", r.ID, r.Judge, r.Cmp, r.Target, r.Unit, fmtVals(vals))
}

func fmtVals(v []float64) string {
	s := ""
	for i, x := range v {
		if i > 0 {
			s += " "
		}
		s += fmt.Sprintf("%.4g", x)
	}
	return s
}

// percentile uses the nearest rank on a sorted copy: with few samples p99 is the maximum, which is the honest reading.
func percentile(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	idx := int(math.Ceil(p*float64(len(s)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	return s[idx]
}

func dist(xs []float64) map[string]float64 {
	return map[string]float64{
		"p50": percentile(xs, .50), "p95": percentile(xs, .95), "p99": percentile(xs, .99),
		"max": percentile(xs, 1), "min": percentile(xs, 0),
	}
}
