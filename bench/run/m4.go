package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"kairan/internal/wire"
)

// ---- M4a: the existing Go benchmarks ----

// A benchmark line: BenchmarkDecide/rules=1000-12   1000000   123.4 ns/op   0 B/op   0 allocs/op
var benchLine = regexp.MustCompile(`^(Benchmark\S+?)(?:-\d+)?\s+(\d+)\s+([0-9.]+) ns/op(?:\s+([0-9.]+) B/op\s+([0-9.]+) allocs/op)?`)

type benchSample struct{ ns, bytes, allocs float64 }

// goOut runs a go command in the repository root and returns its combined output.
func (o *opts) goOut(timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = o.root
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// benchPackages finds, with `go test -list`, the packages that define benchmarks. The packages are discovered,
// not named here: this lane only runs the benchmarks and never reads the code under test.
func (o *opts) benchPackages() []string {
	list, err := o.goOut(5*time.Minute, "list", "./...")
	if err != nil {
		fatalf("go list: %v\n%s", err, list)
	}
	var pkgs []string
	for _, p := range strings.Fields(list) {
		if strings.Contains(p, "/bench") || strings.Contains(p, "/test/") || strings.Contains(p, "/deploy/") {
			continue
		}
		out, err := o.goOut(5*time.Minute, "test", "-run", "^$", "-list", "^Benchmark", p)
		if err != nil {
			fatalf("go test -list %s: %v\n%s", p, err, out)
		}
		if strings.Contains(out, "Benchmark") {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

func (o *opts) benchM4Go() {
	pkgs := o.benchPackages()
	logf("M4 Go benchmarks in %v: go test -bench, %d runs (-count)", pkgs, o.runs)
	if len(pkgs) == 0 {
		fatalf("no package defines a benchmark")
	}
	args := append([]string{"test", "-run", "^$", "-bench", ".", "-benchmem", "-benchtime", "1s", "-count", strconv.Itoa(o.runs)}, pkgs...)
	raw, err := o.goOut(30*time.Minute, args...)
	if err != nil {
		fatalf("go test -bench failed: %v\n%s", err, raw)
	}
	_ = os.MkdirAll(o.out, 0o755)
	_ = os.WriteFile(filepath.Join(o.out, "m4-go-bench.txt"), []byte(raw), 0o644)
	byName := map[string][]benchSample{}
	var order []string
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		m := benchLine.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		var s benchSample
		s.ns, _ = strconv.ParseFloat(m[3], 64)
		s.bytes, _ = strconv.ParseFloat(m[4], 64)
		s.allocs, _ = strconv.ParseFloat(m[5], 64)
		if _, ok := byName[m[1]]; !ok {
			order = append(order, m[1])
		}
		byName[m[1]] = append(byName[m[1]], s)
	}
	if len(order) == 0 {
		fatalf("no benchmark lines in the output:\n%s", raw)
	}
	for _, name := range order {
		ss := byName[name]
		id := "M4-go-" + strings.NewReplacer("/", "-", "=", "").Replace(strings.TrimPrefix(name, "Benchmark"))
		ns := Result{ID: id + "-ns", Metric: "M4", Unit: "ns/op", Judge: "ns_per_op", Cmp: "<=", Target: 1000,
			Title: "Go benchmark " + name + ": time per op (go test -bench, one sample per -count iteration)",
			Notes: "PRD target: decide <= 1 us/op median on 1,000 rules (ARCHITECTURE: BenchmarkDecide uses 1,000 rules; this lane ran it but did not read it). Applied to every benchmark whose name contains 'Decide'; others are informational."}
		al := Result{ID: id + "-allocs", Metric: "M4", Unit: "allocs/op", Judge: "allocs_per_op", Cmp: "==", Target: 0,
			Title: "Go benchmark " + name + ": allocations per op",
			Notes: "PRD target: 0 allocs on 1,000 rules. Applied to 'Decide' benchmarks; others are informational."}
		for i, s := range ss {
			ns.Runs = append(ns.Runs, Run{Index: i + 1, N: 1, Stats: map[string]float64{"ns_per_op": s.ns}})
			al.Runs = append(al.Runs, Run{Index: i + 1, N: 1, Stats: map[string]float64{"allocs_per_op": s.allocs, "bytes_per_op": s.bytes}})
		}
		if !strings.Contains(name, "Decide") {
			ns.Notes, al.Notes = "informational: no PRD target applies to this benchmark", "informational: no PRD target applies to this benchmark"
			ns.Cmp, al.Cmp = "info", "info"
		}
		o.save(ns)
		o.save(al)
	}
}

// ---- M4b: tools/call latency with and without the proxy, all on loopback ----

const (
	m4Net   = "kairan-bench-m4"
	m4CP    = "kairan-bench-m4-cp"
	m4Proxy = "kairan-bench-m4-proxy"
	m4Fake  = "kairan-bench-m4-fakemcp"
	m4Port  = 18680
	m4Key   = "bench-key-sales"
)

func m4Cleanup() {
	for _, c := range []string{m4Fake, m4Proxy, m4CP} {
		_, _ = docker("rm", "-f", "-v", c)
	}
	_, _ = docker("volume", "rm", "-f", "kairan-bench-m4-cp-data", "kairan-bench-m4-proxy-data")
	_, _ = docker("network", "rm", m4Net)
}

func (w *world) benchM4E2E() {
	o := w.o
	logf("M4 tools/call latency with and without the proxy (one network namespace, loopback only): %d runs", o.runs)
	m4Cleanup()
	defer m4Cleanup()
	// noise control: the dashboards are not part of the data path, so pause them while latencies are sampled
	for _, c := range []string{"kairan-prometheus", "kairan-grafana"} {
		if containerRunning(c) {
			if _, err := docker("pause", c); err == nil {
				defer func(c string) { _, _ = docker("unpause", c) }(c)
			}
		}
	}
	dir := filepath.Join(o.out, "m4")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatalf("%v", err)
	}
	build := exec.Command("go", "build", "-o", filepath.Join(dir, "m4client"), "./bench/m4client")
	build.Dir = o.root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if out, err := build.CombinedOutput(); err != nil {
		fatalf("build m4client: %v\n%s", err, out)
	}
	const tok = "bench-proxy-token"
	cpCfg, _ := json.Marshal(map[string]any{
		"listen": "0.0.0.0:8080", "metrics_listen": "0.0.0.0:9100", "data_dir": "/data", "allow_plaintext": true,
		"log_level": "info", "canary_dwell_seconds": 1,
		"tenants":     map[string]any{"bench": map[string]any{"threshold": 2, "admin_keys": w.pubs}},
		"enrollments": []map[string]string{{"proxy_id": "bench-proxy", "tenant": "bench", "group": "canary", "token_sha256": sha256hex(tok)}},
	})
	pxCfg, _ := json.Marshal(map[string]any{
		"tenant": "bench", "proxy_id": "bench-proxy", "cp_url": "http://cp-bench:8080", "token": tok,
		"trusted_keys": w.pubs, "threshold": 2, "listen": "127.0.0.1:8080", "metrics_listen": "127.0.0.1:9090",
		"upstream": "http://127.0.0.1:9000", "api_keys": map[string]string{m4Key: "sales"}, "data_dir": "/data", "allow_plaintext": true,
	})
	if err := os.WriteFile(filepath.Join(dir, "cp.json"), cpCfg, 0o644); err != nil {
		fatalf("%v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "proxy.json"), pxCfg, 0o644); err != nil {
		fatalf("%v", err)
	}
	adminTok := randHex(16)
	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	mustDocker("network", "create", m4Net)
	mustDocker("volume", "create", "kairan-bench-m4-cp-data")
	mustDocker("volume", "create", "kairan-bench-m4-proxy-data")
	args := append([]string{"run", "-d", "--name", m4CP, "--network", m4Net, "--network-alias", "cp-bench",
		"-e", "KCP_ADMIN_TOKEN=" + adminTok, "-v", "kairan-bench-m4-cp-data:/data",
		"-v", filepath.Join(dir, "cp.json") + ":/etc/kairan/cp.json:ro", "-p", fmt.Sprintf("127.0.0.1:%d:8080", m4Port)}, hard...)
	mustDocker(append(args, image, "kairan-cp", "-config", "/etc/kairan/cp.json")...)
	c := newCP(fmt.Sprintf("http://127.0.0.1:%d", m4Port), adminTok)
	waitFor(60*time.Second, 300*time.Millisecond, "the bench control plane", func() (bool, string) {
		code, _, err := c.do("GET", wire.PathFleet+"?tenant=bench", nil, nil)
		return err == nil && code == 200, fmt.Sprintf("HTTP %d %v", code, err)
	})
	args = append([]string{"run", "-d", "--name", m4Proxy, "--network", m4Net, "-v", "kairan-bench-m4-proxy-data:/data",
		"-v", filepath.Join(dir, "proxy.json") + ":/etc/kairan/proxy.json:ro"}, hard...)
	mustDocker(append(args, image, "kairan-proxy", "-config", "/etc/kairan/proxy.json")...)
	mustDocker(append([]string{"run", "-d", "--name", m4Fake, "--network", "container:" + m4Proxy}, append(hard, image, "fakemcp", "-addr", "127.0.0.1:9000")...)...)
	v, _, err := w.release(c, "bench", 1)
	if err != nil {
		fatalf("%v", err)
	}
	c.waitAcked("bench", v, nil, 60*time.Second)
	time.Sleep(2 * time.Second)

	added99 := Result{ID: "M4-e2e-added-p99", Metric: "M4", Unit: "ms", Judge: "added_p99_ms", Cmp: "<=", Target: 2,
		Title: "tools/call latency added by the proxy, p99 (p99 through the proxy minus p99 direct to the upstream), loopback",
		Notes: "REAL proxy and REAL fakemcp (Prometheus and Grafana of the compose stack are paused during sampling to cut noise). Client, proxy and upstream share one network namespace (all loopback), one keep-alive connection per path, 3000 alternating pairs after 500 warm-up pairs per run. Both paths carry the same JSON-RPC body; the proxy path also pays API-key lookup, the policy decision and forwarding."}
	added50 := Result{ID: "M4-e2e-added-p50", Metric: "M4", Unit: "ms", Judge: "added_p50_ms", Cmp: "info", Target: 0,
		Title: "tools/call latency added by the proxy, median (informational; the PRD target is on p99)"}
	for i := 1; i <= o.runs; i++ {
		out, err := exec.Command("docker", "run", "--rm", "--network", "container:"+m4Proxy, "-v", dir+":/bench:ro", "--entrypoint", "/bench/m4client",
			image, "-key", m4Key, "-n", "3000", "-warm", "500").Output()
		if err != nil {
			fatalf("m4client: %v", err)
		}
		var r struct {
			Direct []int64 `json:"direct_us"`
			Proxy  []int64 `json:"proxy_us"`
			Errors int     `json:"errors"`
		}
		if err := json.Unmarshal(out, &r); err != nil {
			fatalf("m4client output: %v", err)
		}
		if r.Errors > 0 || len(r.Direct) < 2500 {
			fatalf("m4client: %d failed pairs, %d good (the call through the proxy must be allowed)", r.Errors, len(r.Direct))
		}
		d, p := toMS(r.Direct), toMS(r.Proxy)
		dd, pd := dist(d), dist(p)
		st := map[string]float64{
			"added_p99_ms": pd["p99"] - dd["p99"], "added_p50_ms": pd["p50"] - dd["p50"],
			"direct_p50_ms": dd["p50"], "direct_p99_ms": dd["p99"], "proxy_p50_ms": pd["p50"], "proxy_p99_ms": pd["p99"],
		}
		added99.Runs = append(added99.Runs, Run{Index: i, N: len(d), Stats: st})
		added50.Runs = append(added50.Runs, Run{Index: i, N: len(d), Stats: st})
		logf("M4 e2e run %d: direct p50 %.3f p99 %.3f ms; proxy p50 %.3f p99 %.3f ms; added p50 %.3f p99 %.3f ms", i, dd["p50"], dd["p99"], pd["p50"], pd["p99"], st["added_p50_ms"], st["added_p99_ms"])
	}
	o.save(added99)
	o.save(added50)
}

func toMS(us []int64) []float64 {
	out := make([]float64, len(us))
	for i, x := range us {
		out[i] = float64(x) / 1000
	}
	return out
}
