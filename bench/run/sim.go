package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"kairan/internal/wire"
)

// Everything in this file is SIMULATED proxies (kairan-sim: ids sim-0000.., "simulated": true in its result).
// They hold no keys, verify nothing and enforce nothing; they load the REAL kairan-cp, which runs in its own
// hardened container with nothing but a network of its own and the simulator beside it.

const (
	simTenant   = "bsim"
	simCanaries = 5 // sim-0000 .. sim-0004 are the canary group
	simPort     = 18580
	simMetPort  = 19580
	clockTick   = 100.0 // USER_HZ on Linux
)

type simCP struct {
	w         *world
	n         int
	net, cp   string
	sim       string
	vol       string
	c         *cpc
	adminTok  string
	startedAt time.Time
}

func simCanaryIDs() []string {
	var out []string
	for i := 0; i < simCanaries; i++ {
		out = append(out, fmt.Sprintf("sim-%04d", i))
	}
	return out
}

func simMainIDs(n int) []string {
	var out []string
	for i := simCanaries; i < n; i++ {
		out = append(out, fmt.Sprintf("sim-%04d", i))
	}
	return out
}

func (s *simCP) cleanup() {
	for _, c := range []string{s.sim, s.cp} {
		_, _ = docker("rm", "-f", "-v", c)
	}
	_, _ = docker("volume", "rm", "-f", s.vol)
	_, _ = docker("network", "rm", s.net)
}

// startSimCP starts a fresh kairan-cp (the real one) and n simulated proxies against it; it returns once all n
// show as healthy in the fleet view.
func (w *world) startSimCP(n int) *simCP {
	tag := fmt.Sprintf("bsim%d", n)
	s := &simCP{w: w, n: n, net: "kairan-" + tag, cp: "kairan-" + tag + "-cp", sim: "kairan-" + tag + "-sim", vol: "kairan-" + tag + "-cp-data"}
	s.cleanup()
	dir := filepath.Join(w.o.out, tag)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatalf("%v", err)
	}
	hash := func(x string) string { h := sha256.Sum256([]byte(x)); return hex.EncodeToString(h[:]) }
	enroll := make([]map[string]string, 0, n)
	for i := 0; i < n; i++ {
		g := "main"
		if i < simCanaries {
			g = "canary"
		}
		enroll = append(enroll, map[string]string{"proxy_id": fmt.Sprintf("sim-%04d", i), "tenant": simTenant, "group": g,
			"token_sha256": hash(fmt.Sprintf("sim-token-%04d", i))})
	}
	cfg, _ := json.Marshal(map[string]any{
		"listen": "0.0.0.0:8080", "metrics_listen": "0.0.0.0:9100", "data_dir": "/data", "allow_plaintext": true,
		"log_level": "info", "canary_dwell_seconds": m1Dwell,
		"tenants":     map[string]any{simTenant: map[string]any{"threshold": 2, "admin_keys": w.pubs}},
		"enrollments": enroll,
	})
	if err := os.WriteFile(filepath.Join(dir, "cp.json"), cfg, 0o644); err != nil {
		fatalf("%v", err)
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		fatalf("%v", err)
	}
	s.adminTok = hex.EncodeToString(buf)

	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	mustDocker("network", "create", s.net)
	mustDocker("volume", "create", s.vol)
	args := []string{"run", "-d", "--name", s.cp, "--network", s.net, "--network-alias", "cp-bench",
		"-e", "KCP_ADMIN_TOKEN=" + s.adminTok, "-v", s.vol + ":/data",
		"-v", filepath.Join(dir, "cp.json") + ":/etc/kairan/cp.json:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", simPort), "-p", fmt.Sprintf("127.0.0.1:%d:9100", simMetPort)}
	args = append(args, hard...)
	args = append(args, image, "kairan-cp", "-config", "/etc/kairan/cp.json")
	mustDocker(args...)
	s.c = newCP(fmt.Sprintf("http://127.0.0.1:%d", simPort), s.adminTok)
	waitFor(60*time.Second, 300*time.Millisecond, "the sim control plane to answer", func() (bool, string) {
		code, _, err := s.c.do("GET", wire.PathFleet+"?tenant="+simTenant, nil, nil)
		return err == nil && code == 200, fmt.Sprintf("HTTP %d %v", code, err)
	})
	s.startedAt = time.Now()
	args = []string{"run", "-d", "--name", s.sim, "--network", s.net, "--ulimit", "nofile=65536:65536"}
	args = append(args, hard...)
	args = append(args, image, "kairan-sim", "-cp", "http://cp-bench:8080", "-n", strconv.Itoa(n), "-tenant", simTenant,
		"-ramp", "10s", "-duration", "30m")
	mustDocker(args...)
	waitFor(180*time.Second, 500*time.Millisecond, fmt.Sprintf("all %d simulated proxies to be healthy", n), func() (bool, string) {
		fv, err := s.c.fleet(simTenant)
		if err != nil {
			return false, err.Error()
		}
		healthy := 0
		for _, r := range fv.Proxies {
			if r.Health == wire.HealthHealthy {
				healthy++
			}
		}
		return healthy == n, fmt.Sprintf("%d of %d healthy", healthy, n)
	})
	return s
}

// ---- M1 with simulated proxies ----

func (w *world) benchM1Sim(n int) {
	name := fmt.Sprintf("sim%d", n)
	logf("M1 propagation, %d SIMULATED proxies (kairan-sim) against the REAL kairan-cp: %d runs x %d rounds", n, w.o.runs, w.o.rounds)
	canary := Result{ID: "M1-" + name + "-canary", Metric: "M1", Simulated: true, Unit: "ms", Judge: "p99", Cmp: "<=", Target: 3000,
		Title: fmt.Sprintf("SIMULATED: propagation, publish to canary ack (%d simulated proxies, %d in the canary group)", n, simCanaries),
		Notes: "SIMULATED proxies: they apply nothing and verify no signatures, so this measures the control plane's fan-out, not a real proxy's apply. The PRD target (3 s) is stated for 1,000; the same bound is applied to 100."}
	mainR := Result{ID: "M1-" + name + "-main", Metric: "M1", Simulated: true, Unit: "ms", Judge: "p99", Cmp: "<=", Target: 3000,
		Title: fmt.Sprintf("SIMULATED: propagation, main group ack after the canary dwell (%d simulated proxies, %d mains)", n, n-simCanaries),
		Notes: "SIMULATED. Sample = main ack minus (last canary ack + 5 s dwell). The PRD target (3 s) is stated for 1,000; the same bound is applied to 100."}
	for i := 1; i <= w.o.runs; i++ {
		s := w.startSimCP(n)
		var all stageSamples
		for r := 0; r < w.o.rounds; r++ {
			st, err := w.m1SimRound(s)
			if err != nil {
				s.cleanup()
				fatalf("M1 sim%d run %d: %v", n, i, err)
			}
			all.canary = append(all.canary, st.canary...)
			all.main = append(all.main, st.main...)
		}
		s.cleanup()
		canary.Runs = append(canary.Runs, stageRun(i, all.canary, nil))
		mainR.Runs = append(mainR.Runs, stageRun(i, all.main, nil))
		logf("M1 sim%d run %d: canary p99 %.0f ms (n=%d), main p99 %.0f ms (n=%d)", n, i, percentile(all.canary, .99), len(all.canary), percentile(all.main, .99), len(all.main))
	}
	w.o.save(canary)
	w.o.save(mainR)
}

func (w *world) m1SimRound(s *simCP) (stageSamples, error) {
	return w.m1Round(s.c, "", []string{simTenant}, func(string) []string { return simCanaryIDs() }, func(string) []string { return simMainIDs(s.n) }, 120*time.Second)
}

// ---- M7 (and the 1,000-proxy leg of M1): control plane cost with 1,000 simulated proxies ----

type procSample struct {
	at           time.Time
	rssKB, hwmKB int64
	ticks        int64
}

// sampleProc reads VmRSS, VmHWM and utime+stime of PID 1 in the container.
func sampleProc(container string) (procSample, bool) {
	out, err := execOut("docker", "exec", container, "sh", "-c", "cat /proc/1/status; echo ---; cat /proc/1/stat")
	s := procSample{at: time.Now()}
	if err != nil {
		return s, false
	}
	parts := strings.SplitN(out, "---", 2)
	for _, ln := range strings.Split(parts[0], "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && (f[0] == "VmRSS:" || f[0] == "VmHWM:") {
			n, _ := strconv.ParseInt(f[1], 10, 64)
			if f[0] == "VmRSS:" {
				s.rssKB = n
			} else {
				s.hwmKB = n
			}
		}
	}
	if len(parts) == 2 {
		if i := strings.LastIndex(parts[1], ")"); i >= 0 {
			f := strings.Fields(parts[1][i+1:])
			if len(f) > 12 {
				u, _ := strconv.ParseInt(f[11], 10, 64)
				k, _ := strconv.ParseInt(f[12], 10, 64)
				s.ticks = u + k
			}
		}
	}
	return s, s.rssKB > 0
}

func (w *world) benchM7() {
	const n = 1000
	const window = 60 * time.Second
	logf("M7 + M1 at 1,000: %d SIMULATED proxies against the REAL kairan-cp, %d runs (each: ramp, v1 rollout, %s steady state, %d more rounds)", n, w.o.runs, window, w.o.rounds-1)
	rss := Result{ID: "M7-rss", Metric: "M7", Simulated: true, Unit: "MB", Judge: "rss_hwm_mb", Cmp: "<=", Target: 150,
		Title: "SIMULATED: control plane RSS with 1,000 simulated proxies, 60 s steady state",
		Notes: "SIMULATED proxies against the real kairan-cp. Judged on the kernel's VmHWM (peak since process start, including the ramp-up and the v1 rollout), the strictest reading; the sampled peak during the 60 s window is reported beside it."}
	cpu := Result{ID: "M7-cpu", Metric: "M7", Simulated: true, Unit: "cores", Judge: "cores", Cmp: "<=", Target: 0.5,
		Title: "SIMULATED: control plane CPU with 1,000 simulated proxies over 60 s",
		Notes: "SIMULATED. utime+stime of the kairan-cp process (/proc/1/stat) over the 60 s window divided by the window; 1.0 = one core."}
	canary := Result{ID: "M1-sim1000-canary", Metric: "M1", Simulated: true, Unit: "ms", Judge: "p99", Cmp: "<=", Target: 3000,
		Title: fmt.Sprintf("SIMULATED: propagation, publish to canary ack (1,000 simulated proxies, %d in the canary group)", simCanaries),
		Notes: "SIMULATED proxies: they apply nothing and verify no signatures, so this measures the control plane's fan-out, not a real proxy's apply."}
	mainR := Result{ID: "M1-sim1000-main", Metric: "M1", Simulated: true, Unit: "ms", Judge: "p99", Cmp: "<=", Target: 3000,
		Title: fmt.Sprintf("SIMULATED: propagation, main group ack after the canary dwell (1,000 simulated proxies, %d mains)", n-simCanaries),
		Notes: "SIMULATED. Sample = main ack minus (last canary ack + 5 s dwell)."}
	for i := 1; i <= w.o.runs; i++ {
		s := w.startSimCP(n)
		var all stageSamples
		st, err := w.m1SimRound(s) // round 1 = v1; the 60 s window starts once every proxy acked it
		if err != nil {
			s.cleanup()
			fatalf("M7 run %d: %v", i, err)
		}
		all.canary, all.main = append(all.canary, st.canary...), append(all.main, st.main...)
		time.Sleep(3 * time.Second)

		var samples []procSample
		end := time.Now().Add(window)
		for time.Now().Before(end) {
			if smp, ok := sampleProc(s.cp); ok {
				samples = append(samples, smp)
			}
			time.Sleep(1500 * time.Millisecond)
		}
		if len(samples) < 20 {
			s.cleanup()
			fatalf("M7 run %d: only %d samples", i, len(samples))
		}
		var peak, hwm int64
		for _, x := range samples {
			if x.rssKB > peak {
				peak = x.rssKB
			}
			if x.hwmKB > hwm {
				hwm = x.hwmKB
			}
		}
		first, last := samples[0], samples[len(samples)-1]
		span := last.at.Sub(first.at).Seconds()
		cores := float64(last.ticks-first.ticks) / clockTick / span
		stats, _ := docker("stats", "--no-stream", "--format", "{{.MemUsage}} | {{.NetIO}} | pids {{.PIDs}}", s.cp)
		for r := 1; r < w.o.rounds; r++ { // more M1 rounds on the same warm control plane
			st, err := w.m1SimRound(s)
			if err != nil {
				s.cleanup()
				fatalf("M1 sim1000 run %d: %v", i, err)
			}
			all.canary, all.main = append(all.canary, st.canary...), append(all.main, st.main...)
		}
		s.cleanup()
		det := map[string]any{"samples": len(samples), "window_s": span, "docker_stats": stats}
		rss.Runs = append(rss.Runs, Run{Index: i, N: len(samples), Stats: map[string]float64{"rss_hwm_mb": float64(hwm) / 1024, "rss_peak_mb": float64(peak) / 1024}, Detail: det})
		cpu.Runs = append(cpu.Runs, Run{Index: i, N: len(samples), Stats: map[string]float64{"cores": cores}, Detail: det})
		canary.Runs = append(canary.Runs, stageRun(i, all.canary, nil))
		mainR.Runs = append(mainR.Runs, stageRun(i, all.main, nil))
		logf("M7 run %d: RSS high-water %.1f MB (sampled peak %.1f MB), CPU %.3f cores over %.0f s; M1 canary p99 %.0f ms, main p99 %.0f ms",
			i, float64(hwm)/1024, float64(peak)/1024, cores, span, percentile(all.canary, .99), percentile(all.main, .99))
	}
	w.o.save(rss)
	w.o.save(cpu)
	w.o.save(canary)
	w.o.save(mainR)
}
