package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/wire"
)

// S13 reconnect storm (optional; M7, THREATS #8) and the real-control-plane run of kairan-sim (Q-05).
//
// EVERY PROXY HERE IS SIMULATED (kairan-sim: ids sim-0000.., the JSON result says "simulated": true). They do
// not verify signatures or enforce anything; they exist to load the REAL kairan-cp, which runs in its own
// hardened container. Topology: network kairan-s13 with kairan-s13-cp (real) and kairan-s13-sim (kairan-sim).
//
// Phase A (1,000 simulated proxies): all poll and report; v1 is published and rolled out (a canary and 999
// mains); once every proxy acked it, 60 s of steady state is sampled (M7: <= 150 MB RSS and <= 0.5 core);
// then the control plane is restarted (docker restart) while all 1,000 proxies are polling: pass when it
// comes back, all 1,000 report again, and a v2 published afterwards reaches all 1,000 (catch-up), with no
// unexpected 503 storm at 1,000 (the cap is 5,000) and no crash (one restart only).
//
// Phase B (the cap): 5,600 simulated proxies against the same control plane (poll cap 5,000). Pass when the
// control plane stays up (same container start time, no restart or OOM), answers a probe poll over the cap
// with 503 + Retry-After + code unavailable, keeps serving admin requests, and answers the same probe normally
// once the load is gone.
const (
	s13Net       = "kairan-s13"
	s13CP        = "kairan-s13-cp"
	s13Sim       = "kairan-s13-sim"
	s13Tenant    = "sim"
	s13Port      = 18380
	s13MetPort   = 19380
	s13N         = 1000
	s13CapN      = 5600
	s13Window    = 60 * time.Second
	s13MaxRSSMB  = 150
	s13MaxCores  = 0.5
	s13ProbeIDs  = 40
	s13PollCap   = 5000
	s13TokenFmt  = "sim-token-%04d"
	s13ProbeFmt  = "probe-token-%02d"
	s13ClockTick = 100.0 // USER_HZ on Linux
)

type cpClient struct {
	base, token string
	hc          *http.Client
}

func (c *cpClient) do(method, path string, body, out any) (int, wire.ErrorCode, error) {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+c.token)
	if body != nil {
		req.Header.Set("Content-Type", wire.ContentTypeJSON)
	}
	res, err := c.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if res.StatusCode/100 != 2 {
		var er wire.ErrorResponse
		_ = json.Unmarshal(data, &er)
		return res.StatusCode, er.Code, nil
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return res.StatusCode, "", err
		}
	}
	return res.StatusCode, "", nil
}

type procSample struct {
	at     time.Time
	rssKB  int64
	hwmKB  int64
	ticks  int64
	failed bool
}

// sampleProc reads VmRSS, VmHWM and utime+stime of PID 1 in the container.
func sampleProc(container string) procSample {
	out, err := exec.Command("docker", "exec", container, "sh", "-c", "cat /proc/1/status; echo ---; cat /proc/1/stat").Output()
	s := procSample{at: time.Now()}
	if err != nil {
		s.failed = true
		return s
	}
	parts := strings.SplitN(string(out), "---", 2)
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
		st := parts[1]
		if i := strings.LastIndex(st, ")"); i >= 0 {
			f := strings.Fields(st[i+1:])
			if len(f) > 12 {
				u, _ := strconv.ParseInt(f[11], 10, 64)
				k, _ := strconv.ParseInt(f[12], 10, 64)
				s.ticks = u + k
			}
		}
	}
	if s.rssKB == 0 {
		s.failed = true
	}
	return s
}

type sampler struct {
	container string
	stop      chan struct{}
	wg        sync.WaitGroup
	mu        sync.Mutex
	samples   []procSample
}

func startSampler(container string, every time.Duration) *sampler {
	s := &sampler{container: container, stop: make(chan struct{})}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			if smp := sampleProc(container); !smp.failed {
				s.mu.Lock()
				s.samples = append(s.samples, smp)
				s.mu.Unlock()
			}
			select {
			case <-s.stop:
				return
			case <-time.After(every):
			}
		}
	}()
	return s
}

func (s *sampler) halt() []procSample {
	close(s.stop)
	s.wg.Wait()
	return s.samples
}

// summarise returns peak RSS (MB, sampled and kernel high-water mark) and average CPU cores over the samples.
func summarise(ss []procSample) (peakRSSMB, hwmMB, cores float64, span time.Duration, n int) {
	if len(ss) == 0 {
		return
	}
	var peak, hwm int64
	for _, s := range ss {
		if s.rssKB > peak {
			peak = s.rssKB
		}
		if s.hwmKB > hwm {
			hwm = s.hwmKB
		}
	}
	first, last := ss[0], ss[len(ss)-1]
	span = last.at.Sub(first.at)
	if span > 0 && last.ticks >= first.ticks {
		cores = float64(last.ticks-first.ticks) / s13ClockTick / span.Seconds()
	}
	return float64(peak) / 1024, float64(hwm) / 1024, cores, span, len(ss)
}

type simResult struct {
	Simulated bool   `json:"simulated"`
	Label     string `json:"label"`
	Proxies   int    `json:"proxies"`
	Polls     struct {
		Total       int `json:"total"`
		Modified    int `json:"modified"`
		NotModified int `json:"not_modified"`
		Unavailable int `json:"unavailable"`
		Errors      int `json:"errors"`
	} `json:"polls"`
	Status struct {
		Sent   int `json:"sent"`
		OK     int `json:"ok"`
		Errors int `json:"errors"`
	} `json:"status"`
	Acks struct {
		Total     int `json:"total"`
		ByVersion []struct {
			Version  uint64 `json:"version"`
			Proxies  int    `json:"proxies"`
			FirstAck int64  `json:"first_acked_unix_ms"`
			LastAck  int64  `json:"last_acked_unix_ms"`
		} `json:"by_version"`
	} `json:"acks"`
	Errors        struct{ Total int } `json:"errors"`
	FinalVersions map[string]int      `json:"final_versions"`
	DurationMS    int64               `json:"duration_ms"`
}

func simResultOf(t *testing.T, container string) simResult {
	t.Helper()
	out, err := exec.Command("docker", "logs", container).Output() // stdout only: the JSON result
	if err != nil {
		t.Fatalf("docker logs %s: %v", container, err)
	}
	var r simResult
	if err := json.Unmarshal(out, &r); err != nil {
		t.Fatalf("kairan-sim result is not JSON: %v\n%.400s", err, out)
	}
	return r
}

func s13Cleanup() {
	for _, c := range []string{s13Sim, s13CP} {
		_, _ = docker("rm", "-f", "-v", c)
	}
	_, _ = docker("volume", "rm", "-f", "kairan-s13-cp-data")
	_, _ = docker("network", "rm", s13Net)
}

func TestS13ReconnectStorm(t *testing.T) {
	w := need(t)
	s13Cleanup()
	t.Cleanup(s13Cleanup)

	dir := filepath.Join(w.run, "s13")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var pubs []string
	pb, err := os.ReadFile(filepath.Join(w.run, "trusted-keys.json"))
	if err != nil || json.Unmarshal(pb, &pubs) != nil {
		t.Fatalf("trusted-keys.json: %v", err)
	}
	// enrollments: s13CapN simulated proxies (sim-0000 is the canary) plus probe proxies for the cap check
	enroll := make([]map[string]string, 0, s13CapN+s13ProbeIDs)
	hash := func(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
	for i := 0; i < s13CapN; i++ {
		g := "main"
		if i == 0 {
			g = "canary"
		}
		enroll = append(enroll, map[string]string{"proxy_id": fmt.Sprintf("sim-%04d", i), "tenant": s13Tenant, "group": g,
			"token_sha256": hash(fmt.Sprintf(s13TokenFmt, i))})
	}
	for i := 0; i < s13ProbeIDs; i++ {
		enroll = append(enroll, map[string]string{"proxy_id": fmt.Sprintf("probe-%02d", i), "tenant": s13Tenant, "group": "main",
			"token_sha256": hash(fmt.Sprintf(s13ProbeFmt, i))})
	}
	cfg, _ := json.Marshal(map[string]any{
		"listen": "0.0.0.0:8080", "metrics_listen": "0.0.0.0:9100", "data_dir": "/data", "allow_plaintext": true,
		"log_level": "info", "canary_dwell_seconds": 1,
		"tenants":     map[string]any{s13Tenant: map[string]any{"threshold": 2, "admin_keys": pubs}},
		"enrollments": enroll,
	})
	if err := os.WriteFile(filepath.Join(dir, "cp.json"), cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	rb := make([]byte, 16)
	cryptoRand(rb)
	adminTok := hex.EncodeToString(rb)
	cp := &cpClient{base: fmt.Sprintf("http://127.0.0.1:%d", s13Port), token: adminTok, hc: &http.Client{Timeout: 20 * time.Second}}

	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	mustDocker(t, "network", "create", s13Net)
	mustDocker(t, "volume", "create", "kairan-s13-cp-data")
	mustDocker(t, append(append([]string{"run", "-d", "--name", s13CP, "--network", s13Net, "--network-alias", "cp-s13",
		"-e", "KCP_ADMIN_TOKEN=" + adminTok, "-v", "kairan-s13-cp-data:/data",
		"-v", filepath.Join(dir, "cp.json") + ":/etc/kairan/cp.json:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", s13Port), "-p", fmt.Sprintf("127.0.0.1:%d:9100", s13MetPort)}, hard...),
		image, "kairan-cp", "-config", "/etc/kairan/cp.json")...)
	waitCP := func(what string) {
		eventually(t, 60*time.Second, 300*time.Millisecond, what, func() (bool, string) {
			code, _, err := cp.do("GET", wire.PathFleet+"?tenant="+s13Tenant, nil, nil)
			return err == nil && code == 200, fmt.Sprintf("HTTP %d %v", code, err)
		})
	}
	waitCP("the s13 control plane to answer")
	startedAt := func() string {
		out, _ := docker("inspect", "-f", "{{.State.StartedAt}} restarts={{.RestartCount}} oom={{.State.OOMKilled}}", s13CP)
		return out
	}
	started0 := startedAt()

	fleetCounts := func() (total, healthy int, minApplied uint64, err error) {
		var fv wire.FleetView
		code, ec, err := cp.do("GET", wire.PathFleet+"?tenant="+s13Tenant, nil, &fv)
		if err != nil || code != 200 {
			return 0, 0, 0, fmt.Errorf("fleet HTTP %d %s %v", code, ec, err)
		}
		minApplied = ^uint64(0)
		for _, r := range fv.Proxies {
			if idx, err := strconv.Atoi(strings.TrimPrefix(string(r.ProxyID), "sim-")); strings.HasPrefix(string(r.ProxyID), "sim-") && err == nil && idx < s13N {
				total++
				if r.Health == wire.HealthHealthy {
					healthy++
				}
				if r.AppliedVersion < minApplied {
					minApplied = r.AppliedVersion
				}
			}
		}
		if total == 0 {
			minApplied = 0
		}
		return total, healthy, minApplied, nil
	}
	release := func(version uint64) {
		t.Helper()
		env := w.envelope(payload(s13Tenant, version, time.Now().Add(-time.Minute), time.Now().Add(72*time.Hour), nil), "admin-a", "admin-b")
		if code, ec, err := cp.do("POST", wire.PathPolicies, env, nil); err != nil || code/100 != 2 {
			t.Fatalf("publish v%d: HTTP %d %s %v", version, code, ec, err)
		}
		if code, ec, err := cp.do("POST", wire.PathRollouts, wire.RolloutRequest{Tenant: s13Tenant, Version: version, CanaryDwellSeconds: 1}, nil); err != nil || code/100 != 2 {
			t.Fatalf("rollout v%d: HTTP %d %s %v", version, code, ec, err)
		}
	}
	waitAll := func(n int, atLeast uint64, limit time.Duration, what string) time.Duration {
		return eventually(t, limit, 500*time.Millisecond, what, func() (bool, string) {
			total, healthy, minApplied, err := fleetCounts()
			if err != nil {
				return false, err.Error()
			}
			return total == n && healthy == n && minApplied >= atLeast, fmt.Sprintf("%d in the fleet view, %d healthy, lowest applied v%d", total, healthy, minApplied)
		})
	}
	startSim := func(name string, n int, extra ...string) {
		args := []string{"run", "-d", "--name", name, "--network", s13Net, "--ulimit", "nofile=65536:65536"}
		args = append(args, hard...)
		args = append(args, image, "kairan-sim", "-cp", "http://cp-s13:8080", "-n", strconv.Itoa(n), "-tenant", s13Tenant)
		mustDocker(t, append(args, extra...)...)
	}

	// ---------------- phase A ----------------
	startSim(s13Sim, s13N, "-ramp", "10s", "-until-version", "2", "-duration", "10m")
	up := waitAll(s13N, 0, 120*time.Second, "all 1,000 simulated proxies to appear healthy")
	t.Logf("S13 (SIMULATED proxies, real kairan-cp): %d simulated proxies visible and healthy after %.1fs", s13N, up.Seconds())
	release(1)
	ack1 := waitAll(s13N, 1, 120*time.Second, "all 1,000 simulated proxies to ack v1")
	t.Logf("S13: v1 (canary + 999 mains) acked by all %d simulated proxies %.1fs after the publish", s13N, ack1.Seconds())

	// steady state: 60 s of polls and status reports
	smp := startSampler(s13CP, 2*time.Second)
	time.Sleep(s13Window)
	ss := smp.halt()
	rss, hwm, cores, span, n := summarise(ss)
	t.Logf("S13 M7 (SIMULATED proxies): %d simulated proxies, steady state over %.0fs (%d samples): control plane RSS peak %.1f MB (kernel high-water %.1f MB), CPU %.3f cores; limits %d MB and %.1f core",
		s13N, span.Seconds(), n, rss, hwm, cores, s13MaxRSSMB, s13MaxCores)
	if n < 20 || span < 50*time.Second {
		t.Errorf("M7: only %d samples over %.0fs: the measurement is not valid", n, span.Seconds())
	}
	if hwm > s13MaxRSSMB || rss > s13MaxRSSMB {
		t.Errorf("M7: control plane RSS %.1f MB (high-water %.1f MB) exceeds %d MB for %d simulated proxies", rss, hwm, s13MaxRSSMB, s13N)
	}
	if cores > s13MaxCores {
		t.Errorf("M7: control plane used %.3f cores over %.0fs, limit %.1f", cores, span.Seconds(), s13MaxCores)
	}
	if out, err := docker("stats", "--no-stream", "--format", "{{.CPUPerc}} cpu, {{.MemUsage}}, {{.NetIO}}, pids {{.PIDs}}", s13CP); err == nil {
		t.Logf("S13 docker stats (instant): %s", out)
	}

	// the storm: restart the control plane while every simulated proxy has a poll open
	smp2 := startSampler(s13CP, 2*time.Second)
	t0 := time.Now()
	mustDocker(t, "restart", "-t", "10", s13CP)
	waitCP("the control plane to answer again after the restart")
	backUp := time.Since(t0)
	storm := waitAll(s13N, 1, 180*time.Second, "all 1,000 simulated proxies to report again after the restart")
	t.Logf("S13: control plane restarted: answering after %.1fs; all %d simulated proxies healthy again %.1fs after it answered", backUp.Seconds(), s13N, storm.Seconds())
	release(2)
	ack2 := waitAll(s13N, 2, 180*time.Second, "all 1,000 simulated proxies to catch up to v2 after the restart")
	t.Logf("S13: v2 published after the restart reached all %d simulated proxies in %.1fs", s13N, ack2.Seconds())
	time.Sleep(10 * time.Second)
	ss2 := smp2.halt()
	rss2, hwm2, cores2, span2, n2 := summarise(ss2)
	t.Logf("S13 storm window (SIMULATED proxies): %d samples over %.0fs after the restart: RSS peak %.1f MB (high-water %.1f MB), CPU %.3f cores (start-up included)", n2, span2.Seconds(), rss2, hwm2, cores2)
	if hwm2 > s13MaxRSSMB {
		t.Errorf("control plane RSS during the reconnect storm: %.1f MB (high-water), limit %d MB", hwm2, s13MaxRSSMB)
	}
	st := startedAt()
	t.Logf("S13: container state before -> after: %q -> %q", started0, st)
	if !strings.Contains(st, "oom=false") {
		t.Errorf("the control plane was OOM-killed: %s", st)
	}

	// the simulator exits by itself once every proxy acked v2
	eventually(t, 60*time.Second, time.Second, "kairan-sim to finish", func() (bool, string) {
		out, _ := docker("inspect", "-f", "{{.State.Running}}", s13Sim)
		return out == "false", "still running"
	})
	r := simResultOf(t, s13Sim)
	if !r.Simulated || !strings.Contains(r.Label, "SIMULATED") {
		t.Errorf("kairan-sim result is not labelled simulated: %+v", r)
	}
	t.Logf("S13 kairan-sim result (SIMULATED): %d proxies; polls %d (200: %d, 304: %d, 503: %d, errors: %d); status %d sent, %d ok, %d errors; final versions %v; ran %.0fs",
		r.Proxies, r.Polls.Total, r.Polls.Modified, r.Polls.NotModified, r.Polls.Unavailable, r.Polls.Errors, r.Status.Sent, r.Status.OK, r.Status.Errors, r.FinalVersions, float64(r.DurationMS)/1000)
	if r.FinalVersions["2"] != s13N {
		t.Errorf("final versions %v, want all %d at v2", r.FinalVersions, s13N)
	}
	if r.Polls.Unavailable != 0 {
		t.Errorf("%d poll answers were 503 with only %d proxies against a cap of %d: the cap must not trigger early", r.Polls.Unavailable, s13N, s13PollCap)
	}

	// ---------------- phase B: over the cap ----------------
	startedB := startedAt()
	startSim(s13Sim+"-cap", s13CapN, "-ramp", "10s", "-duration", "85s")
	smp3 := startSampler(s13CP, 2*time.Second)
	var got503 bool
	var retryAfter string
	var code503 wire.ErrorCode
	probeHC := &http.Client{Timeout: 2 * time.Second}
	probe := func(i int) (int, string, wire.ErrorCode) {
		q := wire.PollRequest{Tenant: s13Tenant, ProxyID: wire.ID(fmt.Sprintf("probe-%02d", i%s13ProbeIDs)), Have: 2}.Query()
		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d%s?%s", s13Port, wire.PathPoll, q.Encode()), nil)
		req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+fmt.Sprintf(s13ProbeFmt, i%s13ProbeIDs))
		res, err := probeHC.Do(req)
		if err != nil {
			return 0, "", ""
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		var er wire.ErrorResponse
		_ = json.Unmarshal(b, &er)
		return res.StatusCode, res.Header.Get("Retry-After"), er.Code
	}
	time.Sleep(25 * time.Second) // ramp (10 s) plus time to fill the cap
	var statuses []int
	for i := 0; i < s13ProbeIDs && !got503; i++ {
		c, ra, ec := probe(i)
		statuses = append(statuses, c)
		if c == http.StatusServiceUnavailable {
			got503, retryAfter, code503 = true, ra, ec
		}
		time.Sleep(time.Second)
	}
	if !got503 {
		t.Errorf("no probe poll was answered 503 while %d simulated proxies held polls against a cap of %d; statuses %v", s13CapN, s13PollCap, statuses)
	} else {
		secs, err := strconv.Atoi(retryAfter)
		if err != nil || secs < 1 {
			t.Errorf("503 without a usable Retry-After header: %q", retryAfter)
		}
		if code503 != wire.ErrUnavailable {
			t.Errorf("503 body code %q, want %q", code503, wire.ErrUnavailable)
		}
		t.Logf("S13 cap: probe poll over the cap answered 503, Retry-After %ss, code %s (after %d probe(s))", retryAfter, code503, len(statuses))
	}
	if code, _, err := cp.do("GET", wire.PathFleet+"?tenant="+s13Tenant, nil, nil); err != nil || code != 200 {
		t.Errorf("admin fleet request while the poll cap is full: HTTP %d %v", code, err)
	}
	eventually(t, 150*time.Second, time.Second, "the cap-phase simulator to finish", func() (bool, string) {
		out, _ := docker("inspect", "-f", "{{.State.Running}}", s13Sim+"-cap")
		return out == "false", "still running"
	})
	ss3 := smp3.halt()
	rss3, hwm3, cores3, span3, n3 := summarise(ss3)
	rc := simResultOf(t, s13Sim+"-cap")
	t.Logf("S13 cap phase (SIMULATED, %d proxies against cap %d): polls %d (200: %d, 304: %d, 503: %d, errors: %d); control plane RSS peak %.1f MB (high-water %.1f MB), CPU %.3f cores over %.0fs (%d samples)",
		rc.Proxies, s13PollCap, rc.Polls.Total, rc.Polls.Modified, rc.Polls.NotModified, rc.Polls.Unavailable, rc.Polls.Errors, rss3, hwm3, cores3, span3.Seconds(), n3)
	if rc.Polls.Unavailable == 0 {
		t.Errorf("the simulator never saw a 503 with %d proxies against a cap of %d", s13CapN, s13PollCap)
	}
	if st := startedAt(); st != startedB || !strings.Contains(st, "oom=false") {
		t.Errorf("the control plane restarted or was OOM-killed during the cap phase: %q -> %q", startedB, st)
	}
	// load gone: the same probe is served normally (200 with the envelope, or 304 after the hold), not refused
	eventually(t, 90*time.Second, 2*time.Second, "the probe poll to be accepted again after the load is gone", func() (bool, string) {
		// have=2 equals the desired version, so an accepted probe is held (the 2 s client timeout fires, code 0) or answered 304
		c, _, _ := probe(0)
		return c != http.StatusServiceUnavailable, fmt.Sprintf("HTTP %d", c)
	})
	if code, _, err := cp.do("GET", wire.PathFleet+"?tenant="+s13Tenant, nil, nil); err != nil || code != 200 {
		t.Errorf("admin fleet request after the cap phase: HTTP %d %v", code, err)
	}
}

func cryptoRand(b []byte) {
	f, err := os.Open("/dev/urandom")
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, _ = io.ReadFull(f, b)
}
