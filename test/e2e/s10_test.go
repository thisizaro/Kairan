package e2e

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"kairan/internal/wire"
)

// S10 leak check (G7, M8, I4, PRD J1): canary secrets are planted in prompts, tool arguments, tool results,
// tool names, API keys, headers and URL paths, mixed traffic is driven through the real compose stack, and
// everything the control plane side can see is scanned for the canaries (and for their hex, base64 and URL
// encodings). Pass: 0 hits.
//
// Wiring (nothing simulated, no new image; two small stdlib tools are built from deploy/compose/s10tool and
// mounted into kairan:demo containers, like the S9 forward proxy):
//
//	agents -> real kairan-proxy (all 10) -> upstream "s10-up" (one per tenant network; its tool results,
//	                                         descriptions and a response header carry canaries)
//	real kairan-proxy (all 10) -> capture sidecar "s10-cap" (cloud network) -> kairan-cp
//
// The 10 proxies' config files are edited on disk (cp_url -> the capture sidecar, upstream -> the canary
// upstream) and the proxies restarted; the cleanup restores both. The sidecar writes every request and
// response (headers and bodies, raw) to deploy/compose/.run/s10/capture.raw (gitignored; never committed).
//
// Scanned: the raw capture of all proxy-to-CP traffic (polls, policy envelopes, status reports, error
// bodies), the CP's logs, the CP's /metrics, the CP's data_dir (docker cp), the fleet JSON, rollout JSON,
// timeline JSON and the fleet page in English and Japanese for both tenants, every proxy's /metrics and
// /v1/self, Prometheus's label sets, and the proxies' own logs (tool-name canaries there are reported but not
// failed: a local deny log may name the tool). Positive controls prove each capture point sees real data.
const (
	s10CapPort   = 18199
	s10UpBankA   = 18197
	s10UpCityB   = 18198
	s10CapAlias  = "s10-cap"
	s10UpAlias   = "s10-up"
	s10Traffic   = 30 * time.Second
	s10Workers   = 8
	s10BigFiller = 60 << 10
)

var s10Containers = []string{"kairan-s10-cap", "kairan-s10-up-bank-a", "kairan-s10-up-city-b"}

func s10Cleanup() {
	for _, c := range s10Containers {
		_, _ = docker("rm", "-f", "-v", c)
	}
}

func httpGetBytes(hc *http.Client, url string, user string, pass string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	return b, res.StatusCode, nil
}

func (w *world) adminRaw(path string) ([]byte, error) {
	req, _ := http.NewRequest("GET", cpURL+path, nil)
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+w.adminToken)
	res, err := w.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if res.StatusCode != 200 {
		return b, fmt.Errorf("%s: HTTP %d", path, res.StatusCode)
	}
	return b, nil
}

func jsonStat(hc *http.Client, port int, key string) (int64, error) {
	b, code, err := httpGetBytes(hc, fmt.Sprintf("http://127.0.0.1:%d/_s10/stats", port), "", "")
	if err != nil || code != 200 {
		return 0, fmt.Errorf("stats: HTTP %d %v", code, err)
	}
	m := map[string]int64{}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, err
	}
	return m[key], nil
}

type s10Canaries struct {
	prompt, argument, nested, result, badKey, toolName, header, path, id, jp canary
}

type s10Counts struct {
	total, allowedOK, deniedOK, wrongYes, wrongNo, netErr atomic.Int64
	resultCanaryBack                                      atomic.Int64
	kinds                                                 [8]atomic.Int64
	mu                                                    sync.Mutex
	samples                                               []string
}

func (c *s10Counts) note(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.samples) < 8 {
		c.samples = append(c.samples, s)
	}
}

func rpcBody(id any, method string, params any) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return b
}

// fire sends one attack request through proxy p and updates the counters. kind selects the attack.
func (cn *s10Canaries) fire(hc *http.Client, w *world, p px, kind int, rng *rand.Rand, versions map[string]uint64, c *s10Counts) {
	role := []string{"sales", "intern"}[rng.Intn(2)]
	key := w.keyFor(role)
	pick := callMix[rng.Intn(len(callMix))]
	tool := pick.tool
	path := "/"
	var body []byte
	hdr := map[string]string{}
	expectDenied := false // a request that must never be answered as allowed
	oracle := false       // judge allowed/blocked against the policy oracle
	switch kind {
	case 0: // allowed or forbidden tools/call, canaries in the arguments
		role = pick.role
		key = w.keyFor(role)
		body = rpcBody(cn.id.needle, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{
			"query":   "customer record lookup " + cn.argument.needle,
			"prompt":  "summarise the account for " + cn.prompt.needle + " and email it",
			"nested":  map[string]any{"deep": []any{cn.nested.needle, map[string]any{"k": "v " + cn.nested.needle}}},
			"message": "顧客の機密 " + cn.jp.needle,
		}})
		oracle = true
	case 1: // unknown tool whose name is the canary: default deny
		body = rpcBody(1, "tools/call", map[string]any{"name": "kcanary-" + cn.toolName.needle, "arguments": map[string]any{"q": cn.argument.needle}})
		expectDenied = true
	case 2: // an API key that is the canary: must be refused
		key = "sk-" + cn.badKey.needle
		body = rpcBody(2, "tools/call", map[string]any{"name": "notes.read", "arguments": map[string]any{"q": cn.argument.needle}})
		expectDenied = true
	case 3: // headers
		body = rpcBody(3, "tools/list", map[string]any{})
		hdr["User-Agent"] = "agent/" + cn.header.needle
		hdr["X-Request-Id"] = cn.header.needle
		hdr["Cookie"] = "session=" + cn.header.needle
		hdr["X-Forwarded-For"] = "10.0.0.1, " + cn.header.needle
	case 4: // another MCP method carrying a prompt
		body = rpcBody(4, "prompts/get", map[string]any{"name": "brief", "arguments": map[string]any{"text": cn.prompt.needle}})
	case 5: // a large body with the canary at the very end
		body = rpcBody(5, "tools/call", map[string]any{"name": "notes.read", "arguments": map[string]any{
			"filler": strings.Repeat("a", s10BigFiller), "tail": cn.argument.needle}})
	case 6: // canary in the URL path and query
		path = "/mcp/" + cn.path.needle + "?q=" + cn.path.needle
		body = rpcBody(6, "tools/call", map[string]any{"name": "crm.export", "arguments": map[string]any{}})
		expectDenied = true // crm.export is X: denied for every role
	case 7: // Japanese prompt inside an allowed read
		body = rpcBody(7, "tools/call", map[string]any{"name": "notes.read", "arguments": map[string]any{
			"prompt": "以下の顧客情報を要約してください: " + cn.jp.needle + " / " + cn.prompt.needle}})
		oracle = true
		role, tool, key = "sales", "notes.read", w.salesKey
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://127.0.0.1:%d%s", p.MCP, path), bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(wire.HeaderAuthorization, wire.BearerPrefix+key)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := hc.Do(req)
	c.total.Add(1)
	c.kinds[kind].Add(1)
	if err != nil {
		c.netErr.Add(1)
		c.note(fmt.Sprintf("transport error on %s kind %d: %v", p.ID, kind, err))
		return
	}
	rb, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	res.Body.Close()
	text := string(rb)
	var doc struct {
		Result *struct {
			IsError bool `json:"isError"`
		} `json:"result"`
	}
	_ = json.Unmarshal(rb, &doc)
	blocked := strings.Contains(text, "blocked by policy")
	allowed := res.StatusCode == 200 && doc.Result != nil && !doc.Result.IsError && !blocked
	if allowed && strings.Contains(text, cn.result.needle) {
		c.resultCanaryBack.Add(1)
	}
	switch {
	case expectDenied && allowed:
		c.wrongYes.Add(1)
		c.note(fmt.Sprintf("WRONGLY ALLOWED kind %d on %s: %.120s", kind, p.ID, text))
	case oracle:
		want := wantAllowed(role, tool, versions[p.Tenant])
		switch {
		case allowed && !want:
			c.wrongYes.Add(1)
			c.note(fmt.Sprintf("WRONGLY ALLOWED on %s: %s/%s: %.120s", p.ID, role, tool, text))
		case !allowed && want:
			c.wrongNo.Add(1)
			c.note(fmt.Sprintf("wrongly blocked on %s: %s/%s: HTTP %d %.120s", p.ID, role, tool, res.StatusCode, text))
		case allowed:
			c.allowedOK.Add(1)
		default:
			c.deniedOK.Add(1)
		}
	}
}

func dockerCPData(container, dir string) (map[string][]byte, error) {
	out, err := exec.Command("docker", "cp", container+":"+dir+"/.", "-").Output()
	if err != nil {
		return nil, fmt.Errorf("docker cp %s:%s: %w", container, dir, err)
	}
	files := map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(out))
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		b, _ := io.ReadAll(tr)
		files[h.Name] = b
	}
	return files, nil
}

func TestS10LeakCheck(t *testing.T) {
	w := need(t)
	w.baseline(t)
	s10Cleanup()

	dir := filepath.Join(w.run, "s10")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o777)
	capFile := filepath.Join(dir, "capture.raw")

	// ---- canaries ----
	cn := &s10Canaries{
		prompt: newCanary("prompt"), argument: newCanary("argument"), nested: newCanary("argument-nested"),
		result: newCanary("result"), badKey: newCanary("api-key"), toolName: newCanary("tool-name"),
		header: newCanary("header"), path: newCanary("path"), id: newCanary("jsonrpc-id"), jp: newCanary("prompt-ja"),
	}
	secrets := []canary{cn.prompt, cn.argument, cn.nested, cn.result, cn.badKey, cn.toolName, cn.header, cn.path, cn.id, cn.jp,
		{kind: "real-api-key", needle: w.salesKey}, {kind: "real-api-key", needle: w.internKey}}
	respHeaderCanary := newCanary("upstream-response-header")
	secrets = append(secrets, respHeaderCanary)

	// ---- tools ----
	root := filepath.Join(w.compose, "..", "..")
	tool := filepath.Join(dir, "s10tool")
	build := exec.Command("go", "build", "-o", tool, "./deploy/compose/s10tool")
	build.Dir = root
	build.Env = append(os.Environ(), "CGO_ENABLED=0", "GOFLAGS=-trimpath")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build s10tool: %v\n%s", err, out)
	}

	// ---- restore on the way out, whatever happens ----
	origCfg := map[string][]byte{}
	var restoreOnce sync.Once
	restore := func() {
		restoreOnce.Do(func() {
			for _, p := range proxies {
				if b, ok := origCfg[p.ID]; ok {
					_ = os.WriteFile(filepath.Join(w.run, "proxies", p.ID+".json"), b, 0o644)
				}
			}
			if len(origCfg) > 0 {
				var wg sync.WaitGroup
				for _, p := range proxies {
					wg.Add(1)
					go func(p px) { defer wg.Done(); _, _ = docker("restart", "-t", "5", p.Container) }(p)
				}
				wg.Wait()
			}
			s10Cleanup()
			w.baseline(t)
		})
	}
	t.Cleanup(restore)

	hard := []string{"--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"}
	mustDocker(t, append(append([]string{"run", "-d", "--name", "kairan-s10-cap", "--network", cloudNet, "--network-alias", s10CapAlias,
		"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", dir + ":/cap", "-v", tool + ":/usr/local/bin/s10tool:ro",
		"-p", fmt.Sprintf("127.0.0.1:%d:8080", s10CapPort)}, hard...),
		image, "s10tool", "capture", "-listen", "0.0.0.0:8080", "-to", "http://cp:8080", "-out", "/cap/capture.raw")...)
	for i, tn := range tenants {
		mustDocker(t, append(append([]string{"run", "-d", "--name", "kairan-s10-up-" + tn, "--network", "kairan-demo_" + tn, "--network-alias", s10UpAlias,
			"-v", tool + ":/usr/local/bin/s10tool:ro", "-p", fmt.Sprintf("127.0.0.1:%d:9000", s10UpBankA+i)}, hard...),
			image, "s10tool", "upstream", "-listen", "0.0.0.0:9000", "-result", cn.result.needle, "-header", respHeaderCanary.needle, "-seen", cn.argument.needle)...)
	}
	eventually(t, 30*time.Second, 300*time.Millisecond, "capture sidecar and canary upstreams to answer", func() (bool, string) {
		for _, port := range []int{s10CapPort, s10UpBankA, s10UpCityB} {
			if _, err := jsonStat(w.hc, port, "requests"); err != nil {
				return false, fmt.Sprintf("port %d: %v", port, err)
			}
		}
		return true, ""
	})

	// ---- put all 10 real proxies behind the sidecar and the canary upstream (config on disk + restart) ----
	for _, p := range proxies {
		path := filepath.Join(w.run, "proxies", p.ID+".json")
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		origCfg[p.ID] = b
		var cfg map[string]any
		if err := json.Unmarshal(b, &cfg); err != nil {
			t.Fatal(err)
		}
		cfg["cp_url"] = "http://" + s10CapAlias + ":8080"
		cfg["upstream"] = "http://" + s10UpAlias + ":9000"
		nb, _ := json.Marshal(cfg)
		if err := os.WriteFile(path, nb, 0o644); err != nil { // same inode: the bind mount sees it
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for _, p := range proxies {
		wg.Add(1)
		go func(p px) { defer wg.Done(); _, _ = docker("restart", "-t", "5", p.Container) }(p)
	}
	wg.Wait()
	eventually(t, 90*time.Second, time.Second, "all 10 proxies to report through the capture sidecar", func() (bool, string) {
		raw, _ := os.ReadFile(capFile)
		var missing []string
		for _, p := range proxies {
			tok, err := readTrim(filepath.Join(w.run, "proxies", p.ID+".token"))
			if err != nil || !bytes.Contains(raw, []byte(tok)) {
				missing = append(missing, p.ID)
			}
		}
		if len(missing) > 0 {
			return false, "not seen in capture: " + strings.Join(missing, ",")
		}
		for _, tn := range tenants {
			fv, err := w.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			for _, r := range fv.Proxies {
				if r.Health != wire.HealthHealthy || r.State != wire.StateEnforcing || r.Drift != 0 {
					return false, fmt.Sprintf("%s %s %s", r.ProxyID, r.Health, r.State)
				}
			}
		}
		return true, ""
	})

	// the oracle needs a policy where the answer is the same before and after the mid-run release
	versions := map[string]uint64{}
	for _, tn := range tenants {
		if cur := w.currentVersion(t, tn); cur < 2 {
			v, _, _ := w.release(t, tn, 2)
			w.ackTimes(t, map[string]uint64{tn: v}, 60*time.Second)
		}
		versions[tn] = w.currentVersion(t, tn)
	}

	// ---- traffic ----
	counts := &s10Counts{}
	stop := make(chan struct{})
	var twg sync.WaitGroup
	for i := 0; i < s10Workers; i++ {
		twg.Add(1)
		go func(seed int64) {
			defer twg.Done()
			rng := rand.New(rand.NewSource(seed))
			hc := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			for n := 0; ; n++ {
				select {
				case <-stop:
					return
				default:
				}
				cn.fire(hc, w, proxies[rng.Intn(len(proxies))], n%8, rng, versions, counts)
				time.Sleep(2 * time.Millisecond)
			}
		}(int64(i) + time.Now().UnixNano())
	}
	// control plane activity during the traffic: a new release of each tenant (policy envelopes, statuses and
	// acks flow through the capture) and a rejected publish (an error body)
	time.Sleep(s10Traffic / 3)
	rel := map[string]uint64{}
	for _, tn := range tenants {
		v, _, _ := w.release(t, tn, 2)
		rel[tn] = v
	}
	bad := w.envelope(goodPayload("bank-a", w.nextVersion("bank-a")), "admin-a") // one signature only
	if code, _, _, err := w.publish(bad); err != nil || code/100 == 2 {
		t.Errorf("a one-signature publish should be refused: HTTP %d %v", code, err)
	}
	w.ackTimes(t, rel, 60*time.Second)
	time.Sleep(s10Traffic - s10Traffic/3)
	close(stop)
	twg.Wait()
	// let the periodic status reports and metrics scrapes (10 s) happen after the last call
	time.Sleep(14 * time.Second)

	t.Logf("S10 traffic: %d requests through the proxies: %d allowed as expected, %d denied as expected, %d wrongly allowed, %d wrongly blocked, %d transport errors; attack kinds %v",
		counts.total.Load(), counts.allowedOK.Load(), counts.deniedOK.Load(), counts.wrongYes.Load(), counts.wrongNo.Load(), counts.netErr.Load(), func() []int64 {
			var o []int64
			for i := range counts.kinds {
				o = append(o, counts.kinds[i].Load())
			}
			return o
		}())
	for _, s := range counts.samples {
		t.Logf("  sample: %s", s)
	}
	if counts.wrongYes.Load() != 0 {
		t.Errorf("I3 violated: %d requests were allowed that policy or authentication forbids", counts.wrongYes.Load())
	}
	if counts.wrongNo.Load() != 0 {
		t.Errorf("%d requests the policy allows were blocked", counts.wrongNo.Load())
	}
	if counts.total.Load() < 500 || counts.allowedOK.Load() == 0 || counts.deniedOK.Load() == 0 {
		t.Errorf("traffic too thin to mean anything: %d requests, %d allowed, %d denied", counts.total.Load(), counts.allowedOK.Load(), counts.deniedOK.Load())
	}

	// ---- positive controls: the canaries really travelled, and the capture points really see data ----
	var seenUp int64
	for i := range tenants {
		n, err := jsonStat(w.hc, s10UpBankA+i, "calls_with_seen")
		if err != nil {
			t.Errorf("upstream stats: %v", err)
		}
		seenUp += n
	}
	if seenUp < 50 {
		t.Errorf("only %d calls reached the upstreams carrying the argument canary: the plant did not happen", seenUp)
	}
	if counts.resultCanaryBack.Load() < 50 {
		t.Errorf("only %d allowed answers carried the upstream result canary back to the agent", counts.resultCanaryBack.Load())
	}

	// ---- collect and scan ----
	strict := newScanner(secrets...)
	var nonToolName []canary
	for _, c := range secrets {
		if c.kind != "tool-name" {
			nonToolName = append(nonToolName, c)
		}
	}
	local := newScanner(nonToolName...)
	toolInfo := newScanner(cn.toolName)

	// pipeline control: a request that carries a known canary through the sidecar must show up in the capture
	// (and the scanner must flag it there), proving the capture and the scan can see a leak if there were one
	control := newCanary("control")
	if req, err := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/v1/poll?tenant=bank-a&junk=%s", s10CapPort, control.needle), nil); err == nil {
		req.Header.Set("X-S10-Control", control.needle)
		if res, err := w.hc.Do(req); err == nil {
			_ = res.Body.Close()
		}
	}
	raw, err := os.ReadFile(capFile)
	if err != nil {
		t.Fatalf("capture file: %v", err)
	}
	if ctl := newScanner(control); func() bool { ctl.scan("control", raw); return len(ctl.Hits) == 0 }() {
		t.Errorf("positive control failed: a canary sent through the capture sidecar was not found in the capture")
	}
	capRequests, err := jsonStat(w.hc, s10CapPort, "requests")
	if err != nil || capRequests < 100 {
		t.Fatalf("capture sidecar saw %d requests (%v): too few to mean anything", capRequests, err)
	}
	for _, p := range proxies {
		tok, _ := readTrim(filepath.Join(w.run, "proxies", p.ID+".token"))
		if !bytes.Contains(raw, []byte(tok)) {
			t.Errorf("positive control: the capture never saw %s's enrollment token", p.ID)
		}
	}
	for _, must := range []string{"POST /v1/status", "GET /v1/poll", "\"payloadType\"", "\"applied_version\""} {
		if !bytes.Contains(raw, []byte(must)) {
			t.Errorf("positive control: the capture holds no %q (policy delivery or status reports not captured)", must)
		}
	}
	strict.scan("proxy-to-cp capture (raw)", raw)

	if out, err := docker("logs", "kairan-cp"); err == nil {
		strict.scan("cp docker logs", []byte(out))
	} else {
		t.Errorf("cp logs: %v", err)
	}
	if b, code, err := httpGetBytes(w.hc, "http://127.0.0.1:19100/metrics", "", ""); err == nil && code == 200 {
		strict.scan("cp /metrics", b)
	} else {
		t.Errorf("cp /metrics: HTTP %d %v", code, err)
	}
	cpFiles, err := dockerCPData("kairan-cp", "/data")
	if err != nil || len(cpFiles) == 0 {
		t.Errorf("cp data_dir: %v (%d files)", err, len(cpFiles))
	}
	haveTenant := false
	for name, b := range cpFiles {
		strict.scan("cp data_dir: "+name, b)
		if bytes.Contains(b, []byte("bank-a")) {
			haveTenant = true
		}
	}
	if !haveTenant {
		t.Errorf("positive control: the cp data_dir scan found no file mentioning the tenant (%d files)", len(cpFiles))
	}
	for _, tn := range tenants {
		for _, path := range []string{wire.PathFleet, wire.PathTimeline, wire.PathRollouts} {
			if b, err := w.adminRaw(path + "?tenant=" + tn); err == nil {
				strict.scan("cp "+path+" "+tn, b)
			} else {
				t.Errorf("%s %s: %v", path, tn, err)
			}
		}
		for _, lang := range []string{"en", "ja"} {
			if page, err := w.fleetPage(tn, lang); err == nil {
				strict.scan("fleet page "+lang+" "+tn, []byte(page))
			} else {
				t.Errorf("fleet page %s %s: %v", tn, lang, err)
			}
		}
	}
	for _, p := range proxies {
		if b, code, err := httpGetBytes(w.hc, fmt.Sprintf("http://127.0.0.1:%d/metrics", p.Metrics), "", ""); err == nil && code == 200 {
			strict.scan("proxy /metrics", b)
		} else {
			t.Errorf("%s /metrics: HTTP %d %v", p.ID, code, err)
		}
		if b, code, err := httpGetBytes(w.hc, fmt.Sprintf("http://127.0.0.1:%d/v1/self", p.Metrics), "", ""); err == nil && code == 200 {
			strict.scan("proxy /v1/self", b)
		}
		if out, err := docker("logs", p.Container); err == nil {
			local.scan("proxy docker logs", []byte(out))
			toolInfo.scan("proxy docker logs (tool-name canary, informational)", []byte(out))
		}
	}
	if b, code, err := httpGetBytes(w.hc, `http://127.0.0.1:19090/api/v1/series?match[]=%7B__name__%3D~%22.%2B%22%7D`, "", ""); err == nil && code == 200 {
		strict.scan("prometheus series (label sets)", b)
	} else {
		t.Logf("prometheus series not scanned: HTTP %d %v", code, err)
	}

	t.Logf("S10 scanned %d bytes in %d artifacts (%d proxy-to-CP requests captured, %d canary strings x their encodings):\n%s",
		strict.Bytes+local.Bytes, strict.Items+local.Items, capRequests, len(secrets), strict.report()+local.report())
	t.Logf("S10 proxy logs: tool-name canary appears %d time(s) in local logs (informational, not a failure)", len(toolInfo.Hits))
	for _, h := range append(strict.Hits, local.Hits...) {
		t.Errorf("LEAK: canary of kind %q found in %q (encoding %s, offset %d)", h.kind, h.source, h.variant, h.offset)
	}
	t.Logf("S10 result: %d canary hits in %d bytes over %d artifacts; %d proxy-to-CP requests captured", len(strict.Hits)+len(local.Hits),
		strict.Bytes+local.Bytes, strict.Items+local.Items, capRequests)

	restore()
}
