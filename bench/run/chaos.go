package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// M5, M6 and M8 are reported from chaos scenarios, not re-measured (decision M-D66):
//
//	M5 outage correctness  <- S2 (control plane killed mid-traffic)
//	M6 bad-policy rejection <- S5 (unsigned, 1 signature, old version, wrong tenant, expired, corrupted)
//	M8 data leakage        <- S10 (canary strings planted in prompts, arguments and results; captured traffic scanned)
//
// The harness runs `E2E=1 go test -json` for S1 (so S2 starts from v2), S2, S5 and S10 against a fresh compose stack
// (the e2e TestMain builds and tears it down) and keeps the raw event stream next to a small summary.

// ChaosRun is the evidence of one go test invocation.
type ChaosRun struct {
	Index   int               `json:"run"`
	Tests   map[string]ChaosT `json:"tests"`
	Elapsed float64           `json:"elapsed_s"`
}

// ChaosT is one scenario's outcome plus the numbers parsed from its own log lines. -1 = the line was not found.
type ChaosT struct {
	Pass bool     `json:"pass"`
	Log  []string `json:"log,omitempty"` // the lines the numbers came from

	// S2 -> M5
	CallsTotal        int `json:"calls_total"`
	CallsDuringOutage int `json:"calls_during_outage"`
	WronglyAllowed    int `json:"wrongly_allowed"`
	WronglyBlocked    int `json:"wrongly_blocked"`
	// S5 -> M6
	BadPolicies int `json:"bad_policies"`
	Applied     int `json:"applied"`
	// S10 -> M8
	CanaryHits int `json:"canary_hits"`
	Bytes      int `json:"bytes_scanned"`
	Artifacts  int `json:"artifacts"`
	CPRequests int `json:"cp_requests_captured"`
}

type Chaos struct {
	Runs []ChaosRun `json:"runs"`
}

var (
	reTraffic = regexp.MustCompile(`traffic: (\d+) calls: \d+ allowed as expected, \d+ blocked as expected, (\d+) wrongly allowed, (\d+) wrongly blocked`)
	reOutage  = regexp.MustCompile(`calls during the outage window: (\d+)`)
	reS5      = regexp.MustCompile(`S5 result: (\d+) bad policies, (\d+) applied`)
	reS10     = regexp.MustCompile(`S10 result: (\d+) canary hits in (\d+) bytes over (\d+) artifacts; (\d+) proxy-to-CP requests captured`)
)

// Two invocations, each on a fresh stack. go test runs tests in file-name order and "s10_test.go" sorts before
// "s1_test.go", so one invocation would run S10 first and hand S1 a stack S10 has already used (S1 expects the
// pristine v1 stack of demo.sh).
var chaosGroups = [][]string{
	{"TestS1HappyRollout", "TestS2ControlPlaneKilledMidTraffic", "TestS5BadPolicies"},
	{"TestS10LeakCheck"},
}

var chaosTests = []string{"TestS1HappyRollout", "TestS2ControlPlaneKilledMidTraffic", "TestS5BadPolicies", "TestS10LeakCheck"}

func (o *opts) benchChaos(runs int) {
	logf("chaos evidence for M5 (S2), M6 (S5), M8 (S10): %d run(s), each on a fresh compose stack", runs)
	var ch Chaos
	for i := 1; i <= runs; i++ {
		raw := &bytes.Buffer{}
		run := ChaosRun{Index: i, Tests: map[string]ChaosT{}}
		t0 := time.Now()
		for _, grp := range chaosGroups {
			part := &bytes.Buffer{}
			cmd := exec.Command("go", "test", "-json", "-count=1", "-timeout", "40m", "-run", "^("+strings.Join(grp, "|")+")$", "./test/e2e/")
			cmd.Dir = o.root
			cmd.Env = append(os.Environ(), "E2E=1")
			cmd.Stdout = part
			cmd.Stderr = os.Stderr
			_ = cmd.Run() // a failing scenario is a result, parsed below
			raw.Write(part.Bytes())
			parseChaos(part, run.Tests)
		}
		run.Elapsed = time.Since(t0).Seconds()
		_ = os.WriteFile(filepath.Join(o.out, fmt.Sprintf("chaos-run%d.jsonl", i)), raw.Bytes(), 0o644)
		for _, name := range chaosTests {
			t := run.Tests[name]
			logf("chaos run %d: %s pass=%v %+v", i, name, t.Pass, summaryOf(t))
		}
		ch.Runs = append(ch.Runs, run)
	}
	if err := writeJSON(filepath.Join(o.out, "chaos.json"), ch); err != nil {
		fatalf("%v", err)
	}
}

func summaryOf(t ChaosT) string {
	return fmt.Sprintf("calls=%d outage=%d wrongly_allowed=%d bad=%d applied=%d hits=%d", t.CallsTotal, t.CallsDuringOutage, t.WronglyAllowed, t.BadPolicies, t.Applied, t.CanaryHits)
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func parseChaos(raw *bytes.Buffer, tests map[string]ChaosT) {
	sc := bufio.NewScanner(raw)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		var ev struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
			Output string `json:"Output"`
		}
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		t := tests[ev.Test]
		switch ev.Action {
		case "pass":
			t.Pass = true
		case "fail", "skip":
			t.Pass = false
		case "output":
			ln := strings.TrimSpace(ev.Output)
			if m := reTraffic.FindStringSubmatch(ln); m != nil {
				t.CallsTotal, t.WronglyAllowed, t.WronglyBlocked = atoi(m[1]), atoi(m[2]), atoi(m[3])
				t.Log = append(t.Log, ln)
			} else if m := reOutage.FindStringSubmatch(ln); m != nil {
				t.CallsDuringOutage = atoi(m[1])
				t.Log = append(t.Log, ln)
			} else if m := reS5.FindStringSubmatch(ln); m != nil {
				t.BadPolicies, t.Applied = atoi(m[1]), atoi(m[2])
				t.Log = append(t.Log, ln)
			} else if m := reS10.FindStringSubmatch(ln); m != nil {
				t.CanaryHits, t.Bytes, t.Artifacts, t.CPRequests = atoi(m[1]), atoi(m[2]), atoi(m[3]), atoi(m[4])
				t.Log = append(t.Log, ln)
			}
		}
		tests[ev.Test] = t
	}
}
