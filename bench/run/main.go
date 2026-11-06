// Command run is the Kairan benchmark harness (PLAN Q-06). It measures PRD section 9 targets M1, M2, M3, M4
// and M7 on the local Docker stack and writes machine-readable results to bench/out (gitignored).
// M5, M6 and M8 are not re-measured: the harness runs chaos scenarios S2, S5 and S10 and records their outcome.
// bench/results turns bench/out into RESULTS.md.
//
//	go run ./bench/run [-runs 5] [-rounds 3] [-only m1,m1sim,m2m3,m4go,m4e2e,m7,chaos] [-reuse] [-keep]
//
// Real measurements use the 10 real proxies of deploy/compose. Everything that uses kairan-sim is SIMULATED
// and says so in its result. A missed target is a result, never an error.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func sha256hex(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		fatalf("%v", err)
	}
	return hex.EncodeToString(b)
}

func main() {
	o := &opts{only: map[string]bool{}}
	var only string
	flag.IntVar(&o.runs, "runs", 5, "repetitions per metric (the PRD asks for at least 5)")
	flag.IntVar(&o.rounds, "rounds", 3, "rollouts per run for the propagation metric")
	flag.StringVar(&only, "only", "", "comma list of: m1, m1sim, m2m3, m4go, m4e2e, m7, chaos (default all)")
	flag.StringVar(&o.out, "out", "bench/out", "output directory")
	flag.BoolVar(&o.reuse, "reuse", false, "a compose stack is already up: do not build it or tear it down")
	flag.BoolVar(&o.keep, "keep", false, "leave the compose stack up at the end")
	chaosRuns := flag.Int("chaos-runs", 1, "how many times to run the chaos scenarios S1, S2, S5, S10")
	flag.Parse()
	if o.runs < 5 {
		fmt.Fprintln(os.Stderr, "bench: warning: fewer than 5 runs; the result will say so")
	}
	for _, s := range strings.Split(only, ",") {
		if s = strings.TrimSpace(s); s != "" {
			o.only[s] = true
		}
	}
	root, err := os.Getwd()
	if err != nil {
		fatalf("%v", err)
	}
	if _, err := os.Stat(root + "/go.mod"); err != nil {
		fatalf("run from the repository root (no go.mod in %s)", root)
	}
	o.root = root
	if !strings.HasPrefix(o.out, "/") {
		o.out = root + "/" + o.out
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		fatalf("%v", err)
	}
	o.writeEnv(*chaosRuns)

	if o.want("m4go") {
		o.benchM4Go()
	}
	needStack := o.want("m1") || o.want("m2m3") || o.want("m4e2e") || o.want("m1sim") || o.want("m7")
	if needStack {
		if !o.reuse {
			o.stackUp()
			if !o.keep {
				defer o.stackDown()
			}
		}
		w, err := o.loadWorld()
		if err != nil {
			fatalf("load the stack's generated secrets (is the compose stack up?): %v", err)
		}
		if o.want("m1") {
			w.benchM1Real()
		}
		if o.want("m4e2e") {
			w.benchM4E2E()
		}
		if o.want("m1sim") {
			w.benchM1Sim(100)
		}
		if o.want("m7") {
			w.benchM7() // also yields M1 with 1,000 simulated proxies
		}
		if o.want("m2m3") {
			w.benchM2M3()
		}
	}
	if o.want("chaos") {
		if needStack && !o.reuse && !o.keep {
			o.stackDown() // the chaos tests bring up their own fresh stack
		}
		o.benchChaos(*chaosRuns)
	}
	logf("done; results in %s", o.out)
}

// Env describes the machine and the tree the numbers were measured on.
type Env struct {
	Commit   string `json:"commit"`
	Dirty    bool   `json:"dirty"`
	DirtyWhy string `json:"dirty_files,omitempty"`
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

func sh(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (o *opts) writeEnv(chaosRuns int) {
	_ = chaosRuns
	e := Env{Date: time.Now().UTC().Format(time.RFC3339), Cores: runtime.NumCPU(), Go: runtime.Version(), Runs: o.runs, Rounds: o.rounds}
	e.Commit = sh("git", "-C", o.root, "rev-parse", "HEAD")
	// bench/out is ignored; any other change to a tracked or new file makes the tree dirty
	dirty := sh("git", "-C", o.root, "status", "--porcelain")
	e.Dirty, e.DirtyWhy = dirty != "", dirty
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "model name") {
				e.CPU = strings.TrimSpace(ln[strings.Index(ln, ":")+1:])
				break
			}
		}
	}
	if b, err := os.ReadFile("/proc/meminfo"); err == nil {
		var kb int
		fmt.Sscanf(strings.TrimPrefix(strings.Split(string(b), "\n")[0], "MemTotal:"), "%d", &kb)
		e.RAMMB = kb / 1024
	}
	osName := ""
	if b, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(ln, "PRETTY_NAME=") {
				osName = strings.Trim(strings.TrimPrefix(ln, "PRETTY_NAME="), `"`)
			}
		}
	}
	e.OS = strings.TrimSpace(osName + ", kernel " + sh("uname", "-r"))
	e.Docker = sh("docker", "version", "--format", "server {{.Server.Version}}, client {{.Client.Version}}")
	if info := sh("docker", "info", "--format", "{{.OperatingSystem}}, {{.NCPU}} CPUs, {{.MemTotal}} bytes"); info != "" {
		e.Docker += " (" + info + ")"
	}
	e.Go = sh("go", "version")
	if err := writeJSON(o.out+"/env.json", e); err != nil {
		fatalf("%v", err)
	}
}
