package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"kairan/internal/wire"
)

// The compose stack of deploy/compose: 10 REAL kairan-proxy containers (nothing simulated).
type px struct{ ID, Tenant, Group, Container string }

var tenants = []string{"bank-a", "city-b"}

var proxies = func() []px {
	spec := []struct{ t, g string }{
		{"bank-a", "canary"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"}, {"bank-a", "main"},
		{"city-b", "canary"}, {"city-b", "main"}, {"city-b", "main"}, {"city-b", "main"},
	}
	var out []px
	mains := 0
	for _, s := range spec {
		id := s.t + "-" + s.g
		if s.g == "main" {
			mains++
			id += fmt.Sprintf("-%d", mains)
		} else {
			mains = 0
		}
		out = append(out, px{ID: id, Tenant: s.t, Group: s.g, Container: "kairan-" + id})
	}
	return out
}()

func tenantProxies(tenant string) []px {
	var out []px
	for _, p := range proxies {
		if p.Tenant == tenant {
			out = append(out, p)
		}
	}
	return out
}

func proxyByID(id string) px {
	for _, p := range proxies {
		if p.ID == id {
			return p
		}
	}
	panic("unknown proxy " + id)
}

func containerRunning(name string) bool {
	out, err := docker("inspect", "-f", "{{.State.Running}}", name)
	return err == nil && out == "true"
}

// stackUp builds the image and brings the stack up with deploy/compose/demo.sh (v1 published, 10 acks).
func (o *opts) stackUp() {
	logf("bringing the compose stack up with deploy/compose/demo.sh (builds kairan:demo; DEMO_SRC=%q)", os.Getenv("DEMO_SRC"))
	cmd := exec.Command("bash", filepath.Join(o.root, "deploy", "compose", "demo.sh"), "demo")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		fatalf("demo.sh failed: %v", err)
	}
}

func (o *opts) stackDown() {
	_ = exec.Command("bash", filepath.Join(o.root, "deploy", "compose", "demo.sh"), "down").Run()
}

// baseline heals anything a previous measurement left broken and waits until all 10 proxies are healthy, in sync.
func (w *world) baseline() {
	for _, name := range []string{"kairan-cp", "kairan-fakemcp-bank-a", "kairan-fakemcp-city-b"} {
		if !containerRunning(name) {
			mustDocker("start", name)
		}
	}
	for _, p := range proxies {
		if !containerRunning(p.Container) {
			mustDocker("start", p.Container)
		}
		_, _ = docker("network", "connect", cloudNet, p.Container) // "already exists" is fine
	}
	waitFor(120*time.Second, time.Second, "baseline: all proxies healthy at their desired version", func() (bool, string) {
		var bad []string
		for _, tn := range tenants {
			fv, err := w.cp.fleet(tn)
			if err != nil {
				return false, err.Error()
			}
			if len(fv.Proxies) != len(tenantProxies(tn)) {
				return false, fmt.Sprintf("%s: %d proxies in fleet view", tn, len(fv.Proxies))
			}
			for _, r := range fv.Proxies {
				if r.Health != wire.HealthHealthy || r.Drift != 0 || r.State != wire.StateEnforcing {
					bad = append(bad, fmt.Sprintf("%s(%s,%s,drift %d)", r.ProxyID, r.Health, r.State, r.Drift))
				}
			}
		}
		return len(bad) == 0, strings.Join(bad, " ")
	})
}

// waitAcked polls the fleet view every 100 ms until the listed proxies of tenant applied >= v.
func (c *cpc) waitAcked(tenant string, v uint64, only []string, limit time.Duration) {
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	waitFor(limit, 100*time.Millisecond, fmt.Sprintf("%s proxies to ack v%d", tenant, v), func() (bool, string) {
		fv, err := c.fleet(tenant)
		if err != nil {
			return false, err.Error()
		}
		var behind []string
		n := 0
		for _, r := range fv.Proxies {
			if len(want) > 0 && !want[string(r.ProxyID)] {
				continue
			}
			n++
			if r.AppliedVersion < v {
				behind = append(behind, fmt.Sprintf("%s@%d", r.ProxyID, r.AppliedVersion))
			}
		}
		if len(want) > 0 && n != len(want) {
			return false, fmt.Sprintf("%d of %d listed proxies in the view", n, len(want))
		}
		return len(behind) == 0 && n > 0, "behind: " + strings.Join(behind, ",")
	})
}
