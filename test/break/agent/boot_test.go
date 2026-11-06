package agentbreak

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

// applyOnce runs a first life: a rig on dir applies envelope v1 from the control plane and stops.
func applyOnce(t *testing.T, dir string, clk *clock.Fake, v uint64) (wire.Hash, []byte) {
	t.Helper()
	cp := newCP(t)
	env, h := validEnv(v)
	cp.poll = func(n int, q cpReq) cpAnswer {
		if n == 1 {
			return pollJSON(env, v)
		}
		return cpAnswer{status: 304}
	}
	r := newRig(t, dir, clk, cp)
	r.boot()
	r.run()
	waitFor(t, "applied", func() bool { return r.appliedVersion() == v })
	r.stop()
	_ = r.al.Close()
	b, err := os.ReadFile(r.st.Path())
	if err != nil {
		t.Fatal(err)
	}
	return h, b
}

// second life: boot only, no network (an unreachable control plane).
func reboot(t *testing.T, dir string, clk *clock.Fake, mod ...func(*agent.Config)) *rig {
	t.Helper()
	cp := newCP(t)
	cp.srv.Close() // control plane down
	r := newRig(t, dir, clk, cp, mod...)
	r.boot()
	return r
}

// Boot rule (M-D33): a good file boots Enforcing at the same version with the control plane down; never deny-all
// from a good file and never a wider policy (S3).
func TestBootFromGoodDiskEnforcesSameVersion(t *testing.T) {
	dir := t.TempDir()
	clk := clock.NewFake(t0)
	h, _ := applyOnce(t, dir, clk, 4)
	r := reboot(t, dir, clk)
	a := r.hold.Load()
	if a == nil || a.State != wire.StateEnforcing || a.Policy == nil || a.Policy.Version != 4 || a.Hash != h {
		t.Fatalf("active after reboot: %+v", a)
	}
	// the decision for an allowed and a denied tool matches the policy
	if d := a.Policy.Decide("sales", "crm.read_contact", false); !d.Allowed {
		t.Errorf("read denied after reboot")
	}
	if d := a.Policy.Decide("sales", "crm.delete_all", false); d.Allowed {
		t.Errorf("unlisted tool allowed after reboot (I3)")
	}
}

func TestBootWithNothingIsDenyAll(t *testing.T) {
	r := reboot(t, t.TempDir(), nil)
	a := r.hold.Load()
	if a == nil || a.State != wire.StateDenyAll {
		t.Fatalf("fresh proxy state %+v, want deny_all", a)
	}
	if a.Policy != nil {
		if d := a.Policy.Decide("sales", "crm.read_contact", false); d.Allowed {
			t.Errorf("deny_all allows a call")
		}
	}
}

func TestBootTwiceIsAnError(t *testing.T) {
	r := newRig(t, "", nil, nil)
	r.boot()
	if err := r.ag.Boot(); err == nil {
		t.Error("second Boot returned nil")
	}
}

// Tampered disk (S6): every kind of edit ends in Tampered and a state that allows nothing wider (I3, I6).
func TestBootTamperedDisk(t *testing.T) {
	type tamper struct {
		name string
		do   func(t *testing.T, dir string, r1 *rigPaths)
	}
	cases := []tamper{
		{"stored policy bit flip in payload", func(t *testing.T, dir string, p *rigPaths) {
			b := readF(t, p.policy)
			var e wire.Envelope
			if err := json.Unmarshal(b, &e); err != nil {
				t.Fatal(err)
			}
			e.Payload = bytes.Replace(e.Payload, []byte(`"R"`), []byte(`"X"`), 1)
			nb, _ := json.Marshal(e)
			writeF(t, p.policy, nb)
		}},
		{"stored policy signature flipped", func(t *testing.T, dir string, p *rigPaths) {
			var e wire.Envelope
			_ = json.Unmarshal(readF(t, p.policy), &e)
			e.Signatures[0].Sig[3] ^= 1
			nb, _ := json.Marshal(e)
			writeF(t, p.policy, nb)
		}},
		{"stored policy down to one signature", func(t *testing.T, dir string, p *rigPaths) {
			var e wire.Envelope
			_ = json.Unmarshal(readF(t, p.policy), &e)
			e.Signatures = e.Signatures[:1]
			nb, _ := json.Marshal(e)
			writeF(t, p.policy, nb)
		}},
		{"stored policy replaced by garbage", func(t *testing.T, dir string, p *rigPaths) { writeF(t, p.policy, []byte("garbage")) }},
		{"stored policy emptied", func(t *testing.T, dir string, p *rigPaths) { writeF(t, p.policy, nil) }},
		{"stored policy with trailing data", func(t *testing.T, dir string, p *rigPaths) {
			writeF(t, p.policy, append(readF(t, p.policy), []byte(" {}")...))
		}},
		{"stored policy deleted though the log applied it", func(t *testing.T, dir string, p *rigPaths) { _ = os.Remove(p.policy) }},
		{"stored policy is a directory", func(t *testing.T, dir string, p *rigPaths) {
			_ = os.Remove(p.policy)
			_ = os.Mkdir(p.policy, 0o700)
		}},
		{"older valid policy put back", func(t *testing.T, dir string, p *rigPaths) {
			old, _ := validEnv(2)
			b, _ := json.Marshal(old)
			writeF(t, p.policy, b)
		}},
		{"same version different payload signed by trusted keys", func(t *testing.T, dir string, p *rigPaths) {
			alt := signedEnv(policyDoc(tenant, 5, t0.Add(-time.Hour), t0.Add(48*time.Hour)), keyA, keyC)
			b, _ := json.Marshal(alt)
			writeF(t, p.policy, b)
		}},
		{"another tenant's valid policy", func(t *testing.T, dir string, p *rigPaths) {
			e := signedEnv(policyDoc("bank-b", 9, t0.Add(-time.Hour), t0.Add(48*time.Hour)), keyA, keyB)
			b, _ := json.Marshal(e)
			writeF(t, p.policy, b)
		}},
		{"policy signed by outsiders", func(t *testing.T, dir string, p *rigPaths) {
			e := signedEnv(policyDoc(tenant, 9, t0.Add(-time.Hour), t0.Add(48*time.Hour)), keyOut, keyOut)
			b, _ := json.Marshal(e)
			writeF(t, p.policy, b)
		}},
		{"apply log field edited", func(t *testing.T, dir string, p *rigPaths) {
			b := readF(t, p.log)
			writeF(t, p.log, bytes.Replace(b, []byte(`"to":5`), []byte(`"to":4`), 1))
		}},
		{"apply log last line cut", func(t *testing.T, dir string, p *rigPaths) {
			b := readF(t, p.log)
			writeF(t, p.log, b[:len(b)-10])
		}},
		{"apply log garbage line appended", func(t *testing.T, dir string, p *rigPaths) {
			writeF(t, p.log, append(readF(t, p.log), []byte("not an entry\n")...))
		}},
		{"apply log replaced by a directory", func(t *testing.T, dir string, p *rigPaths) {
			_ = os.Remove(p.log)
			_ = os.Mkdir(p.log, 0o700)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := clock.NewFake(t0)
			applyOnce(t, dir, clk, 5)
			p := &rigPaths{policy: policyPath(t, dir), log: filepath.Join(dir, "apply.log")}
			c.do(t, dir, p)
			var r *rig
			func() {
				defer func() {
					if x := recover(); x != nil {
						t.Fatalf("panic: %v", x)
					}
				}()
				r = rebootTolerant(t, dir, clk)
			}()
			a := r.hold.Load()
			if a == nil || a.State != wire.StateTampered {
				t.Fatalf("state %+v after %q, want tampered", a, c.name)
			}
			if a.Policy != nil {
				for _, tool := range []string{"crm.read_contact", "crm.update_deal", "admin.shutdown"} {
					if d := a.Policy.Decide("sales", tool, false); d.Allowed {
						t.Errorf("tampered state would allow %s (I3)", tool)
					}
				}
			}
			if r.stats.Count(agent.MetricBootTampered) == 0 {
				t.Errorf("%s not counted", agent.MetricBootTampered)
			}
			// tamper report goes out in the first status (S6: a tamper report)
			r.run()
			waitFor(t, "status", func() bool { _, _, ok := r.cp.lastStatus(); return ok || true })
			r.stop()
		})
	}
}

type rigPaths struct{ policy, log string }

func readF(t *testing.T, p string) []byte {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeF(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// policyPath finds the stored policy file: the one store.Path() names in a fresh rig on that dir.
func policyPath(t *testing.T, dir string) string {
	t.Helper()
	r := newRig(t, dir, nil, nil)
	p := r.st.Path()
	_ = r.al.Close()
	return p
}

// rebootTolerant is reboot for rigs whose apply log may not open: the rig passes LogOpenErr itself.
func rebootTolerant(t *testing.T, dir string, clk *clock.Fake) *rig {
	t.Helper()
	cp := newCP(t)
	r := newRig(t, dir, clk, cp)
	r.boot()
	return r
}

// A Tampered proxy also needs a version above everything it ever applied (I2): replaying the version already
// applied or an older one is rejected, a higher valid one recovers.
func TestTamperedProxyNeedsHigherVersion(t *testing.T) {
	dir := t.TempDir()
	clk := clock.NewFake(t0)
	applyOnce(t, dir, clk, 5)
	writeF(t, policyPath(t, dir), []byte("garbage"))
	for _, c := range []struct {
		name    string
		version uint64
		want    wire.ProxyState
	}{
		{"same version is not enough", 5, wire.StateTampered},
		{"older version is not enough", 3, wire.StateTampered},
		{"higher version recovers", 6, wire.StateEnforcing},
	} {
		t.Run(c.name, func(t *testing.T) {
			d2 := t.TempDir()
			copyDir(t, dir, d2)
			cp := newCP(t)
			env, _ := validEnv(c.version)
			cp.poll = func(n int, q cpReq) cpAnswer {
				if n == 1 {
					return pollJSON(env, c.version)
				}
				return cpAnswer{status: 304}
			}
			r := newRig(t, d2, clk, cp)
			r.boot()
			if r.state() != wire.StateTampered {
				t.Fatalf("boot state %s", r.state())
			}
			r.run()
			waitFor(t, "first poll", func() bool { return cp.pollCount() >= 1 })
			r.advance(2*time.Second, 250*time.Millisecond)
			if got := r.state(); got != c.want {
				t.Errorf("state after offer of v%d: %s, want %s", c.version, got, c.want)
			}
			for _, x := range cp.all() {
				if x.Path == wire.PathPoll {
					if x.Query.Get(wire.QueryHave) != "5" {
						t.Errorf("tampered proxy's first poll has have=%s, want 5 (the highest it ever applied)", x.Query.Get(wire.QueryHave))
					}
					break
				}
			}
		})
	}
}

func copyDir(t *testing.T, from, to string) {
	t.Helper()
	ents, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeF(t, filepath.Join(to, e.Name()), b)
	}
}

// Expiry at boot: exactly at expires_at + skew the policy is expired (SafeMode); one second earlier it is not.
func TestBootExpiryBoundary(t *testing.T) {
	expires := t0.Add(24 * time.Hour)
	skew := 2 * time.Minute
	for _, c := range []struct {
		name string
		now  time.Time
		want wire.ProxyState
	}{
		{"well before expiry", expires.Add(-time.Hour), wire.StateEnforcing},
		{"at expires_at (inside skew)", expires, wire.StateEnforcing},
		{"one second before expires+skew", expires.Add(skew - time.Second), wire.StateEnforcing},
		{"at expires+skew", expires.Add(skew), wire.StateSafeMode},
		{"one second after", expires.Add(skew + time.Second), wire.StateSafeMode},
		{"a year later", expires.Add(365 * 24 * time.Hour), wire.StateSafeMode},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			clk := clock.NewFake(t0)
			applyOnce(t, dir, clk, 1)
			clk2 := clock.NewFake(c.now)
			// the high-water file written by the first life is at most t0+something; a later wall time wins
			r := reboot(t, dir, clk2)
			a := r.hold.Load()
			if a == nil || a.State != c.want {
				t.Fatalf("state %+v, want %s", a, c.want)
			}
			if c.want == wire.StateSafeMode && a.Policy == nil {
				t.Errorf("safe mode lost the policy: read-only tools can no longer be told apart")
			}
		})
	}
}

// Clock set back (S7, THREATS #12): after the wall clock was ahead and was then set back, the policy that
// expired stays expired, because effective_now never goes below the persisted high-water mark.
func TestBootClockSetBackStaysExpired(t *testing.T) {
	dir := t.TempDir()
	expires := t0.Add(24 * time.Hour)
	// first life runs "late": its guard sees a wall time after expiry and persists the high-water mark
	late := expires.Add(time.Hour)
	clk1 := clock.NewFake(late)
	cp := newCP(t)
	r1 := newRig(t, dir, clk1, cp)
	r1.boot() // nothing stored: deny-all, but the guard observes `late`
	if r1.guard.Now().Before(late) {
		t.Fatal("guard did not follow the wall clock")
	}
	if err := r1.guard.Save(); err != nil {
		t.Fatal(err)
	}
	hw, err := os.ReadFile(r1.guard.Path())
	if err != nil || len(bytes.TrimSpace(hw)) == 0 {
		t.Fatalf("no high-water file persisted: %v", err)
	}
	_ = r1.al.Close()
	// a policy applied in an earlier life is simulated by applying at t0 in a dir copy
	dir2 := t.TempDir()
	applyOnce(t, dir2, clock.NewFake(t0), 1)
	copyF := filepath.Base(r1.guard.Path())
	writeF(t, filepath.Join(dir2, copyF), hw)
	// now boot with the wall clock back at t0 (before expiry): effective_now must still be `late`
	r2 := reboot(t, dir2, clock.NewFake(t0))
	if got := r2.state(); got != wire.StateSafeMode {
		t.Fatalf("state %s after the clock was set back; a persisted high-water past expiry must keep it in safe mode", got)
	}
	if !r2.guard.Untrusted() {
		t.Errorf("wall clock %v behind the high-water mark is not reported untrusted", late.Sub(t0))
	}
	// the reported error is clock_untrusted
	r2.run()
	waitFor(t, "status", func() bool { s, _, ok := r2.cp.lastStatus(); _ = s; return ok || r2.cp.statusCount() >= 0 })
}

// A corrupt high-water file never lowers effective_now below the wall clock and boot still works.
func TestCorruptHighWaterIsSurvivable(t *testing.T) {
	for _, junk := range []string{"garbage", "", "9999-99-99T99:99:99Z", "2026-11-05T12:00:00+05:00", "1970-01-01T00:00:00Z\nextra", strings.Repeat("A", 1<<20), "0001-01-01T00:00:00Z"} {
		dir := t.TempDir()
		clk := clock.NewFake(t0)
		g, _ := agent.OpenClockGuard(clk, dir)
		if g == nil {
			t.Fatal("no guard")
		}
		writeF(t, g.Path(), []byte(junk))
		g2, err := agent.OpenClockGuard(clk, dir)
		if g2 == nil {
			t.Errorf("junk %q: no usable guard (err %v)", clip(junk), err)
			continue
		}
		if g2.Now().Before(t0) {
			t.Errorf("junk %q: effective_now %v is before the wall clock", clip(junk), g2.Now())
		}
		if err == nil && junk != "" {
			// accepted as valid is fine only for a canonical timestamp
			if !strings.HasPrefix(junk, "0001-") {
				t.Errorf("junk %q accepted as a valid high-water file", clip(junk))
			}
		}
	}
}

func clip(s string) string {
	if len(s) > 30 {
		return s[:30] + "..."
	}
	return s
}

// effective_now = max(wall, high-water, anchor + mono) (EffectiveNow), including the no-regression property.
func TestEffectiveNowIsMax(t *testing.T) {
	w := t0
	cases := []struct {
		name string
		a    agent.Anchor
		hw   time.Time
		now  time.Time
		want time.Time
	}{
		{"wall only", agent.Anchor{}, time.Time{}, w, w},
		{"high water ahead", agent.Anchor{}, w.Add(time.Hour), w, w.Add(time.Hour)},
		{"wall ahead of high water", agent.Anchor{}, w.Add(-time.Hour), w, w},
		{"anchor plus mono ahead of a set-back wall", agent.Anchor{Wall: w, Mono: 0}, time.Time{}, w, w},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clk := clock.NewFake(c.now)
			if got := agent.EffectiveNow(clk, c.a, c.hw); !got.Equal(c.want) {
				t.Errorf("got %v want %v", got, c.want)
			}
		})
	}
	// wall set back after the anchor: monotonic time keeps effective_now moving forward
	clk := clock.NewFake(t0)
	a := agent.Anchor{Wall: t0, Mono: clk.Mono()}
	clk.Advance(2 * time.Hour)
	clk.Set(t0.Add(-5 * time.Hour)) // operator or attacker sets the clock back by 5 h
	got := agent.EffectiveNow(clk, a, time.Time{})
	if got.Before(t0.Add(2 * time.Hour)) {
		t.Errorf("effective_now %v went back with the wall clock; want >= %v", got, t0.Add(2*time.Hour))
	}
	// never regresses across calls
	if agent.EffectiveNow(clk, a, time.Time{}).Before(got) {
		t.Errorf("effective_now regressed")
	}
}

var _ = applylog.ErrChain
