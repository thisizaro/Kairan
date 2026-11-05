package agent

import (
	"errors"
	"net/url"
	"os"
	"testing"
	"time"

	"kairan/internal/proxy/applylog"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

func TestConfigValidate(t *testing.T) {
	r := newRig(t)
	https, _ := url.Parse("https://cp.example.com")
	http1, _ := url.Parse("http://cp.example.com")
	tests := []struct {
		name string
		mod  func(c *Config)
		ok   bool
	}{
		{"good plaintext allowed", func(c *Config) {}, true},
		{"https without allow_plaintext", func(c *Config) { c.CP, c.AllowPlaintext = https, false }, true},
		{"http without allow_plaintext", func(c *Config) { c.CP, c.AllowPlaintext = http1, false }, false},
		{"no cp", func(c *Config) { c.CP = nil }, false},
		{"ftp cp", func(c *Config) { c.CP = &url.URL{Scheme: "ftp", Host: "x"} }, false},
		{"cp without host", func(c *Config) { c.CP = &url.URL{Scheme: "https"} }, false},
		{"empty token", func(c *Config) { c.Token = "" }, false},
		{"bad tenant", func(c *Config) { c.Tenant = "Bank A" }, false},
		{"bad proxy id", func(c *Config) { c.ProxyID = "" }, false},
		{"no guard", func(c *Config) { c.Guard = nil }, false},
		{"skew 5m ok", func(c *Config) { c.Skew = 5 * time.Minute }, true},
		{"skew zero ok", func(c *Config) { c.Skew = 0 }, true},
		{"skew over 5m", func(c *Config) { c.Skew = 5*time.Minute + time.Nanosecond }, false},
		{"negative skew", func(c *Config) { c.Skew = -time.Second }, false},
		{"threshold 1", func(c *Config) { c.Root.Threshold = 1 }, false},
		{"threshold 0", func(c *Config) { c.Root.Threshold = 0 }, false},
		{"threshold above keys", func(c *Config) { c.Root.Threshold = 4 }, false},
		{"root for another tenant", func(c *Config) { c.Root.Tenant = "other" }, false},
		{"empty root", func(c *Config) { c.Root = trust.Root{} }, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := r.cfg
			tc.mod(&cfg)
			err := cfg.Validate()
			if (err == nil) != tc.ok {
				t.Fatalf("Validate = %v, want ok=%v", err, tc.ok)
			}
			if _, nerr := New(cfg, r.st, r.al, r.holder, r.clk, r.hc, quietLog(), r.stats); (nerr == nil) != tc.ok {
				t.Fatalf("New = %v, want ok=%v", nerr, tc.ok)
			}
		})
	}
}

func TestNewRejectsMissingParts(t *testing.T) {
	r := newRig(t)
	if _, err := New(r.cfg, nil, r.al, r.holder, r.clk, r.hc, nil, nil); err == nil {
		t.Fatal("nil store accepted")
	}
	if _, err := New(r.cfg, r.st, r.al, nil, r.clk, r.hc, nil, nil); err == nil {
		t.Fatal("nil holder accepted")
	}
	if _, err := New(r.cfg, r.st, r.al, r.holder, nil, r.hc, nil, nil); err == nil {
		t.Fatal("nil clock accepted")
	}
	if _, err := New(r.cfg, r.st, r.al, r.holder, r.clk, nil, nil, nil); err == nil {
		t.Fatal("nil http client accepted")
	}
	if _, err := New(r.cfg, r.st, nil, r.holder, r.clk, r.hc, nil, nil); err == nil {
		t.Fatal("nil apply log without LogOpenErr accepted")
	}
	// nil logger and stats are fine
	if _, err := New(r.cfg, r.st, r.al, r.holder, r.clk, r.hc, nil, nil); err != nil {
		t.Fatalf("nil logger/stats: %v", err)
	}
}

// Before Boot the holder is untouched (nil Active = deny-all) and Run refuses.
func TestRunBeforeBootFails(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if r.active() != nil {
		t.Fatal("holder set before Boot")
	}
	if err := a.Run(t.Context()); err == nil {
		t.Fatal("Run before Boot succeeded")
	}
}

func TestBootEmptyIsDenyAll(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	act := r.active()
	if act == nil || act.State != wire.StateDenyAll || act.Policy != nil || act.Hash != "" {
		t.Fatalf("active = %+v", act)
	}
	rep := a.report()
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
	if rep.State != wire.StateDenyAll || rep.AppliedVersion != 0 || rep.LogSeq != 0 || rep.LastError != nil {
		t.Fatalf("report = %+v", rep)
	}
}

func TestBootTwiceFails(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if err := a.Boot(); err == nil {
		t.Fatal("second Boot succeeded")
	}
}

// applyDirect persists and logs an envelope the way a successful apply does,
// so boot tests can start from a known disk state.
func (r *rig) seedDisk(env wire.Envelope, appendLog bool) {
	r.t.Helper()
	v, _, err := trust.Verify(env, r.cfg.Root)
	if err != nil {
		r.t.Fatal(err)
	}
	if err := r.st.Save(env); err != nil {
		r.t.Fatal(err)
	}
	if appendLog {
		if _, err := r.al.Append(applylog.Entry{To: v.Policy.Version, Hash: v.Hash}); err != nil {
			r.t.Fatal(err)
		}
	}
}

func TestBootValid(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	act := r.active()
	if act.State != wire.StateEnforcing || act.Policy == nil || act.Policy.Version != 3 || !act.Hash.Valid() {
		t.Fatalf("active = %+v", act)
	}
	rep := a.report()
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
	if rep.AppliedVersion != 3 || rep.PolicyHash != act.Hash || rep.LogSeq != 1 || rep.LogHead == "" {
		t.Fatalf("report = %+v", rep)
	}
	if n := len(r.logEntries()); n != 1 {
		t.Fatalf("boot of a consistent disk appended %d entries", n-1)
	}
}

func TestBootExpiredIsSafeMode(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.clk.Advance(2 * time.Hour)
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	act := r.active()
	if act.State != wire.StateSafeMode || act.Policy == nil || act.Policy.Version != 3 {
		t.Fatalf("active = %+v", act)
	}
	rep := a.report()
	if err := rep.Validate(); err != nil || rep.AppliedVersion != 3 {
		t.Fatalf("report = %+v err %v", rep, err)
	}
}

// The skew applies at boot as it does in trust.Accept: expired at
// expires_at + skew, not before.
func TestBootExpiryUsesSkew(t *testing.T) {
	for _, tc := range []struct {
		name string
		at   time.Duration // clock after seeding, relative to expires_at
		want wire.ProxyState
	}{
		{"just before expires+skew", time.Minute - time.Nanosecond, wire.StateEnforcing},
		{"exactly expires+skew", time.Minute, wire.StateSafeMode},
		{"before expires_at", -time.Second, wire.StateEnforcing},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
			r.clk.Advance(time.Hour + tc.at)
			a := r.reopen()
			if err := a.Boot(); err != nil {
				t.Fatal(err)
			}
			if got := r.active().State; got != tc.want {
				t.Fatalf("state = %s, want %s", got, tc.want)
			}
		})
	}
}

// Wall clock set back across a restart must not revive an expired policy:
// effective_now comes from the persisted high-water mark (M-D30).
func TestBootClockSetBackStaysExpired(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.clk.Advance(3 * time.Hour)
	r.guard.Now()
	if err := r.guard.Save(); err != nil {
		t.Fatal(err)
	}
	r.clk.Set(start) // an hour before expiry again
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if got := r.active().State; got != wire.StateSafeMode {
		t.Fatalf("state = %s, want safe_mode", got)
	}
	rep := a.report()
	if rep.LastError == nil || rep.LastError.Code != wire.ErrClockUntrusted {
		t.Fatalf("clock set back by 3h not reported: %+v", rep.LastError)
	}
}

func TestBootTamperedCases(t *testing.T) {
	t.Run("stored file garbage", func(t *testing.T) {
		r := newRig(t)
		r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
		if err := os.WriteFile(r.st.Path(), []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		a := r.reopen()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
	t.Run("stored file has one signature", func(t *testing.T) {
		r := newRig(t)
		r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
		weak := signed(payload(3, tenant, start.Add(time.Hour)), r.keys.a)
		if err := r.st.Save(weak); err != nil {
			t.Fatal(err)
		}
		a := r.reopen()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
	t.Run("stored file older than the log", func(t *testing.T) {
		r := newRig(t)
		r.seedDisk(r.keys.goodEnv(5, time.Hour), true)
		if err := r.st.Save(r.keys.goodEnv(4, time.Hour)); err != nil {
			t.Fatal(err)
		}
		a := r.reopen()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
	t.Run("stored file deleted but log has applied", func(t *testing.T) {
		r := newRig(t)
		r.seedDisk(r.keys.goodEnv(5, time.Hour), true)
		if err := os.Remove(r.st.Path()); err != nil {
			t.Fatal(err)
		}
		a := r.reopen()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
	t.Run("stored file for another tenant", func(t *testing.T) {
		r := newRig(t)
		other := signed(payload(3, "other", start.Add(time.Hour)), r.keys.a, r.keys.b)
		if err := r.st.Save(other); err != nil {
			t.Fatal(err)
		}
		a := r.reopen()
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
	t.Run("apply log failed to open", func(t *testing.T) {
		r := newRig(t)
		r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
		r.cfg.LogOpenErr = errors.New("applylog: chain broken")
		r.cfg.Guard = r.guard
		r.holder = newHolder()
		a, err := New(r.cfg, r.st, nil, r.holder, r.clk, r.hc, quietLog(), r.stats)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Boot(); err != nil {
			t.Fatal(err)
		}
		checkTampered(t, r, a)
	})
}

func checkTampered(t *testing.T, r *rig, a *Agent) {
	t.Helper()
	act := r.active()
	if act == nil || act.State != wire.StateTampered || act.Policy != nil {
		t.Fatalf("active = %+v, want tampered with no policy", act)
	}
	rep := a.report()
	if err := rep.Validate(); err != nil {
		t.Fatal(err)
	}
	if rep.State != wire.StateTampered || rep.AppliedVersion != 0 || rep.LastError == nil || rep.LastError.Code != wire.ErrTampered {
		t.Fatalf("report = %+v last_error %+v", rep, rep.LastError)
	}
	if got := r.stats.Count(MetricBootTampered); got != 1 {
		t.Fatalf("boot tampered counter = %d", got)
	}
}

// Crash between Save and Append: the file is newer than the log. Boot accepts
// it and appends a repair entry (M-D33).
func TestBootRepairsNewerStoredPolicy(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.seedDisk(r.keys.goodEnv(4, time.Hour), false) // saved, never logged
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 4 {
		t.Fatalf("active = %+v", act)
	}
	es := r.logEntries()
	if len(es) != 2 || es[1].To != 4 || es[1].From != 3 || es[1].Result != "" {
		t.Fatalf("log = %+v", es)
	}
	if rep := a.report(); rep.LogSeq != 2 || rep.AppliedVersion != 4 {
		t.Fatalf("report = %+v", rep)
	}
	// And a second boot finds a consistent disk.
	a = r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if len(r.logEntries()) != 2 {
		t.Fatal("second boot appended again")
	}
}

func TestBootRepairOnEmptyLog(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(1, time.Hour), false)
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	es := r.logEntries()
	if len(es) != 1 || es[0].To != 1 || es[0].From != 0 {
		t.Fatalf("log = %+v", es)
	}
	if got := r.active().State; got != wire.StateEnforcing {
		t.Fatalf("state = %s", got)
	}
}

// Expiry is judged at effective_now: a policy that expires while the wall
// clock was set back stays expired once the high-water mark says so.
func TestBootRepairedButExpiredIsSafeMode(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(1, time.Hour), false)
	r.clk.Advance(2 * time.Hour)
	a := r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if got := r.active().State; got != wire.StateSafeMode {
		t.Fatalf("state = %s", got)
	}
	if len(r.logEntries()) != 1 {
		t.Fatal("repair entry missing")
	}
}

// If the repair entry cannot be written, the newer file is not enforced:
// the log must be able to record what is in force.
func TestBootRepairFailureIsTampered(t *testing.T) {
	r := newRig(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.seedDisk(r.keys.goodEnv(4, time.Hour), false)
	a := r.reopen()
	r.al.Close() // every Append now fails
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	checkTampered(t, r, a)
}
