package agent

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"kairan/internal/proxy/applylog"
	"kairan/internal/wire"
)

// A proxy whose apply log was damaged by hand goes Tampered at boot (S6) and
// leaves it when a newer valid policy arrives: the broken log is kept as
// evidence and a new chain starts (P-13, M-D64, Q-D30).

// damages are the three ways the tests break a two-entry log (v3, v5).
var damages = []struct {
	name string
	do   func(t *testing.T, path string)
}{
	{"edited", func(t *testing.T, path string) {
		b, _ := os.ReadFile(path)
		if !bytes.Contains(b, []byte(`"to":5`)) {
			t.Fatal("test setup: no to:5 in the log")
		}
		os.WriteFile(path, bytes.Replace(b, []byte(`"to":5`), []byte(`"to":2`), 1), 0o600)
	}},
	{"truncated", func(t *testing.T, path string) {
		b, _ := os.ReadFile(path)
		os.WriteFile(path, b[:len(b)-20], 0o600)
	}},
	{"garbage appended", func(t *testing.T, path string) {
		b, _ := os.ReadFile(path)
		os.WriteFile(path, append(b, "garbage\n"...), 0o600)
	}},
}

// brokenAgent leaves v3 then v5 on disk, damages the log, and boots an agent
// the way cmd/kairan-proxy does: nil log, the open error, the log path.
func (r *rig) brokenAgent(cp *fakeCP, damage func(*testing.T, string)) *Agent {
	r.t.Helper()
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.seedDisk(r.keys.goodEnv(5, time.Hour), true)
	r.al.Close()
	damage(r.t, r.dir+"/apply.log")
	return r.bootBroken(cp)
}

func (r *rig) bootBroken(cp *fakeCP) *Agent {
	r.t.Helper()
	var err error
	r.al, err = applylog.Open(r.dir+"/apply.log", r.clk)
	if err == nil {
		r.t.Fatal("the damaged log opened")
	}
	r.cfg.LogOpenErr, r.cfg.LogPath = err, r.dir+"/apply.log"
	r.cfg.CP = cp.url()
	r.holder = newHolder()
	r.al = nil
	a, nerr := New(r.cfg, r.st, nil, r.holder, r.clk, r.hc, r.logger(), r.stats)
	if nerr != nil {
		r.t.Fatal(nerr)
	}
	r.a = a
	if err := a.Boot(); err != nil {
		r.t.Fatal(err)
	}
	return a
}

var logBuf bytes.Buffer

func (r *rig) logger() *slog.Logger {
	logBuf.Reset()
	return slog.New(slog.NewJSONHandler(&logBuf, nil))
}

func (r *rig) readFile(name string) []byte {
	r.t.Helper()
	b, err := os.ReadFile(r.dir + "/" + name)
	if err != nil {
		r.t.Fatal(err)
	}
	return b
}

func (r *rig) exists(name string) bool {
	_, err := os.Stat(r.dir + "/" + name)
	return err == nil
}

func TestBrokenLogRecoversOnNewerVersion(t *testing.T) {
	for _, d := range damages {
		t.Run(d.name, func(t *testing.T) {
			r := newRig(t)
			cp := newFakeCP(t)
			a := r.brokenAgent(cp, d.do)
			broken := r.readFile("apply.log")
			if r.active().State != wire.StateTampered {
				t.Fatalf("state = %v, want tampered", r.active().State)
			}

			// The same and an older version do not recover, and keep the evidence untouched.
			for _, v := range []uint64{5, 4, 3, 1} {
				cp.pollFn = serveEnv(r.keys.goodEnv(v, time.Hour), v)
				a.pollOnce(t.Context())
				if r.active().State != wire.StateTampered {
					t.Fatalf("version %d lifted tampered", v)
				}
				if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrNotNewer {
					t.Fatalf("version %d: last_error %+v, want not_newer", v, rep.LastError)
				}
				if r.exists("apply.log.broken-1") || !bytes.Equal(r.readFile("apply.log"), broken) {
					t.Fatalf("version %d: the broken log was touched", v)
				}
			}
			if got := cp.polls[0].Get(wire.QueryHave); got != "5" {
				t.Fatalf("have = %q, want 5 (the stored policy and the log agree)", got)
			}
			if r.stats.Count(MetricLogReset) != 0 {
				t.Fatal("reset counted without a reset")
			}

			// A newer valid one does.
			cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
			a.pollOnce(t.Context())
			act := r.active()
			if act.State != wire.StateEnforcing || act.Policy.Version != 6 {
				t.Fatalf("active = %+v, want enforcing v6", act)
			}
			if got := r.readFile("apply.log.broken-1"); !bytes.Equal(got, broken) {
				t.Fatal("the broken log was not kept byte for byte")
			}
			es := r.logEntries() // verifies the whole new chain
			if len(es) != 2 || es[0].Reset.File != "apply.log.broken-1" || es[0].From != 5 || es[0].Result != wire.ErrTampered ||
				es[1].To != 6 || es[1].From != 5 || es[1].Result != "" || es[1].Prev != es[0].Self {
				t.Fatalf("new log = %+v", es)
			}

			// It is reported: counter, status (last_error and the anchor), bilingual log line.
			if r.stats.Count(MetricLogReset) != 1 {
				t.Errorf("reset counter = %d", r.stats.Count(MetricLogReset))
			}
			rep := a.report()
			if err := rep.Validate(); err != nil {
				t.Fatal(err)
			}
			if rep.State != wire.StateEnforcing || rep.AppliedVersion != 6 || rep.LogSeq != 2 || rep.LogHead != es[1].Self ||
				rep.LastError == nil || rep.LastError.Code != wire.ErrTampered || rep.LastError.Version != 6 {
				t.Errorf("report = %+v last_error %+v", rep, rep.LastError)
			}
			if !strings.Contains(logBuf.String(), "apply log reset") || !strings.Contains(logBuf.String(), "リセット") {
				t.Errorf("no bilingual reset line in the log: %s", logBuf.String())
			}
			// The next ordinary apply clears last_error; no second reset.
			cp.pollFn = serveEnv(r.keys.goodEnv(7, time.Hour), 7)
			a.pollOnce(t.Context())
			if rep := a.report(); rep.LastError != nil || r.active().Policy.Version != 7 {
				t.Errorf("after v7: last_error %+v", rep.LastError)
			}
			if r.exists("apply.log.broken-2") || len(r.logEntries()) != 3 {
				t.Error("a second reset happened on a healthy log")
			}

			// A restart boots from the new chain.
			r.al, r.cfg.LogOpenErr = a.alog(), nil
			a = r.reopen()
			if err := a.Boot(); err != nil {
				t.Fatal(err)
			}
			if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 7 {
				t.Fatalf("after restart: %+v", act)
			}
		})
	}
}

// The stored policy raises the floor when the damaged log lost the entry that
// proves it.
func TestBrokenLogFloorIncludesStoredPolicy(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.brokenAgent(cp, func(t *testing.T, path string) {
		os.WriteFile(path, []byte("garbage first line\n"), 0o600)
	})
	cp.pollFn = serveEnv(r.keys.goodEnv(5, time.Hour), 5)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateTampered || r.exists("apply.log.broken-1") {
		t.Fatal("v5 recovered although the stored policy is v5")
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateEnforcing {
		t.Fatal("v6 did not recover")
	}
	es := r.logEntries()
	if es[0].Reset.Seq != 0 || es[0].Hash != "" || es[0].Reset.Reason != applylog.ReasonMalformed {
		t.Fatalf("reset entry for an empty prefix: %+v", es[0])
	}
}

// A bad envelope never resets anything, however new its version.
func TestBrokenLogNotResetByInvalidEnvelope(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.brokenAgent(cp, damages[2].do)
	broken := r.readFile("apply.log")
	for name, env := range map[string]wire.Envelope{
		"one signature": signed(payload(9, tenant, start.Add(time.Hour)), r.keys.a),
		"wrong tenant":  signed(payload(9, "other", start.Add(time.Hour)), r.keys.a, r.keys.b),
		"expired":       signed(payload(9, tenant, start.Add(-time.Hour)), r.keys.a, r.keys.b),
	} {
		cp.pollFn = serveEnv(env, 9)
		a.pollOnce(t.Context())
		if r.active().State != wire.StateTampered || r.exists("apply.log.broken-1") || !bytes.Equal(r.readFile("apply.log"), broken) {
			t.Fatalf("%s: the broken log was touched or tampered lifted", name)
		}
	}
	if r.stats.Count(MetricLogReset) != 0 {
		t.Fatal("reset counted")
	}
}

// Without a log path (an embedding that does not set it) nothing recovers, as
// before.
func TestBrokenLogWithoutPathStaysTampered(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	r.cfg.LogPath = ""
	a := r.brokenAgent(cp, damages[2].do)
	a.cfg.LogPath = ""
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateTampered || r.exists("apply.log.broken-1") {
		t.Fatal("recovered without a log path")
	}
	if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrPersist {
		t.Fatalf("last_error = %+v", rep.LastError)
	}
}

// Crash between the reset and the first apply: the next boot is Tampered
// (fail closed, although the stored policy is valid) and the next newer offer
// recovers without a second reset.
func TestCrashAfterResetBootsTamperedAndRecovers(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	r.seedDisk(r.keys.goodEnv(3, time.Hour), true)
	r.seedDisk(r.keys.goodEnv(5, time.Hour), true)
	r.al.Close()
	damages[0].do(t, r.dir+"/apply.log")
	l, _, err := applylog.Reset(r.dir+"/apply.log", r.clk, 5) // ... and the process dies here
	if err != nil {
		t.Fatal(err)
	}
	l.Close()

	var oerr error
	if r.al, oerr = applylog.Open(r.dir+"/apply.log", r.clk); oerr != nil {
		t.Fatal(oerr)
	}
	r.cfg.CP, r.cfg.LogPath = cp.url(), r.dir+"/apply.log"
	r.holder = newHolder()
	a := r.build()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	checkTampered(t, r, a) // the valid v5 on disk is not enforced
	cp.pollFn = serveEnv(r.keys.goodEnv(5, time.Hour), 5)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateTampered {
		t.Fatal("v5 lifted tampered")
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 6 {
		t.Fatalf("active = %+v", act)
	}
	if r.exists("apply.log.broken-2") {
		t.Fatal("a second reset on a log that was already reset")
	}
	// reset, the rejected v5, then the apply of v6
	if es := r.logEntries(); len(es) != 3 || es[1].Result != wire.ErrNotNewer || es[2].To != 6 || es[2].Result != "" {
		t.Fatalf("log = %+v", es)
	}
	if rep := a.report(); rep.LastError == nil || rep.LastError.Code != wire.ErrTampered {
		t.Fatalf("the reset was not reported after recovery: %+v", rep.LastError)
	}
}

// The other crash window: the broken log was linked aside but not yet
// replaced. It is still broken, so Tampered; the next offer reuses the kept
// file.
func TestCrashBeforeRenameReusesKeptFile(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.brokenAgent(cp, damages[1].do)
	if err := os.Link(r.dir+"/apply.log", r.dir+"/apply.log.broken-1"); err != nil {
		t.Fatal(err)
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateEnforcing || r.exists("apply.log.broken-2") {
		t.Fatalf("state %v, broken-2 exists %v", r.active().State, r.exists("apply.log.broken-2"))
	}
}

func TestTwoResetsKeepTwoFiles(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.brokenAgent(cp, damages[0].do)
	first := r.readFile("apply.log")
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateEnforcing {
		t.Fatal("first recovery failed")
	}
	// Restart, someone edits the new log, restart again.
	r.a.alog().Close()
	damages[2].do(t, r.dir+"/apply.log")
	second := r.readFile("apply.log")
	a = r.bootBroken(cp)
	if r.active().State != wire.StateTampered {
		t.Fatal("not tampered after the second edit")
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateTampered {
		t.Fatal("v6 again lifted tampered")
	}
	cp.pollFn = serveEnv(r.keys.goodEnv(7, time.Hour), 7)
	a.pollOnce(t.Context())
	if r.active().State != wire.StateEnforcing || r.active().Policy.Version != 7 {
		t.Fatalf("second recovery: %+v", r.active())
	}
	if !bytes.Equal(r.readFile("apply.log.broken-1"), first) || !bytes.Equal(r.readFile("apply.log.broken-2"), second) {
		t.Fatal("a kept file was changed")
	}
	es := r.logEntries()
	if len(es) != 2 || es[0].Reset.File != "apply.log.broken-2" || es[0].From != 6 {
		t.Fatalf("log = %+v", es)
	}
}

// An offline import follows the same rule (P-11).
func TestImportRecoversBrokenLog(t *testing.T) {
	r := newRig(t)
	a := r.brokenAgent(newFakeCP(t), damages[0].do)
	broken := r.readFile("apply.log")
	if _, err := a.Import(envJSON(t, r.keys.goodEnv(5, time.Hour))); err == nil {
		t.Fatal("v5 imported over a broken log")
	}
	if r.exists("apply.log.broken-1") || !bytes.Equal(r.readFile("apply.log"), broken) {
		t.Fatal("the broken log was touched by a rejected import")
	}
	got, err := a.Import(envJSON(t, r.keys.goodEnv(6, time.Hour)))
	if err != nil || got.Version != 6 || got.Previous != 5 {
		t.Fatalf("import = %+v %v", got, err)
	}
	if !bytes.Equal(r.readFile("apply.log.broken-1"), broken) {
		t.Fatal("broken log not kept")
	}
	if es := r.logEntries(); len(es) != 2 || es[0].Reset.File == "" || es[1].To != 6 {
		t.Fatalf("log = %+v", es)
	}
}

// The status report stays free of anything but wire types (I4) after a reset.
func TestResetReportIsWireOnly(t *testing.T) {
	r := newRig(t)
	cp := newFakeCP(t)
	a := r.brokenAgent(cp, damages[0].do)
	cp.pollFn = serveEnv(r.keys.goodEnv(6, time.Hour), 6)
	a.pollOnce(t.Context())
	b, _ := json.Marshal(a.report())
	if strings.Contains(string(b), "broken") || strings.Contains(string(b), "apply.log") {
		t.Fatalf("report mentions files: %s", b)
	}
}
