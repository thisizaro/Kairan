package agent

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"kairan/internal/clock"
)

// Q-D35 (M-D65): the guard logs a bilingual warning when the clock becomes
// untrusted and an info line when it is trusted again, once per change.

type warnBuf struct{ bytes.Buffer }

func (b *warnBuf) records(t *testing.T) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not a log record: %q", l)
		}
		out = append(out, m)
	}
	return out
}

func TestGuardLogsClockUntrustedAndTrustedAgain(t *testing.T) {
	f := clock.NewFake(t0)
	g := open(t, f, t.TempDir())
	var buf warnBuf
	g.SetLog(slog.New(slog.NewJSONHandler(&buf, nil)))

	if g.Untrusted() || len(buf.records(t)) != 0 {
		t.Fatalf("a healthy clock logged something: %s", buf.String())
	}
	f.Advance(time.Hour)
	f.Set(f.Now().Add(-time.Hour)) // wall set back an hour: behind effective time
	for i := 0; i < 3; i++ {       // observed three times: still one line
		if !g.Untrusted() {
			t.Fatal("clock not untrusted after a step back")
		}
	}
	recs := buf.records(t)
	if len(recs) != 1 {
		t.Fatalf("want one line for the change, got %d:\n%s", len(recs), buf.String())
	}
	r := recs[0]
	if r["level"] != "WARN" || r["msg"] != evClockUntrusted.en || r["msg_ja"] != evClockUntrusted.ja {
		t.Errorf("untrusted line: %v", r)
	}

	f.Set(f.Now().Add(2 * time.Hour)) // wall catches up
	if g.Untrusted() {
		t.Fatal("clock still untrusted after catching up")
	}
	g.Untrusted()
	recs = buf.records(t)
	if len(recs) != 2 {
		t.Fatalf("want a second line when trusted again, got %d:\n%s", len(recs), buf.String())
	}
	if r := recs[1]; r["level"] != "INFO" || r["msg"] != evClockTrusted.en || r["msg_ja"] != evClockTrusted.ja {
		t.Errorf("trusted line: %v", r)
	}
	for _, r := range recs {
		for k, v := range r {
			if s, ok := v.(string); ok && strings.Contains(s, t.TempDir()) {
				t.Errorf("field %s holds a path: %q", k, s)
			}
		}
	}
}

// New wires the agent's logger into the guard.
func TestNewGivesTheGuardTheAgentLog(t *testing.T) {
	r := newRig(t)
	var buf warnBuf
	a, err := New(r.cfg, r.st, r.al, r.holder, r.clk, r.hc, slog.New(slog.NewJSONHandler(&buf, nil)), r.stats)
	if err != nil {
		t.Fatal(err)
	}
	r.clk.Advance(time.Hour)
	r.clk.Set(r.clk.Now().Add(-time.Hour))
	if !a.Snapshot().ClockUntrusted {
		t.Fatal("snapshot does not show an untrusted clock")
	}
	if recs := buf.records(t); len(recs) != 1 || recs[0]["msg"] != evClockUntrusted.en {
		t.Fatalf("agent log: %s", buf.String())
	}
}
