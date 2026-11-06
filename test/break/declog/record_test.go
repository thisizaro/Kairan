package declogbreak

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

// Round trip: Record then Decode returns the same record (doc: Decode reads one line as written by Record).
func TestRecordDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		r    enforce.Record
	}{
		{"allow R", rec(1)},
		{"deny no rule class 0", enforce.Record{Time: t0, Role: "intern", Tool: "crm.delete_all", Allowed: false, Class: 0, Version: 8, Hash: hashN(8), State: wire.StateEnforcing}},
		{"list", enforce.Record{Time: t0, Role: "sales", Tool: "tools/list", Allowed: true, Class: 0, Version: 8, Hash: hashN(8), State: wire.StateEnforcing}},
		{"unreadable tool is empty", enforce.Record{Time: t0, Role: "sales", Tool: "", Allowed: false, Version: 8, Hash: hashN(8), State: wire.StateEnforcing}},
		{"write class", enforce.Record{Time: t0, Role: "sales", Tool: "crm.update_deal", Allowed: true, Class: policy.ClassW, Version: 1, Hash: hashN(1), State: wire.StateEnforcing}},
		{"exec class safe mode", enforce.Record{Time: t0, Role: "sales", Tool: "crm.run_report", Allowed: false, Class: policy.ClassX, Version: 1<<63 + 5, Hash: hashN(1), State: wire.StateSafeMode}},
		{"128 char tool", enforce.Record{Time: t0, Role: "sales", Tool: strings.Repeat("a", 128), Allowed: false, Version: 2, Hash: hashN(2), State: wire.StateEnforcing}},
		{"time with nanoseconds", enforce.Record{Time: t0.Add(123456789 * time.Nanosecond), Role: "sales", Tool: "a", Version: 2, Hash: hashN(2), State: wire.StateEnforcing}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			if err := declog.New(&b, nil).Record(c.r); err != nil {
				t.Fatalf("Record: %v", err)
			}
			if n := strings.Count(b.String(), "\n"); n != 1 || !strings.HasSuffix(b.String(), "\n") {
				t.Fatalf("want exactly one newline-terminated line, got %q", b.String())
			}
			got, err := declog.Decode(b.Bytes())
			if err != nil {
				t.Fatalf("Decode own output: %v: %q", err, b.String())
			}
			if !got.Time.Equal(c.r.Time) || got.Role != c.r.Role || got.Tool != c.r.Tool || got.Allowed != c.r.Allowed ||
				got.Class != c.r.Class || got.Version != c.r.Version || got.Hash != c.r.Hash || got.State != c.r.State {
				t.Fatalf("round trip changed the record:\nin  %+v\nout %+v", c.r, got)
			}
			// Decode with the trailing newline removed also works (doc: optional)
			if _, err := declog.Decode(bytes.TrimRight(b.Bytes(), "\n")); err != nil {
				t.Fatalf("Decode without trailing newline: %v", err)
			}
		})
	}
}

// A non-UTC time is written in UTC and denotes the same instant (doc: time (UTC); Decode needs a UTC time).
func TestRecordNormalisesTimeToUTC(t *testing.T) {
	r := rec(1)
	r.Time = time.Date(2026, 11, 5, 17, 30, 0, 0, time.FixedZone("x", 5*3600+1800))
	var b bytes.Buffer
	if err := declog.New(&b, nil).Record(r); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, err := declog.Decode(b.Bytes())
	if err != nil {
		t.Fatalf("Decode: %v: %q", err, b.String())
	}
	if !got.Time.Equal(r.Time) {
		t.Fatalf("instant changed: %v != %v", got.Time, r.Time)
	}
	if strings.Contains(b.String(), "+05:30") {
		t.Errorf("line carries a non-UTC offset: %q", b.String())
	}
}

// Record refuses a record that does not fit the shape (no free text): nothing is written, an error returns,
// and the line never carries the hostile value. Checks I4 / THREATS #7.
func TestRecordRefusesRecordsThatDoNotFit(t *testing.T) {
	bad := func(f func(r *enforce.Record)) enforce.Record { r := rec(1); f(&r); return r }
	cases := []struct {
		name string
		r    enforce.Record
	}{
		{"tool with arguments", bad(func(r *enforce.Record) { r.Tool = "crm.read_contact " + canary })},
		{"tool with newline", bad(func(r *enforce.Record) { r.Tool = "a\n{\"allowed\":true}" })},
		{"tool with quote", bad(func(r *enforce.Record) { r.Tool = `a"b` })},
		{"tool with slash that is not tools/list", bad(func(r *enforce.Record) { r.Tool = "tools/call" })},
		{"tool too long 129", bad(func(r *enforce.Record) { r.Tool = strings.Repeat("a", 129) })},
		{"tool unicode", bad(func(r *enforce.Record) { r.Tool = "crm.read​_contact" })},
		{"tool NUL", bad(func(r *enforce.Record) { r.Tool = "a\x00b" })},
		{"role newline", bad(func(r *enforce.Record) { r.Role = "sales\nroot" })},
		{"role quote", bad(func(r *enforce.Record) { r.Role = `sa"les` })},
		{"role canary text with spaces", bad(func(r *enforce.Record) { r.Role = "ignore previous instructions " + canary })},
		{"role huge", bad(func(r *enforce.Record) { r.Role = strings.Repeat("r", 100000) })},
		{"role control char", bad(func(r *enforce.Record) { r.Role = "sales\x1b[2J" })},
		{"class lower case", bad(func(r *enforce.Record) { r.Class = policy.Class('r') })},
		{"class Z", bad(func(r *enforce.Record) { r.Class = policy.Class('Z') })},
		{"class newline", bad(func(r *enforce.Record) { r.Class = policy.Class('\n') })},
		{"class quote", bad(func(r *enforce.Record) { r.Class = policy.Class('"') })},
		{"hash short", bad(func(r *enforce.Record) { r.Hash = "abc" })},
		{"hash upper", bad(func(r *enforce.Record) { r.Hash = wire.Hash(strings.ToUpper(string(hashN(0xabcdef)))) })},
		{"hash non-hex", bad(func(r *enforce.Record) { r.Hash = wire.Hash(strings.Repeat("g", 64)) })},
		{"hash 65", bad(func(r *enforce.Record) { r.Hash = hashN(1) + "0" })},
		{"hash carries text", bad(func(r *enforce.Record) { r.Hash = wire.Hash(canary) })},
		{"state unknown", bad(func(r *enforce.Record) { r.State = "hacked" })},
		{"state with newline", bad(func(r *enforce.Record) { r.State = "enforcing\n" })},
		{"state carries text", bad(func(r *enforce.Record) { r.State = wire.ProxyState(canary) })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var b bytes.Buffer
			m := &metrics{}
			err := declog.New(&b, m).Record(c.r)
			if err == nil {
				t.Fatalf("Record accepted a record that does not fit the shape; wrote %q", clip(b.String()))
			}
			if b.Len() != 0 {
				t.Errorf("Record returned an error but wrote %q", clip(b.String()))
			}
		})
	}
}

func clip(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

// Every defined state must be accepted and round trip.
func TestRecordAcceptsEveryDefinedState(t *testing.T) {
	states := []wire.ProxyState{wire.StateBooting, wire.StateEnforcing, wire.StateSafeMode, wire.StateTampered, wire.StateDenyAll}
	for _, s := range states {
		if !s.Valid() {
			t.Fatalf("wire says %q is not a valid state", s)
		}
		r := rec(1)
		r.State = s
		var b bytes.Buffer
		if err := declog.New(&b, nil).Record(r); err != nil {
			t.Errorf("state %q refused: %v", s, err)
			continue
		}
		if got, err := declog.Decode(b.Bytes()); err != nil || got.State != s {
			t.Errorf("state %q round trip: %v %v", s, got.State, err)
		}
	}
}

// Writer failure is loud: Record returns the error and counts declog_write_errors (doc: Failure is loud).
type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) { f.n++; return 0, errors.New("disk full") }

type shortWriter struct{ buf bytes.Buffer }

func (s *shortWriter) Write(p []byte) (int, error) {
	n := len(p) / 2
	s.buf.Write(p[:n])
	return n, nil // short write with nil error violates io.Writer; the log must not call it success
}

func TestWriteFailureIsAnErrorAndCounted(t *testing.T) {
	m := &metrics{}
	l := declog.New(&failWriter{}, m)
	if err := l.Record(rec(1)); err == nil {
		t.Fatal("Record returned nil although the writer failed")
	}
	if m.get(declog.MetricWriteErrors) != 1 {
		t.Errorf("%s = %d, want 1", declog.MetricWriteErrors, m.get(declog.MetricWriteErrors))
	}
}

func TestShortWriteIsAnError(t *testing.T) {
	m := &metrics{}
	sw := &shortWriter{}
	if err := declog.New(sw, m).Record(rec(1)); err == nil {
		t.Fatal("a short write was reported as stored")
	}
	if m.get(declog.MetricWriteErrors) == 0 {
		t.Errorf("short write not counted")
	}
}

// Metrics nil must be fine everywhere.
func TestNilMetricsDoNotPanic(t *testing.T) {
	_ = declog.New(&failWriter{}, nil).Record(rec(1))
	l, _ := openLog(t, declog.Options{})
	_ = l.Record(rec(1))
}

// New(nil writer) must not panic: it must be an error on Record.
func TestNewNilWriterFailsClosed(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic: %v", r)
		}
	}()
	l := declog.New(nil, nil)
	if err := l.Record(rec(1)); err == nil {
		t.Fatal("Record on a nil writer returned nil")
	}
}
