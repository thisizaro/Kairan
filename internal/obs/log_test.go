package obs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

const canary = "CANARY-tool-arg-s3cr3t"

func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not JSON: %q: %v", ln, err)
		}
		out = append(out, m)
	}
	return out
}

func TestLoggerJSONUTCAndLevel(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelWarn)
	l.Info("dropped")
	l.Warn("kept", Tenant("bank-a"), Proxy("bank-a-p1"), slog.Uint64("version", 3))
	lines := logLines(t, &buf)
	if len(lines) != 1 {
		t.Fatalf("got %d lines, want 1: %s", len(lines), buf.String())
	}
	m := lines[0]
	if m["msg"] != "kept" || m["level"] != "WARN" || m["tenant"] != "bank-a" || m["proxy"] != "bank-a-p1" || m["version"] != float64(3) {
		t.Errorf("unexpected line: %v", m)
	}
	ts, err := time.Parse(time.RFC3339Nano, m["time"].(string))
	if err != nil || !strings.HasSuffix(m["time"].(string), "Z") || ts.Location() != time.UTC {
		t.Errorf("time %v is not UTC RFC3339: %v", m["time"], err)
	}
}

func TestHelpersRejectInvalidIDs(t *testing.T) {
	a := Tenant(wire.ID("a\"b\nSECRET"))
	if strings.Contains(a.Value.String(), "SECRET") {
		t.Fatalf("free text passed through Tenant: %v", a)
	}
	if Tenant("bank-a").Value.String() != "bank-a" {
		t.Fatal("valid ID altered")
	}
}

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]slog.Level{
		"debug": slog.LevelDebug, "info": slog.LevelInfo, "": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "error": slog.LevelError, "ERROR": slog.LevelError, " Info ": slog.LevelInfo,
	} {
		got, err := ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"trace", "5", "verbose", "info\nerror"} {
		if _, err := ParseLevel(in); err == nil {
			t.Errorf("ParseLevel(%q) should fail", in)
		}
	}
}

// The I4 guard: whatever a caller tries to log, request bodies and the other
// call data carriers must not reach the output.
func TestLoggerNeverEmitsBodies(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/x?token="+canary, strings.NewReader(canary))
	req.Header.Set("Authorization", "Bearer "+canary)
	type wrapped struct{ Body []byte }

	cases := map[string][]any{
		"body key":          {"body", canary},
		"payload key":       {"payload", canary},
		"Prompt key caps":   {"Prompt", canary},
		"arguments key":     {"arguments", canary},
		"params key":        {"params", canary},
		"result key":        {"result", canary},
		"authorization key": {"authorization", canary},
		"api_key key":       {"api_key", canary},
		"token key":         {"token", canary},
		"password key":      {"password", canary},
		"secret key":        {"secret", canary},
		"cookie key":        {"cookie", canary},
		"dashed key":        {"request-body", canary},
		"byte slice":        {"data", []byte(canary)},
		"raw message":       {"data", json.RawMessage(`{"a":"` + canary + `"}`)},
		"reader":            {"data", io.NopCloser(strings.NewReader(canary))},
		"bytes buffer":      {"data", bytes.NewBufferString(canary)},
		"http request":      {"req", req},
		"http header":       {"hdr", req.Header},
		"url values":        {"q", req.URL.Query()},
		"slog.Any bytes":    {slog.Any("data", []byte(canary))},
		"byte slice ptr":    {"data", &[]byte{'a'}},
		"struct with body":  {"data", wrapped{Body: []byte(canary)}},
		"map":               {"data", map[string]string{"k": canary}},
		"string slice":      {"data", []string{canary}},
		"group":             {slog.Group("req", slog.String("body", canary))},
		"nested group":      {slog.Group("a", slog.Group("b", slog.String("payload", canary)))},
		"sensitive group":   {slog.Group("body", slog.String("x", canary))},
		"upstream_body":     {"upstream_body", canary},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			l := NewLogger(&buf, slog.LevelDebug)
			l.Info("event", args...)
			l.With(args...).Warn("event2")
			l.WithGroup("g").Error("event3", args...)
			out := buf.String()
			// slog's JSON handler base64-encodes []byte, so look for that too.
			if strings.Contains(out, canary) || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(canary))[:20]) {
				t.Fatalf("canary leaked: %s", out)
			}
			logLines(t, &buf) // still valid JSON
		})
	}
}

func TestLoggerTruncatesLongStrings(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	long := strings.Repeat("a", MaxLogValueBytes) + canary
	l.Info("event", "detail", long)
	l.Info(long)
	l.Info("event", "err", errors.New(long))
	if strings.Contains(buf.String(), canary) {
		t.Fatalf("tail of an oversized value survived: %s", buf.String())
	}
	buf.Reset()
	l.Info("event", "detail", "short ok")
	if !strings.Contains(buf.String(), "short ok") {
		t.Fatal("short values must pass through")
	}
}

func TestLoggerKeepsOrdinaryAttrs(t *testing.T) {
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("applied", "version", 4, "hash_prefix", "abcd", "err", errors.New("signature invalid"), "ok", true,
		"dur", 3*time.Millisecond, "tenant", wire.ID("bank-a"), "state", wire.StateEnforcing)
	m := logLines(t, &buf)[0]
	if m["version"] != float64(4) || m["err"] != "signature invalid" || m["ok"] != true || m["hash_prefix"] != "abcd" ||
		m["tenant"] != "bank-a" || m["state"] != "enforcing" {
		t.Fatalf("ordinary attributes damaged: %v", m)
	}
}

// API guard: obs helpers that put an identifier into a log line or a metric
// label accept only wire.ID, never string or any.
func TestExportedAPIHasNoFreeTextParameters(t *testing.T) {
	for name, fn := range map[string]any{"Tenant": Tenant, "Proxy": Proxy} {
		ft := reflect.TypeOf(fn)
		for i := 0; i < ft.NumIn(); i++ {
			if ft.In(i) != reflect.TypeOf(wire.ID("")) {
				t.Errorf("%s param %d is %v, want wire.ID", name, i, ft.In(i))
			}
		}
	}
	idSlice := reflect.TypeOf([]wire.ID(nil))
	for name, ft := range map[string]reflect.Type{
		"Counter.With":   reflect.TypeOf((*Counter).With),
		"Gauge.With":     reflect.TypeOf((*Gauge).With),
		"Gauge.Delete":   reflect.TypeOf((*Gauge).Delete),
		"Histogram.With": reflect.TypeOf((*Histogram).With),
	} {
		if ft.NumIn() != 2 || ft.In(1) != idSlice {
			t.Errorf("%s must take ...wire.ID, got %v", name, ft)
		}
	}
}

type derefStringer struct{ secret string }

func (d *derefStringer) String() string { return d.secret }

type derefError struct{ secret string }

func (d *derefError) Error() string { return d.secret }

type leakStringer struct{ secret string }

func (l leakStringer) String() string { return "tool-call:" + l.secret }

type panicStringer struct{}

func (panicStringer) String() string { panic("boom " + canary) }

// Q-D9: a typed nil pointer whose String or Error method dereferences it must
// not take the process down; the value is redacted.
func TestLoggerSurvivesNilPointerStringers(t *testing.T) {
	var ds *derefStringer
	var de *derefError
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("m", slog.Any("s", ds), slog.Any("e", de), slog.Any("p", panicStringer{}), slog.Any("ok", "kept"))
	out := buf.String()
	if strings.Contains(out, canary) {
		t.Fatalf("panic text leaked: %s", out)
	}
	if !strings.Contains(out, `"ok":"kept"`) || strings.Count(out, `"[redacted`) < 3 {
		t.Fatalf("want 3 redacted values and the good one kept: %s", out)
	}
}

// Q-D14: Stringers are redacted unless allowlisted; a URL is never rendered.
func TestLoggerRedactsStringers(t *testing.T) {
	u, _ := url.Parse("https://x.example/path?q=" + canary)
	tm := time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	l := NewLogger(&buf, slog.LevelInfo)
	l.Info("m",
		slog.Any("u", u), slog.Any("uv", *u), slog.Any("l", leakStringer{canary}),
		slog.Any("t", tm), slog.Any("tp", &tm), slog.Any("d", 1500*time.Millisecond),
		slog.Any("code", wire.ErrThreshold), slog.Any("id", wire.ID("bank-a")))
	out := buf.String()
	if strings.Contains(out, canary) || strings.Contains(out, "x.example") {
		t.Fatalf("Stringer output leaked: %s", out)
	}
	m := logLines(t, bytes.NewBufferString(out))[0]
	for _, k := range []string{"u", "uv", "l"} {
		if s, _ := m[k].(string); !strings.HasPrefix(s, "[redacted") {
			t.Errorf("%s = %v, want redacted", k, m[k])
		}
	}
	if m["code"] != string(wire.ErrThreshold) || m["id"] != "bank-a" {
		t.Errorf("wire types altered: %v %v", m["code"], m["id"])
	}
	for _, k := range []string{"t", "tp"} {
		if s, _ := m[k].(string); !strings.HasPrefix(s, "2026-11-05") {
			t.Errorf("%s = %v, want the time", k, m[k])
		}
	}
	if m["d"] == nil || m["d"] == "[redacted]" {
		t.Errorf("duration lost: %v", m["d"])
	}
}
