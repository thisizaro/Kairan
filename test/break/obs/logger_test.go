package obsbreak

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"kairan/internal/obs"
	"kairan/internal/wire"
)

func newBuf() (*bytes.Buffer, *slog.Logger) {
	b := &bytes.Buffer{}
	return b, obs.NewLogger(b, slog.LevelDebug)
}

func noCanary(t *testing.T, name, out string) {
	t.Helper()
	if strings.Contains(out, canary) || strings.Contains(out, "9f3b27") {
		t.Fatalf("%s: canary reached the log:\n%s", name, out)
	}
}

func lines(t *testing.T, out string) []map[string]any {
	t.Helper()
	var res []map[string]any
	for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if ln == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("log line is not a JSON object: %v: %q", err, ln)
		}
		res = append(res, m)
	}
	return res
}

type valuer struct{ v slog.Value }

func (l valuer) LogValue() slog.Value { return l.v }

type nilStringer struct{ name string }

func (n *nilStringer) String() string { return n.name }

type secretStruct struct {
	Body   string
	Prompt string
}

func TestLoggerFormatUTCAndLevel(t *testing.T) {
	b := &bytes.Buffer{}
	l := obs.NewLogger(b, slog.LevelWarn)
	l.Debug("dropped-debug")
	l.Info("dropped-info")
	l.Warn("kept-warn", "n", 1)
	l.Error("kept-error")
	ls := lines(t, b.String())
	if len(ls) != 2 {
		t.Fatalf("got %d lines at level warn: %s", len(ls), b.String())
	}
	for _, m := range ls {
		ts, _ := m["time"].(string)
		if !strings.HasSuffix(ts, "Z") {
			t.Fatalf("time %q is not UTC (Z)", ts)
		}
		if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
			t.Fatalf("time %q: %v", ts, err)
		}
	}
	// a JST clock on the host must not leak into the log
	old := time.Local
	time.Local = time.FixedZone("JST", 9*3600)
	defer func() { time.Local = old }()
	b.Reset()
	l.Warn("x")
	if ts := lines(t, b.String())[0]["time"].(string); !strings.HasSuffix(ts, "Z") {
		t.Fatalf("with local zone JST the time is %q, want UTC", ts)
	}
}

func TestParseLevel(t *testing.T) {
	ok := map[string]slog.Level{
		"debug": slog.LevelDebug, "DEBUG": slog.LevelDebug, " info ": slog.LevelInfo, "": slog.LevelInfo, "Info": slog.LevelInfo,
		"warn": slog.LevelWarn, "warning": slog.LevelWarn, "WARNING\n": slog.LevelWarn, "error": slog.LevelError, "\tERROR": slog.LevelError,
	}
	for in, want := range ok {
		got, err := obs.ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("ParseLevel(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"trace", "fatal", "info\x00", "i nfo", "debug+2", "0", "-4", "warn,error", strings.Repeat("a", 100000), "infoo", "everything", "ｉｎｆｏ"} {
		if got, err := obs.ParseLevel(in); err == nil {
			t.Errorf("ParseLevel(%q) accepted as %v", truncate(in), got)
		}
	}
}

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}

func TestRedactedKeysEverywhere(t *testing.T) {
	keys := []string{
		"body", "payload", "prompt", "arguments", "params", "result", "authorization", "token", "secret", "password", "cookie",
		"Body", "PAYLOAD", "Prompt", "Arguments", "Authorization", "AUTHORIZATION", "Set-Cookie", "set_cookie", "x.token",
		"request_body", "request-body", "tool.arguments", "tool_arguments", "api_token", "result_code", "token_count",
		"bo_dy", "p-a-y-l-o-a-d", "pro.mpt", "Pass_Word", "SECRET", "user_password", "client_secret", "call_params",
	}
	for _, k := range keys {
		t.Run(k, func(t *testing.T) {
			b, l := newBuf()
			l.Info("m", k, canary)
			l.Info("m", slog.String(k, canary))
			l.Info("m", slog.Group("g", slog.String(k, canary)))
			l.Info("m", slog.Group("g", slog.Group("h", slog.Group("i", slog.String(k, canary)))))
			l.With(k, canary).Info("with")
			l.With(slog.Group("g", slog.String(k, canary))).Info("with-group")
			l.WithGroup("g").With(k, canary).Info("withgroup-with")
			l.WithGroup("g").WithGroup("h").Info("deep", k, canary)
			l.Info("m", slog.Any(k, []byte(canary)))
			l.Info("m", slog.Any(k, map[string]string{"x": canary}))
			noCanary(t, k, b.String())
			lines(t, b.String()) // still valid JSON
		})
	}
}

func TestRedactedGroupNamesRedactEverythingInside(t *testing.T) {
	for _, g := range []string{"body", "Payload", "request_body", "authorization", "headers.cookie"} {
		b, l := newBuf()
		l.Info("m", slog.Group(g, slog.String("innocent", canary), slog.Int("n", 1)))
		l.WithGroup(g).Info("m", "innocent", canary)
		l.WithGroup(g).WithGroup("x").Info("m", slog.String("innocent", canary))
		noCanary(t, "group "+g, b.String())
	}
}

func TestCompositeAndBinaryValuesNeverRendered(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://example.test/mcp?q="+url.QueryEscape(canary), strings.NewReader(canary))
	req.Header.Set("Authorization", "Bearer "+canary)
	req.Header.Set("X-Api-Key", canary)
	rr := *req
	buf := bytes.NewBufferString(canary)
	f, _ := os.CreateTemp(t.TempDir(), "x")
	f.WriteString(canary)
	f.Seek(0, 0)
	defer f.Close()
	cyc := map[string]any{"s": canary}
	cyc["self"] = cyc
	type node struct {
		Next *node
		S    string
	}
	n := &node{S: canary}
	n.Next = n
	var nilReq *http.Request
	values := map[string]any{
		"bytes":           []byte(canary),
		"rawmessage":      json.RawMessage(`{"a":"` + canary + `"}`),
		"rawmessage-ptr":  &[]json.RawMessage{json.RawMessage(canary)},
		"byte-array":      [20]byte{'C', 'A', 'N', 'A', 'R', 'Y', '-', '9', 'f', '3', 'b', '2', '7'},
		"strings-slice":   []string{canary},
		"any-slice":       []any{canary, 1},
		"map":             map[string]string{"k": canary},
		"map-any":         map[string]any{"k": []byte(canary)},
		"struct":          secretStruct{Body: canary, Prompt: canary},
		"struct-ptr":      &secretStruct{Body: canary},
		"ptr-ptr":         func() any { p := &secretStruct{Body: canary}; return &p }(),
		"reader":          strings.NewReader(canary),
		"bytes-buffer":    buf,
		"bytes-reader":    bytes.NewReader([]byte(canary)),
		"file":            f,
		"io.Reader-iface": io.Reader(strings.NewReader(canary)),
		"http.Request":    req,
		"http.Request-v":  rr,
		"nil-request":     nilReq,
		"http.Header":     req.Header,
		// "url": *url.URL is a fmt.Stringer, which the doc says passes: see change-request Q-URL below.
		"url-value":       *req.URL,
		"url.Values":      req.URL.Query(),
		"cyclic-map":      cyc,
		"cyclic-ptr":      n,
		"chan":            make(chan string, 1),
		"func":            func() string { return canary },
		"nil":             nil,
		"nested-any":      map[string][]map[string]any{"a": {{"b": canary}}},
		"error-wrap-body": nil, // placeholder to keep map shape
		"logvaluer-bytes": valuer{slog.AnyValue([]byte(canary))},
		"logvaluer-group": valuer{slog.GroupValue(slog.Any("body", canary), slog.Any("x", []byte(canary)))},
		"logvaluer-any":   valuer{slog.AnyValue(secretStruct{Body: canary})},
		"logvaluer-ptr":   valuer{slog.AnyValue(&secretStruct{Prompt: canary})},
		"time-struct-ptr": &struct {
			T time.Time
			S string
		}{time.Now(), canary},
	}
	for name, v := range values {
		t.Run(name, func(t *testing.T) {
			b, l := newBuf()
			finish := make(chan struct{})
			go func() {
				defer close(finish)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("logger panicked on %s: %v", name, r)
					}
				}()
				l.Info("m", "k", v)
				l.Info("m", slog.Any("k", v))
				l.Info("m", slog.Group("g", slog.Any("k", v)))
				l.With("k", v).Info("with")
				l.WithGroup("a").WithGroup("b").Info("deep", "k", v)
			}()
			select {
			case <-finish:
			case <-time.After(5 * time.Second):
				t.Fatalf("logger hung or recursed on %s", name)
			}
			noCanary(t, name, b.String())
			lines(t, b.String())
		})
	}
}

// A nil pointer whose String method dereferences it: fmt.Sprint recovers from this and prints
// "<nil>"; a logger that calls String() directly crashes the goroutine that logs.
func TestNilAndHostileStringers(t *testing.T) {
	var ns *nilStringer
	calls := map[string]func(l *slog.Logger){
		"nil-stringer-ptr":      func(l *slog.Logger) { l.Info("m", "k", ns) },
		"nil-stringer-slog-any": func(l *slog.Logger) { l.Info("m", slog.Any("k", ns)) },
		"nil-stringer-in-with":  func(l *slog.Logger) { l.With("k", ns).Info("m") },
		"nil-stringer-in-group": func(l *slog.Logger) { l.Info("m", slog.Group("g", slog.Any("k", ns))) },
		"nil-error":             func(l *slog.Logger) { l.Info("m", "k", error(nil)) },
		"nil-buffer-ptr":        func(l *slog.Logger) { l.Info("m", "k", (*bytes.Buffer)(nil)) },
		"nil-stringer-iface":    func(l *slog.Logger) { l.Info("m", "k", (fmt.Stringer)(nil)) },
		"nil-bytes":             func(l *slog.Logger) { l.Info("m", "k", []byte(nil)) },
		"nil-url-ptr":           func(l *slog.Logger) { l.Info("m", "k", (*url.URL)(nil)) },
		"nil-time-ptr":          func(l *slog.Logger) { l.Info("m", "k", (*time.Time)(nil)) },
	}
	for name, f := range calls {
		t.Run(name, func(t *testing.T) {
			b, l := newBuf()
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("logging panicked: %v", r)
				}
			}()
			f(l)
			lines(t, b.String())
		})
	}
}

func TestStringsAndErrorsPassButTruncate(t *testing.T) {
	limit := obs.MaxLogValueBytes
	if limit != 512 {
		t.Fatalf("MaxLogValueBytes = %d, doc says 512", limit)
	}
	b, l := newBuf()
	exact := strings.Repeat("a", limit)
	over := strings.Repeat("b", limit+1)
	huge := strings.Repeat("c", 1<<20)
	l.Info("m", "exact", exact, "over", over, "huge", huge)
	m := lines(t, b.String())[0]
	if m["exact"] != exact {
		t.Fatalf("a string of exactly %d bytes was altered (len %d)", limit, len(m["exact"].(string)))
	}
	for _, k := range []string{"over", "huge"} {
		s, _ := m[k].(string)
		if len(s) > limit+64 {
			t.Fatalf("%s: %d bytes written, limit %d", k, len(s), limit)
		}
		if len(s) == 0 {
			t.Fatalf("%s vanished", k)
		}
	}
	if b.Len() > 4096 {
		t.Fatalf("one line with three long values is %d bytes", b.Len())
	}

	// canary hidden beyond the limit
	for _, form := range []string{"string", "error", "stringer", "msg", "any-string"} {
		b, l = newBuf()
		long := strings.Repeat("x", limit+10) + canary
		switch form {
		case "string":
			l.Info("m", "note", long)
		case "error":
			l.Info("m", "err", errors.New(long))
			l.Error("m", slog.Any("error", fmt.Errorf("wrap: %w", errors.New(long))))
		case "stringer":
			l.Info("m", "note", &nilStringer{name: long})
		case "msg":
			l.Info(long)
		case "any-string":
			l.Info("m", slog.Any("note", long))
		}
		noCanary(t, form, b.String())
		if b.Len() > 4096 {
			t.Fatalf("%s: line of %d bytes", form, b.Len())
		}
	}

	// multi-byte runes cut at the limit stay valid UTF-8
	for _, r := range []string{"é", "回", "😀"} {
		b, l = newBuf()
		s := strings.Repeat(r, 400)
		l.Info("m", "k", s)
		if !utf8.Valid(b.Bytes()) {
			t.Fatalf("truncating %q runes produced invalid UTF-8", r)
		}
		out := lines(t, b.String())[0]["k"].(string)
		if !utf8.ValidString(out) || strings.ContainsRune(out, utf8.RuneError) {
			t.Fatalf("truncated %q string has a broken rune: %q", r, out[len(out)-20:])
		}
	}
}

func TestLinesStayLinesAndOneRecordIsOneLine(t *testing.T) {
	b, l := newBuf()
	evil := "x\n{\"time\":\"2026-01-01T00:00:00Z\",\"level\":\"INFO\",\"msg\":\"forged\"}\r\n"
	l.Info(evil, evil, evil, slog.Group(evil, slog.String(evil, evil)))
	l.With(evil, evil).Info("w")
	l.WithGroup(evil).Info("g", "k", evil)
	l.Error(evil, "err", errors.New(evil))
	out := b.String()
	if n := strings.Count(out, "\n"); n != 4 {
		t.Fatalf("%d lines for 4 records:\n%q", n, out)
	}
	for _, m := range lines(t, out) {
		if m["msg"] == "forged" {
			t.Fatal("log forging succeeded")
		}
	}
}

func TestSafeAttributesStillLogged(t *testing.T) {
	b, l := newBuf()
	l.Info("applied", obs.Tenant("bank-a"), obs.Proxy("p1"), "version", 8, "ok", true, "took", 250*time.Millisecond, "ratio", 0.5, "outcome", "applied")
	m := lines(t, b.String())[0]
	if m["msg"] != "applied" || m["version"] != float64(8) || m["ok"] != true || m["outcome"] != "applied" {
		t.Fatalf("legitimate fields lost or altered: %v", m)
	}
	flat := b.String()
	if !strings.Contains(flat, "bank-a") || !strings.Contains(flat, `"p1"`) {
		t.Fatalf("tenant/proxy missing: %s", flat)
	}
	// typed attrs: hostile IDs replaced
	b.Reset()
	l.Info("x", obs.Tenant(wire.ID(canary)), obs.Proxy("a\nb"))
	noCanary(t, "typed attrs", b.String())
}

func TestLoggerWithContextAndHandlerEnabled(t *testing.T) {
	b, l := newBuf()
	l.LogAttrs(context.Background(), slog.LevelInfo, "m", slog.Any("body", canary), slog.String("ok", "fine"))
	if !l.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("a debug-level logger reports debug as disabled")
	}
	noCanary(t, "LogAttrs", b.String())
}

// The handler is shared across derived loggers: an unsynchronised writer must still see whole lines.
func TestLoggerConcurrentWritersKeepLinesIntact(t *testing.T) {
	b := &bytes.Buffer{} // deliberately not goroutine safe
	base := obs.NewLogger(b, slog.LevelInfo)
	var wg sync.WaitGroup
	const workers, per = 24, 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			l := base
			switch w % 3 {
			case 1:
				l = base.With("worker", w)
			case 2:
				l = base.WithGroup("g").With("worker", w)
			}
			for i := 0; i < per; i++ {
				l.Info("tick", "i", i, "body", canary, "note", strings.Repeat("n", 700))
			}
		}(w)
	}
	wg.Wait()
	out := b.String()
	noCanary(t, "concurrent", out)
	if n := len(lines(t, out)); n != workers*per {
		t.Fatalf("%d intact lines, want %d (interleaved or lost writes)", n, workers*per)
	}
}

func TestLoggerDoesNotWriteWhenDisabledOrToNilSafe(t *testing.T) {
	b := &bytes.Buffer{}
	l := obs.NewLogger(b, slog.LevelError)
	l.Info("x", "body", canary)
	l.Warn("x", "body", canary)
	if b.Len() != 0 {
		t.Fatalf("below-level records were written: %q", b.String())
	}
	// failing writer must not panic the caller
	fl := obs.NewLogger(failWriter{}, slog.LevelInfo)
	fl.Info("m", "k", 1)
	fl.Error("m")
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func FuzzLoggerNeverLeaksOrBreaks(f *testing.F) {
	f.Add("body", "v", "msg")
	f.Add("Set-Cookie", canary, "x\ny")
	f.Add("k", strings.Repeat("a", 600)+canary, "m")
	f.Add("", "", "")
	f.Fuzz(func(t *testing.T, key, val, msg string) {
		b, l := newBuf()
		l.Info(msg, key, val, slog.Group(key, slog.String(key, val)), slog.Any(key, []byte(val)))
		l.With(key, val).WithGroup(key).Info(msg, key, val)
		out := b.String()
		for _, ln := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				t.Fatalf("invalid JSON line %q: %v", ln, err)
			}
		}
		if len(out) > 20000 {
			t.Fatalf("output %d bytes for inputs of %d/%d/%d bytes: truncation not applied", len(out), len(key), len(val), len(msg))
		}
		if !utf8.Valid(b.Bytes()) {
			t.Fatal("invalid UTF-8 in log output")
		}
	})
}
