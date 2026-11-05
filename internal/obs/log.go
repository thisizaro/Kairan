package obs

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"strings"
	"unicode/utf8"

	"kairan/internal/wire"
)

// ParseLevel maps a config string to a slog level: debug, info (also empty),
// warn or warning, error. Case and surrounding space are ignored.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("obs: unknown log level %q (want debug, info, warn or error)", truncate(s))
}

// Tenant and Proxy are the typed attributes for the two identifiers that
// belong in nearly every line. An invalid ID is replaced by InvalidLabel.
func Tenant(id wire.ID) slog.Attr { return slog.String("tenant", string(sanitize(id))) }
func Proxy(id wire.ID) slog.Attr  { return slog.String("proxy", string(sanitize(id))) }

// NewLogger returns a JSON logger writing UTC timestamps to w. It is the
// I4 guard for logs. Every attribute passes a redactor that:
//
//   - replaces the value of any key naming call data or credentials (body,
//     payload, prompt, arguments, params, result, authorization, token,
//     secret, password, cookie, ...; case, '_', '-' and '.' ignored), at any
//     group depth, also when the group itself carries such a name;
//   - replaces byte slices, io.Readers/Writers, *http.Request and every
//     composite value (structs, maps, slices, pointers) with a placeholder;
//   - passes numbers, bools, durations, times, strings, errors and
//     fmt.Stringers, truncating strings longer than MaxLogValueBytes.
//
// This cannot stop a caller from putting call data in the message text or in
// an error string; code must not do that. It stops the accidental cases.
func NewLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{
		Level:       level,
		ReplaceAttr: redact,
	}))
}

const redacted = "[redacted]"

var sensitiveKeys = []string{
	"body", "payload", "prompt", "argument", "args", "param", "result",
	"authorization", "apikey", "token", "password", "passwd", "secret",
	"cookie", "credential",
}

func sensitiveKey(k string) bool {
	var b strings.Builder
	for _, r := range strings.ToLower(k) {
		if r != '_' && r != '-' && r != '.' && r != ' ' {
			b.WriteRune(r)
		}
	}
	n := b.String()
	for _, s := range sensitiveKeys {
		if strings.Contains(n, s) {
			return true
		}
	}
	return false
}

func truncate(s string) string {
	if len(s) <= MaxLogValueBytes {
		return s
	}
	cut := MaxLogValueBytes
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "...(truncated)"
}

func redact(groups []string, a slog.Attr) slog.Attr {
	top := len(groups) == 0
	if top {
		switch a.Key {
		case slog.TimeKey:
			if a.Value.Kind() == slog.KindTime {
				a.Value = slog.TimeValue(a.Value.Time().UTC())
				return a
			}
		case slog.LevelKey:
			if _, ok := a.Value.Any().(slog.Level); ok {
				return a
			}
		case slog.MessageKey:
			if a.Value.Kind() == slog.KindString {
				a.Value = slog.StringValue(truncate(a.Value.String()))
				return a
			}
		}
	}
	if sensitiveKey(a.Key) {
		return slog.String(a.Key, redacted)
	}
	for _, g := range groups {
		if sensitiveKey(g) {
			return slog.String(a.Key, redacted)
		}
	}
	a.Value = a.Value.Resolve()
	switch a.Value.Kind() {
	case slog.KindString:
		a.Value = slog.StringValue(truncate(a.Value.String()))
	case slog.KindAny:
		a.Value = safeAny(a.Value.Any())
	}
	return a
}

var (
	readerType  = reflect.TypeOf((*io.Reader)(nil)).Elem()
	writerType  = reflect.TypeOf((*io.Writer)(nil)).Elem()
	requestType = reflect.TypeOf((*http.Request)(nil))
)

// isByteSeq reports whether t is a slice or array of bytes, or a pointer to
// one, including named types such as json.RawMessage.
func isByteSeq(t reflect.Type) bool {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) && t.Elem().Kind() == reflect.Uint8
}

func safeAny(v any) slog.Value {
	if v == nil {
		return slog.StringValue("<nil>")
	}
	t := reflect.TypeOf(v)
	if t == requestType || t.Implements(readerType) || t.Implements(writerType) || isByteSeq(t) {
		return slog.StringValue(redacted)
	}
	switch rv := reflect.ValueOf(v); t.Kind() {
	case reflect.String:
		return slog.StringValue(truncate(rv.String()))
	case reflect.Bool:
		return slog.BoolValue(rv.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return slog.Int64Value(rv.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return slog.Uint64Value(rv.Uint())
	case reflect.Float32, reflect.Float64:
		return slog.Float64Value(rv.Float())
	}
	switch x := v.(type) {
	case error:
		return slog.StringValue(truncate(x.Error()))
	case fmt.Stringer:
		return slog.StringValue(truncate(x.String()))
	}
	return slog.StringValue("[redacted:" + t.Kind().String() + "]")
}
