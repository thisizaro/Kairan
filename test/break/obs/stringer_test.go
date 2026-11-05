package obsbreak

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

type secretStringer struct{ s string }

func (s secretStringer) String() string { return s.s }

type ptrStringer struct{ s string }

func (p *ptrStringer) String() string { return p.s }

// I4, ruling Q-D14 / M-D48: fmt.Stringer values are redacted except an allowlist (time.Time,
// time.Duration, wire named types, error codes). *url.URL is never rendered: a URL with a query
// string or userinfo is a classic carrier of call data and credentials.
func TestStringerURLQueryIsNotLogged(t *testing.T) {
	u, err := url.Parse("https://user:" + canary + "@example.test/mcp?q=" + canary)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("GET", u.String(), strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]any{"url-ptr": u, "url-value": *u, "request-url": req.URL} {
		b, l := newBuf()
		l.Info("m", "k", v)
		noCanary(t, name, b.String())
		if strings.Contains(b.String(), "example.test") {
			t.Fatalf("%s: *url.URL must never be rendered, not even the host: %s", name, b.String())
		}
	}
}

// Q-D14: arbitrary Stringers (value or pointer receivers) are not on the allowlist, so they are redacted.
func TestArbitraryStringerIsRedacted(t *testing.T) {
	cases := map[string]any{
		"value-receiver":   secretStringer{canary},
		"pointer-receiver": &ptrStringer{canary},
		"in-group":         nil,
	}
	for name, v := range cases {
		b, l := newBuf()
		if name == "in-group" {
			l.Info("m", "g", map[string]any{"x": secretStringer{canary}})
		} else {
			l.Info("m", "k", v)
		}
		noCanary(t, name, b.String())
	}
	b, l := newBuf()
	l.Info("m", "k", fmt.Stringer(secretStringer{canary}))
	noCanary(t, "iface", b.String())
}

// Q-D14: the allowlist still passes: time.Duration, time.Time, wire named types, errors.
func TestAllowlistedStringersStillRender(t *testing.T) {
	b, l := newBuf()
	l.Info("m", "d", 1500*time.Millisecond, "t", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), "id", wire.ID("bank-a"), "st", wire.StateBooting, "err", fmt.Errorf("boom-visible"))
	out := b.String()
	for _, want := range []string{"2026-01-02T03:04:05", "bank-a", "boom-visible"} {
		if !strings.Contains(out, want) {
			t.Fatalf("allowlisted value %q was dropped: %s", want, out)
		}
	}
	if !strings.Contains(out, "1500000000") && !strings.Contains(out, "1.5s") {
		t.Fatalf("time.Duration was dropped: %s", out)
	}
}
