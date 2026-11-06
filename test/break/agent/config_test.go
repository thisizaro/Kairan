package agentbreak

import (
	"crypto/ed25519"
	"net/url"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/store"
	"kairan/internal/wire"
)

func mustURL(s string) *url.URL { u, _ := url.Parse(s); return u }

// agent.New / Config.Validate refuse a config that must not run (doc "Use"): no URL, http:// without
// AllowPlaintext, empty token, skew outside 0..5m, a trust root below the floor (I1, M-D33).
func TestConfigValidationRefusals(t *testing.T) {
	g, _ := agent.OpenClockGuard(clock.NewFake(t0), t.TempDir())
	ok := func() agent.Config {
		return agent.Config{CP: mustURL("https://cp.example.test"), Tenant: tenant, ProxyID: proxy, Token: token,
			Root: root(tenant, keyA, keyB, keyC), Skew: 2 * time.Minute, Guard: g}
	}
	if err := ok().Validate(); err != nil {
		t.Fatalf("baseline config refused: %v", err)
	}
	cases := []struct {
		name string
		mod  func(c *agent.Config)
		bad  bool
	}{
		{"nil CP", func(c *agent.Config) { c.CP = nil }, true},
		{"http without AllowPlaintext", func(c *agent.Config) { c.CP = mustURL("http://cp.example.test") }, true},
		{"http with AllowPlaintext", func(c *agent.Config) { c.CP = mustURL("http://cp.example.test"); c.AllowPlaintext = true }, false},
		{"ftp scheme", func(c *agent.Config) { c.CP = mustURL("ftp://cp.example.test"); c.AllowPlaintext = true }, true},
		{"no scheme", func(c *agent.Config) { c.CP = mustURL("cp.example.test") }, true},
		{"empty host", func(c *agent.Config) { c.CP = mustURL("https://") }, true},
		{"file scheme", func(c *agent.Config) { c.CP = mustURL("file:///etc/passwd") }, true},
		{"empty token", func(c *agent.Config) { c.Token = "" }, true},
		{"skew exactly 5m", func(c *agent.Config) { c.Skew = 5 * time.Minute }, false},
		{"skew 5m+1ns", func(c *agent.Config) { c.Skew = 5*time.Minute + 1 }, true},
		{"skew 1h", func(c *agent.Config) { c.Skew = time.Hour }, true},
		{"skew negative", func(c *agent.Config) { c.Skew = -time.Second }, true},
		{"skew zero", func(c *agent.Config) { c.Skew = 0 }, false},
		{"invalid tenant", func(c *agent.Config) { c.Tenant = "Bank A" }, true},
		{"invalid proxy id", func(c *agent.Config) { c.ProxyID = "" }, true},
		{"root of another tenant", func(c *agent.Config) { c.Root = root("bank-b", keyA, keyB, keyC) }, true},
		{"threshold 1", func(c *agent.Config) { c.Root.Threshold = 1 }, true},
		{"threshold 0", func(c *agent.Config) { c.Root.Threshold = 0 }, true},
		{"threshold negative", func(c *agent.Config) { c.Root.Threshold = -1 }, true},
		{"threshold above keys", func(c *agent.Config) { c.Root.Threshold = 4 }, true},
		{"one key, threshold 2", func(c *agent.Config) { c.Root = root(tenant, keyA) }, true},
		{"no keys", func(c *agent.Config) { c.Root = root(tenant) }, true},
		{"nil keys", func(c *agent.Config) { c.Root.Keys = nil }, true},
		{"two keys threshold 2", func(c *agent.Config) { c.Root = root(tenant, keyA, keyB) }, false},
		{"key id does not match key", func(c *agent.Config) {
			c.Root.Keys = map[wire.Hash]ed25519Pub{keyA.id: keyB.pub, keyB.id: keyB.pub, keyC.id: keyC.pub}
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := ok()
			c.mod(&cfg)
			err := cfg.Validate()
			if c.bad && err == nil {
				t.Fatalf("Validate accepted it")
			}
			if !c.bad && err != nil {
				t.Fatalf("Validate refused: %v", err)
			}
			// New agrees with Validate and never panics
			dir := t.TempDir()
			st, _ := store.Open(dir)
			al, _ := applylog.Open(dir+"/a.log", clock.NewFake(t0))
			hc, _ := agent.NewHTTPClient("")
			_, nerr := agent.New(cfg, st, al, &enforce.Holder{}, clock.NewFake(t0), hc, nil, nil)
			if c.bad && nerr == nil {
				t.Errorf("agent.New accepted a config that Validate refuses")
			}
			if !c.bad && nerr != nil {
				t.Errorf("agent.New refused a config that Validate accepts: %v", nerr)
			}
		})
	}
}

// An Agent built with a nil Guard must not panic (Config.Guard is required by the doc).
func TestNilGuardDoesNotPanic(t *testing.T) {
	defer func() {
		if x := recover(); x != nil {
			t.Fatalf("panic: %v", x)
		}
	}()
	dir := t.TempDir()
	st, _ := store.Open(dir)
	al, _ := applylog.Open(dir+"/a.log", clock.NewFake(t0))
	hc, _ := agent.NewHTTPClient("")
	cfg := agent.Config{CP: mustURL("https://cp.example.test"), Tenant: tenant, ProxyID: proxy, Token: token, Root: root(tenant, keyA, keyB), Skew: time.Minute}
	if a, err := agent.New(cfg, st, al, &enforce.Holder{}, clock.NewFake(t0), hc, nil, nil); err == nil {
		_ = a.Boot()
	}
}

type ed25519Pub = ed25519.PublicKey
