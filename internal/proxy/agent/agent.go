package agent

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sync"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/state"
	"kairan/internal/proxy/store"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// Config is everything the agent needs that is not a live object. The trust
// root comes from local config only, never from the control plane (I1).
type Config struct {
	CP      *url.URL // control plane base URL; https unless AllowPlaintext
	Tenant  wire.ID
	ProxyID wire.ID
	Token   string     // enrollment token, sent as a bearer token; never logged
	Root    trust.Root // threshold >= 2, at least that many keys, same tenant
	Skew    time.Duration
	// Guard supplies effective_now (M-D30, P-10). The caller opens it with
	// OpenClockGuard; the agent runs its persister and saves it at shutdown.
	Guard *ClockGuard
	// AllowPlaintext permits an http:// control plane URL (Docker demo only;
	// LIMITATIONS, M-D31).
	AllowPlaintext bool
	// LogOpenErr is the error from applylog.Open when the log failed to
	// verify. Pass a nil *applylog.Log with it: the proxy boots into Tampered
	// and applies nothing (M-D33).
	LogOpenErr error
}

// Validate reports whether the config can be used. A bad trust root is an
// error here, so a proxy never starts with a root that could accept a policy
// on the strength of one key (invariant I1, M-D33).
func (c Config) Validate() error {
	switch {
	case c.CP == nil || c.CP.Host == "":
		return errors.New("agent: config: control plane URL missing")
	case c.CP.Scheme != "https" && !(c.CP.Scheme == "http" && c.AllowPlaintext):
		return errors.New("agent: config: control plane URL must be https (http only with allow_plaintext)")
	case c.Token == "":
		return errors.New("agent: config: token missing")
	case !c.Tenant.Valid():
		return errors.New("agent: config: bad tenant id")
	case !c.ProxyID.Valid():
		return errors.New("agent: config: bad proxy id")
	case c.Guard == nil:
		return errors.New("agent: config: clock guard missing")
	case c.Skew < 0 || c.Skew > trust.MaxSkew:
		return errors.New("agent: config: skew must be between 0 and 5m")
	case c.Root.Tenant != c.Tenant:
		return errors.New("agent: config: trust root is for another tenant")
	}
	// Verify checks the root floor first, whatever the envelope is.
	if _, _, err := trust.Verify(wire.Envelope{}, c.Root); errors.Is(err, trust.ErrBadRoot) {
		return fmt.Errorf("agent: config: %w", err)
	}
	return nil
}

// Agent is the proxy's control-plane client. Make one with New, call Boot,
// then Run.
type Agent struct {
	cfg   Config
	st    *store.Store
	al    *applylog.Log // nil only with cfg.LogOpenErr set
	hold  *enforce.Holder
	clk   clock.Clock
	hc    *http.Client
	log   *slog.Logger
	stats *Stats

	pollTimeout   time.Duration
	statusTimeout time.Duration
	jitter        func() float64 // [0,1); replaced in tests

	started time.Duration // clk.Mono at New: uptime origin

	kick   chan struct{} // send a status report now
	wakeEx chan struct{} // expiry changed

	mu        sync.Mutex
	booted    bool
	st8       wire.ProxyState
	view      *enforceView // policy in force, nil if none
	lastErr   *wire.ApplyError
	seq       uint64
	failures  int // consecutive poll failures, for backoff
	lastRej   rejKey
	statusHld time.Duration // do not POST status before this Mono (Retry-After)
}

// enforceView is what the agent remembers about the policy in force.
type enforceView struct {
	active  *enforce.Active
	version uint64
	expires time.Time // expires_at + skew: expired when effective_now >= this
}

type rejKey struct {
	to   uint64
	hash wire.Hash
	code wire.ErrorCode
	set  bool
}

// New checks the config and builds an Agent. It does not touch the disk or
// the network. stats and log may be nil. hc should come from NewHTTPClient;
// it must not carry its own Timeout (the agent sets a deadline per request).
func New(cfg Config, st *store.Store, al *applylog.Log, h *enforce.Holder, clk clock.Clock, hc *http.Client, log *slog.Logger, stats *Stats) (*Agent, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	switch {
	case st == nil:
		return nil, errors.New("agent: store missing")
	case al == nil && cfg.LogOpenErr == nil:
		return nil, errors.New("agent: apply log missing")
	case h == nil:
		return nil, errors.New("agent: holder missing")
	case clk == nil:
		return nil, errors.New("agent: clock missing")
	case hc == nil:
		return nil, errors.New("agent: http client missing")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if stats == nil {
		stats = &Stats{}
	}
	return &Agent{
		cfg: cfg, st: st, al: al, hold: h, clk: clk, hc: hc, log: log, stats: stats,
		pollTimeout:   wire.PollClientTimeout,
		statusTimeout: statusTimeout,
		jitter:        rand.Float64,
		started:       clk.Mono(),
		kick:          make(chan struct{}, 1),
		wakeEx:        make(chan struct{}, 1),
		st8:           wire.StateBooting,
	}, nil
}

// statusTimeout is the status POST deadline (M-D31).
const statusTimeout = 10 * time.Second

// Boot is the boot rule of ARCHITECTURE section 4 (M-D33). It loads the
// stored envelope, re-verifies it with trust.Verify against the local root,
// compares it with the apply log, appends a repair entry if a crash fell
// between Save and Append, decides expiry at effective_now, and installs the
// resulting Active in the Holder. Nothing is enforced that did not pass
// Verify. Boot returns an error only for a programming error (called twice);
// a bad disk is a Tampered state, not an error.
func (a *Agent) Boot() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.booted {
		return errors.New("agent: Boot called twice")
	}
	a.booted = true

	now := a.cfg.Guard.Now()
	var verified trust.Verified
	verify := func(env wire.Envelope) (store.Checked, error) {
		v, code, err := trust.Verify(env, a.cfg.Root)
		if err != nil {
			return store.Checked{}, fmt.Errorf("%w (%s)", err, code)
		}
		verified = v
		return store.Checked{Version: v.Policy.Version, Hash: v.Hash, Expires: v.Policy.ExpiresAt.Add(a.cfg.Skew)}, nil
	}
	stored, _ := store.Inspect(a.st, verify)

	lv := store.LogView{OpenErr: a.cfg.LogOpenErr}
	if a.al != nil {
		lv.Seq, _ = a.al.Head()
		lv.AppliedVer, lv.AppliedHash = a.al.LastApplied()
	}
	dec := store.DecideBoot(stored, lv, now)
	say(a.log, slog.LevelInfo, evBoot, "reason", dec.Reason)

	ev := dec.Event
	if dec.Repair {
		if _, err := a.al.Append(applylog.Entry{From: lv.AppliedVer, To: stored.Checked.Version, Hash: stored.Checked.Hash}); err != nil {
			// The log cannot record what is on disk: refuse to enforce it.
			say(a.log, slog.LevelError, evRepairNotWritten, "err", err)
			ev = state.BootTampered
		}
	}

	next := state.Next(wire.StateBooting, ev)
	a.st8 = next
	switch next {
	case wire.StateEnforcing, wire.StateSafeMode:
		a.setPolicyLocked(verified.Policy, verified.Hash, next)
		a.cfg.Guard.MarkApplied()
	default:
		a.hold.Store(&enforce.Active{State: next})
	}
	if next == wire.StateTampered {
		a.lastErr = &wire.ApplyError{Code: wire.ErrTampered}
		a.stats.Inc(MetricBootTampered)
	}
	return nil
}
