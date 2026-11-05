package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/wire"
)

const (
	tmpPrefix = ".tmp-"
	ext       = ".json"

	// heartbeatFlush bounds how long a heartbeat that changes nothing
	// important may stay in memory only. With 1,000 proxies reporting every
	// 10s, writing each heartbeat would be 100 fsyncs a second and would slow
	// the acks that matter. A crash loses at most this much SeenAt, Seq and
	// counter freshness; the next heartbeat restores it.
	heartbeatFlush = 30 * time.Second
)

// ---- on-disk records (strict JSON, unknown fields rejected) ----

type envFile struct {
	Tenant   wire.ID       `json:"tenant"`
	Version  uint64        `json:"version"`
	Hash     wire.Hash     `json:"hash"`
	Envelope wire.Envelope `json:"envelope"`
}

type rolloutFile struct {
	Tenant   wire.ID           `json:"tenant"`
	Version  uint64            `json:"version"`
	Previous uint64            `json:"previous"`
	Phase    wire.RolloutPhase `json:"phase"`
	Reason   wire.ErrorCode    `json:"reason,omitempty"`
	DwellNs  int64             `json:"dwell_ns"`
	CanaryOK time.Time         `json:"canary_ok,omitzero"`
}

// tlRec is a timeline entry plus the apply-log anchor of the latest report
// seen while it was current (M-D35). wire.TimelineEntry has no anchor fields
// yet; see the change-request that asks for them.
type tlRec struct {
	wire.TimelineEntry
	LogSeq  uint64    `json:"log_seq"`
	LogHead wire.Hash `json:"log_head,omitempty"`
}

type proxyFile struct {
	Group    wire.ID           `json:"group"`
	Report   wire.StatusReport `json:"report"`
	SeenAt   time.Time         `json:"seen_at"`
	Timeline []tlRec           `json:"timeline"`
}

// ---- in-memory state ----

type proxyRec struct {
	last    fleet.Last
	tl      []tlRec
	flushed time.Time // SeenAt of the last report written to disk
}

type tenantState struct {
	envs    map[uint64]wire.Envelope
	rollout *rollout.Rollout
	proxies map[wire.ID]*proxyRec
}

type files struct {
	root string
	mu   sync.RWMutex
	ten  map[wire.ID]*tenantState
}

// OpenFiles opens (creating if needed) the state directory dir and loads all
// of it. Any damaged file fails the open with ErrCorrupt.
func OpenFiles(dir string) (Store, error) {
	if err := ensureDir(dir); err != nil {
		return nil, fmt.Errorf("store: open %s: %w", dir, err)
	}
	f := &files{root: dir, ten: map[wire.ID]*tenantState{}}
	if err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *files) tenant(id wire.ID) *tenantState {
	t := f.ten[id]
	if t == nil {
		t = &tenantState{envs: map[uint64]wire.Envelope{}, proxies: map[wire.ID]*proxyRec{}}
		f.ten[id] = t
	}
	return t
}

// ---- loading ----

func corrupt(rel string) error { return fmt.Errorf("%w: %s", ErrCorrupt, rel) }

// readDir lists dir; a missing directory is empty. Leftover temp files from a
// crashed write are removed and not returned.
func readDir(dir string) ([]os.DirEntry, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: read %s: %w", dir, err)
	}
	out := ents[:0]
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), tmpPrefix) {
			if !e.IsDir() {
				_ = os.Remove(filepath.Join(dir, e.Name()))
			}
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func decodeFile(path, rel string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("store: read %s: %w", rel, err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return corrupt(rel)
	}
	if _, err := dec.Token(); err != io.EOF {
		return corrupt(rel) // trailing data
	}
	return nil
}

func (f *files) load() error {
	if err := f.loadEnvelopes(); err != nil {
		return err
	}
	if err := f.loadRollouts(); err != nil {
		return err
	}
	return f.loadFleet()
}

func (f *files) tenantDirs(kind string) ([]wire.ID, error) {
	ents, err := readDir(filepath.Join(f.root, kind))
	if err != nil {
		return nil, err
	}
	var ids []wire.ID
	for _, e := range ents {
		id := wire.ID(e.Name())
		if !e.IsDir() || !id.Valid() {
			return nil, corrupt(filepath.Join(kind, e.Name()))
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (f *files) loadEnvelopes() error {
	tenants, err := f.tenantDirs("envelopes")
	if err != nil {
		return err
	}
	for _, tn := range tenants {
		dir := filepath.Join(f.root, "envelopes", string(tn))
		ents, err := readDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			rel := filepath.Join("envelopes", string(tn), e.Name())
			ver, ok := parseVersionName(e.Name())
			if !ok || e.IsDir() {
				return corrupt(rel)
			}
			var rec envFile
			if err := decodeFile(filepath.Join(dir, e.Name()), rel, &rec); err != nil {
				return err
			}
			if rec.Tenant != tn || rec.Version != ver ||
				checkEnvelope(rec.Envelope, EnvelopeMeta{Tenant: rec.Tenant, Version: rec.Version, Hash: rec.Hash}) != nil {
				return corrupt(rel)
			}
			f.tenant(tn).envs[ver] = rec.Envelope
		}
	}
	return nil
}

func (f *files) loadRollouts() error {
	ents, err := readDir(filepath.Join(f.root, "rollouts"))
	if err != nil {
		return err
	}
	for _, e := range ents {
		rel := filepath.Join("rollouts", e.Name())
		tn := wire.ID(strings.TrimSuffix(e.Name(), ext))
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext) || !tn.Valid() {
			return corrupt(rel)
		}
		var rec rolloutFile
		if err := decodeFile(filepath.Join(f.root, rel), rel, &rec); err != nil {
			return err
		}
		r := rollout.Rollout{Tenant: rec.Tenant, Version: rec.Version, Previous: rec.Previous,
			Phase: rec.Phase, Reason: rec.Reason, Dwell: time.Duration(rec.DwellNs), CanaryOK: rec.CanaryOK}
		if rec.Tenant != tn || checkRollout(r) != nil {
			return corrupt(rel)
		}
		f.tenant(tn).rollout = &r
	}
	return nil
}

func (f *files) loadFleet() error {
	tenants, err := f.tenantDirs("fleet")
	if err != nil {
		return err
	}
	for _, tn := range tenants {
		dir := filepath.Join(f.root, "fleet", string(tn))
		ents, err := readDir(dir)
		if err != nil {
			return err
		}
		for _, e := range ents {
			rel := filepath.Join("fleet", string(tn), e.Name())
			px := wire.ID(strings.TrimSuffix(e.Name(), ext))
			if e.IsDir() || !strings.HasSuffix(e.Name(), ext) || !px.Valid() {
				return corrupt(rel)
			}
			var rec proxyFile
			if err := decodeFile(filepath.Join(dir, e.Name()), rel, &rec); err != nil {
				return err
			}
			if checkProxyFile(rec, tn, px) != nil {
				return corrupt(rel)
			}
			rec.SeenAt = rec.SeenAt.UTC()
			f.tenant(tn).proxies[px] = &proxyRec{
				last:    fleet.Last{Group: rec.Group, Report: rec.Report, SeenAt: rec.SeenAt},
				tl:      rec.Timeline,
				flushed: rec.SeenAt,
			}
		}
	}
	return nil
}

func parseVersionName(name string) (uint64, bool) {
	digits, ok := strings.CutSuffix(name, ext)
	if !ok || len(digits) != 20 {
		return 0, false
	}
	v, err := strconv.ParseUint(digits, 10, 64)
	if err != nil || v == 0 {
		return 0, false
	}
	return v, true
}

func versionName(v uint64) string { return fmt.Sprintf("%020d%s", v, ext) }

// ---- validation ----

func invalid(what string) error { return fmt.Errorf("%w: %s", wire.ErrInvalid, what) }

func payloadHash(b []byte) wire.Hash {
	h := sha256.Sum256(b)
	return wire.Hash(hex.EncodeToString(h[:]))
}

func checkEnvelope(env wire.Envelope, m EnvelopeMeta) error {
	switch {
	case !m.Tenant.Valid():
		return invalid("tenant")
	case m.Version == 0:
		return invalid("version")
	}
	if err := env.ValidateShape(); err != nil {
		return err
	}
	if m.Hash != payloadHash(env.Payload) {
		return invalid("hash does not match payload")
	}
	return nil
}

func checkRollout(r rollout.Rollout) error {
	switch {
	case !r.Tenant.Valid():
		return invalid("rollout tenant")
	case r.Dwell < 0:
		return invalid("rollout dwell")
	case r.Reason != "" && !r.Reason.Valid():
		return invalid("rollout reason")
	}
	switch r.Phase {
	case wire.PhaseCanary, wire.PhasePromoting, wire.PhaseHalted, wire.PhaseComplete:
		return nil
	}
	return invalid("rollout phase")
}

func checkProxyFile(p proxyFile, tenant, proxy wire.ID) error {
	if !p.Group.Valid() || p.SeenAt.IsZero() {
		return invalid("group or seen_at")
	}
	if err := p.Report.Validate(); err != nil {
		return err
	}
	if p.Report.Tenant != tenant || p.Report.ProxyID != proxy {
		return invalid("report does not match its file")
	}
	for _, e := range p.Timeline {
		switch {
		case e.ProxyID != proxy,
			(e.Version == 0) != (e.PolicyHash == ""),
			e.PolicyHash != "" && !e.PolicyHash.Valid(),
			e.LastSeenUnixMs < e.FirstSeenUnixMs,
			(e.LogSeq == 0) != (e.LogHead == ""),
			e.LogHead != "" && !e.LogHead.Valid():
			return invalid("timeline entry")
		}
	}
	return nil
}

// ---- copies ----

func cloneEnv(e wire.Envelope) wire.Envelope {
	out := e
	out.Payload = bytes.Clone(e.Payload)
	out.Signatures = make([]wire.Signature, len(e.Signatures))
	for i, s := range e.Signatures {
		out.Signatures[i] = wire.Signature{KeyID: s.KeyID, Sig: bytes.Clone(s.Sig)}
	}
	return out
}

func cloneReport(r wire.StatusReport) wire.StatusReport {
	if r.LastError != nil {
		e := *r.LastError
		r.LastError = &e
	}
	return r
}

// ---- Store ----

func (f *files) PutEnvelope(env wire.Envelope, m EnvelopeMeta) error {
	if err := checkEnvelope(env, m); err != nil {
		return err
	}
	env = cloneEnv(env)
	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tenant(m.Tenant)
	if _, ok := t.envs[m.Version]; ok {
		return ErrConflict
	}
	b, err := json.Marshal(envFile{Tenant: m.Tenant, Version: m.Version, Hash: m.Hash, Envelope: env})
	if err != nil {
		return fmt.Errorf("store: encode envelope: %w", err)
	}
	dir := filepath.Join(f.root, "envelopes", string(m.Tenant))
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("store: write envelope: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, versionName(m.Version)), b); err != nil {
		return fmt.Errorf("store: write envelope: %w", err)
	}
	t.envs[m.Version] = env
	return nil
}

func (f *files) Envelope(tenant wire.ID, version uint64) (wire.Envelope, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if t := f.ten[tenant]; t != nil {
		if e, ok := t.envs[version]; ok {
			return cloneEnv(e), nil
		}
	}
	return wire.Envelope{}, ErrNotFound
}

func (f *files) PutRollout(r rollout.Rollout) error {
	if err := checkRollout(r); err != nil {
		return err
	}
	b, err := json.Marshal(rolloutFile{Tenant: r.Tenant, Version: r.Version, Previous: r.Previous,
		Phase: r.Phase, Reason: r.Reason, DwellNs: int64(r.Dwell), CanaryOK: r.CanaryOK.UTC()})
	if err != nil {
		return fmt.Errorf("store: encode rollout: %w", err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	dir := filepath.Join(f.root, "rollouts")
	if err := ensureDir(dir); err != nil {
		return fmt.Errorf("store: write rollout: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, string(r.Tenant)+ext), b); err != nil {
		return fmt.Errorf("store: write rollout: %w", err)
	}
	r.CanaryOK = r.CanaryOK.UTC()
	f.tenant(r.Tenant).rollout = &r
	return nil
}

func (f *files) Rollout(tenant wire.ID) (rollout.Rollout, bool, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if t := f.ten[tenant]; t != nil && t.rollout != nil {
		return *t.rollout, true, nil
	}
	return rollout.Rollout{}, false, nil
}

func (f *files) RecordStatus(l fleet.Last) error {
	if err := l.Report.Validate(); err != nil {
		return err
	}
	if !l.Group.Valid() {
		return invalid("group")
	}
	if l.SeenAt.IsZero() {
		return invalid("seen_at")
	}
	l.Report = cloneReport(l.Report)
	l.SeenAt = l.SeenAt.UTC()
	tn, px := l.Report.Tenant, l.Report.ProxyID

	f.mu.Lock()
	defer f.mu.Unlock()
	t := f.tenant(tn)
	prev := t.proxies[px]

	var tl []tlRec
	var flushed time.Time
	important := prev == nil
	if prev != nil {
		tl, flushed = prev.tl, prev.flushed
		important = importantChange(prev.last, l)
	}
	tl, grew := extendTimeline(tl, l)
	if grew {
		important = true
	}
	flush := important || l.SeenAt.Before(flushed) || l.SeenAt.Sub(flushed) >= heartbeatFlush
	if flush {
		b, err := json.Marshal(proxyFile{Group: l.Group, Report: l.Report, SeenAt: l.SeenAt, Timeline: tl})
		if err != nil {
			return fmt.Errorf("store: encode status: %w", err)
		}
		dir := filepath.Join(f.root, "fleet", string(tn))
		if err := ensureDir(dir); err != nil {
			return fmt.Errorf("store: write status: %w", err)
		}
		if err := writeFileAtomic(filepath.Join(dir, string(px)+ext), b); err != nil {
			return fmt.Errorf("store: write status: %w", err)
		}
		flushed = l.SeenAt
	}
	t.proxies[px] = &proxyRec{last: l, tl: tl, flushed: flushed}
	return nil
}

// importantChange is true when a report differs from the last one in more
// than heartbeat noise (Seq, uptime and counters moving forward).
func importantChange(prev fleet.Last, next fleet.Last) bool {
	p, n := prev.Report, next.Report
	if prev.Group != next.Group || n.Seq < p.Seq || n.UptimeSeconds < p.UptimeSeconds {
		return true // a restart shows as Seq or uptime going backwards
	}
	p.Seq, n.Seq = 0, 0
	p.UptimeSeconds, n.UptimeSeconds = 0, 0
	p.Counters, n.Counters = wire.Counters{}, wire.Counters{}
	return !reflect.DeepEqual(p, n)
}

// extendTimeline returns tl with the report folded in: the last entry is
// extended while the proxy keeps reporting the same version and hash, else a
// new entry starts. It never modifies tl's backing array. grew reports a new entry.
func extendTimeline(tl []tlRec, l fleet.Last) (out []tlRec, grew bool) {
	r := l.Report
	ms := l.SeenAt.UnixMilli()
	if n := len(tl); n > 0 && tl[n-1].Version == r.AppliedVersion && tl[n-1].PolicyHash == r.PolicyHash {
		last := tl[n-1]
		if ms > last.LastSeenUnixMs {
			last.LastSeenUnixMs = ms
		}
		last.LogSeq, last.LogHead = r.LogSeq, r.LogHead
		out = append(tl[:n-1:n-1], last)
		return out, false
	}
	e := tlRec{
		TimelineEntry: wire.TimelineEntry{ProxyID: r.ProxyID, Version: r.AppliedVersion, PolicyHash: r.PolicyHash,
			FirstSeenUnixMs: ms, LastSeenUnixMs: ms},
		LogSeq: r.LogSeq, LogHead: r.LogHead,
	}
	return append(tl[:len(tl):len(tl)], e), true
}

func (f *files) Fleet(tenant wire.ID) ([]fleet.Last, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	t := f.ten[tenant]
	if t == nil {
		return []fleet.Last{}, nil
	}
	out := make([]fleet.Last, 0, len(t.proxies))
	for _, p := range t.proxies {
		l := p.last
		l.Report = cloneReport(l.Report)
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Report.ProxyID < out[j].Report.ProxyID })
	return out, nil
}

func (f *files) Timeline(tenant wire.ID) ([]wire.TimelineEntry, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := []wire.TimelineEntry{}
	for _, e := range f.timelineLocked(tenant) {
		out = append(out, e.TimelineEntry)
	}
	return out, nil
}

// timelineLocked returns the tenant's entries sorted by proxy ID, then in order seen.
func (f *files) timelineLocked(tenant wire.ID) []tlRec {
	t := f.ten[tenant]
	if t == nil {
		return nil
	}
	ids := make([]wire.ID, 0, len(t.proxies))
	for id := range t.proxies {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	var out []tlRec
	for _, id := range ids {
		out = append(out, t.proxies[id].tl...)
	}
	return out
}

// anchor is a timeline entry's apply-log anchor (M-D35). Until wire carries
// the anchor in TimelineEntry it is kept on disk and visible to tests only.
type anchor struct {
	proxy   wire.ID
	version uint64
	logSeq  uint64
	logHead wire.Hash
}

func (f *files) anchors(tenant wire.ID) []anchor {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var out []anchor
	for _, e := range f.timelineLocked(tenant) {
		out = append(out, anchor{e.ProxyID, e.Version, e.LogSeq, e.LogHead})
	}
	return out
}
