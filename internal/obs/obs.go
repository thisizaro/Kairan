// Package obs is the metrics and logging layer shared by the control plane
// and the proxy.
//
// Invariant I4 (no call data to the control plane, in code, logs or metrics)
// shapes the API:
//
//   - Metric label values are wire.ID only. A free-text value cannot compile
//     as a label, and an invalid ID forced in through a conversion is replaced
//     by InvalidLabel before it can reach the exposition.
//   - The slog logger redacts values that commonly carry call data (byte
//     slices, readers, HTTP requests and headers, composite values) and keys
//     that name it (body, payload, prompt, arguments, ...). See NewLogger.
//
// The package does no clock reads of its own and starts no goroutines.
package obs

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"kairan/internal/wire"
)

const (
	// InvalidLabel replaces any label value that is not a valid wire.ID.
	// It is not itself a valid wire.ID (leading underscore), so it cannot
	// collide with a real tenant, proxy or group.
	InvalidLabel = "_invalid_"

	// MaxSeriesPerMetric bounds memory: a metric beyond this many distinct
	// label sets stops creating series (existing ones keep working) and the
	// loss is counted in kairan_obs_dropped_series_total.
	MaxSeriesPerMetric = 10000

	// MaxLogValueBytes is the longest string the logger passes through.
	MaxLogValueBytes = 512
)

const droppedName = "kairan_obs_dropped_series_total"

// DefaultLatencyBuckets suit the M1 propagation and M4 call-latency targets:
// 0.5 ms to 30 s, in seconds.
var DefaultLatencyBuckets = []float64{
	0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
}

type kind int

const (
	kCounter kind = iota
	kGauge
	kHistogram
)

func (k kind) String() string {
	switch k {
	case kCounter:
		return "counter"
	case kGauge:
		return "gauge"
	}
	return "histogram"
}

// series is one label set of one family.
type series struct {
	labels []wire.ID

	bits atomic.Uint64 // counter value, or float64 bits for a gauge

	mu      sync.Mutex // histogram only
	buckets []uint64   // per-bucket (non-cumulative); last slot is +Inf
	sum     float64
}

type family struct {
	reg        *Registry
	name, help string
	kind       kind
	labelNames []string
	bounds     []float64 // histogram upper bounds, ascending, no +Inf

	mu     sync.Mutex
	series map[string]*series
	h      any // the one public handle (*Counter, *Gauge or *Histogram) for this family
}

// handle returns the family's public handle, creating it on first use, so a
// repeated identical registration returns the same pointer.
func (f *family) handle(mk func() any) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.h == nil {
		f.h = mk()
	}
	return f.h
}

// Registry holds metric families and renders them. The zero value is not
// usable; call NewRegistry. All methods are safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	families map[string]*family
	names    map[string]bool // every sample name in use
	dropped  atomic.Uint64
}

func NewRegistry() *Registry {
	return &Registry{families: map[string]*family{}, names: map[string]bool{}}
}

func validName(s string, colon bool) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || (colon && c == ':') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func sampleNames(name string, k kind) []string {
	if k == kHistogram {
		return []string{name, name + "_bucket", name + "_sum", name + "_count"}
	}
	return []string{name}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalFloats(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// register adds a family or returns the identical existing one. Any invalid
// or conflicting registration panics: names are static, so this is a
// programming error that tests catch.
func (r *Registry) register(name, help string, k kind, bounds []float64, labelNames []string) *family {
	if !validName(name, true) || strings.HasPrefix(name, "__") {
		panic("obs: invalid metric name " + strconv.Quote(name))
	}
	seen := map[string]bool{}
	for _, l := range labelNames {
		if !validName(l, false) || strings.HasPrefix(l, "__") {
			panic("obs: invalid label name " + strconv.Quote(l))
		}
		if k == kHistogram && l == "le" {
			panic("obs: label name le is reserved on histograms")
		}
		if seen[l] {
			panic("obs: duplicate label name " + strconv.Quote(l))
		}
		seen[l] = true
	}
	if k == kHistogram {
		if len(bounds) == 0 {
			panic("obs: histogram needs buckets")
		}
		for i, b := range bounds {
			if b != b || b > 1.7976931348623157e308 || (i > 0 && b <= bounds[i-1]) {
				panic("obs: histogram buckets must be finite and strictly ascending (+Inf is implicit)")
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.families[name]; ok {
		if f.kind != k || f.help != help || !equalStrings(f.labelNames, labelNames) || !equalFloats(f.bounds, bounds) {
			panic("obs: metric " + name + " re-registered with a different definition")
		}
		return f
	}
	for _, n := range sampleNames(name, k) {
		if r.names[n] || n == droppedName {
			panic("obs: metric name " + n + " collides with an existing one")
		}
	}
	for _, n := range sampleNames(name, k) {
		r.names[n] = true
	}
	f := &family{
		reg: r, name: name, help: help, kind: k,
		labelNames: append([]string(nil), labelNames...),
		bounds:     append([]float64(nil), bounds...),
		series:     map[string]*series{},
	}
	r.families[name] = f
	return f
}

func sanitize(v wire.ID) wire.ID {
	if v.Valid() {
		return v
	}
	return InvalidLabel
}

// get returns the series for these label values, creating it if needed.
// Past MaxSeriesPerMetric it returns a detached series instead.
func (f *family) get(values []wire.ID) *series {
	if len(values) != len(f.labelNames) {
		panic("obs: " + f.name + " takes " + strconv.Itoa(len(f.labelNames)) + " label values, got " + strconv.Itoa(len(values)))
	}
	clean := make([]wire.ID, len(values))
	var key strings.Builder
	for i, v := range values {
		clean[i] = sanitize(v)
		key.WriteString(string(clean[i]))
		key.WriteByte(0)
	}
	k := key.String()
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.series[k]; ok {
		return s
	}
	s := &series{labels: clean}
	if f.kind == kHistogram {
		s.buckets = make([]uint64, len(f.bounds)+1)
	}
	if len(f.series) >= MaxSeriesPerMetric {
		f.reg.dropped.Add(1)
		return s
	}
	f.series[k] = s
	return s
}

// --- counter ---

// Counter is a monotonically increasing metric family.
type Counter struct{ f *family }

// CounterValue is one series of a Counter.
type CounterValue struct{ s *series }

func (r *Registry) Counter(name, help string, labelNames ...string) *Counter {
	f := r.register(name, help, kCounter, nil, labelNames)
	return f.handle(func() any { return &Counter{f} }).(*Counter)
}

// With selects a series. It panics if the number of values differs from the
// label names given at registration.
func (c *Counter) With(labelValues ...wire.ID) *CounterValue {
	return &CounterValue{c.f.get(labelValues)}
}
func (v *CounterValue) Inc()         { v.s.bits.Add(1) }
func (v *CounterValue) Add(n uint64) { v.s.bits.Add(n) }

// --- gauge ---

// Gauge is a metric family that can go up and down.
type Gauge struct{ f *family }

// GaugeValue is one series of a Gauge.
type GaugeValue struct{ s *series }

func (r *Registry) Gauge(name, help string, labelNames ...string) *Gauge {
	f := r.register(name, help, kGauge, nil, labelNames)
	return f.handle(func() any { return &Gauge{f} }).(*Gauge)
}

func (g *Gauge) With(labelValues ...wire.ID) *GaugeValue { return &GaugeValue{g.f.get(labelValues)} }

// Delete removes a series, for example when a proxy leaves the fleet.
func (g *Gauge) Delete(labelValues ...wire.ID) {
	if len(labelValues) != len(g.f.labelNames) {
		panic("obs: " + g.f.name + ": wrong number of label values")
	}
	var key strings.Builder
	for _, v := range labelValues {
		key.WriteString(string(sanitize(v)))
		key.WriteByte(0)
	}
	g.f.mu.Lock()
	delete(g.f.series, key.String())
	g.f.mu.Unlock()
}

func (v *GaugeValue) Set(x float64) { v.s.bits.Store(f64bits(x)) }
func (v *GaugeValue) Add(x float64) {
	for {
		old := v.s.bits.Load()
		if v.s.bits.CompareAndSwap(old, f64bits(f64from(old)+x)) {
			return
		}
	}
}

// --- histogram ---

// Histogram counts observations into fixed buckets.
type Histogram struct{ f *family }

// HistogramValue is one series of a Histogram.
type HistogramValue struct {
	s *series
	f *family
}

// Histogram registers a histogram. buckets are finite, strictly ascending
// upper bounds; +Inf is added automatically.
func (r *Registry) Histogram(name, help string, buckets []float64, labelNames ...string) *Histogram {
	f := r.register(name, help, kHistogram, buckets, labelNames)
	return f.handle(func() any { return &Histogram{f} }).(*Histogram)
}

func (h *Histogram) With(labelValues ...wire.ID) *HistogramValue {
	return &HistogramValue{h.f.get(labelValues), h.f}
}

// Observe records x. NaN is ignored.
func (v *HistogramValue) Observe(x float64) {
	if x != x {
		return
	}
	i := sort.SearchFloat64s(v.f.bounds, x) // first bound >= x
	v.s.mu.Lock()
	v.s.buckets[i]++
	v.s.sum += x
	v.s.mu.Unlock()
}

// --- exposition ---

// Handler serves the text format 0.0.4 on GET and HEAD.
func (r *Registry) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet && req.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body := r.render()
		h := w.Header()
		h.Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}

func (r *Registry) render() []byte {
	r.mu.RLock()
	names := make([]string, 0, len(r.families)+1)
	for n := range r.families {
		names = append(names, n)
	}
	fams := make(map[string]*family, len(r.families))
	for n, f := range r.families {
		fams[n] = f
	}
	r.mu.RUnlock()
	dropped := r.dropped.Load()
	if dropped > 0 {
		names = append(names, droppedName)
	}
	sort.Strings(names)

	var b []byte
	for _, n := range names {
		if n == droppedName {
			b = appendHeader(b, n, "Series refused because a metric hit its series cap.", kCounter)
			b = append(b, n...)
			b = append(b, ' ')
			b = strconv.AppendUint(b, dropped, 10)
			b = append(b, '\n')
			continue
		}
		b = fams[n].appendTo(b)
	}
	return b
}

func appendHeader(b []byte, name, help string, k kind) []byte {
	b = append(b, "# HELP "...)
	b = append(b, name...)
	b = append(b, ' ')
	b = appendEscaped(b, help, false)
	b = append(b, "\n# TYPE "...)
	b = append(b, name...)
	b = append(b, ' ')
	b = append(b, k.String()...)
	return append(b, '\n')
}

// appendEscaped writes s with backslash and newline escaped, and double
// quote too when quoted (label values).
func appendEscaped(b []byte, s string, quoted bool) []byte {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			b = append(b, '\\', '\\')
		case c == '\n':
			b = append(b, '\\', 'n')
		case quoted && c == '"':
			b = append(b, '\\', '"')
		default:
			b = append(b, c)
		}
	}
	return b
}

func (f *family) appendTo(b []byte) []byte {
	f.mu.Lock()
	all := make([]*series, 0, len(f.series))
	for _, s := range f.series {
		all = append(all, s)
	}
	f.mu.Unlock()
	sort.Slice(all, func(i, j int) bool {
		a, c := all[i].labels, all[j].labels
		for k := range a {
			if a[k] != c[k] {
				return a[k] < c[k]
			}
		}
		return false
	})

	b = appendHeader(b, f.name, f.help, f.kind)
	for _, s := range all {
		switch f.kind {
		case kCounter:
			b = f.appendSample(b, f.name, s, "", strconv.AppendUint(nil, s.bits.Load(), 10))
		case kGauge:
			b = f.appendSample(b, f.name, s, "", appendFloat(nil, f64from(s.bits.Load())))
		case kHistogram:
			s.mu.Lock()
			counts := append([]uint64(nil), s.buckets...)
			sum := s.sum
			s.mu.Unlock()
			var cum uint64
			for i, c := range counts {
				cum += c
				le := "+Inf"
				if i < len(f.bounds) {
					le = string(appendFloat(nil, f.bounds[i]))
				}
				b = f.appendSample(b, f.name+"_bucket", s, le, strconv.AppendUint(nil, cum, 10))
			}
			b = f.appendSample(b, f.name+"_sum", s, "", appendFloat(nil, sum))
			b = f.appendSample(b, f.name+"_count", s, "", strconv.AppendUint(nil, cum, 10))
		}
	}
	return b
}

// appendSample writes `name{labels[,le="x"]} value`. le is empty for
// non-bucket samples.
func (f *family) appendSample(b []byte, name string, s *series, le string, value []byte) []byte {
	b = append(b, name...)
	if len(f.labelNames) > 0 || le != "" {
		b = append(b, '{')
		for i, ln := range f.labelNames {
			if i > 0 {
				b = append(b, ',')
			}
			b = append(b, ln...)
			b = append(b, '=', '"')
			b = appendEscaped(b, string(s.labels[i]), true)
			b = append(b, '"')
		}
		if le != "" {
			if len(f.labelNames) > 0 {
				b = append(b, ',')
			}
			b = append(b, `le="`...)
			b = append(b, le...)
			b = append(b, '"')
		}
		b = append(b, '}')
	}
	b = append(b, ' ')
	b = append(b, value...)
	return append(b, '\n')
}
