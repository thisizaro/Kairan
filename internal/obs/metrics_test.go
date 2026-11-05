package obs

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"kairan/internal/wire"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	return rec.Body.String()
}

func mustParse(t *testing.T, text string) []*parsedFamily {
	t.Helper()
	fams, err := parseStrict(text)
	if err != nil {
		t.Fatalf("strict parse: %v\n%s", err, text)
	}
	return fams
}

func mustPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: expected panic", name)
		}
	}()
	f()
}

func TestGoldenExposition(t *testing.T) {
	r := NewRegistry()
	// Registered out of order on purpose: output is sorted by name.
	g := r.Gauge("kairan_proxy_state", "Current proxy state.", "state")
	c := r.Counter("kairan_cp_publishes_total", "Publishes accepted.", "tenant", "outcome")
	h := r.Histogram("kairan_cp_ack_seconds", "Publish to ack.", []float64{0.1, 1}, "tenant")
	g.With("enforcing").Set(1)
	g.With("deny-all").Set(0)
	c.With("bank-b", "ok").Add(2)
	c.With("bank-a", "ok").Inc()
	c.With("bank-a", "rejected").Inc()
	h.With("bank-a").Observe(0.05)
	h.With("bank-a").Observe(0.5)
	h.With("bank-a").Observe(7)

	want := `# HELP kairan_cp_ack_seconds Publish to ack.
# TYPE kairan_cp_ack_seconds histogram
kairan_cp_ack_seconds_bucket{tenant="bank-a",le="0.1"} 1
kairan_cp_ack_seconds_bucket{tenant="bank-a",le="1"} 2
kairan_cp_ack_seconds_bucket{tenant="bank-a",le="+Inf"} 3
kairan_cp_ack_seconds_sum{tenant="bank-a"} 7.55
kairan_cp_ack_seconds_count{tenant="bank-a"} 3
# HELP kairan_cp_publishes_total Publishes accepted.
# TYPE kairan_cp_publishes_total counter
kairan_cp_publishes_total{tenant="bank-a",outcome="ok"} 1
kairan_cp_publishes_total{tenant="bank-a",outcome="rejected"} 1
kairan_cp_publishes_total{tenant="bank-b",outcome="ok"} 2
# HELP kairan_proxy_state Current proxy state.
# TYPE kairan_proxy_state gauge
kairan_proxy_state{state="deny-all"} 0
kairan_proxy_state{state="enforcing"} 1
`
	got := render(t, r)
	if got != want {
		t.Fatalf("exposition mismatch\n--- got ---\n%s--- want ---\n%s", got, want)
	}
	mustParse(t, got)
	for i := 0; i < 5; i++ {
		if again := render(t, r); again != got {
			t.Fatalf("render %d differs from first", i)
		}
	}
}

func TestEmptyRegistryAndUnlabeled(t *testing.T) {
	r := NewRegistry()
	if got := render(t, r); got != "" {
		t.Fatalf("empty registry rendered %q", got)
	}
	c := r.Counter("kairan_x_total", "x")
	g := r.Gauge("kairan_y", "y")
	c.With().Inc()
	g.With().Set(2.5)
	want := "# HELP kairan_x_total x\n# TYPE kairan_x_total counter\nkairan_x_total 1\n" +
		"# HELP kairan_y y\n# TYPE kairan_y gauge\nkairan_y 2.5\n"
	if got := render(t, r); got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestFamilyWithNoSeriesStillDeclared(t *testing.T) {
	r := NewRegistry()
	r.Counter("kairan_a_total", "a", "tenant")
	got := render(t, r)
	if got != "# HELP kairan_a_total a\n# TYPE kairan_a_total counter\n" {
		t.Fatalf("got %q", got)
	}
	mustParse(t, got)
}

func TestHelpEscaping(t *testing.T) {
	r := NewRegistry()
	r.Counter("kairan_h_total", "line1\nline2 back\\slash \"q\"").With().Inc()
	got := render(t, r)
	if !strings.Contains(got, `# HELP kairan_h_total line1\nline2 back\\slash "q"`+"\n") {
		t.Fatalf("help not escaped: %q", got)
	}
	fams := mustParse(t, got)
	if fams[0].help != "line1\nline2 back\\slash \"q\"" {
		t.Fatalf("help round trip: %q", fams[0].help)
	}
}

func TestGaugeValues(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("kairan_g", "g", "k")
	g.With("a").Set(-1.5)
	g.With("b").Add(2)
	g.With("b").Add(0.25)
	g.With("c").Set(1e21)
	g.With("d").Set(0)
	got := render(t, r)
	for _, w := range []string{`kairan_g{k="a"} -1.5`, `kairan_g{k="b"} 2.25`, `kairan_g{k="c"} 1e+21`, `kairan_g{k="d"} 0`} {
		if !strings.Contains(got, w+"\n") {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
	nan := r.Gauge("kairan_nan", "n")
	nan.With().Set(nan0())
	if !strings.Contains(render(t, r), "kairan_nan NaN\n") {
		t.Error("NaN not rendered as NaN")
	}
	inf := r.Gauge("kairan_inf", "n")
	inf.With().Set(inf0(1))
	ninf := r.Gauge("kairan_ninf", "n")
	ninf.With().Set(inf0(-1))
	out := render(t, r)
	if !strings.Contains(out, "kairan_inf +Inf\n") || !strings.Contains(out, "kairan_ninf -Inf\n") {
		t.Errorf("infinities: %s", out)
	}
	mustParse(t, out)
}

func TestGaugeDelete(t *testing.T) {
	r := NewRegistry()
	g := r.Gauge("kairan_g", "g", "proxy")
	g.With("p1").Set(1)
	g.With("p2").Set(1)
	g.Delete("p1")
	got := render(t, r)
	if strings.Contains(got, `"p1"`) || !strings.Contains(got, `proxy="p2"`) {
		t.Fatalf("delete: %s", got)
	}
}

func TestSameSeriesSameValue(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("kairan_c_total", "c", "t")
	c.With("a").Inc()
	c.With("a").Inc()
	if !strings.Contains(render(t, r), `kairan_c_total{t="a"} 2`+"\n") {
		t.Fatal("two With calls must hit the same series")
	}
	if r.Counter("kairan_c_total", "c", "t") != c {
		t.Fatal("identical re-registration should return the existing counter")
	}
}

func TestRegistrationPanics(t *testing.T) {
	r := NewRegistry()
	r.Counter("kairan_c_total", "c", "t")
	for name, f := range map[string]func(){
		"bad metric name":      func() { r.Counter("1bad", "x") },
		"empty metric name":    func() { r.Counter("", "x") },
		"space in name":        func() { r.Gauge("a b", "x") },
		"bad label name":       func() { r.Counter("kairan_z_total", "x", "bad-label") },
		"reserved label":       func() { r.Counter("kairan_z_total", "x", "__name") },
		"duplicate label":      func() { r.Counter("kairan_z_total", "x", "a", "a") },
		"le label on hist":     func() { r.Histogram("kairan_h", "x", []float64{1}, "le") },
		"type clash":           func() { r.Gauge("kairan_c_total", "c", "t") },
		"label clash":          func() { r.Counter("kairan_c_total", "c", "other") },
		"help clash":           func() { r.Counter("kairan_c_total", "different", "t") },
		"hist no buckets":      func() { r.Histogram("kairan_h", "x", nil) },
		"hist unsorted":        func() { r.Histogram("kairan_h", "x", []float64{2, 1}) },
		"hist duplicate":       func() { r.Histogram("kairan_h", "x", []float64{1, 1}) },
		"hist inf bucket":      func() { r.Histogram("kairan_h", "x", []float64{1, inf0(1)}) },
		"hist nan bucket":      func() { r.Histogram("kairan_h", "x", []float64{nan0()}) },
		"hist sample suffix":   func() { r.Histogram("kairan_c_total_x", "x", []float64{1}); r.Counter("kairan_c_total_x_bucket", "x") },
		"label count mismatch": func() { r.Counter("kairan_c_total", "c", "t").With("a", "b") },
		"label count missing":  func() { r.Counter("kairan_c_total", "c", "t").With() },
	} {
		mustPanic(t, name, f)
	}
}

func TestInvalidLabelValueIsNeutralised(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("kairan_c_total", "c", "t")
	// A free-text value smuggled in via a conversion must not reach the output.
	evil := "bank\"}\ninjected_metric 1\n# tool-args: SECRET"
	c.With(wire.ID(evil)).Inc()
	c.With(wire.ID("")).Inc()
	c.With(wire.ID("Upper")).Inc()
	c.With(wire.ID("deny_all")).Inc()
	got := render(t, r)
	if strings.Contains(got, "SECRET") || strings.Contains(got, "injected") {
		t.Fatalf("free text leaked into exposition:\n%s", got)
	}
	fams := mustParse(t, got)
	if len(fams[0].samples) != 1 || fams[0].samples[0].value != 4 {
		t.Fatalf("invalid values should collapse to one series: %+v", fams[0].samples)
	}
	if v, _ := fams[0].samples[0].label("t"); v != InvalidLabel {
		t.Fatalf("label = %q, want %q", v, InvalidLabel)
	}
}

func TestStateLabel(t *testing.T) {
	for _, s := range []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode} {
		id := StateLabel(s)
		if !id.Valid() {
			t.Errorf("StateLabel(%q) = %q is not a valid wire.ID", s, id)
		}
	}
	if StateLabel(wire.StateDenyAll) != "deny-all" || StateLabel(wire.StateSafeMode) != "safe-mode" {
		t.Error("underscores should map to hyphens")
	}
}

func TestHistogramBuckets(t *testing.T) {
	r := NewRegistry()
	h := r.Histogram("kairan_lat_seconds", "lat", []float64{0.001, 0.01, 0.1})
	for _, x := range []float64{0.0005, 0.001, 0.005, 0.5, 100} {
		h.With().Observe(x)
	}
	h.With().Observe(nan0()) // ignored, must not poison the sum
	got := render(t, r)
	for _, w := range []string{
		`kairan_lat_seconds_bucket{le="0.001"} 2`,
		`kairan_lat_seconds_bucket{le="0.01"} 3`,
		`kairan_lat_seconds_bucket{le="0.1"} 3`,
		`kairan_lat_seconds_bucket{le="+Inf"} 5`,
		`kairan_lat_seconds_count 5`,
	} {
		if !strings.Contains(got, w+"\n") {
			t.Errorf("missing %q in\n%s", w, got)
		}
	}
	mustParse(t, got)
}

func TestDefaultLatencyBucketsAreValid(t *testing.T) {
	r := NewRegistry()
	r.Histogram("kairan_d_seconds", "d", DefaultLatencyBuckets).With().Observe(0.002)
	mustParse(t, render(t, r))
	if len(DefaultLatencyBuckets) < 8 {
		t.Fatal("expected a useful number of default buckets")
	}
}

func TestSeriesCap(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("kairan_c_total", "c", "t")
	for i := 0; i < MaxSeriesPerMetric+50; i++ {
		c.With(wire.ID("t" + itoa(i))).Inc() // must not panic or grow without bound
	}
	fams := mustParse(t, render(t, r))
	if n := len(fams[0].samples); n != MaxSeriesPerMetric {
		t.Fatalf("series = %d, want cap %d", n, MaxSeriesPerMetric)
	}
	if !strings.Contains(render(t, r), "kairan_obs_dropped_series_total 50\n") {
		t.Fatal("refused series must be counted")
	}
	// Existing series keep working after the cap is hit.
	c.With("t0").Inc()
	if !strings.Contains(render(t, r), `kairan_c_total{t="t0"} 2`+"\n") {
		t.Fatal("existing series stopped updating at the cap")
	}
}

func TestConcurrentUse(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("kairan_c_total", "c", "t")
	g := r.Gauge("kairan_g", "g", "t")
	h := r.Histogram("kairan_h_seconds", "h", DefaultLatencyBuckets, "t")
	const workers, per = 8, 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := wire.ID("t" + itoa(w%3))
			for i := 0; i < per; i++ {
				c.With(id).Inc()
				g.With(id).Add(1)
				h.With(id).Observe(0.003)
				if i%50 == 0 {
					mustParse(t, render(t, r))
				}
				if i%97 == 0 {
					r.Counter("kairan_late_"+itoa(w)+"_total", "late") // register while scraping
				}
			}
		}(w)
	}
	wg.Wait()
	fams := mustParse(t, render(t, r))
	var total float64
	for _, f := range fams {
		if f.name == "kairan_c_total" {
			for _, s := range f.samples {
				total += s.value
			}
		}
	}
	if total != workers*per {
		t.Fatalf("counter total %v, want %d", total, workers*per)
	}
}

func TestHandlerHTTP(t *testing.T) {
	r := NewRegistry()
	r.Counter("kairan_c_total", "c").With().Inc()
	h := r.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; version=0.0.4; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing nosniff")
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/metrics", nil))
	if rec.Code != 200 || rec.Body.Len() != 0 {
		t.Errorf("HEAD: code %d body %d bytes", rec.Code, rec.Body.Len())
	}

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/metrics", strings.NewReader("secret-body")))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: code %d, want 405", m, rec.Code)
		}
		if rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s: Allow = %q", m, rec.Header().Get("Allow"))
		}
	}
}

// FuzzLabelValues: whatever string is forced into a wire.ID, the output must
// still pass the strict parser and must not contain the raw input unless it
// is a valid ID.
func FuzzLabelValues(f *testing.F) {
	for _, s := range []string{"", "bank-a", "a\"b", "a\nb", "a\\b", "{}", "\xff\xfe", "é", strings.Repeat("a", 64)} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		r := NewRegistry()
		c := r.Counter("kairan_f_total", "help "+a, "x", "y")
		g := r.Gauge("kairan_fg", "help", "x")
		c.With(wire.ID(a), wire.ID(b)).Inc()
		g.With(wire.ID(b)).Set(1)
		got := render(t, r)
		if _, err := parseStrict(got); err != nil {
			t.Fatalf("strict parse failed for %q,%q: %v\n%s", a, b, err, got)
		}
		if !wire.ID(a).Valid() && a != "" && len(a) > 1 && strings.Contains(got, `"`+a+`"`) {
			t.Fatalf("invalid label value echoed: %q", a)
		}
	})
}
