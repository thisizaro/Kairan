package obsbreak

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/obs"
	"kairan/internal/wire"
)

const canary = "CANARY-9f3b27-SECRET"

// I4 / M-D29: a label value that is not a wire.ID can only get in by conversion, and must be
// replaced before it reaches the exposition.
func TestLabelInjectionIsNeutralised(t *testing.T) {
	hostile := []string{
		"a\"} 1\nfake_metric{x=\"y",
		"a\nb",
		"x\"y",
		"x\\y",
		"x}y",
		"x{y",
		"# TYPE evil counter",
		"a b",
		"",
		strings.Repeat("a", 64),
		"UPPER",
		"-leading",
		"under_score",
		"émoji-é",
		"nul\x00byte",
		"tab\there",
		"cr\rlf",
		" sep",
		canary,
		"kairan-ok\n",
		"../../etc/passwd",
		obs.InvalidLabel,
		"a=\"b\"",
		"\xff\xfe",
	}
	r := obs.NewRegistry()
	c := r.Counter("kairan_test_total", "help", "tenant", "proxy")
	g := r.Gauge("kairan_test_gauge", "help", "tenant")
	h := r.Histogram("kairan_test_seconds", "help", obs.DefaultLatencyBuckets, "tenant")
	for _, v := range hostile {
		c.With(wire.ID(v), "ok").Inc()
		c.With("ok", wire.ID(v)).Inc()
		g.With(wire.ID(v)).Set(1)
		h.With(wire.ID(v)).Observe(0.01)
	}
	// one valid value for contrast
	c.With("bank-a", "p1").Inc()
	body := scrape(t, r)
	ex := mustParse(t, body)

	for _, bad := range []string{"fake_metric", "# TYPE evil", canary, "passwd", "émoji", "\x00", "UPPER", "under_score", " "} {
		if strings.Contains(body, bad) {
			t.Fatalf("hostile label content %q reached the exposition", bad)
		}
	}
	for _, s := range ex.samples {
		for k, v := range s.labels {
			if k == "le" {
				continue
			}
			if v != obs.InvalidLabel && !wire.ID(v).Valid() {
				t.Fatalf("sample %s has label %s=%q that is neither a valid wire.ID nor %q", s.name, k, v, obs.InvalidLabel)
			}
		}
	}
	// All hostile values collapse into one _invalid_ series per label position; none created by "ok" values.
	found := 0
	for _, s := range ex.find("kairan_test_total") {
		if s.labels["tenant"] == obs.InvalidLabel && s.labels["proxy"] == "ok" {
			found++
			if s.value != float64(len(hostile)) {
				t.Fatalf("_invalid_ series counted %v, want %d (every hostile value lands here)", s.value, len(hostile))
			}
		}
	}
	if found != 1 {
		t.Fatalf("expected exactly one tenant=_invalid_ series, found %d", found)
	}
	if got := len(ex.find("kairan_test_total")); got != 3 { // (_invalid_,ok) (ok,_invalid_) (bank-a,p1)
		t.Fatalf("%d counter series, want 3: %v", got, ex.find("kairan_test_total"))
	}
}

func TestValidLabelValuesPassThroughUnchanged(t *testing.T) {
	r := obs.NewRegistry()
	g := r.Gauge("kairan_g", "h", "a")
	valid := []wire.ID{"bank-a", "a", "0", "9z", wire.ID(strings.Repeat("z", 63)), "a-b-c", "canary"}
	for i, v := range valid {
		g.With(v).Set(float64(i))
	}
	ex := mustParse(t, scrape(t, r))
	got := map[string]float64{}
	for _, s := range ex.find("kairan_g") {
		got[s.labels["a"]] = s.value
	}
	for i, v := range valid {
		if got[string(v)] != float64(i) {
			t.Fatalf("label %q = %v, want %d", v, got[string(v)], i)
		}
	}
}

func TestStateLabelValuesValidAndDistinct(t *testing.T) {
	states := []wire.ProxyState{wire.StateBooting, wire.StateDenyAll, wire.StateTampered, wire.StateEnforcing, wire.StateSafeMode}
	seen := map[wire.ID]wire.ProxyState{}
	for _, s := range states {
		l := obs.StateLabel(s)
		if !l.Valid() {
			t.Fatalf("StateLabel(%q) = %q is not a valid wire.ID", s, l)
		}
		if o, dup := seen[l]; dup {
			t.Fatalf("StateLabel collision: %q and %q -> %q", o, s, l)
		}
		seen[l] = s
	}
	if obs.StateLabel(wire.StateDenyAll) != "deny-all" || obs.StateLabel(wire.StateSafeMode) != "safe-mode" {
		t.Fatal("documented mapping underscores->hyphens is not applied")
	}
	// hostile states, through the metric path, must still be harmless
	r := obs.NewRegistry()
	g := r.Gauge("kairan_proxy_state", "s", "state")
	for _, s := range []wire.ProxyState{"x\ny", "a\"b", "", "evil_{}"} {
		g.With(obs.StateLabel(s)).Set(1)
	}
	mustParse(t, scrape(t, r))
}

func TestTypedLogAttrsReplaceInvalidIDs(t *testing.T) {
	for _, bad := range []wire.ID{"", "A", "a\nb", "x y", canary} {
		if v := obs.Tenant(bad).Value.String(); v != obs.InvalidLabel {
			t.Fatalf("Tenant(%q) value = %q, want %q", bad, v, obs.InvalidLabel)
		}
		if v := obs.Proxy(bad).Value.String(); v != obs.InvalidLabel {
			t.Fatalf("Proxy(%q) value = %q, want %q", bad, v, obs.InvalidLabel)
		}
	}
	if obs.Tenant("bank-a").Value.String() != "bank-a" || obs.Proxy("p-1").Value.String() != "p-1" {
		t.Fatal("valid IDs altered")
	}
}

// Registration of nonsense: the registry may panic (programmer error) or refuse, but must never
// render a body a scraper would misread.
func TestHostileNamesAndHelpNeverBreakTheFormat(t *testing.T) {
	names := []string{"", "9abc", "a b", "a-b", "a\nb", "a{b}", "é", "a\"b", "a=b", "x 1\nfake 2", "#x", "a\\b", "_ok_name", "ok:name"}
	for _, n := range names {
		for _, kind := range []string{"counter", "gauge", "histogram"} {
			t.Run(fmt.Sprintf("%s/%q", kind, n), func(t *testing.T) {
				r := obs.NewRegistry()
				p := panics(func() {
					switch kind {
					case "counter":
						r.Counter(n, "h").With().Inc()
					case "gauge":
						r.Gauge(n, "h").With().Set(1)
					default:
						r.Histogram(n, "h", []float64{1}).With().Observe(0.5)
					}
				})
				body := scrape(t, r)
				if _, err := parseExposition(body); err != nil {
					t.Fatalf("panicked=%v but the exposition is invalid: %v\n%s", p, err, body)
				}
				if strings.Contains(body, "fake") {
					t.Fatalf("name injection reached the exposition: %q", body)
				}
			})
		}
	}
	helps := []string{"plain", "multi\nline", "x\n# TYPE fake counter\nfake 99", "back\\slash", "quote\"", "", "\r\n", "emoji é 回覧", strings.Repeat("h", 100000)}
	for i, h := range helps {
		r := obs.NewRegistry()
		r.Counter(fmt.Sprintf("kairan_h%d_total", i), h).With().Inc()
		body := scrape(t, r)
		ex, err := parseExposition(body)
		if err != nil {
			t.Fatalf("help %q: invalid exposition: %v", h, err)
		}
		if strings.Contains(body, "fake") && !strings.HasPrefix(ex.help[fmt.Sprintf("kairan_h%d_total", i)], "x") {
			t.Fatalf("help injection created a line: %.200s", body)
		}
		for _, n := range ex.names() {
			if n == "fake" {
				t.Fatal("injected sample 'fake' exists")
			}
		}
	}
	// label names
	for _, ln := range []string{"", "a b", "9x", "a-b", "a\nb", "a\"b", "__name__", "é", "a=b", "le"} {
		r := obs.NewRegistry()
		p := panics(func() { r.Counter("kairan_l_total", "h", ln).With("v").Inc() })
		body := scrape(t, r)
		if _, err := parseExposition(body); err != nil {
			t.Fatalf("label name %q (panicked=%v): invalid exposition: %v", ln, p, err)
		}
	}
	r := obs.NewRegistry()
	p := panics(func() { r.Counter("kairan_dup_total", "h", "a", "a").With("x", "y").Inc() })
	if _, err := parseExposition(scrape(t, r)); err != nil {
		t.Fatalf("duplicate label names (panicked=%v) gave an invalid exposition: %v", p, err)
	}
}

func TestReRegistrationRules(t *testing.T) {
	r := obs.NewRegistry()
	c1 := r.Counter("kairan_x_total", "h", "tenant")
	c1.With("a").Inc()
	c2 := r.Counter("kairan_x_total", "h", "tenant")
	c2.With("a").Inc()
	ex := mustParse(t, scrape(t, r))
	if s := ex.find("kairan_x_total"); len(s) != 1 || s[0].value != 2 {
		t.Fatalf("identical re-registration did not share the series: %+v", s)
	}
	for name, f := range map[string]func(){
		"gauge-over-counter":   func() { r.Gauge("kairan_x_total", "h", "tenant") },
		"histogram-over-count": func() { r.Histogram("kairan_x_total", "h", []float64{1}, "tenant") },
		"different-labels":     func() { r.Counter("kairan_x_total", "h", "proxy") },
		"more-labels":          func() { r.Counter("kairan_x_total", "h", "tenant", "proxy") },
		"fewer-labels":         func() { r.Counter("kairan_x_total", "h") },
	} {
		if !panics(f) {
			t.Errorf("%s: conflicting re-registration did not panic (silently two families, or shared wrong shape)", name)
		}
	}
	// the exposition must still be consistent after the attempts
	mustParse(t, scrape(t, r))
	// two registries are independent
	r2 := obs.NewRegistry()
	r2.Counter("kairan_x_total", "h", "tenant").With("b").Inc()
	ex = mustParse(t, scrape(t, r))
	for _, s := range ex.find("kairan_x_total") {
		if s.labels["tenant"] == "b" {
			t.Fatal("registries share state")
		}
	}
}

func TestWithLabelCountMismatchPanics(t *testing.T) {
	r := obs.NewRegistry()
	c := r.Counter("kairan_c_total", "h", "a", "b")
	g := r.Gauge("kairan_g", "h")
	h := r.Histogram("kairan_h", "h", []float64{1}, "a")
	for name, f := range map[string]func(){
		"counter-zero":  func() { c.With() },
		"counter-one":   func() { c.With("x") },
		"counter-three": func() { c.With("x", "y", "z") },
		"gauge-extra":   func() { g.With("x") },
		"hist-zero":     func() { h.With() },
		"hist-two":      func() { h.With("x", "y") },
		"gauge-delete":  func() { g.Delete("x") },
	} {
		if !panics(f) {
			t.Errorf("%s: label count mismatch did not panic (documented for With)", name)
		}
	}
	// no half-created series
	body := scrape(t, r)
	if strings.Contains(body, `kairan_c_total{`) {
		t.Fatalf("a mismatched With created a series:\n%s", body)
	}
}

func TestSeriesCapAndDroppedCounter(t *testing.T) {
	if obs.MaxSeriesPerMetric != 10000 {
		t.Fatalf("MaxSeriesPerMetric = %d, doc says 10000", obs.MaxSeriesPerMetric)
	}
	r := obs.NewRegistry()
	g := r.Gauge("kairan_many", "h", "id")
	other := r.Counter("kairan_other_total", "h", "id")
	const extra = 137
	for i := 0; i < obs.MaxSeriesPerMetric+extra; i++ {
		g.With(wire.ID(fmt.Sprintf("p%d", i))).Set(float64(i))
	}
	// a metric's cap does not eat into another metric's
	other.With("x").Inc()
	// existing series keep working after the cap is hit; dropped ones do not panic
	g.With("p0").Set(777)
	d := g.With(wire.ID(fmt.Sprintf("p%d", obs.MaxSeriesPerMetric+5)))
	d.Set(1)
	d.Add(2)
	ex := mustParse(t, scrape(t, r))
	series := ex.find("kairan_many")
	if len(series) != obs.MaxSeriesPerMetric {
		t.Fatalf("%d series exposed, want exactly the cap %d", len(series), obs.MaxSeriesPerMetric)
	}
	for _, s := range series {
		if s.labels["id"] == "p0" && s.value != 777 {
			t.Fatalf("existing series stopped updating after the cap: %v", s.value)
		}
	}
	dropped := ex.find("kairan_obs_dropped_series_total")
	if len(dropped) == 0 {
		t.Fatal("dropped series not counted in kairan_obs_dropped_series_total")
	}
	var total float64
	for _, s := range dropped {
		total += s.value
	}
	if total < extra {
		t.Fatalf("dropped counter = %v, want at least %d", total, extra)
	}
	if len(ex.find("kairan_other_total")) != 1 {
		t.Fatal("another metric lost its series")
	}
}

func TestGaugeDeleteRemovesSeries(t *testing.T) {
	r := obs.NewRegistry()
	g := r.Gauge("kairan_g", "h", "proxy")
	g.With("p1").Set(1)
	g.With("p2").Set(2)
	g.Delete("p1")
	g.Delete("never-existed")
	g.Delete(wire.ID("bad\nid")) // converted hostile ID: must not panic or delete others
	ex := mustParse(t, scrape(t, r))
	s := ex.find("kairan_g")
	if len(s) != 1 || s[0].labels["proxy"] != "p2" {
		t.Fatalf("after Delete: %+v", s)
	}
	g.With("p1").Add(5) // recreated from zero
	ex = mustParse(t, scrape(t, r))
	for _, s := range ex.find("kairan_g") {
		if s.labels["proxy"] == "p1" && s.value != 5 {
			t.Fatalf("recreated gauge = %v, want 5", s.value)
		}
	}
	// deleting the invalid bucket must not take valid series with it
	g.With("bad\nid").Set(9)
	g.Delete("other\nbad")
	ex = mustParse(t, scrape(t, r))
	if n := len(ex.find("kairan_g")); n < 2 {
		t.Fatalf("Delete of a hostile id removed valid series: %d left", n)
	}
}

func TestValuesRenderedInPrometheusSyntax(t *testing.T) {
	r := obs.NewRegistry()
	g := r.Gauge("kairan_v", "h", "k")
	vals := map[wire.ID]float64{
		"nan": math.NaN(), "pinf": math.Inf(1), "ninf": math.Inf(-1), "negzero": math.Copysign(0, -1),
		"big": 1e308, "tiny": 5e-324, "frac": 0.1, "neg": -123456789.125, "maxint": float64(1 << 53),
	}
	for k, v := range vals {
		g.With(k).Set(v)
	}
	c := r.Counter("kairan_c_total", "h")
	c.With().Add(math.MaxUint64)
	c0 := r.Counter("kairan_c0_total", "h")
	c0.With().Add(0)
	ex := mustParse(t, scrape(t, r)) // strict float syntax is checked by the parser
	for _, s := range ex.find("kairan_v") {
		want := vals[wire.ID(s.labels["k"])]
		if math.IsNaN(want) != math.IsNaN(s.value) || !math.IsNaN(want) && s.value != want {
			t.Fatalf("%s rendered as %q (%v), want %v", s.labels["k"], s.rawVal, s.value, want)
		}
	}
	if s := ex.find("kairan_c_total"); len(s) != 1 || s[0].value < 1.8446744073709551e19 {
		t.Fatalf("uint64 max counter rendered as %+v", s)
	}
	if s := ex.find("kairan_c0_total"); len(s) != 1 || s[0].value != 0 {
		t.Fatalf("Add(0) series %+v", s)
	}
}

func TestHistogramSemantics(t *testing.T) {
	r := obs.NewRegistry()
	b := []float64{0.001, 0.01, 0.1, 1}
	h := r.Histogram("kairan_lat_seconds", "h", b, "route")
	v := h.With("poll")
	for _, x := range []float64{0, 0.001, 0.0010000001, 0.01, 0.5, 1, 1.0000001, 100, -5, math.Inf(1), math.NaN(), math.Inf(-1)} {
		v.Observe(x)
	}
	ex := mustParse(t, scrape(t, r))
	buckets := map[string]float64{}
	var count, sum float64
	var haveSum, haveCount bool
	for _, s := range ex.samples {
		switch s.name {
		case "kairan_lat_seconds_bucket":
			if s.labels["route"] != "poll" {
				t.Fatalf("bucket lost its label: %+v", s)
			}
			buckets[s.labels["le"]] = s.value
		case "kairan_lat_seconds_count":
			count, haveCount = s.value, true
		case "kairan_lat_seconds_sum":
			sum, haveSum = s.value, true
		}
	}
	if !haveCount || !haveSum {
		t.Fatal("missing _count or _sum")
	}
	// NaN ignored (doc); the other 11 observations count.
	if count != 11 {
		t.Fatalf("_count = %v, want 11 (NaN ignored)", count)
	}
	inf, ok := buckets["+Inf"]
	if !ok || inf != count {
		t.Fatalf("+Inf bucket %v (present %v) must equal _count %v", inf, ok, count)
	}
	// le is inclusive: -Inf,-5,0 and 0.001 are <= 0.001; 0.01 joins at le=0.01.
	want := map[string]float64{"0.001": 4, "0.01": 6, "0.1": 6, "1": 8, "+Inf": 11}
	for le, w := range want {
		if buckets[le] != w {
			t.Fatalf("bucket le=%s = %v, want %v (all: %v)", le, buckets[le], w, buckets)
		}
	}
	if len(buckets) != len(b)+1 {
		t.Fatalf("bucket set %v", buckets)
	}
	if !math.IsNaN(sum) && !math.IsInf(sum, 0) {
		t.Fatalf("sum with +Inf and -Inf observed should be NaN (or Inf), got %v", sum)
	}
	// the le series in file order must be cumulative and ascending
	prev := -1.0
	for _, s := range ex.samples {
		if s.name == "kairan_lat_seconds_bucket" {
			if s.value < prev {
				t.Fatalf("bucket counts not cumulative: %v after %v", s.value, prev)
			}
			prev = s.value
		}
	}
}

func TestHistogramBadBucketsNeverBreakTheFormat(t *testing.T) {
	cases := map[string][]float64{
		"empty":      {},
		"nil":        nil,
		"unsorted":   {1, 0.5},
		"duplicate":  {1, 1},
		"nan":        {math.NaN()},
		"inf":        {1, math.Inf(1)},
		"neg-inf":    {math.Inf(-1), 1},
		"negative":   {-1, 0, 1},
		"huge-count": make([]float64, 5000),
	}
	for i := range cases["huge-count"] {
		cases["huge-count"][i] = float64(i + 1)
	}
	for name, bs := range cases {
		t.Run(name, func(t *testing.T) {
			r := obs.NewRegistry()
			p := panics(func() { r.Histogram("kairan_h", "h", bs).With().Observe(0.5) })
			body := scrape(t, r)
			ex, err := parseExposition(body)
			if err != nil {
				t.Fatalf("panicked=%v, exposition invalid: %v", p, err)
			}
			if p {
				return
			}
			prev := -1.0
			var le []string
			for _, s := range ex.find("kairan_h_bucket") {
				le = append(le, s.labels["le"])
				if s.value < prev {
					t.Fatalf("non-cumulative buckets %v", le)
				}
				prev = s.value
			}
			if n := len(ex.find("kairan_h_bucket")); n > 0 {
				seen := map[string]bool{}
				for _, l := range le {
					if seen[l] {
						t.Fatalf("duplicate le=%s series (a scraper rejects the whole target)", l)
					}
					seen[l] = true
				}
			}
		})
	}
	// the caller's slice is not retained: mutating it after registration changes nothing
	r := obs.NewRegistry()
	bs := []float64{1, 2, 3}
	r.Histogram("kairan_ret", "h", bs).With().Observe(1.5)
	bs[0], bs[1], bs[2] = 9, 8, 7
	ex := mustParse(t, scrape(t, r))
	var les []string
	for _, s := range ex.find("kairan_ret_bucket") {
		les = append(les, s.labels["le"])
	}
	if strings.Join(les, ",") != "1,2,3,+Inf" {
		t.Fatalf("buckets changed through the caller's slice: %v", les)
	}
	// DefaultLatencyBuckets is shared: a registration must not reorder or alter it
	before := fmt.Sprint(obs.DefaultLatencyBuckets)
	obs.NewRegistry().Histogram("kairan_d", "h", obs.DefaultLatencyBuckets).With().Observe(1)
	if fmt.Sprint(obs.DefaultLatencyBuckets) != before {
		t.Fatal("registration modified DefaultLatencyBuckets")
	}
}

func TestExpositionDeterministic(t *testing.T) {
	r := obs.NewRegistry()
	for i := 0; i < 20; i++ {
		r.Counter(fmt.Sprintf("kairan_m%02d_total", 19-i), "h", "id").With(wire.ID(fmt.Sprintf("z%d", i%7))).Inc()
	}
	g := r.Gauge("kairan_g", "h", "id")
	for i := 0; i < 50; i++ {
		g.With(wire.ID(fmt.Sprintf("p%d", (i*7)%50))).Set(float64(i))
	}
	a := scrape(t, r)
	for i := 0; i < 5; i++ {
		if b := scrape(t, r); b != a {
			t.Fatal("two scrapes of an unchanged registry differ (unstable ordering breaks diffs and tests)")
		}
	}
	mustParse(t, a)
}

func TestHandlerMethodsAndHeaders(t *testing.T) {
	r := obs.NewRegistry()
	r.Counter("kairan_x_total", "h").With().Inc()
	h := r.Handler()
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "/metrics?name=evil&x=1", nil))
	if get.Code != 200 {
		t.Fatalf("GET: %d", get.Code)
	}
	if ct := get.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("Content-Type %q", ct)
	}
	if get.Body.Len() == 0 {
		t.Fatal("empty GET body")
	}
	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequest("HEAD", "/metrics", nil))
	if head.Code != 200 || head.Body.Len() != 0 {
		t.Fatalf("HEAD: %d with %d body bytes", head.Code, head.Body.Len())
	}
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "BREW"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/metrics", strings.NewReader("kairan_x_total 99\n")))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status %d, want 405", m, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "kairan_x_total") {
			t.Errorf("%s: metrics body leaked on a refused method", m)
		}
	}
}

func TestConcurrentUseUnderRace(t *testing.T) {
	r := obs.NewRegistry()
	c := r.Counter("kairan_c_total", "h", "id")
	g := r.Gauge("kairan_g", "h", "id")
	h := r.Histogram("kairan_h_seconds", "h", obs.DefaultLatencyBuckets, "id")
	const workers, iters = 32, 500
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			id := wire.ID(fmt.Sprintf("w%d", w%8))
			for i := 0; i < iters; i++ {
				c.With(id).Inc()
				c.With("shared").Add(2)
				g.With("shared").Add(1)
				g.With(id).Set(float64(i))
				h.With(id).Observe(float64(i) / 1000)
				if i%50 == 0 {
					g.Delete(id)
					r.Counter("kairan_c_total", "h", "id") // idempotent re-registration while in use
				}
			}
		}(w)
	}
	// scrapers
	stop := make(chan struct{})
	var swg sync.WaitGroup
	for s := 0; s < 4; s++ {
		swg.Add(1)
		go func() {
			defer swg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					if _, err := parseExposition(scrape(t, r)); err != nil {
						t.Errorf("concurrent scrape invalid: %v", err)
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	swg.Wait()
	ex := mustParse(t, scrape(t, r))
	var total, shared float64
	for _, s := range ex.find("kairan_c_total") {
		if s.labels["id"] == "shared" {
			shared = s.value
		} else {
			total += s.value
		}
	}
	if total != workers*iters || shared != 2*workers*iters {
		t.Fatalf("lost increments: per-id %v (want %d), shared %v (want %d)", total, workers*iters, shared, 2*workers*iters)
	}
	for _, s := range ex.find("kairan_g") {
		if s.labels["id"] == "shared" && s.value != workers*iters {
			t.Fatalf("lost gauge Adds: %v", s.value)
		}
	}
}

func TestNoGoroutinesStarted(t *testing.T) {
	before := runtime.NumGoroutine()
	for i := 0; i < 50; i++ {
		r := obs.NewRegistry()
		r.Counter("kairan_a_total", "h", "x").With("y").Inc()
		r.Gauge("kairan_b", "h").With().Set(1)
		r.Histogram("kairan_c", "h", []float64{1}).With().Observe(1)
		_ = scrape(t, r)
	}
	time.Sleep(50 * time.Millisecond)
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("goroutines grew %d -> %d (doc: obs starts no goroutines)", before, after)
	}
}

func FuzzLabelValue(f *testing.F) {
	for _, s := range []string{"bank-a", "a\nb", "\"}\nfake 1\n", "", "\\", "é", canary, "a=\"b\"", strings.Repeat("x", 70)} {
		f.Add(s, s)
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		r := obs.NewRegistry()
		c := r.Counter("kairan_f_total", "h", "x", "y")
		c.With(wire.ID(a), wire.ID(b)).Inc()
		body := scrape(t, r)
		ex, err := parseExposition(body)
		if err != nil {
			t.Fatalf("labels %q %q produced invalid exposition: %v", a, b, err)
		}
		s := ex.find("kairan_f_total")
		if len(s) != 1 {
			t.Fatalf("%d series for one With: %v", len(s), s)
		}
		for k, in := range map[string]string{"x": a, "y": b} {
			got := s[0].labels[k]
			if wire.ID(in).Valid() {
				if got != in {
					t.Fatalf("valid id %q became %q", in, got)
				}
			} else if got != obs.InvalidLabel {
				t.Fatalf("invalid id %q exposed as %q", in, got)
			}
		}
	})
}
