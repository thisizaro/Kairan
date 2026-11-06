// Package obsbreak holds black-box attack tests for the obs package (task C-05).
// Sources: PRD invariant I4, ARCHITECTURE section 1 (label values are wire.ID
// only, M-D29), the obs LLD and the go doc of obs.
package obsbreak

import (
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"kairan/internal/obs"
)

type sample struct {
	name   string
	labels map[string]string
	order  []string
	value  float64
	rawVal string
	line   int
}

type exposition struct {
	samples []sample
	help    map[string]string
	typ     map[string]string
}

var (
	reMetricName = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	reLabelName  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	reFloat      = regexp.MustCompile(`^(NaN|[+-]Inf|[+-]?([0-9]+\.?[0-9]*|\.[0-9]+)([eE][+-]?[0-9]+)?)$`)
)

// parseExposition is a strict reader of the Prometheus text format 0.0.4. Any line it cannot
// classify is an error: a hostile label value must never create a line the scraper reads as a metric.
func parseExposition(body string) (*exposition, error) {
	ex := &exposition{help: map[string]string{}, typ: map[string]string{}}
	if body != "" && !strings.HasSuffix(body, "\n") {
		return nil, fmt.Errorf("exposition does not end with a newline")
	}
	lines := strings.Split(strings.TrimSuffix(body, "\n"), "\n")
	for i, ln := range lines {
		n := i + 1
		if ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "# HELP ") {
			rest := strings.TrimPrefix(ln, "# HELP ")
			name, text, _ := strings.Cut(rest, " ")
			if !reMetricName.MatchString(name) {
				return nil, fmt.Errorf("line %d: bad HELP name %q", n, name)
			}
			if _, dup := ex.help[name]; dup {
				return nil, fmt.Errorf("line %d: duplicate HELP for %s", n, name)
			}
			if err := checkEscapes(text, false); err != nil {
				return nil, fmt.Errorf("line %d: HELP text: %w", n, err)
			}
			ex.help[name] = text
			continue
		}
		if strings.HasPrefix(ln, "# TYPE ") {
			f := strings.Fields(strings.TrimPrefix(ln, "# TYPE "))
			if len(f) != 2 || !reMetricName.MatchString(f[0]) {
				return nil, fmt.Errorf("line %d: bad TYPE line %q", n, ln)
			}
			switch f[1] {
			case "counter", "gauge", "histogram", "summary", "untyped":
			default:
				return nil, fmt.Errorf("line %d: bad TYPE %q", n, f[1])
			}
			if _, dup := ex.typ[f[0]]; dup {
				return nil, fmt.Errorf("line %d: duplicate TYPE for %s", n, f[0])
			}
			ex.typ[f[0]] = f[1]
			continue
		}
		if strings.HasPrefix(ln, "#") {
			return nil, fmt.Errorf("line %d: unexpected comment line %q (injected?)", n, ln)
		}
		s, err := parseSample(ln)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w: %q", n, err, ln)
		}
		s.line = n
		ex.samples = append(ex.samples, s)
	}
	return ex, nil
}

func checkEscapes(s string, quote bool) error {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\n':
			return fmt.Errorf("raw newline")
		case '"':
			if quote {
				return fmt.Errorf("raw quote")
			}
		case '\\':
			i++
			if i >= len(s) {
				return fmt.Errorf("dangling backslash")
			}
			if s[i] != '\\' && s[i] != 'n' && !(quote && s[i] == '"') {
				return fmt.Errorf("bad escape \\%c", s[i])
			}
		}
	}
	return nil
}

func parseSample(ln string) (sample, error) {
	s := sample{labels: map[string]string{}}
	i := 0
	for i < len(ln) && (ln[i] == '_' || ln[i] == ':' || ln[i] >= 'a' && ln[i] <= 'z' || ln[i] >= 'A' && ln[i] <= 'Z' || i > 0 && ln[i] >= '0' && ln[i] <= '9') {
		i++
	}
	s.name = ln[:i]
	if s.name == "" {
		return s, fmt.Errorf("no metric name")
	}
	if i < len(ln) && ln[i] == '{' {
		i++
		for {
			if i >= len(ln) {
				return s, fmt.Errorf("unterminated label set")
			}
			if ln[i] == '}' {
				i++
				break
			}
			j := i
			for j < len(ln) && ln[j] != '=' {
				j++
			}
			if j >= len(ln) {
				return s, fmt.Errorf("label without =")
			}
			ln0 := ln[i:j]
			if !reLabelName.MatchString(ln0) {
				return s, fmt.Errorf("bad label name %q", ln0)
			}
			if _, dup := s.labels[ln0]; dup {
				return s, fmt.Errorf("duplicate label %q", ln0)
			}
			i = j + 1
			if i >= len(ln) || ln[i] != '"' {
				return s, fmt.Errorf("label value not quoted")
			}
			i++
			var val strings.Builder
			closed := false
			for i < len(ln) {
				c := ln[i]
				if c == '\\' {
					i++
					if i >= len(ln) {
						return s, fmt.Errorf("dangling backslash")
					}
					switch ln[i] {
					case '\\':
						val.WriteByte('\\')
					case '"':
						val.WriteByte('"')
					case 'n':
						val.WriteByte('\n')
					default:
						return s, fmt.Errorf("bad escape \\%c", ln[i])
					}
					i++
					continue
				}
				if c == '"' {
					closed = true
					i++
					break
				}
				val.WriteByte(c)
				i++
			}
			if !closed {
				return s, fmt.Errorf("unterminated label value")
			}
			s.labels[ln0] = val.String()
			s.order = append(s.order, ln0)
			if i < len(ln) && ln[i] == ',' {
				i++
			}
		}
	}
	if i >= len(ln) || ln[i] != ' ' {
		return s, fmt.Errorf("no space before the value")
	}
	rest := strings.Fields(ln[i+1:])
	if len(rest) < 1 || len(rest) > 2 {
		return s, fmt.Errorf("want value [timestamp], got %v", rest)
	}
	if !reFloat.MatchString(rest[0]) {
		return s, fmt.Errorf("bad value %q", rest[0])
	}
	s.rawVal = rest[0]
	switch rest[0] {
	case "NaN":
		s.value = math.NaN()
	case "+Inf":
		s.value = math.Inf(1)
	case "-Inf":
		s.value = math.Inf(-1)
	default:
		v, err := strconv.ParseFloat(rest[0], 64)
		if err != nil && !strings.Contains(err.Error(), "range") {
			return s, err
		}
		s.value = v
	}
	return s, nil
}

func scrape(t testing.TB, r *obs.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != 200 {
		t.Fatalf("scrape status %d", rec.Code)
	}
	b, _ := io.ReadAll(rec.Body)
	return string(b)
}

func mustParse(t testing.TB, body string) *exposition {
	t.Helper()
	ex, err := parseExposition(body)
	if err != nil {
		t.Fatalf("exposition is not valid text format 0.0.4: %v\n--- body ---\n%.2000s", err, body)
	}
	for _, s := range ex.samples {
		fam := s.name
		for _, suf := range []string{"_bucket", "_sum", "_count"} {
			if strings.HasSuffix(fam, suf) {
				if ex.typ[strings.TrimSuffix(fam, suf)] == "histogram" {
					fam = strings.TrimSuffix(fam, suf)
				}
			}
		}
		if _, ok := ex.typ[fam]; !ok {
			t.Fatalf("sample %q has no TYPE line", s.name)
		}
	}
	return ex
}

func (e *exposition) find(name string) []sample {
	var out []sample
	for _, s := range e.samples {
		if s.name == name {
			out = append(out, s)
		}
	}
	return out
}

func (e *exposition) names() []string {
	m := map[string]bool{}
	for _, s := range e.samples {
		m[s.name] = true
	}
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func panics(f func()) (p bool) {
	defer func() {
		if recover() != nil {
			p = true
		}
	}()
	f()
	return false
}
