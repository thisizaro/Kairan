package obs

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// A small strict parser for the Prometheus text format 0.0.4 subset that
// Registry emits. It rejects anything a real scraper might tolerate:
// missing trailing newline, blank lines, unknown escapes, samples without a
// preceding HELP and TYPE, unsorted families, duplicate series, and
// non-cumulative histograms.

type parsedSample struct {
	name   string
	labels [][2]string // in emitted order
	value  float64
	raw    string
}

func (s parsedSample) key() string {
	var b strings.Builder
	b.WriteString(s.name)
	for _, l := range s.labels {
		b.WriteString("\x00" + l[0] + "=" + l[1])
	}
	return b.String()
}

func (s parsedSample) label(name string) (string, bool) {
	for _, l := range s.labels {
		if l[0] == name {
			return l[1], true
		}
	}
	return "", false
}

type parsedFamily struct {
	name, help, typ string
	samples         []parsedSample
}

func parseStrict(text string) ([]*parsedFamily, error) {
	if text == "" {
		return nil, nil
	}
	if !strings.HasSuffix(text, "\n") {
		return nil, fmt.Errorf("missing trailing newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	var fams []*parsedFamily
	var cur *parsedFamily
	seen := map[string]bool{}
	for i, ln := range lines {
		fail := func(f string, a ...any) error {
			return fmt.Errorf("line %d %q: %s", i+1, ln, fmt.Sprintf(f, a...))
		}
		if ln == "" {
			return nil, fail("blank line")
		}
		switch {
		case strings.HasPrefix(ln, "# HELP "):
			rest := strings.TrimPrefix(ln, "# HELP ")
			name, help, ok := strings.Cut(rest, " ")
			if !ok {
				name, help = rest, ""
			}
			if !validMetricName(name) {
				return nil, fail("bad metric name")
			}
			h, err := unescape(help, false)
			if err != nil {
				return nil, fail("help: %v", err)
			}
			if len(fams) > 0 && fams[len(fams)-1].name >= name {
				return nil, fail("families not strictly sorted")
			}
			cur = &parsedFamily{name: name, help: h}
			fams = append(fams, cur)
		case strings.HasPrefix(ln, "# TYPE "):
			if cur == nil || cur.typ != "" || len(cur.samples) > 0 {
				return nil, fail("TYPE without fresh HELP")
			}
			name, typ, ok := strings.Cut(strings.TrimPrefix(ln, "# TYPE "), " ")
			if !ok || name != cur.name {
				return nil, fail("TYPE name mismatch")
			}
			if typ != "counter" && typ != "gauge" && typ != "histogram" {
				return nil, fail("unknown type %q", typ)
			}
			cur.typ = typ
		case strings.HasPrefix(ln, "#"):
			return nil, fail("unknown comment")
		default:
			if cur == nil || cur.typ == "" {
				return nil, fail("sample before HELP/TYPE")
			}
			s, err := parseSample(ln)
			if err != nil {
				return nil, fail("%v", err)
			}
			okName := s.name == cur.name
			if cur.typ == "histogram" {
				okName = s.name == cur.name+"_bucket" || s.name == cur.name+"_sum" || s.name == cur.name+"_count"
			}
			if !okName {
				return nil, fail("sample %q not in family %q", s.name, cur.name)
			}
			if seen[s.key()] {
				return nil, fail("duplicate series")
			}
			seen[s.key()] = true
			cur.samples = append(cur.samples, s)
		}
	}
	for _, f := range fams {
		if f.typ == "" {
			return nil, fmt.Errorf("family %s has no TYPE", f.name)
		}
		if f.typ == "histogram" {
			if err := checkHistogram(f); err != nil {
				return nil, fmt.Errorf("family %s: %v", f.name, err)
			}
		}
	}
	return fams, nil
}

func validMetricName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == ':' || (i > 0 && c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

func validLabelName(s string) bool {
	return validMetricName(s) && !strings.Contains(s, ":")
}

func unescape(s string, quoted bool) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\n':
			return "", fmt.Errorf("raw newline")
		case quoted && c == '"':
			return "", fmt.Errorf("raw quote")
		case c == '\\':
			i++
			if i >= len(s) {
				return "", fmt.Errorf("dangling backslash")
			}
			switch {
			case s[i] == '\\':
				b.WriteByte('\\')
			case s[i] == 'n':
				b.WriteByte('\n')
			case quoted && s[i] == '"':
				b.WriteByte('"')
			default:
				return "", fmt.Errorf("unknown escape \\%c", s[i])
			}
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

func parseSample(ln string) (parsedSample, error) {
	s := parsedSample{raw: ln}
	i := 0
	for i < len(ln) && ln[i] != '{' && ln[i] != ' ' {
		i++
	}
	s.name = ln[:i]
	if !validMetricName(s.name) {
		return s, fmt.Errorf("bad sample name")
	}
	if i < len(ln) && ln[i] == '{' {
		i++
		for {
			if i >= len(ln) {
				return s, fmt.Errorf("unterminated labels")
			}
			j := i
			for j < len(ln) && ln[j] != '=' {
				j++
			}
			if j+1 >= len(ln) || ln[j+1] != '"' {
				return s, fmt.Errorf("label without quoted value")
			}
			lname := ln[i:j]
			if !validLabelName(lname) {
				return s, fmt.Errorf("bad label name %q", lname)
			}
			k := j + 2
			for k < len(ln) && ln[k] != '"' {
				if ln[k] == '\\' {
					k++
				}
				k++
			}
			if k >= len(ln) {
				return s, fmt.Errorf("unterminated label value")
			}
			v, err := unescape(ln[j+2:k], true)
			if err != nil {
				return s, err
			}
			s.labels = append(s.labels, [2]string{lname, v})
			i = k + 1
			if i < len(ln) && ln[i] == ',' {
				i++
				continue
			}
			if i < len(ln) && ln[i] == '}' {
				i++
				break
			}
			return s, fmt.Errorf("bad label separator")
		}
	}
	if i >= len(ln) || ln[i] != ' ' {
		return s, fmt.Errorf("missing space before value")
	}
	val := ln[i+1:]
	if val == "" || strings.ContainsAny(val, " \t") {
		return s, fmt.Errorf("bad value %q", val)
	}
	switch val {
	case "NaN":
		s.value = math.NaN()
	case "+Inf":
		s.value = math.Inf(1)
	case "-Inf":
		s.value = math.Inf(-1)
	default:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
			return s, fmt.Errorf("bad value %q", val)
		}
		s.value = f
	}
	return s, nil
}

// checkHistogram verifies, per label set, that le is ascending, buckets are
// cumulative, the last bucket is +Inf, and _count equals it.
func checkHistogram(f *parsedFamily) error {
	type series struct {
		les      []float64
		counts   []float64
		sum, cnt *float64
	}
	groups := map[string]*series{}
	var order []string
	for _, s := range f.samples {
		var rest [][2]string
		le := ""
		for _, l := range s.labels {
			if l[0] == "le" {
				le = l[1]
			} else {
				rest = append(rest, l)
			}
		}
		k := fmt.Sprint(rest)
		g := groups[k]
		if g == nil {
			g = &series{}
			groups[k] = g
			order = append(order, k)
		}
		v := s.value
		switch s.name {
		case f.name + "_bucket":
			if le == "" {
				return fmt.Errorf("bucket without le")
			}
			var x float64
			if le == "+Inf" {
				x = math.Inf(1)
			} else {
				var err error
				if x, err = strconv.ParseFloat(le, 64); err != nil {
					return fmt.Errorf("bad le %q", le)
				}
			}
			g.les = append(g.les, x)
			g.counts = append(g.counts, v)
		case f.name + "_sum":
			g.sum = &v
		case f.name + "_count":
			g.cnt = &v
		}
	}
	for _, k := range order {
		g := groups[k]
		if len(g.les) == 0 || !math.IsInf(g.les[len(g.les)-1], 1) {
			return fmt.Errorf("series %s: no +Inf bucket", k)
		}
		if !sort.Float64sAreSorted(g.les) {
			return fmt.Errorf("series %s: le not ascending", k)
		}
		if !sort.Float64sAreSorted(g.counts) {
			return fmt.Errorf("series %s: buckets not cumulative", k)
		}
		if g.sum == nil || g.cnt == nil {
			return fmt.Errorf("series %s: missing _sum or _count", k)
		}
		if *g.cnt != g.counts[len(g.counts)-1] {
			return fmt.Errorf("series %s: _count != +Inf bucket", k)
		}
	}
	return nil
}
