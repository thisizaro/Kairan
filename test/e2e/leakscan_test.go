package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// A canary is a secret planted by a scenario. needle is the exact string that must never show up in any
// artifact the control plane side can see. The scanner looks for it in the raw form and in the encodings a
// careless implementation could produce (upper case, hex, base64 at every byte alignment, base64url,
// URL-escaped, and the raw bytes when the needle is itself hex).
type canary struct {
	kind   string // prompt, argument, result, api-key, tool-name, header, path, id, real-key
	needle string
}

func newCanary(kind string) canary {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return canary{kind: kind, needle: hex.EncodeToString(b)}
}

type variant struct {
	name string
	data []byte
}

// variants returns every form of the needle the scanner searches for.
func (c canary) variants() []variant {
	seen := map[string]bool{}
	var out []variant
	add := func(name string, b []byte) {
		if len(b) < 8 || seen[string(b)] {
			return
		}
		seen[string(b)] = true
		out = append(out, variant{name, b})
	}
	n := c.needle
	add("raw", []byte(n))
	add("upper", []byte(strings.ToUpper(n)))
	add("url-escaped", []byte(url.QueryEscape(n)))
	add("hex-of-text", []byte(hex.EncodeToString([]byte(n))))
	add("HEX-of-text", []byte(strings.ToUpper(hex.EncodeToString([]byte(n)))))
	if raw, err := hex.DecodeString(n); err == nil {
		add("raw-bytes", raw)
	}
	// base64 of the text at the three byte alignments; the unstable leading and trailing characters are cut
	// so the remainder appears whatever surrounds the text.
	lead := []int{0, 2, 3}
	for k := 0; k < 3; k++ {
		in := append(bytes.Repeat([]byte{'x'}, k), []byte(n)...)
		for _, enc := range []struct {
			name string
			e    *base64.Encoding
		}{{"base64", base64.StdEncoding}, {"base64url", base64.URLEncoding}} {
			s := enc.e.EncodeToString(in)
			s = strings.TrimRight(s, "=")
			if len(s) > lead[k]+4 {
				s = s[lead[k] : len(s)-3]
			}
			add(fmt.Sprintf("%s+%d", enc.name, k), []byte(s))
		}
	}
	return out
}

type leakHit struct {
	source, kind, variant string
	offset                int
}

// scanner scans artifacts and counts how much it looked at.
type scanner struct {
	cans    []canary
	vars    [][]variant
	Bytes   int64
	Items   int
	PerItem map[string]int
	Hits    []leakHit
}

func newScanner(cans ...canary) *scanner {
	s := &scanner{cans: cans, PerItem: map[string]int{}}
	for _, c := range cans {
		s.vars = append(s.vars, c.variants())
	}
	return s
}

func (s *scanner) scan(source string, data []byte) {
	s.Items++
	s.Bytes += int64(len(data))
	s.PerItem[source] += len(data)
	for i, c := range s.cans {
		for _, v := range s.vars[i] {
			if off := bytes.Index(data, v.data); off >= 0 {
				s.Hits = append(s.Hits, leakHit{source, c.kind, v.name, off})
			}
		}
	}
}

func (s *scanner) report() string {
	var names []string
	for n := range s.PerItem {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		fmt.Fprintf(&b, "  %-34s %10d bytes\n", n, s.PerItem[n])
	}
	return b.String()
}

// The scanner itself must not miss a leak: plant every variant in noise and require a hit, and require
// none in clean data. Runs without Docker.
func TestLeakScannerFindsEveryEncoding(t *testing.T) {
	c := newCanary("argument")
	for _, v := range c.variants() {
		s := newScanner(c)
		noise := []byte(`{"seen":"nothing here","n":1}` + "\n")
		data := append(append(append([]byte(nil), noise...), v.data...), noise...)
		s.scan("planted-"+v.name, data)
		if len(s.Hits) == 0 {
			t.Errorf("scanner missed variant %q of the canary", v.name)
		}
	}
	// base64 of the text inside longer text, at each alignment
	for k := 0; k < 3; k++ {
		in := append(bytes.Repeat([]byte{'y'}, k), []byte("prefix "+c.needle+" suffix")...)
		for _, e := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding} {
			s := newScanner(c)
			s.scan("b64", []byte(`{"blob":"`+e.EncodeToString(in)+`"}`))
			if len(s.Hits) == 0 {
				t.Errorf("scanner missed base64 (alignment %d) of text containing the canary", k)
			}
		}
	}
	clean := newScanner(c)
	clean.scan("clean", []byte(`{"tenant":"bank-a","version":2,"hash":"`+strings.Repeat("ab", 32)+`"}`))
	if len(clean.Hits) != 0 || clean.Bytes == 0 || clean.Items != 1 {
		t.Errorf("clean data produced hits or wrong counts: %+v", clean)
	}
	// two canaries are distinct
	a, b := newCanary("a"), newCanary("b")
	if a.needle == b.needle || len(a.needle) != 24 {
		t.Errorf("canaries must be unique 24-character values: %q %q", a.needle, b.needle)
	}
}
