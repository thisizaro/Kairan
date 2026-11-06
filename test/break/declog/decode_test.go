package declogbreak

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"kairan/internal/proxy/declog"
)

// Decode is strict (doc): exactly the eight fields, each once, lowercase, a UTC time, valid values.
func TestDecodeStrict(t *testing.T) {
	good := string(goodLine(t))
	if _, err := declog.Decode([]byte(good)); err != nil {
		t.Fatalf("baseline good line rejected: %v", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(good), &keys); err != nil {
		t.Fatal(err)
	}
	if len(keys) != 8 {
		t.Fatalf("a line has %d keys, doc says exactly eight", len(keys))
	}
	for _, want := range []string{"time", "role", "tool", "allowed", "class", "version", "hash", "state"} {
		if _, ok := keys[want]; !ok {
			t.Errorf("line has no %q key (doc lists time, role, tool, allowed, class, version, hash, state)", want)
		}
	}

	cases := []struct {
		name string
		line []byte
	}{
		{"empty", nil},
		{"whitespace", []byte("  \n")},
		{"not json", []byte("hello")},
		{"array", []byte("[]")},
		{"null", []byte("null")},
		{"truncated", []byte(good[:len(good)-3])},
		{"two lines", []byte(good + "\n" + good)},
		{"line then junk", []byte(good + " x")},
		{"two objects", []byte(good + good)},
		{"extra field", mutate(t, func(m map[string]any) { m["extra"] = "x" })},
		{"extra field carrying canary", mutate(t, func(m map[string]any) { m["args"] = canary })},
		{"missing time", mutate(t, func(m map[string]any) { delete(m, "time") })},
		{"missing role", mutate(t, func(m map[string]any) { delete(m, "role") })},
		{"missing tool", mutate(t, func(m map[string]any) { delete(m, "tool") })},
		{"missing allowed", mutate(t, func(m map[string]any) { delete(m, "allowed") })},
		{"missing class", mutate(t, func(m map[string]any) { delete(m, "class") })},
		{"missing version", mutate(t, func(m map[string]any) { delete(m, "version") })},
		{"missing hash", mutate(t, func(m map[string]any) { delete(m, "hash") })},
		{"missing state", mutate(t, func(m map[string]any) { delete(m, "state") })},
		{"time not UTC", mutate(t, func(m map[string]any) { m["time"] = "2026-11-05T17:30:00+05:30" })},
		{"time offset zero not Z", mutate(t, func(m map[string]any) { m["time"] = "2026-11-05T12:00:00+00:00" })},
		{"time not a time", mutate(t, func(m map[string]any) { m["time"] = "yesterday" })},
		{"time number", mutate(t, func(m map[string]any) { m["time"] = 1762344000 })},
		{"time null", mutate(t, func(m map[string]any) { m["time"] = nil })},
		{"role newline", mutate(t, func(m map[string]any) { m["role"] = "a\nb" })},
		{"role huge", mutate(t, func(m map[string]any) { m["role"] = strings.Repeat("r", 5000) })},
		{"role number", mutate(t, func(m map[string]any) { m["role"] = 5 })},
		{"tool spaces and canary", mutate(t, func(m map[string]any) { m["tool"] = "a " + canary })},
		{"tool too long", mutate(t, func(m map[string]any) { m["tool"] = strings.Repeat("a", 129) })},
		{"tool NUL", mutate(t, func(m map[string]any) { m["tool"] = "a\x00" })},
		{"tool null", mutate(t, func(m map[string]any) { m["tool"] = nil })},
		{"allowed string", mutate(t, func(m map[string]any) { m["allowed"] = "true" })},
		{"allowed number", mutate(t, func(m map[string]any) { m["allowed"] = 1 })},
		{"allowed null", mutate(t, func(m map[string]any) { m["allowed"] = nil })},
		{"class bad", mutate(t, func(m map[string]any) { m["class"] = "Q" })},
		{"class lowercase", mutate(t, func(m map[string]any) { m["class"] = "r" })},
		{"class long", mutate(t, func(m map[string]any) { m["class"] = "RW" })},
		{"class canary", mutate(t, func(m map[string]any) { m["class"] = canary })},
		{"version negative", mutate(t, func(m map[string]any) { m["version"] = -1 })},
		{"version float", mutate(t, func(m map[string]any) { m["version"] = 1.5 })},
		{"version string", mutate(t, func(m map[string]any) { m["version"] = "7" })},
		{"version null", mutate(t, func(m map[string]any) { m["version"] = nil })},
		{"version beyond uint64", []byte(strings.Replace(string(goodLine(t)), `"version":2`, `"version":18446744073709551616`, 1))},
		{"hash short", mutate(t, func(m map[string]any) { m["hash"] = "abc" })},
		{"hash upper", mutate(t, func(m map[string]any) { m["hash"] = strings.Repeat("A", 64) })},
		{"hash non hex", mutate(t, func(m map[string]any) { m["hash"] = strings.Repeat("z", 64) })},
		{"hash canary", mutate(t, func(m map[string]any) { m["hash"] = canary })},
		{"state unknown", mutate(t, func(m map[string]any) { m["state"] = "owned" })},
		{"state canary", mutate(t, func(m map[string]any) { m["state"] = canary })},
		{"state empty", mutate(t, func(m map[string]any) { m["state"] = "" })},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if r, err := declog.Decode(c.line); err == nil {
				t.Fatalf("Decode accepted %q -> %+v", clip(string(c.line)), r)
			}
		})
	}
}

// Duplicate and case-variant keys (doc: each once, in lowercase). Built by string surgery because a map
// cannot hold two equal keys.
func TestDecodeRejectsDuplicateAndCaseVariantKeys(t *testing.T) {
	good := string(goodLine(t))
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(good), &m); err != nil {
		t.Fatal(err)
	}
	build := func(pairs ...string) []byte {
		return []byte("{" + strings.Join(pairs, ",") + "}")
	}
	var all []string
	for _, k := range []string{"time", "role", "tool", "allowed", "class", "version", "hash", "state"} {
		all = append(all, `"`+k+`":`+string(m[k]))
	}
	cases := map[string][]byte{}
	for i, k := range []string{"time", "role", "tool", "allowed", "class", "version", "hash", "state"} {
		cases["duplicate "+k] = build(append(append([]string{}, all...), all[i])...)
		// same key, different value: the second one must not win silently
		cases["duplicate "+k+" different value"] = build(append(append([]string{}, all...), `"`+k+`":"x"`)...)
		cases["upper case "+k] = []byte(strings.Replace(good, `"`+k+`"`, `"`+strings.ToUpper(k)+`"`, 1))
		cases["title case "+k] = []byte(strings.Replace(good, `"`+k+`"`, `"`+strings.ToUpper(k[:1])+k[1:]+`"`, 1))
		// the same key twice, once spelled with a \u escape: equal after decoding, so still a duplicate
		cases["escaped duplicate "+k] = build(append(append([]string{}, all...), `"\u`+hex4(k[0])+k[1:]+`":`+string(m[k]))...)
		cases["escaped duplicate "+k+" different value"] = build(append(append([]string{}, all...), `"\u`+hex4(k[0])+k[1:]+`":"x"`)...)
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			if r, err := declog.Decode(line); err == nil {
				t.Fatalf("Decode accepted %q -> %+v", clip(string(line)), r)
			}
		})
	}
}

func hex4(b byte) string {
	const h = "0123456789abcdef"
	return "00" + string(h[b>>4]) + string(h[b&15])
}

// Decode of a huge input must neither panic nor take long.
func TestDecodeHugeInput(t *testing.T) {
	for _, b := range [][]byte{
		bytes.Repeat([]byte("{"), 1<<20),
		[]byte(`{"role":"` + strings.Repeat("a", 4<<20) + `"}`),
		bytes.Repeat([]byte("["), 1<<20),
	} {
		if _, err := declog.Decode(b); err == nil {
			t.Error("huge garbage accepted")
		}
	}
}

func FuzzDecode(f *testing.F) {
	var b bytes.Buffer
	_ = declog.New(&b, nil).Record(rec(1))
	f.Add(b.Bytes())
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"time":"2026-11-05T12:00:00Z","role":"a","tool":"","allowed":true,"class":"R","version":1,"hash":"` + strings.Repeat("a", 64) + `","state":"enforcing"}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		r, err := declog.Decode(in)
		if err != nil {
			return
		}
		// whatever Decode accepts must re-encode through Record into a line Decode accepts again, equal
		var out bytes.Buffer
		if err := declog.New(&out, nil).Record(r); err != nil {
			t.Fatalf("Decode accepted a record that Record refuses: %+v: %v", r, err)
		}
		r2, err := declog.Decode(out.Bytes())
		if err != nil {
			t.Fatalf("own output rejected: %v", err)
		}
		if !r2.Time.Equal(r.Time) || r2.Role != r.Role || r2.Tool != r.Tool || r2.Allowed != r.Allowed || r2.Class != r.Class ||
			r2.Version != r.Version || r2.Hash != r.Hash || r2.State != r.State {
			t.Fatalf("round trip drift: %+v vs %+v", r, r2)
		}
		if bytes.Count(out.Bytes(), []byte("\n")) != 1 {
			t.Fatalf("record is not one line: %q", out.Bytes())
		}
	})
}
