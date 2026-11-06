package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"kairan/internal/wire"
)

// rawTimeline serves a hand-written timeline body (Q-D28, M-D63).
func rawTimeline(t *testing.T, body string) *fakeCP {
	cp := newFakeCP(t, false)
	cp.timeline = func(w http.ResponseWriter, tenant string) {
		writeJSON(w, 200, rawJSON(body))
	}
	return cp
}

var goodEntry = `{"proxy_id":"bank-a-p1","version":9,"policy_hash":"` + string(hh9) + `","first_seen_unix_ms":1793000000000,"last_seen_unix_ms":1793000001000}`

func TestStrictTimelineAnswer(t *testing.T) {
	bad := map[string]string{
		"null count":             `{"tenant":"bank-a","entries":[],"dropped":{"bank-a-p1":null}}`,
		"duplicate dropped key":  `{"tenant":"bank-a","entries":[],"dropped":{"bank-a-p1":1,"bank-a-p1":2}}`,
		"case variant dropped":   `{"tenant":"bank-a","entries":[],"dropped":{"bank-a-p1":1,"Bank-A-P1":2}}`,
		"duplicate top key":      `{"tenant":"bank-a","entries":[],"entries":[],"dropped":{"bank-a-p1":1}}`,
		"duplicate tenant":       `{"tenant":"bank-a","tenant":"bank-a","entries":[]}`,
		"case variant top key":   `{"Tenant":"bank-a","entries":[]}`,
		"case variant entry key": `{"tenant":"bank-a","entries":[` + strings.Replace(goodEntry, `"version"`, `"Version"`, 1) + `]}`,
		"duplicate entry key":    `{"tenant":"bank-a","entries":[` + strings.Replace(goodEntry, `"version":9`, `"version":9,"version":9`, 1) + `]}`,
		"duplicate in 2nd entry": `{"tenant":"bank-a","entries":[` + goodEntry + `,` + strings.Replace(goodEntry, `"version":9`, `"version":9,"version":8`, 1) + `]}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			code, out, e := evid(t, rawTimeline(t, body))
			if code != 1 || !hasBoth(e) || strings.Contains(out, "dropped") {
				t.Errorf("exit %d out %q err %q", code, out, e)
			}
		})
	}
	good := map[string]string{
		"plain":           `{"tenant":"bank-a","entries":[` + goodEntry + `]}`,
		"dropped counts":  `{"tenant":"bank-a","entries":[],"dropped":{"bank-a-p1":2,"bank-a-p2":0}}`,
		"empty dropped":   `{"tenant":"bank-a","entries":[],"dropped":{}}`,
		"two entries":     `{"tenant":"bank-a","entries":[` + goodEntry + `,` + goodEntry + `]}`,
		"whitespace/nest": " {\n \"tenant\" : \"bank-a\" , \"entries\" : [ ] }\n",
	}
	for name, body := range good {
		t.Run("good "+name, func(t *testing.T) {
			code, out, e := evid(t, rawTimeline(t, body))
			if code != 0 {
				t.Errorf("exit %d out %q err %q", code, out, e)
			}
		})
	}
}

func TestStrictTimelineKeysUnit(t *testing.T) {
	for _, c := range []struct {
		in string
		ok bool
	}{
		{`{"tenant":"a","entries":[],"dropped":{"p":1}}`, true},
		{`{"dropped":{"p":1,"p":2}}`, false},
		{`{"dropped":{"p":1,"P":2}}`, false},
		{`{"dropped":{"p":null}}`, false},
		{`{"dropped":{"p":"x"}}`, false},
		{`{"dropped":{"p":{"a":1}}}`, false},
		{`{"dropped":{"p":[1]}}`, false},
		{`{"dropped":null}`, true},
		{`{"dropped":3}`, true}, // the normal decoder refuses it
		{`{"entries":[{"version":1,"Version":2}]}`, false},
		{`{"entries":[{"nope":1}]}`, false},
		{`{"entries":[3,{"version":1}]}`, true},
		{`{"entries":null}`, true},
		{`{"other":1}`, false},
		{`[1]`, true},
		{`{"tenant":`, true}, // syntax errors are left to the decoder
		{``, true},
	} {
		if got := strictTimelineKeys([]byte(c.in)); got != c.ok {
			t.Errorf("%q: got %v want %v", c.in, got, c.ok)
		}
	}
}

func FuzzStrictTimelineKeys(f *testing.F) {
	for _, s := range []string{
		`{"tenant":"a","entries":[` + goodEntry + `],"dropped":{"p":1}}`,
		`{"dropped":{"p":1,"p":2}}`, `{"dropped":{"p":null}}`, `{"Tenant":"a"}`, `{"entries":[{}]}`,
		`{"dropped":{"a":1,"A":1}}`, `[`, `{`, `{"entries":[[[[{}]]]]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		ok := strictTimelineKeys(b) // must not panic or hang
		if !ok {
			return
		}
		// Whatever it accepts and the decoder also accepts has no null count
		// and no repeated or case-variant dropped key.
		var v struct {
			Dropped map[string]json.RawMessage `json:"dropped"`
		}
		var raw map[string]json.RawMessage
		if json.Unmarshal(b, &raw) != nil || raw["dropped"] == nil || json.Unmarshal(raw["dropped"], &v.Dropped) != nil {
			return
		}
		seen := map[string]bool{}
		for k, val := range v.Dropped {
			if string(val) == "null" {
				t.Errorf("accepted null count in %q", b)
			}
			lk := strings.ToLower(k)
			if seen[lk] {
				t.Errorf("accepted case-variant keys in %q", b)
			}
			seen[lk] = true
		}
	})
}

func TestHalfSetAnchorIsFlagged(t *testing.T) {
	_, es := goodLog(t, t.TempDir(), "x.log")
	for name, mut := range map[string]func(*wire.TimelineEntry){
		"seq without head": func(e *wire.TimelineEntry) { e.LogHead = "" },
		"head without seq": func(e *wire.TimelineEntry) { e.LogSeq = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			tle := cleanTimeline(es)
			mut(&tle[1])
			code, out, _ := evid(t, cpWith(t, tle))
			if code != 1 || !strings.Contains(out, "FLAG [anchor]") {
				t.Fatalf("exit %d\n%s", code, out)
			}
			if !strings.Contains(out, "JST") || !strings.Contains(out, "UTC") || !hasJapanese(out) {
				t.Errorf("flag should be bilingual with JST and UTC\n%s", out)
			}
			if n := strings.Count(out, "FLAG ["); n != 1 {
				t.Errorf("want exactly one flag, got %d\n%s", n, out)
			}
		})
	}
	// With the proxy's log, the half-set anchor is still one flag, not several.
	path, es2 := goodLog(t, t.TempDir(), "y.log")
	tle := cleanTimeline(es2)
	tle[1].LogHead = ""
	code, out, _ := evid(t, cpWith(t, tle), "-applylog", "bank-a-p1="+path)
	if code != 1 || strings.Count(out, "FLAG [") != 1 || !strings.Contains(out, "FLAG [anchor]") {
		t.Errorf("with log: exit %d\n%s", code, out)
	}
	// Both set and both empty stay quiet.
	if code, out, _ := evid(t, cpWith(t, cleanTimeline(es))); code != 0 || strings.Contains(out, "FLAG") {
		t.Errorf("clean: exit %d\n%s", code, out)
	}
}
