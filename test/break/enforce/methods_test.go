package enforcebreak

import (
	"fmt"
	"testing"
)

// P-D4 / R-D2 item 1 "exact method spelling": a method that is a case or padding variant of tools/call
// or tools/list must not be passed through, because an upstream that trims or truncates it would run a
// tool the proxy never judged (THREATS #13). The proxy already refuses space, tab, CR, LF, VT, FF and
// the Unicode spaces; these tests cover the remaining padding characters.
func methodPaddingCases(pads map[string]string, t *testing.T) {
	for _, base := range []string{"tools/call", "tools/list"} {
		for name, pad := range pads {
			for _, pos := range []string{"suffix", "prefix"} {
				method := base + pad
				if pos == "prefix" {
					method = pad + base
				}
				t.Run(fmt.Sprintf("%s/%s/%s", base[6:], name, pos), func(t *testing.T) {
					r := newRig(t)
					body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"%s","params":{"name":"crm.delete_all"}}`, method)
					rep := r.post(keySales, body)
					if r.up.count() != 0 {
						t.Fatalf("padded method %q was forwarded to the upstream (answer %d %.100s)", method, rep.code, rep.body)
					}
					for _, rec := range r.dl.all() {
						if rec.Allowed {
							t.Fatalf("allow record: %+v", rec)
						}
					}
				})
			}
		}
	}
}

func TestMethodPaddedWithASCIIControlCharsIsNotPassedThrough(t *testing.T) {
	pads := map[string]string{"nul": `\u0000`, "soh": `\u0001`, "esc": `\u001b`, "us": `\u001f`, "del": `\u007f`,
		"space": ` `, "tab": `\t`, "lf": `\n`, "cr": `\r`, "vt": `\u000b`, "ff": `\u000c`}
	methodPaddingCases(pads, t)
}

func TestMethodPaddedWithInvisibleUnicodeIsNotPassedThrough(t *testing.T) {
	pads := map[string]string{"zero-width-space": `\u200b`, "zwnj": `\u200c`, "zwj": `\u200d`, "bom": `\ufeff`,
		"word-joiner": `\u2060`, "rlo": `\u202e`, "nbsp": `\u00a0`, "ideographic-space": `\u3000`, "line-separator": `\u2028`}
	methodPaddingCases(pads, t)
}

func TestMethodCaseVariantsAreNotPassedThrough(t *testing.T) {
	for _, method := range []string{"Tools/call", "tools/Call", "TOOLS/CALL", "tOoLs/CaLl", "Tools/list", "tools/List", "TOOLS/LIST"} {
		r := newRig(t)
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{"name":"crm.delete_all"}}`, method)
		rep := r.post(keySales, body)
		if r.up.count() != 0 {
			t.Errorf("case variant %q was forwarded (answer %d %.100s)", method, rep.code, rep.body)
		}
	}
}

// The pass-through methods (initialize, ping, notifications, unknown methods) are not tools/call, are not
// judged, and are not recorded as tool decisions (doc step 5).
func TestOrdinaryMethodsPassThroughUnjudged(t *testing.T) {
	for _, m := range []string{"initialize", "ping", "notifications/initialized", "notifications/cancelled", "resources/list",
		"resources/read", "prompts/list", "completion/complete", "logging/setLevel", "tools", "tools/", "tools/calls", "tool/call", "tools/listing", "x"} {
		r := newRig(t)
		body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":{}}`, m)
		rep := r.post(keySales, body)
		if rep.code/100 != 2 || r.up.count() != 1 {
			t.Errorf("%s: %d %.80s, upstream %d", m, rep.code, rep.body, r.up.count())
			continue
		}
		for _, rec := range r.dl.all() {
			if rec.Tool != "" && rec.Tool != "tools/list" {
				t.Errorf("%s: pass-through produced a tool decision %+v", m, rec)
			}
		}
	}
}
