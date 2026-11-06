package enforcebreak

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"kairan/internal/policy"
)

// upstreamView reads a forwarded tools/call the way several plausible upstream JSON parsers would and
// returns every (method, tool) reading: encoding/json (last duplicate wins, field names case-insensitive)
// and a first-duplicate-wins token reader. Used as the differential oracle for request smuggling (R-D2,
// THREATS #13): whatever the proxy forwards must be allowed under every reading.
func upstreamReadings(body []byte) (readings [][2]string) {
	var std struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	if json.Unmarshal(body, &std) == nil {
		readings = append(readings, [2]string{std.Method, std.Params.Name})
	}
	// first-wins, case-sensitive, via a generic map decoded key by key
	first := func(raw []byte, key string) (json.RawMessage, bool) {
		dec := json.NewDecoder(bytes.NewReader(raw))
		if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
			return nil, false
		}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, false
			}
			var v json.RawMessage
			if err := dec.Decode(&v); err != nil {
				return nil, false
			}
			if k, _ := kt.(string); strings.EqualFold(k, key) {
				return v, true
			}
		}
		return nil, false
	}
	if m, ok := first(body, "method"); ok {
		var ms string
		_ = json.Unmarshal(m, &ms)
		if p, ok := first(body, "params"); ok {
			if n, ok := first(p, "name"); ok {
				var ns string
				_ = json.Unmarshal(n, &ns)
				readings = append(readings, [2]string{ms, ns})
			}
		}
	}
	return
}

// checkNoSmuggling asserts, for everything the upstream received, that any tools/call reading is allowed
// for the role by the policy.
func (r *rig) checkNoSmuggling(role string, p *policy.Policy) {
	r.t.Helper()
	for _, u := range r.up.requests() {
		for _, rd := range upstreamReadings(u.Body) {
			if strings.EqualFold(strings.TrimSpace(rd[0]), "tools/call") && !allowedBy(p, role, rd[1], false) {
				r.t.Errorf("SMUGGLED: the upstream would run %q (method %q) for role %s, which the policy denies; body %.300q", rd[1], rd[0], role, u.Body)
			}
		}
	}
}

// R-D2 / M-D33 items 1, 2, 3, 6: every request the proxy cannot read strictly is rejected, never forwarded,
// and is a logged deny. The table also holds the differential-parsing vectors.
func TestStrictRequestHandling(t *testing.T) {
	good := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{}}}`
	evil := "crm.delete_all"
	type c struct {
		name string
		ct   string // "" = application/json
		body string
		// reject: must not be forwarded and must be a logged deny. If false the request may be served,
		// but then the smuggling oracle must hold.
		reject bool
	}
	cases := []c{
		// item 1: duplicate and non-lowercase keys, envelope level
		{"dup-method-allowed-then-evil", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call","params":{"name":"` + evil + `"}}`, true},
		{"dup-method-evil-then-list", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","method":"tools/list","params":{"name":"` + evil + `"}}`, true},
		{"dup-params-first-evil", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + evil + `"},"params":{"name":"crm.read_contact"}}`, true},
		{"dup-params-last-evil", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"},"params":{"name":"` + evil + `"}}`, true},
		{"dup-id", "", `{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/call","params":{"name":"crm.read_contact"}}`, true},
		{"dup-jsonrpc", "", `{"jsonrpc":"2.0","jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"}}`, true},
		// item 1: params level
		{"dup-name-allowed-then-evil", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","name":"` + evil + `"}}`, true},
		{"dup-name-evil-then-allowed", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + evil + `","name":"crm.read_contact"}}`, true},
		{"dup-arguments", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{},"arguments":{}}}`, true},
		{"case-Name", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","Name":"` + evil + `"}}`, true},
		{"case-NAME-only", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"NAME":"` + evil + `"}}`, true},
		{"case-Params", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"},"Params":{"name":"` + evil + `"}}`, true},
		{"case-Method", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"` + evil + `"}}`, true},
		{"case-METHOD-only", "", `{"jsonrpc":"2.0","id":1,"METHOD":"tools/call","params":{"name":"` + evil + `"}}`, true},
		{"escaped-key-name", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","name":"` + evil + `"}}`, true},
		{"escaped-key-params", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + evil + `"},"params":{"name":"crm.read_contact"}}`, true},
		{"escaped-key-method", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + evil + `"}}`, true},
		// exact method spelling (P-D4)
		{"method-upper", "", `{"jsonrpc":"2.0","id":1,"method":"TOOLS/CALL","params":{"name":"` + evil + `"}}`, true},
		{"method-mixed", "", `{"jsonrpc":"2.0","id":1,"method":"Tools/Call","params":{"name":"` + evil + `"}}`, true},
		{"method-padded-space", "", `{"jsonrpc":"2.0","id":1,"method":" tools/call","params":{"name":"` + evil + `"}}`, true},
		{"method-padded-trailing", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call ","params":{"name":"` + evil + `"}}`, true},
		{"method-padded-newline", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call\n","params":{"name":"` + evil + `"}}`, true},
		{"method-padded-nul", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call\u0000","params":{"name":"` + evil + `"}}`, true},
		{"method-list-upper", "", `{"jsonrpc":"2.0","id":1,"method":"TOOLS/LIST"}`, true},
		// item 2: batches
		{"batch-one", "", `[` + good + `]`, true},
		{"batch-two-evil", "", `[` + good + `,{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + evil + `"}}]`, true},
		{"batch-empty", "", `[]`, true},
		{"batch-leading-space", "", `
 [` + good + `]`, true},
		{"batch-nested", "", `[[` + good + `]]`, true},
		// item 3: content types
		{"ct-missing", "\x00DEL", good, true},
		{"ct-text-plain", "text/plain", good, true},
		{"ct-form", "application/x-www-form-urlencoded", good, true},
		{"ct-multipart", "multipart/form-data; boundary=x", good, true},
		{"ct-json-suffix", "application/jsonx", good, true},
		{"ct-json-prefix", "xapplication/json", good, true},
		{"ct-vnd-json", "application/vnd.api+json", good, true},
		{"ct-text-json", "text/json", good, true},
		{"ct-utf16", "application/json; charset=utf-16", good, true},
		{"ct-latin1", "application/json; charset=iso-8859-1", good, true},
		{"ct-empty", "", good, false},
		{"ct-two-values", "application/json, text/plain", good, true},
		{"ct-sse", "text/event-stream", good, true},
		// malformed bodies (item 6: any parse failure on a possible tools/call is a logged deny)
		{"empty-body", "", ``, true},
		{"null", "", `null`, true},
		{"number", "", `1`, true},
		{"string", "", `"tools/call"`, true},
		{"truncated", "", good[:len(good)/2], true},
		{"trailing-object", "", good + `{}`, true},
		{"trailing-garbage", "", good + `x`, true},
		{"two-requests-ndjson", "", good + "\n" + good, true},
		{"leading-garbage", "", `x` + good, true},
		{"bom", "", "\xef\xbb\xbf" + good, true},
		{"comment", "", `{/*x*/"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"}}`, true},
		{"trailing-comma", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"},}`, true},
		{"single-quotes", "", `{'jsonrpc':'2.0','id':1,'method':'tools/call','params':{'name':'crm.read_contact'}}`, true},
		{"nan-id", "", `{"jsonrpc":"2.0","id":NaN,"method":"tools/call","params":{"name":"crm.read_contact"}}`, true},
		{"invalid-utf8-name", "", "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"crm.read_contact\xff\"}}", true},
		{"lone-surrogate-name", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact\ud800"}}`, true},
		// params shape on tools/call
		{"params-missing", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call"}`, true},
		{"params-null", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`, true},
		{"params-array", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":["crm.read_contact"]}`, true},
		{"params-string", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":"crm.read_contact"}`, true},
		{"name-missing", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{}}}`, true},
		{"name-null", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":null}}`, true},
		{"name-number", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":5}}`, true},
		{"name-array", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":["crm.read_contact"]}}`, true},
		{"name-object", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":{"a":"crm.read_contact"}}}`, true},
		{"name-empty", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":""}}`, true},
		{"name-evil-plain", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + evil + `"}}`, true},
		{"name-escaped-evil", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.delete_all"}}`, true},
		{"name-escaped-allowed-suffix", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact"}}`, false},
		// arguments carrying look-alike structure must not be mistaken for params
		{"args-contain-name", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"name":"` + evil + `","method":"tools/call"}}}`, false},
		{"args-contain-params", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"params":{"name":"` + evil + `"}}}}`, false},
		{"meta-contains-name", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","_meta":{"name":"` + evil + `"}}}`, false},
		{"name-after-big-arguments", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"arguments":{"a":"` + strings.Repeat("x", 100000) + `"},"name":"crm.read_contact"}}`, false},
		{"deep-nesting", "", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":` + strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}}`, false},
		{"id-string", "", `{"jsonrpc":"2.0","id":"abc","method":"tools/call","params":{"name":"crm.read_contact"}}`, false},
		{"id-null", "", `{"jsonrpc":"2.0","id":null,"method":"tools/call","params":{"name":"crm.read_contact"}}`, false},
		{"id-huge", "", `{"jsonrpc":"2.0","id":123456789012345678901234567890,"method":"tools/call","params":{"name":"crm.read_contact"}}`, false},
		{"no-id-notification-call", "", `{"jsonrpc":"2.0","method":"tools/call","params":{"name":"` + evil + `"}}`, true},
		{"unicode-escape-method-slash", "", `{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"` + evil + `"}}`, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			ct := tc.ct
			if ct == "" && tc.name != "ct-empty" {
				ct = "application/json"
			}
			var hdr []string
			switch tc.ct {
			case "\x00DEL":
				hdr = []string{"Content-Type", "\x00DEL"}
			default:
				if tc.name == "ct-empty" {
					hdr = []string{"Content-Type", "application/json"}
				} else {
					hdr = []string{"Content-Type", ct}
				}
			}
			before := len(r.dl.all())
			rep := r.send("POST", "/", keySales, []byte(tc.body), hdr...)
			recs := r.dl.all()[before:]
			// Always: nothing the policy denies reaches the upstream, under any parser reading.
			r.checkNoSmuggling("sales", mustPolicy(t, 8))
			if tc.reject {
				if r.up.count() != 0 {
					t.Fatalf("a request the proxy cannot read strictly was forwarded: %d %.100s | upstream %.200q", rep.code, rep.body, r.up.requests()[0].Body)
				}
				if rep.code != 400 && rep.code != 413 && rep.code != 415 && !blocked(rep, 8) {
					t.Fatalf("rejection is %d %.100s, want 400/413/415 or the documented block", rep.code, rep.body)
				}
				if len(recs) == 0 {
					t.Fatalf("a rejection left no decision record (doc: every rejection is a logged deny)")
				}
				for _, rec := range recs {
					if rec.Allowed {
						t.Fatalf("allow record for a rejected request: %+v", rec)
					}
				}
				return
			}
			// Not required to be rejected: if served, the record and the forward must agree.
			if r.up.count() > 0 {
				if len(recs) != 1 || !recs[0].Allowed || recs[0].Tool != "crm.read_contact" {
					t.Fatalf("forwarded but record is %+v", recs)
				}
			}
		})
	}
}

// Strict-scan rule: the forwarded bytes are exactly the bytes the proxy inspected (M-D33 item 4).
func TestForwardsExactlyTheInspectedBytes(t *testing.T) {
	bodies := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"q":"a  b"}}}`,
		"{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 7,\n  \"method\": \"tools/call\",\n  \"params\": {\"name\": \"crm.read_contact\", \"arguments\": {}}\n}\n",
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"u":"é😀","n":1.0e5,"big":12345678901234567890}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":9,"method":"ping"}`,
		`{"jsonrpc":"2.0","id":9,"result":{}}`,
	}
	for i, b := range bodies {
		r := newRig(t)
		rep := r.post(keySales, b)
		if rep.code/100 != 2 {
			t.Fatalf("body %d: %d %.100s", i, rep.code, rep.body)
		}
		got := r.up.requests()
		if len(got) != 1 || !bytes.Equal(got[0].Body, []byte(b)) {
			t.Fatalf("body %d: forwarded bytes differ:\n sent %q\n got  %q", i, b, func() []byte {
				if len(got) == 0 {
					return nil
				}
				return got[0].Body
			}())
		}
	}
}

// Request size (M-D31): 1 MiB is allowed, one byte more is 413, chunked included; nothing is forwarded for 413.
func TestBodyCap(t *testing.T) {
	pad := func(total int) []byte {
		head := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"crm.read_contact","arguments":{"p":"`
		tail := `"}}}`
		fill := total - len(head) - len(tail)
		return []byte(head + strings.Repeat("a", fill) + tail)
	}
	r := newRig(t)
	if rep := r.send("POST", "/", keySales, pad(1<<20), "Content-Type", "application/json"); rep.code != 200 {
		t.Errorf("a body of exactly 1 MiB: %d %.100s, want it served", rep.code, rep.body)
	}
	before := r.up.count()
	for name, body := range map[string][]byte{
		"1MiB+1":     pad(1<<20 + 1),
		"2MiB":       pad(2 << 20),
		"16MiB":      pad(16 << 20),
		"only-space": bytes.Repeat([]byte(" "), 1<<20+1),
	} {
		rep := r.send("POST", "/", keySales, body)
		if rep.code != 413 {
			t.Errorf("%s: got %d %.80s, want 413", name, rep.code, rep.body)
		}
	}
	rep := r.send("POST", "/", keySales, pad(2<<20), "Transfer-Encoding", "chunked")
	if rep.code != 413 {
		t.Errorf("chunked 2MiB: got %d, want 413", rep.code)
	}
	if r.up.count() != before {
		t.Errorf("an oversize request reached the upstream")
	}
	for _, rec := range r.dl.all()[1:] {
		if rec.Allowed {
			t.Errorf("allow record for an oversize request: %+v", rec)
		}
	}
	_ = fmt.Sprint
}
