package enforce

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"
)

var methodRE = regexp.MustCompile(`^[A-Za-z0-9_./-]{1,128}$`)

func TestScanRequestAccepted(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		kind     kind
		tool     string
		id       string
		hasParam bool
	}{
		{"call", `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"notes.read","arguments":{"id":1}}}`, kindCall, "notes.read", "7", true},
		{"call string id", `{"jsonrpc":"2.0","id":"a-1","method":"tools/call","params":{"name":"crm.export"}}`, kindCall, "crm.export", `"a-1"`, true},
		{"call null id", `{"id":null,"method":"tools/call","params":{"name":"x"}}`, kindCall, "x", "null", true},
		{"call params before method", `{"params":{"name":"notes.read"},"method":"tools/call","id":1}`, kindCall, "notes.read", "1", true},
		{"call whitespace", " \n\t{ \"id\" : 1 , \"method\" : \"tools/call\" , \"params\" : { \"name\" : \"a\" } }\r\n", kindCall, "a", "1", true},
		{"call mixed-case argument keys allowed", `{"id":1,"method":"tools/call","params":{"name":"a","arguments":{"Method":"tools/list","Name":"b","x":{"X":[1,2.5e3,-0,true,false,null,"s"]}}}}`, kindCall, "a", "1", true},
		{"call with _meta", `{"id":1,"method":"tools/call","params":{"name":"a","_meta":{"progressToken":3}}}`, kindCall, "a", "1", true},
		{"call escaped name value", `{"id":1,"method":"tools/call","params":{"name":"crm\u002eexport"}}`, kindCall, "crm.export", "1", true},
		{"call escaped method value", `{"id":1,"method":"tools\/call","params":{"name":"a"}}`, kindCall, "a", "1", true},
		{"call invalid name still scans", `{"id":1,"method":"tools/call","params":{"name":"../x"}}`, kindCall, "../x", "1", true},
		{"list", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`, kindList, "", "2", false},
		{"list with params", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"abc"}}`, kindList, "", "2", true},
		{"list with empty params", `{"id":2,"method":"tools/list","params":{}}`, kindList, "", "2", true},
		{"initialize camelCase params ok", `{"id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"c"}}}`, kindOther, "", "1", true},
		{"ping", `{"id":1,"method":"ping"}`, kindOther, "", "1", false},
		{"notification", `{"method":"notifications/initialized"}`, kindOther, "", "", false},
		{"client response", `{"jsonrpc":"2.0","id":9,"result":{}}`, kindOther, "", "9", false},
		{"client error response", `{"jsonrpc":"2.0","id":9,"error":{"code":-1,"message":"x"}}`, kindOther, "", "9", false},
		{"unknown method with weird params", `{"id":1,"method":"resources/read","params":{"URI":"x","URI":"y"}}`, kindOther, "", "1", true},
		{"extra lowercase envelope key", `{"id":1,"method":"ping","extra":1}`, kindOther, "", "1", false},
		{"unicode in argument value", "{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"a\",\"arguments\":{\"t\":\"日本語\"}}}", kindCall, "a", "1", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, err := scanRequest([]byte(tc.body))
			if err != nil {
				t.Fatalf("scanRequest: %v", err)
			}
			if env.Kind != tc.kind || env.Tool != tc.tool || string(env.ID) != tc.id {
				t.Fatalf("got kind=%v tool=%q id=%q, want kind=%v tool=%q id=%q", env.Kind, env.Tool, env.ID, tc.kind, tc.tool, tc.id)
			}
		})
	}
}

func TestScanRequestRejected(t *testing.T) {
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	tests := []struct {
		name string
		body string
		want error
	}{
		// R-D2 / M-D33 (1): duplicate and non-lowercase keys.
		{"duplicate method (call then list)", `{"id":1,"method":"tools/call","method":"tools/list","params":{"name":"a"}}`, errDuplicateKey},
		{"duplicate method (list then call)", `{"id":1,"method":"tools/list","method":"tools/call","params":{"name":"a"}}`, errDuplicateKey},
		{"Method capital", `{"method":"tools/call","Method":"tools/list"}`, errBadKey},
		{"METHOD upper", `{"id":1,"METHOD":"tools/call","params":{"name":"a"}}`, errBadKey},
		{"Params capital", `{"id":1,"method":"tools/call","Params":{"name":"a"}}`, errBadKey},
		{"escaped key m", `{"id":1,"\u006dethod":"tools/call","params":{"name":"a"}}`, errBadKey},
		{"escaped key whole", `{"id":1,"\u006d\u0065thod":"tools/call","params":{"name":"a"}}`, errBadKey},
		{"escaped slash in key", `{"id":1,"meth\/od":"x"}`, errBadKey},
		{"unicode fold key (long s in params)", "{\"id\":1,\"method\":\"tools/call\",\"paramſ\":{\"name\":\"a\"}}", errBadKey},
		{"kelvin sign key", "{\"id\":1,\"method\":\"ping\",\"Key\":1}", errBadKey},
		{"duplicate id", `{"id":1,"id":2,"method":"ping"}`, errDuplicateKey},
		{"duplicate escaped vs plain key", `{"id":1,"method":"ping","\u0069d":2}`, errBadKey},
		{"duplicate params key name", `{"id":1,"method":"tools/call","params":{"name":"notes.read","name":"crm.export"}}`, errDuplicateKey},
		{"params Name capital", `{"id":1,"method":"tools/call","params":{"Name":"crm.export","name":"notes.read"}}`, errBadKey},
		{"params escaped name key", `{"id":1,"method":"tools/call","params":{"n\u0061me":"crm.export"}}`, errBadKey},
		{"params duplicate arguments", `{"id":1,"method":"tools/call","params":{"name":"a","arguments":{},"arguments":{}}}`, errDuplicateKey},
		{"list params Cursor", `{"id":1,"method":"tools/list","params":{"Cursor":"x"}}`, errBadKey},
		// Method spelling differentials.
		{"method case variant", `{"id":1,"method":"Tools/Call","params":{"name":"a"}}`, errMethod},
		{"method padded", `{"id":1,"method":" tools/call","params":{"name":"a"}}`, errMethod},
		{"method upper list", `{"id":1,"method":"TOOLS/LIST"}`, errMethod},
		// Q-D17/Q-D18 (M-D55): the method is ^[A-Za-z0-9_./-]{1,128}$, byte-exact.
		{"method NUL prefix", `{"id":1,"method":"\u0000tools/call","params":{"name":"a"}}`, errMethod},
		{"method SOH suffix", `{"id":1,"method":"tools/list\u0001"}`, errMethod},
		{"method ESC", `{"id":1,"method":"\u001btools/list"}`, errMethod},
		{"method US", `{"id":1,"method":"tools/list\u001f"}`, errMethod},
		{"method DEL", `{"id":1,"method":"tools/call\u007f","params":{"name":"a"}}`, errMethod},
		{"method zero-width space", `{"id":1,"method":"tools/call\u200b","params":{"name":"a"}}`, errMethod},
		{"method zero-width joiner", "{\"id\":1,\"method\":\"\u200dtools/call\",\"params\":{\"name\":\"a\"}}", errMethod},
		{"method zero-width non-joiner", `{"id":1,"method":"tools/list\u200c"}`, errMethod},
		{"method BOM", `{"id":1,"method":"\ufefftools/list"}`, errMethod},
		{"method word joiner", `{"id":1,"method":"tools/list\u2060"}`, errMethod},
		{"method RLO", `{"id":1,"method":"\u202etools/list"}`, errMethod},
		{"method non-ASCII other", "{\"id\":1,\"method\":\"ping\u00e9\"}", errMethod},
		{"method non-ASCII lookalike", "{\"id\":1,\"method\":\"tools/call\u0131\",\"params\":{\"name\":\"a\"}}", errMethod},
		{"method empty", `{"id":1,"method":""}`, errMethod},
		{"method space inside", `{"id":1,"method":"ping now"}`, errMethod},
		{"method tab", `{"id":1,"method":"ping\t"}`, errMethod},
		{"method 129 long", `{"id":1,"method":"` + strings.Repeat("a", 129) + `"}`, errMethod},
		{"method dollar", `{"id":1,"method":"$/cancel"}`, errMethod},
		// M-D33 (2): batches.
		{"batch of calls", `[{"id":1,"method":"tools/call","params":{"name":"a"}}]`, errBatch},
		{"batch empty", `[]`, errBatch},
		{"batch with leading space", ` 	[{"id":1,"method":"ping"}]`, errBatch},
		// Syntax.
		{"empty", ``, errSyntax},
		{"only space", `   `, errSyntax},
		{"string", `"tools/call"`, errSyntax},
		{"number", `1`, errSyntax},
		{"null", `null`, errSyntax},
		{"BOM", "\xef\xbb\xbf" + `{"id":1,"method":"ping"}`, errSyntax},
		{"trailing garbage", `{"id":1,"method":"ping"} x`, errSyntax},
		{"two objects", `{"id":1,"method":"ping"}{"id":2,"method":"tools/call","params":{"name":"a"}}`, errSyntax},
		{"truncated", `{"id":1,"method":"tools/call","params":{"name":"a"`, errSyntax},
		{"truncated string", `{"id":1,"method":"tools/ca`, errSyntax},
		{"trailing comma", `{"id":1,"method":"ping",}`, errSyntax},
		{"missing colon", `{"id" 1}`, errSyntax},
		{"single quotes", `{'id':1}`, errSyntax},
		{"unquoted key", `{id:1}`, errSyntax},
		{"raw newline in string", "{\"id\":1,\"method\":\"pi\nng\"}", errSyntax},
		{"bad escape", `{"id":1,"method":"p\qng"}`, errSyntax},
		{"bad unicode escape", `{"id":1,"method":"p\u12g4"}`, errSyntax},
		{"invalid utf8 in value", "{\"id\":1,\"method\":\"ping\",\"x\":\"\xff\"}", errSyntax},
		{"invalid utf8 in method", "{\"id\":1,\"method\":\"pi\xffng\"}", errSyntax},
		{"leading zero number", `{"id":01,"method":"ping"}`, errSyntax},
		{"bad number", `{"id":1.,"method":"ping"}`, errSyntax},
		{"nan", `{"id":NaN,"method":"ping"}`, errSyntax},
		{"too deep", `{"id":1,"method":"ping","x":` + deep + `}`, errSyntax},
		{"NUL byte", "{\"id\":1,\"method\":\"ping\"}\x00", errSyntax},
		// Shape.
		{"no method no result", `{"id":1}`, errMethod},
		{"method not string", `{"id":1,"method":5}`, errShape},
		{"method null", `{"id":1,"method":null}`, errShape},
		{"call without id", `{"method":"tools/call","params":{"name":"a"}}`, errShape},
		{"call with object id", `{"id":{"a":1},"method":"tools/call","params":{"name":"a"}}`, errShape},
		{"call with bool id", `{"id":true,"method":"tools/call","params":{"name":"a"}}`, errShape},
		{"call without params", `{"id":1,"method":"tools/call"}`, errShape},
		{"call params array", `{"id":1,"method":"tools/call","params":["a"]}`, errShape},
		{"call params null", `{"id":1,"method":"tools/call","params":null}`, errShape},
		{"call without name", `{"id":1,"method":"tools/call","params":{"arguments":{}}}`, errShape},
		{"call name number", `{"id":1,"method":"tools/call","params":{"name":5}}`, errShape},
		{"call name null", `{"id":1,"method":"tools/call","params":{"name":null}}`, errShape},
		{"call name object", `{"id":1,"method":"tools/call","params":{"name":{"x":1}}}`, errShape},
		{"list without id", `{"method":"tools/list"}`, errShape},
		{"list params array", `{"id":1,"method":"tools/list","params":[]}`, errShape},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, err := scanRequest([]byte(tc.body))
			if err == nil {
				t.Fatalf("accepted: %+v", env)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "crm.export") || strings.Contains(err.Error(), "notes.read") {
				t.Fatalf("error repeats payload: %v", err)
			}
		})
	}
}

func TestScanRequestAcceptedIsValidJSON(t *testing.T) {
	// Everything the scanner accepts, the standard library accepts too, and agrees on method and tool name.
	bodies := []string{
		`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"notes.read","arguments":{"id":1}}}`,
		`{"id":1,"method":"tools\/call","params":{"name":"crm\u002eexport"}}`,
	}
	for _, b := range bodies {
		env, err := scanRequest([]byte(b))
		if err != nil {
			t.Fatal(err)
		}
		var std struct {
			Method string `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(b), &std); err != nil {
			t.Fatal(err)
		}
		if env.Kind != kindCall || std.Method != "tools/call" || std.Params.Name != env.Tool {
			t.Fatalf("scanner %q vs std %+v", env.Tool, std)
		}
	}
}

func FuzzScanRequest(f *testing.F) {
	seeds := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"notes.read","arguments":{}}}`,
		`{"id":1,"method":"tools/list"}`,
		`{"method":"tools/call","Method":"tools/list"}`,
		`[{"id":1,"method":"tools/call","params":{"name":"a"}}]`,
		`{"id":1,"\u006dethod":"tools/call","params":{"name":"a"}}`,
		`{"id":1,"method":"tools/call","params":{"name":"a","name":"b"}}`,
		`{"id":1,"method":"ping"}`,
		`{"id":"x","method":"initialize","params":{"protocolVersion":"1"}}`,
		"{\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"\xff\"}}",
		`{"id":1,"method":"tools/call","params":{"name":"a","arguments":[1,2,{"k":null}]}}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		env, err := scanRequest(data)
		if err != nil {
			return
		}
		// Accepted input must be valid JSON for the standard library, a single object.
		if !json.Valid(data) {
			t.Fatalf("scanner accepted invalid JSON: %q", data)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("scanner accepted a non-object: %q", data)
		}
		// Every envelope key is exact lowercase ASCII, and the keys are unique (so the map lost nothing).
		var dec = json.NewDecoder(strings.NewReader(string(data)))
		if _, err := dec.Token(); err != nil {
			t.Fatal(err)
		}
		seen := 0
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				t.Fatal(err)
			}
			if ks := k.(string); ks != strings.ToLower(ks) {
				t.Fatalf("non-lowercase envelope key %q accepted: %q", ks, data)
			}
			var skip json.RawMessage
			if err := dec.Decode(&skip); err != nil {
				t.Fatal(err)
			}
			seen++
		}
		if seen != len(top) {
			t.Fatalf("duplicate envelope keys accepted: %q", data)
		}
		// The classification agrees with the standard library's reading of method.
		var m string
		_ = json.Unmarshal(top["method"], &m)
		if _, has := top["method"]; has && !methodRE.MatchString(m) {
			t.Fatalf("method %q outside the charset accepted: %q", m, data)
		}
		switch env.Kind {
		case kindCall:
			var p map[string]json.RawMessage
			if m != "tools/call" || json.Unmarshal(top["params"], &p) != nil {
				t.Fatalf("kindCall but method=%q: %q", m, data)
			}
			var name string
			if json.Unmarshal(p["name"], &name) != nil || name != env.Tool {
				t.Fatalf("tool name differs: scanner %q std %q: %q", env.Tool, name, data)
			}
			if len(p) == 0 {
				t.Fatalf("empty params accepted for a call: %q", data)
			}
		case kindList:
			if m != "tools/list" {
				t.Fatalf("kindList but method=%q: %q", m, data)
			}
		default:
			if m == "tools/call" || m == "tools/list" {
				t.Fatalf("method %q classified as other: %q", m, data)
			}
			if strings.EqualFold(strings.TrimSpace(m), "tools/call") || strings.EqualFold(strings.TrimSpace(m), "tools/list") {
				t.Fatalf("near-miss method %q accepted: %q", m, data)
			}
		}
	})
}

func TestMethodCharset(t *testing.T) {
	for _, m := range []string{"ping", "initialize", "notifications/initialized", "notifications/tools/list_changed", "resources/templates/list", "a", "A-b_c.d/e", strings.Repeat("a", 128)} {
		env, err := scanRequest([]byte(`{"id":1,"method":"` + m + `"}`))
		if err != nil || env.Kind != kindOther {
			t.Errorf("method %q: %+v %v", m, env, err)
		}
	}
}
