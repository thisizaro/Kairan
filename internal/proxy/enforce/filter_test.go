package enforce

import (
	"encoding/json"
	"strings"
	"testing"
)

func vis(names ...string) func(string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(n string) bool { return set[n] }
}

// toolNames reads the tool names out of a JSON-RPC tools/list response.
func toolNames(t *testing.T, msg []byte) []string {
	t.Helper()
	var m struct {
		ID     json.RawMessage `json:"id"`
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(msg, &m); err != nil {
		t.Fatalf("output is not JSON: %v: %q", err, msg)
	}
	names := []string{}
	for _, tl := range m.Result.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// sseData returns the data payload of every event in an SSE body.
func testEvents(body string) []string {
	var out []string
	for _, ev := range strings.Split(body, "\n\n") {
		var data []string
		for _, line := range strings.Split(ev, "\n") {
			if rest, ok := strings.CutPrefix(line, "data: "); ok {
				data = append(data, rest)
			}
		}
		if len(data) > 0 {
			out = append(out, strings.Join(data, "\n"))
		}
	}
	return out
}

const fiveTools = `[{"name":"notes.read","description":"d","inputSchema":{"type":"object"}},{"name":"crm.read_contact"},{"name":"notes.write"},{"name":"crm.update_deal"},{"name":"crm.export"}]`

func jsonResp(id, tools string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"result":{"tools":` + tools + `}}`
}

func TestFilterListJSON(t *testing.T) {
	v := vis("notes.read", "crm.read_contact")
	tests := []struct {
		name string
		body string
		want []string
	}{
		{"filters to visible, keeps order", jsonResp("1", fiveTools), []string{"notes.read", "crm.read_contact"}},
		{"none visible", jsonResp("1", `[{"name":"crm.export"}]`), []string{}},
		{"empty tools", jsonResp("1", `[]`), []string{}},
		{"tools null", jsonResp("1", `null`), []string{}},
		{"tools not an array", jsonResp("1", `{"name":"notes.read"}`), []string{}},
		{"tool without name dropped", jsonResp("1", `[{"description":"x"},{"name":"notes.read"}]`), []string{"notes.read"}},
		{"tool name not a string dropped", jsonResp("1", `[{"name":5},{"name":["notes.read"]},{"name":"notes.read"}]`), []string{"notes.read"}},
		{"tool not an object dropped", jsonResp("1", `["notes.read",null,3,{"name":"notes.read"}]`), []string{"notes.read"}},
		{"duplicate name key: judged name is the one emitted", jsonResp("1", `[{"name":"notes.read","name":"crm.export"}]`), []string{}},
		{"duplicate name key reversed", jsonResp("1", `[{"name":"crm.export","name":"notes.read"}]`), []string{"notes.read"}},
		{"case variant name key drops the tool", jsonResp("1", `[{"name":"notes.read","Name":"crm.export"}]`), []string{}},
		{"no result at all", `{"jsonrpc":"2.0","id":1}`, []string{}},
		{"not JSON", `<html>hi</html>`, []string{}},
		{"batch of responses", `[` + jsonResp("1", fiveTools) + `]`, []string{}},
		{"wrong id", jsonResp("2", fiveTools), []string{}},
		{"string id vs number id", jsonResp(`"1"`, fiveTools), []string{}},
		{"result is an array", `{"jsonrpc":"2.0","id":1,"result":[]}`, []string{}},
		{"empty body", ``, []string{}},
		{"escaped tool name decodes then is judged", jsonResp("1", `[{"name":"crm\u002eexport"},{"name":"notes\u002eread"}]`), []string{"notes.read"}},
		{"case variant Tools key dropped from result", `{"jsonrpc":"2.0","id":1,"result":{"tools":[],"Tools":[{"name":"crm.export"}]}}`, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, isSSE := filterList(v, json.RawMessage("1"), "application/json", []byte(tc.body))
			if isSSE {
				t.Fatal("JSON in, SSE out")
			}
			got := toolNames(t, out)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("tools = %v, want %v\nout: %s", got, tc.want, out)
			}
			if strings.Contains(string(out), "crm.export") || strings.Contains(string(out), "crm.update_deal") {
				t.Fatalf("hidden tool name present in output: %s", out)
			}
			var m struct {
				ID json.RawMessage `json:"id"`
			}
			if err := json.Unmarshal(out, &m); err != nil || string(m.ID) != "1" {
				t.Fatalf("id: %q err=%v", m.ID, err)
			}
		})
	}
}

func TestFilterListJSONKeepsOtherFields(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":"q","result":{"nextCursor":"c2","_meta":{"a":1},"tools":[{"name":"notes.read","description":"read <b>","inputSchema":{"type":"object","properties":{"n":{"type":"number"}}},"annotations":{"readOnlyHint":true}},{"name":"crm.export"}]}}`
	out, _ := filterList(vis("notes.read"), json.RawMessage(`"q"`), "application/json", []byte(body))
	var m struct {
		JSONRPC string `json:"jsonrpc"`
		Result  struct {
			NextCursor string            `json:"nextCursor"`
			Meta       map[string]any    `json:"_meta"`
			Tools      []json.RawMessage `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m.JSONRPC != "2.0" || m.Result.NextCursor != "c2" || m.Result.Meta["a"] != float64(1) || len(m.Result.Tools) != 1 {
		t.Fatalf("lost fields: %s", out)
	}
	for _, want := range []string{`"readOnlyHint":true`, `"inputSchema"`, `read <b>`} {
		if !strings.Contains(string(m.Result.Tools[0]), want) {
			t.Fatalf("tool lost %s: %s", want, m.Result.Tools[0])
		}
	}
}

func TestFilterListJSONError(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"error":{"code":-32603,"message":"boom"}}`
	out, _ := filterList(vis("notes.read"), json.RawMessage("1"), "application/json", []byte(body))
	var m struct {
		ID    json.RawMessage `json:"id"`
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(out, &m); err != nil || m.Error == nil || m.Error.Code != -32603 || m.Result != nil {
		t.Fatalf("error not forwarded: %s err=%v", out, err)
	}
	// Both result and error is not a response we understand.
	both := `{"jsonrpc":"2.0","id":1,"error":{"code":1,"message":"x"},"result":{"tools":[{"name":"crm.export"}]}}`
	out, _ = filterList(vis("notes.read"), json.RawMessage("1"), "application/json", []byte(both))
	if strings.Contains(string(out), "crm.export") || len(toolNames(t, out)) != 0 {
		t.Fatalf("result+error leaked: %s", out)
	}
}

func event(data string) string { return "event: message\ndata: " + data + "\n\n" }

func TestFilterListSSE(t *testing.T) {
	v := vis("notes.read")
	note := `{"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}`
	tests := []struct {
		name      string
		body      string
		wantNames []string // tools in the (single) response event
		wantOther int      // pass-through events besides the response
	}{
		{"one event", event(jsonResp("1", fiveTools)), []string{"notes.read"}, 0},
		{"crlf line ends", strings.ReplaceAll(event(jsonResp("1", fiveTools)), "\n", "\r\n"), []string{"notes.read"}, 0},
		{"cr line ends", strings.ReplaceAll(event(jsonResp("1", fiveTools)), "\n", "\r"), []string{"notes.read"}, 0},
		{"no space after colon", "data:" + jsonResp("1", fiveTools) + "\n\n", []string{"notes.read"}, 0},
		{"final event without blank line", "data: " + jsonResp("1", fiveTools), []string{"notes.read"}, 0},
		{"BOM", "\xef\xbb\xbf" + event(jsonResp("1", fiveTools)), []string{"notes.read"}, 0},
		{"data over several lines", "data: {\"jsonrpc\":\"2.0\",\"id\":1,\ndata: \"result\":{\"tools\":[{\"name\":\"notes.read\"},{\"name\":\"crm.export\"}]}}\n\n", []string{"notes.read"}, 0},
		{"notification then response", event(note) + event(jsonResp("1", fiveTools)), []string{"notes.read"}, 1},
		{"comment and other fields ignored", ": keepalive\nid: 5\nretry: 10\nevent: x\ndata: " + jsonResp("1", fiveTools) + "\n\n", []string{"notes.read"}, 0},
		{"hostile second response with more tools is dropped", event(jsonResp("1", `[{"name":"notes.read"}]`)) + event(jsonResp("1", fiveTools)), []string{"notes.read"}, 0},
		{"hostile extra response for another id is dropped", event(jsonResp("9", fiveTools)) + event(jsonResp("1", `[{"name":"notes.read"}]`)), []string{"notes.read"}, 0},
		{"hostile tools before the response is dropped", event(jsonResp("7", fiveTools)) + event(jsonResp("1", `[]`)), []string{}, 0},
		{"batch event is dropped", event(`[`+jsonResp("1", fiveTools)+`]`) + event(jsonResp("1", `[{"name":"notes.read"}]`)), []string{"notes.read"}, 0},
		{"message with method AND result is dropped", event(`{"jsonrpc":"2.0","method":"x","id":1,"result":{"tools":[{"name":"crm.export"}]}}`) + event(jsonResp("1", `[{"name":"notes.read"}]`)), []string{"notes.read"}, 0},
		{"garbage event dropped, response kept", "data: not json\n\n" + event(jsonResp("1", fiveTools)), []string{"notes.read"}, 0},
		{"no response at all: empty list", event(note), []string{}, 1},
		{"empty stream: empty list", ``, []string{}, 0},
		{"only unparseable: empty list", "data: <<<\n\n", []string{}, 0},
		{"response with wrong id only: empty list", event(jsonResp("2", fiveTools)), []string{}, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out, isSSE := filterList(v, json.RawMessage("1"), "text/event-stream", []byte(tc.body))
			if !isSSE {
				t.Fatal("SSE in, JSON out")
			}
			if strings.Contains(string(out), "crm.export") || strings.Contains(string(out), "crm.update_deal") {
				t.Fatalf("hidden tool present: %s", out)
			}
			datas := testEvents(string(out))
			if len(datas) != 1+tc.wantOther {
				t.Fatalf("%d events, want %d: %q", len(datas), 1+tc.wantOther, out)
			}
			resp := datas[len(datas)-1] // the response is the last event
			got := toolNames(t, []byte(resp))
			if strings.Join(got, ",") != strings.Join(tc.wantNames, ",") {
				t.Fatalf("tools = %v, want %v\nout: %q", got, tc.wantNames, out)
			}
			if !strings.HasSuffix(string(out), "\n\n") {
				t.Fatalf("event not terminated: %q", out)
			}
			for _, d := range datas {
				if strings.ContainsAny(d, "\n\r") {
					t.Fatalf("data is not one line: %q", d)
				}
			}
		})
	}
}

func TestFilterListUnparseableContentTypes(t *testing.T) {
	for _, ct := range []string{"", "text/html", "application/octet-stream", "text/plain", "application/jsonx", "garbage;;;"} {
		out, isSSE := filterList(vis("notes.read"), json.RawMessage("1"), ct, []byte(jsonResp("1", fiveTools)))
		if isSSE || len(toolNames(t, out)) != 0 || strings.Contains(string(out), "crm.export") {
			t.Fatalf("content type %q: %s", ct, out)
		}
	}
	// Parameters on a known type are fine.
	out, _ := filterList(vis("notes.read"), json.RawMessage("1"), "application/json; charset=utf-8", []byte(jsonResp("1", fiveTools)))
	if got := toolNames(t, out); len(got) != 1 {
		t.Fatalf("charset param: %v", got)
	}
	out, isSSE := filterList(vis("notes.read"), json.RawMessage("1"), "Text/Event-Stream; charset=utf-8", []byte(event(jsonResp("1", fiveTools))))
	if !isSSE || len(toolNames(t, []byte(testEvents(string(out))[0]))) != 1 {
		t.Fatalf("sse with params: %s", out)
	}
}

func FuzzFilterList(f *testing.F) {
	f.Add("application/json", jsonResp("1", fiveTools))
	f.Add("text/event-stream", event(jsonResp("1", fiveTools)))
	f.Add("text/event-stream", "data: [1]\n\ndata: {\"id\":1}\n\n")
	f.Add("application/json", `{"id":1,"result":{"tools":[{"name":"a","name":"crm.export"}]}}`)
	v := vis("notes.read")
	f.Fuzz(func(t *testing.T, ct, body string) {
		out, _ := filterList(v, json.RawMessage("1"), ct, []byte(body))
		// Whatever comes in, whatever goes out names no tool except a visible one.
		var scan func(raw []byte)
		var msgs [][]byte
		if strings.HasPrefix(string(out), "{") {
			msgs = append(msgs, out)
		} else {
			for _, d := range testEvents(string(out)) {
				msgs = append(msgs, []byte(d))
			}
		}
		_ = scan
		for _, m := range msgs {
			var r struct {
				Result struct {
					Tools []struct {
						Name string `json:"name"`
					} `json:"tools"`
				} `json:"result"`
			}
			if err := json.Unmarshal(m, &r); err != nil {
				continue
			}
			for _, tl := range r.Result.Tools {
				if tl.Name != "notes.read" {
					t.Fatalf("tool %q leaked: in=%q out=%q", tl.Name, body, out)
				}
			}
		}
	})
}
