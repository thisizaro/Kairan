package enforcebreak

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

// ARCH section 3: "tools/list works the same way, except the proxy removes tools the role cannot use."
// Oracle: a tool is listed iff a call to it would be allowed (policy.Visible == Decide).
func TestListShowsExactlyTheCallableTools(t *testing.T) {
	for _, sse := range []bool{false, true} {
		for _, role := range []struct{ key, name string }{{keySales, "sales"}, {keyEng, "engineer"}, {keyIntern, "intern"}, {keyGhost, "ghost"}} {
			t.Run(fmt.Sprintf("sse=%v/%s", sse, role.name), func(t *testing.T) {
				r := newRig(t)
				r.up.sse = sse
				rep := r.post(role.key, listBody(7))
				if rep.code != 200 {
					t.Fatalf("%d %.100s", rep.code, rep.body)
				}
				ct := rep.hdr.Get("Content-Type")
				if sse && !strings.HasPrefix(ct, "text/event-stream") || !sse && !strings.HasPrefix(ct, "application/json") {
					t.Fatalf("content type %q does not match what the upstream used (sse=%v)", ct, sse)
				}
				got := toolNames(t, rep)
				var want []string
				for _, n := range catalog {
					if allowedBy(mustPolicy(t, 8), role.name, n, false) {
						want = append(want, n)
					}
				}
				if strings.Join(got, ",") != strings.Join(want, ",") {
					t.Fatalf("listed %v, want %v (same order as the upstream)", got, want)
				}
				// Anything not allowed must not appear anywhere in the bytes of the answer.
				for _, n := range catalog {
					if !has(want, n) && strings.Contains(string(rep.body), n) {
						t.Errorf("denied tool %q appears in the answer: %.300s", n, rep.body)
					}
				}
				// The id of the request is the id of the answer.
				if !strings.Contains(string(rep.body), `"id":7`) {
					t.Errorf("answer lost the request id: %.200s", rep.body)
				}
			})
		}
	}
}

// Kept tools keep their description and schema (the proxy filters, it does not rewrite what is listed).
func TestListKeepsAllowedToolsIntact(t *testing.T) {
	r := newRig(t)
	rep := r.post(keySales, listBody(1))
	for _, n := range []string{"crm.read_contact", "crm.update_deal"} {
		if !strings.Contains(string(rep.body), "desc of "+n) || !strings.Contains(string(rep.body), `"inputSchema"`) {
			t.Errorf("%s lost its description or schema: %.400s", n, rep.body)
		}
	}
}

func TestListPerState(t *testing.T) {
	type c struct {
		st       wire.ProxyState
		mode     state.SafeMode
		want     []string
		contacts bool // whether the upstream may be contacted
	}
	rOnly := []string{"crm.read_contact", "crm.read_deal"}
	all := []string{"crm.read_contact", "crm.read_deal", "crm.update_deal", "crm.run_report"}
	cases := []c{
		{wire.StateEnforcing, "", all, true},
		{wire.StateSafeMode, "", rOnly, true},
		{wire.StateSafeMode, state.ReadOnly, rOnly, true},
		{wire.StateSafeMode, state.DenyAll, nil, false},
		{wire.StateSafeMode, "bogus", nil, false},
		{wire.StateDenyAll, "", nil, false},
		{wire.StateTampered, "", nil, false},
		{wire.StateBooting, "", nil, false},
		{"", "", nil, false},
		{"Enforcing", "", nil, false},
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/%s", tc.st, tc.mode), func(t *testing.T) {
			r := newRig(t, func(r *rig) {
				r.active = &enforce.Active{Policy: mustPolicy(t, 8), Hash: hashN(8), State: tc.st}
				r.cfg.SafeMode = tc.mode
			})
			rep := r.post(keySales, listBody(1))
			if rep.code != 200 {
				t.Fatalf("%d %.100s", rep.code, rep.body)
			}
			got := toolNames(t, rep)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("listed %v, want %v", got, tc.want)
			}
			if !tc.contacts && r.up.count() != 0 {
				t.Fatalf("the upstream was contacted although the list is empty by rule (doc step 4)")
			}
			recs := r.dl.all()
			if len(recs) != 1 || recs[0].Tool != "tools/list" || recs[0].State != tc.st && tc.st.Valid() {
				t.Fatalf("records %+v, want one tools/list record in state %s", recs, tc.st)
			}
		})
	}
}

// ARCH 5 / M-D33 item 5: a tools/list response that cannot be parsed gives the agent an empty list;
// whatever the upstream sends, no tool the role cannot call may reach the agent.
func TestListHostileUpstreamAnswers(t *testing.T) {
	denied := `crm.delete_all`
	ok := `crm.read_contact`
	tool := func(n string) string { return fmt.Sprintf(`{"name":%q,"description":"d","inputSchema":{}}`, n) }
	jsonrpc := func(result string) string { return `{"jsonrpc":"2.0","id":1,"result":` + result + `}` }
	type c struct {
		name        string
		ct          string
		body        string
		status      int
		mustBeEmpty bool // the answer cannot be parsed: list must be empty
	}
	cases := []c{
		{"not-json", "application/json", `<html>` + denied + `</html>`, 200, true},
		{"empty-body", "application/json", ``, 200, true},
		{"truncated", "application/json", jsonrpc(`{"tools":[` + tool(ok) + `,` + tool(denied))[:70], 200, true},
		{"wrong-content-type-text", "text/plain", jsonrpc(`{"tools":[` + tool(denied) + `]}`), 200, true},
		{"json-with-trailing-garbage", "application/json", jsonrpc(`{"tools":[`+tool(denied)+`]}`) + `garbage`, 200, true},
		{"tools-not-array", "application/json", jsonrpc(`{"tools":{"name":"` + denied + `"}}`), 200, true},
		{"tools-string", "application/json", jsonrpc(`{"tools":"` + denied + `"}`), 200, true},
		{"tools-null", "application/json", jsonrpc(`{"tools":null}`), 200, true},
		{"tool-entries-not-objects", "application/json", jsonrpc(`{"tools":["` + denied + `",5,null,["` + denied + `"]]}`), 200, true},
		{"tool-without-name", "application/json", jsonrpc(`{"tools":[{"description":"` + denied + `"}]}`), 200, true},
		{"tool-name-number", "application/json", jsonrpc(`{"tools":[{"name":5}]}`), 200, true},
		{"tool-name-empty", "application/json", jsonrpc(`{"tools":[{"name":""}]}`), 200, true},
		{"upstream-500-with-tools", "application/json", jsonrpc(`{"tools":[` + tool(denied) + `]}`), 500, false},
		{"upstream-404", "application/json", `{"error":"` + denied + `"}`, 404, false},
		{"batch-response", "application/json", `[` + jsonrpc(`{"tools":[`+tool(denied)+`]}`) + `]`, 200, true},
		{"result-array", "application/json", jsonrpc(`[` + tool(denied) + `]`), 200, true},
		{"dup-tools-key-denied-last", "application/json", jsonrpc(`{"tools":[` + tool(ok) + `],"tools":[` + tool(denied) + `]}`), 200, false},
		{"dup-tools-key-denied-first", "application/json", jsonrpc(`{"tools":[` + tool(denied) + `],"tools":[` + tool(ok) + `]}`), 200, false},
		{"case-variant-Tools", "application/json", jsonrpc(`{"Tools":[` + tool(denied) + `],"tools":[` + tool(ok) + `]}`), 200, false},
		{"case-variant-Name", "application/json", jsonrpc(`{"tools":[{"Name":"` + denied + `","name":"` + ok + `"}]}`), 200, false},
		{"dup-name-in-tool", "application/json", jsonrpc(`{"tools":[{"name":"` + ok + `","name":"` + denied + `"}]}`), 200, false},
		{"denied-in-meta", "application/json", jsonrpc(`{"tools":[` + tool(ok) + `],"_meta":{"tools":[` + tool(denied) + `]},"nextCursor":"` + denied + `"}`), 200, false},
		{"denied-name-escaped", "application/json", jsonrpc(`{"tools":[{"name":"crm.delete_all"}]}`), 200, false},
		{"denied-name-with-padding", "application/json", jsonrpc(`{"tools":[{"name":"crm.delete_all "}]}`), 200, false},
		{"jsonrpc-error", "application/json", `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"` + denied + `","data":{"tools":[` + tool(denied) + `]}}}`, 200, false},
		{"sse-denied-in-first-event", "text/event-stream", "event: message\ndata: " + jsonrpc(`{"tools":[`+tool(denied)+`]}`) + "\n\nevent: message\ndata: " + jsonrpc(`{"tools":[`+tool(ok)+`]}`) + "\n\n", 200, false},
		{"sse-notification-lists-denied", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"data\":\"" + denied + "\"}}\n\ndata: " + jsonrpc(`{"tools":[`+tool(ok)+`]}`) + "\n\n", 200, false},
		{"sse-multiline-data", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"id\":1,\n data: \"result\":{\"tools\":[" + tool(denied) + "]}}\n\n", 200, false},
		{"sse-crlf", "text/event-stream", "event: message\r\ndata: " + jsonrpc(`{"tools":[`+tool(denied)+`,`+tool(ok)+`]}`) + "\r\n\r\n", 200, false},
		{"sse-comment-and-retry", "text/event-stream", ": " + denied + "\nretry: 10\nid: 7\ndata: " + jsonrpc(`{"tools":[`+tool(ok)+`]}`) + "\n\n", 200, false},
		{"sse-no-data", "text/event-stream", "event: message\n\n", 200, true},
		{"sse-garbage-data", "text/event-stream", "data: not json " + denied + "\n\n", 200, true},
		{"sse-two-responses", "text/event-stream", "data: " + jsonrpc(`{"tools":[`+tool(ok)+`]}`) + "\n\ndata: " + jsonrpc(`{"tools":[`+tool(denied)+`]}`) + "\n\n", 200, false},
		{"sse-unterminated", "text/event-stream", "data: " + jsonrpc(`{"tools":[`+tool(denied)+`,`+tool(ok)+`]}`), 200, false},
		{"ct-json-charset", "application/json; charset=utf-8", jsonrpc(`{"tools":[` + tool(denied) + `,` + tool(ok) + `]}`), 200, false},
		{"ct-json-upper", "Application/JSON", jsonrpc(`{"tools":[` + tool(denied) + `,` + tool(ok) + `]}`), 200, false},
		{"ct-missing", "", jsonrpc(`{"tools":[` + tool(denied) + `,` + tool(ok) + `]}`), 200, false},
		{"ct-sse-with-params", "text/event-stream; charset=utf-8", "data: " + jsonrpc(`{"tools":[`+tool(denied)+`,`+tool(ok)+`]}`) + "\n\n", 200, false},
		{"gzip-marked-plain", "application/json", jsonrpc(`{"tools":[` + tool(denied) + `]}`), 200, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
				if tc.ct != "" {
					w.Header().Set("Content-Type", tc.ct)
				} else {
					w.Header()["Content-Type"] = nil
				}
				if tc.name == "gzip-marked-plain" {
					w.Header().Set("Content-Encoding", "gzip")
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}
			rep := r.post(keySales, listBody(1))
			// The one hard rule: the denied tool name must not reach the agent in any form.
			// Upstream-owned side fields (_meta, nextCursor, JSON-RPC error text, notifications) pass through by
			// design (P-D4); for those cases only the tool lists are judged.
			lenient := tc.name == "denied-in-meta" || tc.name == "jsonrpc-error" || tc.name == "sse-notification-lists-denied"
			if !lenient && strings.Contains(string(rep.body), denied) {
				t.Fatalf("a tool the role cannot call reached the agent: %d %.300s", rep.code, rep.body)
			}
			if rep.code == 200 {
				var names []string
				func() {
					defer func() { _ = recover() }()
					names = toolNames(t, rep)
				}()
				for _, n := range names {
					if !allowedBy(mustPolicy(t, 8), "sales", n, false) {
						t.Fatalf("listed %q, which sales cannot call", n)
					}
				}
				if tc.mustBeEmpty && len(names) != 0 {
					t.Fatalf("an unreadable answer produced a non-empty list %v: %.200s", names, rep.body)
				}
			}
		})
	}
}

// The rebuilt answer is for the right request: ids of every JSON-RPC shape round-trip, and a response with
// another id is not taken for ours (M-D33 item 5, P-D4: "first response with the request id").
func TestListIDsRoundTrip(t *testing.T) {
	for _, id := range []string{`1`, `0`, `-5`, `"abc"`, `"a\"b"`, `null`, `12345678901234567890`, `1.5`, `"é"`} {
		t.Run(id, func(t *testing.T) {
			r := newRig(t)
			rep := r.post(keySales, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/list"}`)
			if rep.code != 200 {
				t.Fatalf("%d %.100s", rep.code, rep.body)
			}
			if !strings.Contains(string(rep.body), `"id":`+id) && !(id == `"é"` && strings.Contains(string(rep.body), `é`)) {
				t.Fatalf("id %s lost: %.200s", id, rep.body)
			}
			for _, n := range toolNames(t, rep) {
				if !allowedBy(mustPolicy(t, 8), "sales", n, false) {
					t.Fatalf("listed %q", n)
				}
			}
		})
	}
	// An upstream answering with someone else's response id must not leak its tools.
	r := newRig(t)
	r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":999,"result":{"tools":%s}}`, toolsJSON(catalog))
	}
	rep := r.post(keySales, listBody(1))
	for _, n := range toolNames(t, rep) {
		if !allowedBy(mustPolicy(t, 8), "sales", n, false) {
			t.Fatalf("listed %q from a response with another id", n)
		}
	}
}

// Params on tools/list (pagination cursor) are forwarded and do not change the filtering.
func TestListWithCursorStillFiltered(t *testing.T) {
	r := newRig(t)
	rep := r.post(keyIntern, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"cursor":"abc"}}`)
	for _, n := range toolNames(t, rep) {
		if !allowedBy(mustPolicy(t, 8), "intern", n, false) {
			t.Fatalf("listed %q for intern", n)
		}
	}
	if r.up.count() != 1 {
		t.Fatalf("upstream saw %d requests", r.up.count())
	}
	// A big catalog: 5000 tools, only the allowed ones come back.
	r2 := newRig(t)
	var names []string
	for i := 0; i < 5000; i++ {
		names = append(names, fmt.Sprintf("crm.read_item%d", i), fmt.Sprintf("crm.drop_%d", i))
	}
	r2.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":%s}}`, toolsJSON(names))
	}
	rep = r2.post(keySales, listBody(1))
	got := toolNames(t, rep)
	if len(got) != 5000 {
		t.Fatalf("listed %d of 5000 allowed tools", len(got))
	}
	for _, n := range got {
		if strings.HasPrefix(n, "crm.drop_") {
			t.Fatalf("listed %q", n)
		}
	}
}
