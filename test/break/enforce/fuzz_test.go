package enforcebreak

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func (u *upstream) reset() {
	u.mu.Lock()
	u.got = nil
	u.mu.Unlock()
}

// FuzzRequestBody sends arbitrary bodies as application/json for the sales role. Invariants: no panic or
// 5xx (the fake upstream is healthy), no forwarded tools/call that the policy denies under any plausible
// upstream reading, every allow record matches a forwarded call, and denied or unreadable input leaves no
// allow record (I3, R-D2).
func FuzzRequestBody(f *testing.F) {
	r := newRig(f)
	p := mustPolicy(f, 8)
	seeds := []string{
		callBody(1, "crm.read_contact", `{}`),
		callBody(1, "crm.delete_all", `{}`),
		listBody(1),
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"x"}}`,
		`[` + callBody(1, "crm.delete_all", `{}`) + `]`,
		`{"method":"tools/call","method":"tools/list"}`,
		`{"method":"tools/call","params":{"name":"crm.delete_all","name":"crm.read_contact"}}`,
		`{"method":"tools/call","params":{"Name":"crm.delete_all"}}`,
		`{"method":"tools/call\u0000","params":{"name":"crm.delete_all"}}`,
		``, `{`, `null`, `"x"`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		r.up.reset()
		before := len(r.dl.all())
		rep := r.send("POST", "/", keySales, body)
		if rep.code == -1 {
			t.Fatalf("transport failure (proxy crashed?): %s", rep.body)
		}
		if rep.code >= 500 && rep.code != 502 && rep.code != 504 {
			t.Fatalf("server error %d for %q: %.200s", rep.code, body, rep.body)
		}
		for _, u := range r.up.requests() {
			if string(u.Body) != string(body) {
				t.Fatalf("forwarded bytes differ from the inspected bytes:\n in  %q\n out %q", body, u.Body)
			}
			for _, rd := range upstreamReadings(u.Body) {
				if strings.EqualFold(strings.TrimSpace(rd[0]), "tools/call") && !allowedBy(p, "sales", rd[1], false) {
					t.Fatalf("SMUGGLED: upstream reading %q of %q is denied for sales", rd, body)
				}
			}
		}
		recs := r.dl.all()[before:]
		allows := 0
		for _, rec := range recs {
			if rec.Allowed && rec.Tool != "tools/list" {
				allows++
				if !allowedBy(p, "sales", rec.Tool, false) {
					t.Fatalf("allow record for a tool the policy denies: %+v", rec)
				}
			}
		}
		if allows > 0 && r.up.count() == 0 {
			t.Fatalf("allow record but nothing was forwarded: %+v", recs)
		}
	})
}

// FuzzListResponse feeds arbitrary upstream answers to a tools/list. Invariant: whatever comes back at
// 200 is valid JSON-RPC (or an event stream of it) and lists only tools sales may call.
func FuzzListResponse(f *testing.F) {
	r := newRig(f)
	p := mustPolicy(f, 8)
	mode := new(string)
	r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {}
	var cur []byte
	r.up.respond = func(w http.ResponseWriter, req *http.Request, body []byte) {
		if strings.HasPrefix(*mode, "sse") {
			w.Header().Set("Content-Type", "text/event-stream")
		} else if *mode == "json" {
			w.Header().Set("Content-Type", "application/json")
		}
		w.Write(cur)
	}
	f.Add("json", []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":`+toolsJSON(catalog)+`}}`))
	f.Add("sse", []byte("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":"+toolsJSON(catalog)+"}}\n\n"))
	f.Add("json", []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"crm.delete_all"}],"tools":[{"name":"crm.read_contact"}]}}`))
	f.Add("none", []byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"crm.delete_all"}]}}`))
	f.Add("sse", []byte("data: x\n\ndata: {\"id\":1}\n\n"))
	f.Fuzz(func(t *testing.T, m string, answer []byte) {
		if m != "json" && m != "sse" && m != "none" {
			return
		}
		*mode, cur = m, answer
		rep := r.post(keySales, listBody(1))
		if rep.code == -1 {
			t.Fatalf("proxy failure: %s", rep.body)
		}
		if rep.code != 200 {
			return
		}
		var names []string
		ok := func() (ok bool) {
			defer func() {
				if recover() != nil {
					ok = false
				}
			}()
			ft := &fakeT{}
			names = toolNames(ft, rep)
			return !ft.failed
		}()
		if !ok {
			t.Fatalf("answer at 200 is not JSON-RPC: %.200q (upstream sent %q as %s)", rep.body, answer, m)
		}
		for _, n := range names {
			if !allowedBy(p, "sales", n, false) {
				t.Fatalf("listed %q, which sales cannot call (upstream sent %q)", n, answer)
			}
		}
	})
}

// fakeT lets toolNames report a parse failure without failing the fuzz iteration directly.
type fakeT struct {
	testing.TB
	failed bool
}

func (f *fakeT) Helper() {}
func (f *fakeT) Fatalf(format string, args ...any) {
	f.failed = true
	panic(fmt.Sprintf(format, args...))
}
