package enforcebreak

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/enforce"
	"kairan/internal/proxy/state"
	"kairan/internal/wire"
)

// ---- authentication (doc step 1) ----

func TestAPIKeyAuthentication(t *testing.T) {
	body := callBody(1, "crm.read_contact", `{}`)
	type c struct {
		name string
		hdr  []string
		code int // 0 = must be served (200)
	}
	cases := []c{
		{"bearer", []string{"Authorization", "Bearer " + keySales}, 0},
		{"x-api-key", []string{"Authorization", "\x00DEL", "X-Api-Key", keySales}, 0},
		{"both-agree", []string{"Authorization", "Bearer " + keySales, "X-Api-Key", keySales}, 0},
		{"both-disagree", []string{"Authorization", "Bearer " + keySales, "X-Api-Key", keyEng}, 401},
		{"both-disagree-wrong-second", []string{"Authorization", "Bearer " + keySales, "X-Api-Key", "nope"}, 401},
		{"both-disagree-wrong-first", []string{"Authorization", "Bearer nope", "X-Api-Key", keySales}, 401},
		{"no-credentials", []string{"Authorization", "\x00DEL"}, 401},
		{"wrong-key", []string{"Authorization", "Bearer nope"}, 401},
		{"key-prefix", []string{"Authorization", "Bearer " + keySales[:len(keySales)-1]}, 401},
		{"key-plus-char", []string{"Authorization", "Bearer " + keySales + "x"}, 401},
		{"key-upper", []string{"Authorization", "Bearer " + strings.ToUpper(keySales)}, 401},
		{"empty-bearer", []string{"Authorization", "Bearer "}, 401},
		{"basic-scheme", []string{"Authorization", "Basic " + keySales}, 401},
		{"raw-key-no-scheme", []string{"Authorization", keySales}, 401},
		{"empty-x-api-key", []string{"Authorization", "\x00DEL", "X-Api-Key", ""}, 401},
		{"key-in-query", []string{"Authorization", "\x00DEL"}, 401},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			path := "/"
			if tc.name == "key-in-query" {
				path = "/?api_key=" + keySales + "&key=" + keySales
			}
			rep := r.send("POST", path, "", []byte(body), tc.hdr...)
			if tc.code == 0 {
				if rep.code != 200 || r.up.count() != 1 {
					t.Fatalf("got %d %.100s (upstream saw %d)", rep.code, rep.body, r.up.count())
				}
				return
			}
			if rep.code != tc.code {
				t.Fatalf("got %d %.100s, want %d", rep.code, rep.body, tc.code)
			}
			if r.up.count() != 0 {
				t.Fatal("an unauthenticated request reached the upstream")
			}
			// Doc: 401 has no role and no decision record.
			if n := len(r.dl.all()); n != 0 {
				t.Fatalf("%d decision records for an unauthenticated request", n)
			}
			if r.met.get("enforce_auth_failed") == 0 {
				t.Errorf("enforce_auth_failed not counted: %v", r.met.names())
			}
		})
	}
}

// Doc: authentication runs before any body is read: a bad key with an oversize or broken body is 401.
func TestAuthBeforeBody(t *testing.T) {
	r := newRig(t)
	for name, body := range map[string][]byte{
		"oversize": []byte(strings.Repeat("a", enforce.MaxBodyBytes+10)),
		"garbage":  []byte("{{{{"),
		"batch":    []byte("[]"),
	} {
		rep := r.send("POST", "/", "wrong", body)
		if rep.code != 401 {
			t.Errorf("%s: got %d, want 401", name, rep.code)
		}
		rep = r.send("POST", "/", "", body, "Content-Type", "text/plain")
		if rep.code != 401 {
			t.Errorf("%s, no key, text/plain: got %d, want 401", name, rep.code)
		}
	}
	if r.up.count() != 0 || len(r.dl.all()) != 0 {
		t.Fatal("unauthenticated traffic left a trace")
	}
}

func TestAPIKeyMapsToExactlyOneRole(t *testing.T) {
	cases := []struct {
		key, tool string
		allow     bool
	}{
		{keySales, "crm.read_contact", true}, {keySales, "crm.update_deal", true}, {keySales, "github.list_repos", false},
		{keyEng, "github.list_repos", true}, {keyEng, "crm.read_contact", false}, {keyEng, "ci.rerun", true},
		{keyIntern, "help.faq", true}, {keyIntern, "crm.update_deal", false}, {keyIntern, "github.list_repos", false},
		{keyGhost, "help.faq", false}, {keyGhost, "crm.read_contact", false}, // role not in the policy
	}
	for _, c := range cases {
		r := newRig(t)
		rep := r.post(c.key, callBody(1, c.tool, `{}`))
		ran := r.up.count() == 1
		if ran != c.allow {
			t.Errorf("%s calls %s: reached upstream=%v, want %v (%d %.100s)", c.key[:9], c.tool, ran, c.allow, rep.code, rep.body)
		}
		if !c.allow && !blocked(rep, 8) {
			t.Errorf("%s calls %s: not the documented block: %d %.120s", c.key[:9], c.tool, rep.code, rep.body)
		}
	}
}

// ---- tools/call decisions (doc step 3) ----

func TestCallDecisionTable(t *testing.T) {
	type c struct {
		role, tool string
		class      policy.Class
		allow      bool
	}
	cases := []c{
		{"sales", "crm.read_contact", 'R', true},
		{"sales", "crm.read_", 'R', true}, // prefix with nothing after it still matches crm.read_*
		{"sales", "crm.update_deal", 'W', true},
		{"sales", "crm.run_report", 'X', true},
		{"sales", "crm.delete_all", 0, false},
		{"sales", "crm.update_deal2", 0, false},
		{"sales", "crm.update", 0, false},
		{"sales", "CRM.read_contact", 0, false},
		{"sales", "crm.READ_contact", 0, false},
		{"sales", "crm.read", 0, false},
		{"sales", "crm.read_contact ", 0, false},
		{"sales", " crm.read_contact", 0, false},
		{"sales", "crm.read_contact\n", 0, false},
		{"sales", "crm.read_contact\x00evil", 0, false},
		{"sales", "crm/read_contact", 0, false},
		{"sales", "crm.read_contact;crm.delete_all", 0, false},
		{"sales", "*", 0, false},
		{"sales", "crm.*", 0, false},
		{"sales", "crm.read_*", 0, false},
		{"sales", "", 0, false},
		{"sales", strings.Repeat("a", 129), 0, false},
		{"sales", "crm.read_" + strings.Repeat("a", 200), 0, false}, // matches the prefix but exceeds 128 chars
		{"sales", "crm.read_é", 0, false},                           // outside the tool alphabet
		{"sales", "crm.read_\u202econtact", 0, false},
		{"sales", "admin.shutdown", 0, false},
		{"engineer", "github.anything_at_all", 'R', true},
		{"engineer", "github.create_issue", 'W', true},
		{"engineer", "github.delete_repo", 'R', true}, // the policy says github.* is R, the proxy follows
		{"engineer", "ci.rerun", 'X', true},
		{"engineer", "ci.rerun2", 0, false},
	}
	for i, c := range cases {
		c := c
		t.Run(fmt.Sprintf("%02d/%s/%q", i, c.role, c.tool), func(t *testing.T) {
			r := newRig(t)
			key := map[string]string{"sales": keySales, "engineer": keyEng}[c.role]
			rep := r.post(key, callBody(i+1, c.tool, `{"x":1}`))
			recs := r.dl.all()
			if len(recs) != 1 {
				t.Fatalf("want exactly one decision record, got %d", len(recs))
			}
			rec := recs[0]
			if rec.Allowed != c.allow {
				t.Fatalf("record says allowed=%v, want %v", rec.Allowed, c.allow)
			}
			if rec.Role != c.role || rec.Version != 8 || rec.Hash != hashN(8) || rec.State != wire.StateEnforcing {
				t.Fatalf("record %+v, want role %s v8 %s enforcing", rec, c.role, hashN(8))
			}
			if c.allow {
				if rep.code != 200 || r.up.count() != 1 || rec.Class != c.class || rec.Tool != c.tool {
					t.Fatalf("allowed call: %d, upstream saw %d, record %+v", rep.code, r.up.count(), rec)
				}
				if !strings.Contains(string(rep.body), "upstream-ran") {
					t.Fatalf("the upstream's answer did not reach the agent: %.100s", rep.body)
				}
				return
			}
			if r.up.count() != 0 {
				t.Fatalf("denied call reached the upstream: %.200q", r.up.requests()[0].Body)
			}
			if !blocked(rep, 8) && rep.code != 400 {
				t.Fatalf("neither the documented deny nor a 400 rejection: %d %.120s", rep.code, rep.body)
			}
			if rep.code == 200 && !strings.Contains(string(rep.body), fmt.Sprintf(`"id":%d`, i+1)) {
				t.Fatalf("the deny does not carry the request id: %.150s", rep.body)
			}
			if rec.Tool != "" && rec.Tool != c.tool {
				t.Fatalf("record tool %q", rec.Tool)
			}
			if c.tool != "" && strings.ContainsAny(c.tool, " \n\x00;é\u202e") && rec.Tool != "" {
				t.Fatalf("a tool name outside the alphabet was logged verbatim: %q (doc: logged as \"\")", rec.Tool)
			}
		})
	}
}

// ---- states (doc step 3/4, ARCH section 4, SafeMode) ----

func TestCallsPerStateAndSafeMode(t *testing.T) {
	type c struct {
		st    wire.ProxyState
		mode  state.SafeMode
		tool  string
		allow bool
	}
	var cases []c
	for _, tool := range []string{"crm.read_contact", "crm.update_deal", "crm.run_report"} {
		cases = append(cases,
			c{wire.StateEnforcing, "", tool, true},
			c{wire.StateEnforcing, state.DenyAll, tool, true}, // the safe-mode option only applies to SafeMode
			c{wire.StateSafeMode, "", tool, tool == "crm.read_contact"},
			c{wire.StateSafeMode, state.ReadOnly, tool, tool == "crm.read_contact"},
			c{wire.StateSafeMode, state.DenyAll, tool, false},
			c{wire.StateSafeMode, "weird-mode", tool, false}, // unknown = deny_all
			c{wire.StateDenyAll, "", tool, false},
			c{wire.StateTampered, "", tool, false},
			c{wire.StateBooting, "", tool, false},
			c{"", "", tool, false},
			c{"enforcing ", "", tool, false},
			c{"ENFORCING", "", tool, false},
			c{"unknown", "", tool, false},
		)
	}
	for _, tc := range cases {
		name := fmt.Sprintf("%s/%s/%s", tc.st, tc.mode, tc.tool)
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(r *rig) {
				r.active = &enforce.Active{Policy: mustPolicy(t, 8), Hash: hashN(8), State: tc.st}
				r.cfg.SafeMode = tc.mode
			})
			rep := r.post(keySales, callBody(1, tc.tool, `{}`))
			if ran := r.up.count() == 1; ran != tc.allow {
				t.Fatalf("reached upstream=%v, want %v (%d %.100s)", ran, tc.allow, rep.code, rep.body)
			}
			recs := r.dl.all()
			if len(recs) != 1 || recs[0].Allowed != tc.allow || (tc.st.Valid() && recs[0].State != tc.st) {
				t.Fatalf("records %+v, want one with allowed=%v state=%s", recs, tc.allow, tc.st)
			}
		})
	}
}

func TestNoPolicyDeniesEverything(t *testing.T) {
	for name, mod := range map[string]func(*rig){
		"holder-never-stored": func(r *rig) { r.active = nil },
		"nil-policy":          func(r *rig) { r.active = &enforce.Active{Policy: nil, Hash: hashN(1), State: wire.StateEnforcing} },
		"zero-policy":         func(r *rig) { r.active = &enforce.Active{Policy: &policy.Policy{}, State: wire.StateEnforcing} },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, mod)
			if name == "holder-never-stored" {
				r.hold.Store(nil)
			}
			for _, k := range []string{keySales, keyEng} {
				before := r.up.count()
				rep := r.post(k, callBody(1, "crm.read_contact", `{}`))
				if r.up.count() != before {
					t.Fatalf("call reached upstream with no policy: %d %.100s", rep.code, rep.body)
				}
				before = r.up.count()
				lrep := r.post(k, listBody(2))
				if names := toolNames(t, lrep); len(names) != 0 {
					t.Fatalf("tools/list with no policy: %v", names)
				}
				if name == "holder-never-stored" && r.up.count() != before {
					t.Fatalf("DenyAll with no policy must not contact the upstream for tools/list")
				}
			}
			for _, rec := range r.dl.all() {
				if rec.Allowed && rec.Tool != "tools/list" {
					t.Fatalf("allow record with no policy: %+v", rec)
				}
			}
		})
	}
}

// Holder.Load before the first Store is nil and means DenyAll.
func TestHolderZeroValue(t *testing.T) {
	var h enforce.Holder
	if h.Load() != nil {
		t.Fatal("Load before Store must be nil")
	}
	a := &enforce.Active{State: wire.StateDenyAll}
	h.Store(a)
	if h.Load() != a {
		t.Fatal("Load does not return the stored pointer")
	}
}

// ---- fail closed: decision log (M-D33 item 3) ----

func TestDecisionLogFailureDeniesAndIsCounted(t *testing.T) {
	r := newRig(t)
	r.dl.err = fmt.Errorf("disk full")
	rep := r.post(keySales, callBody(1, "crm.read_contact", `{}`))
	if r.up.count() != 0 {
		t.Fatalf("a call whose decision could not be stored was forwarded: %d %.100s", rep.code, rep.body)
	}
	if rep.code == 200 && strings.Contains(string(rep.body), "upstream-ran") {
		t.Fatal("agent got the upstream result")
	}
	if r.met.get("enforce_decision_log_errors") == 0 {
		t.Errorf("enforce_decision_log_errors not counted: %v", r.met.names())
	}
	// tools/list is a decision too (Tool "tools/list"): the doc says every decision is recorded.
	r.dl.err = nil
	r.dl.failIf = func(rec enforce.Record) bool { return rec.Tool == "tools/list" }
	lrep := r.post(keySales, listBody(2))
	if names := toolNames(t, lrep); len(names) != 0 && r.met.get("enforce_decision_log_errors") < 2 {
		t.Errorf("tools/list answered with %v although its record failed", names)
	}
}

func TestNilDecisionLogDeniesEverything(t *testing.T) {
	r := newRig(t, func(r *rig) { r.nilLog = true })
	rep := r.post(keySales, callBody(1, "crm.read_contact", `{}`))
	if r.up.count() != 0 {
		t.Fatalf("forwarded with a nil DecisionLog: %d %.100s", rep.code, rep.body)
	}
}

// The record is stored before the call is forwarded (doc: "recorded ... before it is forwarded").
func TestRecordIsWrittenBeforeForwarding(t *testing.T) {
	r := newRig(t)
	r.up.before = func() {
		if len(r.dl.all()) != 1 {
			t.Errorf("upstream received the call but %d decision records exist", len(r.dl.all()))
		}
	}
	r.post(keySales, callBody(1, "crm.read_contact", `{}`))
	if r.up.count() != 1 {
		t.Fatal("not forwarded")
	}
}

// ---- I4 / THREATS #7: no arguments or results in records ----

func TestRecordsHoldNoCallData(t *testing.T) {
	r := newRig(t)
	args := `{"query":"` + canary + `","nested":{"k":["` + canary + `"]}}`
	r.post(keySales, callBody(1, "crm.read_contact", args))
	r.post(keySales, callBody(2, "crm.delete_all", args))
	r.post(keySales, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"`+canary+` x","arguments":`+args+`}}`)
	r.post(keySales, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"crm.read_contact","arguments":`+args+`},"`+canary+`":1}`)
	r.post(keySales, `{"jsonrpc":"2.0","id":5,"method":"`+canary+`"}`)
	r.post(keySales, `{"jsonrpc":"2.0","id":"`+canary+`","method":"tools/list"}`)
	r.send("POST", "/"+canary+"?q="+canary, keySales, []byte(callBody(6, "crm.read_contact", args)), "X-Canary", canary)
	recs := r.dl.all()
	if len(recs) == 0 {
		t.Fatal("no records")
	}
	for _, rec := range recs {
		if s := fmt.Sprintf("%+v", rec); strings.Contains(s, "9f3b27") {
			t.Fatalf("record carries call data: %s", s)
		}
	}
	if len(recs) >= 3 && recs[2].Tool != "" {
		t.Errorf("an invalid tool name was logged as %q, want \"\"", recs[2].Tool)
	}
	for _, n := range r.met.names() {
		if strings.Contains(n, "9f3b27") || strings.ContainsAny(n, " ") {
			t.Errorf("metric name %q carries call data", n)
		}
	}
}

// ---- metrics ----

func TestMetricsCountDecisions(t *testing.T) {
	r := newRig(t)
	r.post(keySales, callBody(1, "crm.read_contact", `{}`))
	r.post(keySales, callBody(2, "crm.delete_all", `{}`))
	r.post(keySales, `[]`)
	r.post("bad", callBody(3, "crm.read_contact", `{}`))
	if r.met.get("enforce_allow") != 1 || r.met.get("enforce_deny") < 1 || r.met.get("enforce_auth_failed") != 1 {
		t.Errorf("counters: %v allow=%d deny=%d auth=%d", r.met.names(), r.met.get("enforce_allow"), r.met.get("enforce_deny"), r.met.get("enforce_auth_failed"))
	}
	if r.met.get("enforce_reject") == 0 && r.met.get("enforce_deny") < 2 {
		t.Errorf("a rejected batch was counted nowhere: %v", r.met.names())
	}
}

// ---- config ----

func TestConfigValidate(t *testing.T) {
	up := newUpstream(t).url()
	ok := enforce.Config{Upstream: up, APIKeys: map[string]string{keySales: "sales"}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a usable config is refused: %v", err)
	}
	bad := map[string]enforce.Config{
		"no-upstream":         {APIKeys: map[string]string{keySales: "sales"}},
		"no-keys":             {Upstream: up},
		"empty-key":           {Upstream: up, APIKeys: map[string]string{"": "sales"}},
		"empty-role":          {Upstream: up, APIKeys: map[string]string{keySales: ""}},
		"unknown-safe-mode":   {Upstream: up, APIKeys: map[string]string{keySales: "sales"}, SafeMode: "wide_open"},
		"negative-timeout":    {Upstream: up, APIKeys: map[string]string{keySales: "sales"}, UpstreamTimeout: -1},
		"upstream-no-host":    {Upstream: mustURL("/just/a/path"), APIKeys: map[string]string{keySales: "sales"}},
		"upstream-bad-scheme": {Upstream: mustURL("file:///etc/passwd"), APIKeys: map[string]string{keySales: "sales"}},
	}
	for name, cfg := range bad {
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted an unusable config", name)
		}
	}
}

// New itself never panics on a bad config and an unusable config denies everything.
func TestUnusableConfigDeniesEverything(t *testing.T) {
	hold := &enforce.Holder{}
	hold.Store(&enforce.Active{Policy: mustPolicy(t, 8), Hash: hashN(8), State: wire.StateEnforcing})
	for name, cfg := range map[string]enforce.Config{
		"zero":        {},
		"no-upstream": {APIKeys: map[string]string{keySales: "sales"}},
		"empty-key":   {APIKeys: map[string]string{"": "sales"}},
	} {
		t.Run(name, func(t *testing.T) {
			dl := &decisionLog{}
			h := enforce.New(cfg, hold, dl, clock.NewReal(), nil)
			for _, key := range []string{"", keySales} {
				req, _ := http.NewRequest("POST", "http://x/", strings.NewReader(callBody(1, "crm.read_contact", `{}`)))
				req.Header.Set("Content-Type", "application/json")
				if key != "" {
					req.Header.Set("Authorization", "Bearer "+key)
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code == 200 && strings.Contains(rec.Body.String(), "upstream-ran") {
					t.Fatalf("an unusable config served a call")
				}
			}
		})
	}
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return u
}
