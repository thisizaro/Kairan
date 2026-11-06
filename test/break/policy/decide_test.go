package policybreak

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/policy"
)

// Attack tests for Decide / Visible (task T-02). Sources: ARCHITECTURE 10.0
// (matching rule), M-D32 (exact > longest prefix > deny, byte-exact), M-D33
// (safe mode read_only = R only), T-D2 (invalid tool names are denied), I3.

func parseRoles(t testing.TB, roles string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(pl{roles: roles}.String()))
	if err != nil {
		t.Fatalf("setup policy rejected: %v (%s)", err, roles)
	}
	return p
}

func TestDecidePrecedence(t *testing.T) {
	p := parseRoles(t, `{
	  "r": {
	    "a.*": "R", "a.b.*": "X", "a.b.c": "W", "a.b.cd*": "R",
	    "crm.*": "R", "crm.export": "X", "crm.read_*": "W",
	    "z": "R", "zz*": "W", "zzz": "X"
	  },
	  "other": {"a.*": "X"}
	}`)
	type row struct {
		tool       string
		allowed    bool
		class      policy.Class
		rule       string
		safeAllowd bool
		ref        string
	}
	rows := []row{
		{"a.q", true, 'R', "a.*", true, "prefix"},
		{"a.b.q", true, 'X', "a.b.*", false, "longest prefix beats shorter"},
		{"a.b.c", true, 'W', "a.b.c", false, "exact beats any prefix"},
		{"a.b.cd", true, 'R', "a.b.cd*", true, "longest of three prefixes"},
		{"a.b.cdx", true, 'R', "a.b.cd*", true, "longest prefix"},
		{"a.b.cx", true, 'X', "a.b.*", false, "falls to shorter prefix, not to exact-sibling"},
		{"crm.export", true, 'X', "crm.export", false, "M-D32/I3: exact X wins over prefix R; safe mode must NOT fall back to crm.* R"},
		{"crm.read_x", true, 'W', "crm.read_*", false, "longer prefix W beats crm.* R; safe mode denies"},
		{"crm.other", true, 'R', "crm.*", true, "prefix"},
		{"z", true, 'R', "z", true, "exact"},
		{"zz", true, 'W', "zz*", false, "prefix 'zz' matches 'zz'? (prefix semantics)"},
		{"zzz", true, 'X', "zzz", false, "exact beats zz*"},
		{"zzzz", true, 'W', "zz*", false, "prefix"},
		{"A.q", false, 0, "", false, "case-sensitive"},
		{"a", false, 0, "", false, "shorter than any prefix 'a.' and no exact"},
		{"b.q", false, 0, "", false, "no match = deny"},
		{"crm", false, 0, "", false, "prefix 'crm.' not matched by 'crm'"},
		{"CRM.export", false, 0, "", false, "case-sensitive"},
		{"crm.EXPORT", true, 'R', "crm.*", true, "case differs from exact, falls to prefix"},
	}
	for _, r := range rows {
		r := r
		t.Run(r.tool, func(t *testing.T) {
			if r.tool == "zz" {
				// Whether prefix "zz" matches tool "zz" itself is not spelled out; only require Visible/Decide agree.
				d := p.Decide("r", "zz", false)
				if got := p.Visible("r", []string{"zz"}, false); (len(got) == 1) != d.Allowed {
					t.Fatalf("Visible/Decide disagree on zz")
				}
				return
			}
			d := p.Decide("r", r.tool, false)
			if d.Allowed != r.allowed || d.Class != r.class || d.Rule != r.rule {
				t.Fatalf("%s: Decide = %+v, want allowed=%v class=%c rule=%q", r.ref, d, r.allowed, r.class, r.rule)
			}
			s := p.Decide("r", r.tool, true)
			if s.Allowed != r.safeAllowd {
				t.Fatalf("%s: safe-mode Allowed=%v, want %v (%+v)", r.ref, s.Allowed, r.safeAllowd, s)
			}
			if s.Class != d.Class || s.Rule != d.Rule {
				t.Fatalf("safe mode must report the same matched rule: %+v vs %+v", s, d)
			}
		})
	}
	// No-match decision is the zero Decision.
	if d := p.Decide("r", "nope", false); d != (policy.Decision{}) {
		t.Fatalf("no match: %+v, want zero", d)
	}
	// Roles do not leak into each other.
	if d := p.Decide("other", "crm.export", false); d.Allowed {
		t.Fatalf("role 'other' got crm.export: %+v", d)
	}
	if d := p.Decide("other", "a.b.c", false); !d.Allowed || d.Class != 'X' || d.Rule != "a.*" {
		t.Fatalf("role other a.*: %+v", d)
	}
}

func TestDecideUnknownRolesAndNames(t *testing.T) {
	p := parseRoles(t, `{"sales":{"crm.read_*":"R","crm.update":"W"}}`)
	for _, role := range []string{"", "Sales", "SALES", "sales ", " sales", "sales\x00", "sale", "sales2", "sales\n", "sаles" /* cyrillic а */, "*", "sales*", strings.Repeat("s", 100000)} {
		for _, safe := range []bool{false, true} {
			if d := p.Decide(role, "crm.read_x", safe); d.Allowed || d != (policy.Decision{}) {
				t.Fatalf("role %q safe=%v: %+v, want denied zero Decision (I3)", abbrev(role), safe, d)
			}
		}
		if got := p.Visible(role, []string{"crm.read_x", "crm.update"}, false); got == nil || len(got) != 0 {
			t.Fatalf("role %q: Visible = %v, want empty non-nil", abbrev(role), got)
		}
	}
	if !p.Decide("sales", "crm.read_x", false).Allowed {
		t.Fatal("sanity: sales should be allowed")
	}
}

func abbrev(s string) string {
	if len(s) > 30 {
		return s[:30] + "..."
	}
	return s
}

// T-D2: tool names outside 1-128 of [A-Za-z0-9_.-] are denied before matching.
func TestDecideInvalidToolNames(t *testing.T) {
	p := parseRoles(t, `{"r":{"crm.read_*":"R","crm.*":"R","a":"R","a*":"R","`+strings.Repeat("l", 128)+`":"R"}}`)
	long128 := strings.Repeat("l", 128)
	bad := []string{
		"", " ", "crm.read_x ", " crm.read_x", "crm.read_x\n", "crm.read_x\x00", "crm.read\x00_x", "crm.read x",
		"crm.read_*", // the pattern text itself must not be callable
		"crm.*",      // same
		"*", "a*", "a/b", "a:b", "a\\b", "a\tb", "a b",
		"crm.read_х", // cyrillic x
		"crm.reаd_x", // cyrillic a
		"crm．read_x", // fullwidth full stop
		"ａ",          // fullwidth a
		"crm.read_é", "crm.read_日本", "crm.read_\u200b", "crm.read_\u202e", "crm.read_\ufeff",
		"crm.read_%2e", "crm.read_\xff", "crm.read_\xc0\xaf",
		"a" + strings.Repeat("l", 128), // 129 chars
		strings.Repeat("a", 129),
		strings.Repeat("a", 1<<20),
		long128 + "x",
	}
	for _, name := range bad {
		for _, safe := range []bool{false, true} {
			d := p.Decide("r", name, safe)
			if d.Allowed || d != (policy.Decision{}) {
				t.Fatalf("invalid tool name %q (len %d) safe=%v: %+v, want denied zero Decision", abbrev(name), len(name), safe, d)
			}
		}
		if v := p.Visible("r", []string{name}, false); len(v) != 0 {
			t.Fatalf("Visible shows invalid tool name %q", abbrev(name))
		}
	}
	// Boundary: exactly 128 and 1 are fine.
	if d := p.Decide("r", long128, false); !d.Allowed || d.Rule != long128 {
		t.Fatalf("128-char exact tool: %+v", d)
	}
	if d := p.Decide("r", "a", false); !d.Allowed || d.Rule != "a" {
		t.Fatalf("1-char exact tool: %+v", d)
	}
	// Every character of the alphabet is accepted; every other ASCII byte is not.
	q := parseRoles(t, `{"r":{"x*":"R"}}`)
	for b := 0; b < 256; b++ {
		name := "x" + string([]byte{byte(b)})
		ok := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '.' || b == '-'
		if got := q.Decide("r", name, false).Allowed; got != ok {
			t.Fatalf("byte 0x%02x in tool name: allowed=%v, want %v", b, got, ok)
		}
	}
}

func TestSafeModeReadOnlyNeverWider(t *testing.T) {
	p := parseRoles(t, `{"r":{"r.*":"R","w.*":"W","x.*":"X","r.w":"W","w.r":"R","x.r":"R","x.w":"W"}}`)
	for _, c := range []struct {
		tool         string
		normal, safe bool
	}{
		{"r.a", true, true}, {"w.a", true, false}, {"x.a", true, false},
		{"r.w", true, false}, // exact W under an R prefix
		{"w.r", true, true},  // exact R under a W prefix
		{"x.r", true, true}, {"x.w", true, false}, {"q", false, false},
	} {
		n, s := p.Decide("r", c.tool, false), p.Decide("r", c.tool, true)
		if n.Allowed != c.normal || s.Allowed != c.safe {
			t.Fatalf("%s: normal=%v safe=%v, want %v/%v", c.tool, n.Allowed, s.Allowed, c.normal, c.safe)
		}
		if s.Allowed && !n.Allowed {
			t.Fatalf("%s: safe mode wider than normal (I3)", c.tool)
		}
		if s.Allowed && s.Class != policy.ClassR {
			t.Fatalf("%s: safe mode allowed class %c", c.tool, s.Class)
		}
	}
	vis := p.Visible("r", []string{"r.a", "w.a", "x.a", "r.w", "w.r", "q"}, true)
	if strings.Join(vis, ",") != "r.a,w.r" {
		t.Fatalf("safe-mode Visible = %v", vis)
	}
}

// A reference model of the section 10.0 matching rule; Decide must equal it on
// random policies and tool names (property test).
type model struct{ roles map[string]map[string]byte }

func (m model) decide(role, tool string, safe bool) (bool, byte, string) {
	n := len(tool)
	if n < 1 || n > 128 {
		return false, 0, ""
	}
	for i := 0; i < n; i++ {
		c := tool[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false, 0, ""
		}
	}
	r, ok := m.roles[role]
	if !ok {
		return false, 0, ""
	}
	if c, ok := r[tool]; ok {
		return !safe || c == 'R', c, tool
	}
	best := ""
	var bc byte
	found := false
	for pat, c := range r {
		if strings.HasSuffix(pat, "*") {
			pre := pat[:len(pat)-1]
			if strings.HasPrefix(tool, pre) && (!found || len(pat) > len(best)) {
				best, bc, found = pat, c, true
			}
		}
	}
	if !found {
		return false, 0, ""
	}
	return !safe || bc == 'R', bc, best
}

func TestDecideMatchesReferenceModel(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	alpha := []string{"a", "b", "a.", ".", "_", "-", "x", "A", "0"}
	rname := func(max int) string {
		var b strings.Builder
		for i, n := 0, 1+rng.Intn(max); i < n; i++ {
			b.WriteString(alpha[rng.Intn(len(alpha))])
		}
		return b.String()
	}
	for iter := 0; iter < 400; iter++ {
		m := model{roles: map[string]map[string]byte{}}
		nroles := 1 + rng.Intn(3)
		var rolesJSON []string
		var names []string
		for ri := 0; ri < nroles; ri++ {
			role := fmt.Sprintf("role-%d", ri)
			m.roles[role] = map[string]byte{}
			var entries []string
			for pi, np := 0, 1+rng.Intn(12); pi < np; pi++ {
				pat := rname(5)
				if rng.Intn(2) == 0 {
					pat += "*"
				}
				if _, dup := m.roles[role][pat]; dup {
					continue
				}
				c := "RWX"[rng.Intn(3)]
				m.roles[role][pat] = c
				entries = append(entries, fmt.Sprintf("%q:%q", pat, string(c)))
				names = append(names, strings.TrimSuffix(pat, "*"))
			}
			rolesJSON = append(rolesJSON, fmt.Sprintf("%q:{%s}", role, strings.Join(entries, ",")))
		}
		p, err := policy.Parse([]byte(pl{roles: "{" + strings.Join(rolesJSON, ",") + "}"}.String()))
		if err != nil {
			t.Fatalf("iter %d: generated policy rejected: %v", iter, err)
		}
		var tools []string
		for i := 0; i < 60; i++ {
			var tool string
			switch rng.Intn(3) {
			case 0:
				tool = rname(7)
			case 1:
				tool = names[rng.Intn(len(names))] + rname(3)
			default:
				tool = names[rng.Intn(len(names))]
			}
			if tool == "" {
				continue
			}
			tools = append(tools, tool)
			for role := range m.roles {
				for _, safe := range []bool{false, true} {
					wa, wc, wr := m.decide(role, tool, safe)
					d := p.Decide(role, tool, safe)
					if d.Allowed != wa || byte(d.Class) != wc || d.Rule != wr {
						t.Fatalf("iter %d role %s tool %q safe=%v: Decide=%+v, model allowed=%v class=%c rule=%q\npolicy roles: %v",
							iter, role, tool, safe, d, wa, wc, wr, m.roles[role])
					}
				}
			}
		}
		// Visible == filter of Decide, order and duplicates kept.
		for role := range m.roles {
			for _, safe := range []bool{false, true} {
				got := p.Visible(role, tools, safe)
				var want []string
				for _, tl := range tools {
					if p.Decide(role, tl, safe).Allowed {
						want = append(want, tl)
					}
				}
				if strings.Join(got, "\x00") != strings.Join(want, "\x00") || len(got) != len(want) {
					t.Fatalf("iter %d: Visible(%s,safe=%v)=%v, Decide filter=%v", iter, role, safe, got, want)
				}
			}
		}
	}
}

func TestVisibleContract(t *testing.T) {
	p := parseRoles(t, `{"r":{"a.*":"R","b":"W","c.*":"X"}}`)
	in := []string{"c.z", "a.1", "nope", "a.1", "b", "bad name", "", "c.y", "a.2"}
	orig := append([]string(nil), in...)
	got := p.Visible("r", in, false)
	want := []string{"c.z", "a.1", "a.1", "b", "c.y", "a.2"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("Visible = %v, want %v (order and duplicates kept)", got, want)
	}
	if strings.Join(in, ",") != strings.Join(orig, ",") {
		t.Fatal("Visible modified its input")
	}
	// New slice: scribbling on the result must not touch the input.
	for i := range got {
		got[i] = "HACKED"
	}
	if strings.Join(in, ",") != strings.Join(orig, ",") {
		t.Fatal("Visible result aliases its input")
	}
	// Spare capacity must not let append write into the input.
	g2 := p.Visible("r", in, false)
	_ = append(g2[:0], "X")
	if strings.Join(in, ",") != strings.Join(orig, ",") {
		t.Fatal("Visible result shares backing array with input")
	}
	// Never nil, even for nil/empty input and when nothing is visible.
	for name, ins := range map[string][]string{"nil": nil, "empty": {}, "none": {"x", "y"}} {
		if v := p.Visible("r", ins, false); v == nil || len(v) != 0 {
			t.Fatalf("%s input: Visible = %#v, want empty non-nil", name, v)
		}
	}
	if v := p.Visible("r", []string{"a.1", "b"}, true); strings.Join(v, ",") != "a.1" {
		t.Fatalf("safe mode Visible = %v, want a.1 only", v)
	}
}

func TestNilAndZeroPolicyDenyEverything(t *testing.T) {
	var np *policy.Policy
	zero := &policy.Policy{}
	for name, p := range map[string]*policy.Policy{"nil": np, "zero": zero} {
		p := p
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("PANIC: %v", r)
				}
			}()
			for _, safe := range []bool{false, true} {
				if d := p.Decide("r", "a", safe); d != (policy.Decision{}) {
					t.Fatalf("Decide = %+v, want denied", d)
				}
				if v := p.Visible("r", []string{"a", "b"}, safe); v == nil || len(v) != 0 {
					t.Fatalf("Visible = %#v, want empty non-nil", v)
				}
			}
			if s := p.Render(); s == "" {
				t.Fatal("Render of nil/zero policy should be a short notice")
			}
		})
	}
}

// Safe-mode decisions use only the matched rule; the empty role map, empty
// policies and rule-less roles deny all.
func TestEmptyPoliciesDenyAll(t *testing.T) {
	for _, roles := range []string{`{}`, `{"r":{}}`} {
		p := parseRoles(t, roles)
		for _, tool := range []string{"a", "x.y", "crm.export"} {
			for _, safe := range []bool{false, true} {
				if d := p.Decide("r", tool, safe); d.Allowed {
					t.Fatalf("roles %s allowed %s", roles, tool)
				}
			}
		}
	}
}

// maxRolesJSON builds a roles object with nRoles roles of nPats patterns each.
func maxRolesJSON(nRoles, nPats int) string {
	var roles []string
	for r := 0; r < nRoles; r++ {
		var ents []string
		for i := 0; i < nPats; i++ {
			c := "RWX"[i%3]
			if i%2 == 0 {
				ents = append(ents, fmt.Sprintf(`"t%d.*":%q`, i, string(c)))
			} else {
				ents = append(ents, fmt.Sprintf(`"t%d.exact":%q`, i, string(c)))
			}
		}
		roles = append(roles, fmt.Sprintf(`"role-%d":{%s}`, r, strings.Join(ents, ",")))
	}
	return "{" + strings.Join(roles, ",") + "}"
}

const payloadCap = 256 << 10 // T-D1

// Limits: the biggest legal policies that fit under the 256 KiB payload cap decide correctly and
// quickly (no quadratic blow-up). Two shapes: every role slot used (MaxRoles roles, as many patterns
// per role as fit) and every pattern slot used (MaxPatterns per role, as many roles as fit).
func TestMaxSizePolicyDecides(t *testing.T) {
	fits := func(roles string) bool { return len(pl{roles: roles}.String()) <= payloadCap }

	// Wide: MaxRoles roles.
	nPats := sort.Search(policy.MaxPatterns, func(n int) bool { return !fits(maxRolesJSON(policy.MaxRoles, n+1)) })
	wide := maxRolesJSON(policy.MaxRoles, nPats)
	if !fits(wide) {
		t.Fatalf("cannot build a %d-role policy under the cap", policy.MaxRoles)
	}
	t.Logf("wide: %d roles x %d patterns, %d bytes", policy.MaxRoles, nPats, len(pl{roles: wide}.String()))
	p := parseRoles(t, wide)
	lastEven := nPats - 1
	if lastEven%2 != 0 {
		lastEven--
	}
	start := time.Now()
	for r := 0; r < policy.MaxRoles; r += 51 {
		role := fmt.Sprintf("role-%d", r)
		d := p.Decide(role, fmt.Sprintf("t%d.zzz", lastEven), false)
		if !d.Allowed || d.Rule != fmt.Sprintf("t%d.*", lastEven) {
			t.Fatalf("%s: %+v", role, d)
		}
	}
	if d := p.Decide(fmt.Sprintf("role-%d", policy.MaxRoles-1), "nomatch.zzz", false); d.Allowed {
		t.Fatalf("a tool no pattern names was allowed: %+v", d)
	}

	// Deep: MaxPatterns patterns per role.
	nRoles := sort.Search(policy.MaxRoles, func(n int) bool { return !fits(maxRolesJSON(n+1, policy.MaxPatterns)) })
	deep := maxRolesJSON(nRoles, policy.MaxPatterns)
	if !fits(deep) {
		t.Fatalf("cannot build a %d-pattern role under the cap", policy.MaxPatterns)
	}
	t.Logf("deep: %d roles x %d patterns, %d bytes", nRoles, policy.MaxPatterns, len(pl{roles: deep}.String()))
	p = parseRoles(t, deep)
	if d := p.Decide(fmt.Sprintf("role-%d", nRoles-1), "t1022.zzz", false); !d.Allowed || d.Rule != "t1022.*" {
		t.Fatalf("%+v", d)
	}
	if d := p.Decide("role-0", "t1023.nope", false); d.Allowed {
		t.Fatalf("t1023.nope must not match t1023.exact: %+v", d)
	}
	if el := time.Since(start); el > 20*time.Second {
		t.Fatalf("max-size decisions took %v", el)
	}
}

func TestDecideConcurrent(t *testing.T) {
	p := parseRoles(t, `{"r":{"a.*":"R","a.b":"W","c.*":"X"},"s":{"c.*":"R"}}`)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if d := p.Decide("r", "a.b", false); !d.Allowed || d.Class != 'W' {
					errs <- "a.b"
					return
				}
				if d := p.Decide("r", "c.z", true); d.Allowed {
					errs <- "safe c.z allowed"
					return
				}
				v := p.Visible("s", []string{"c.1", "a.b"}, true)
				if len(v) != 1 || v[0] != "c.1" {
					errs <- "visible"
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}

// Parse is deterministic and Render is stable; policies parsed from the same
// bytes decide identically (guards against map-iteration dependence).
func TestDecideDeterministicAcrossParses(t *testing.T) {
	roles := `{"r":{"a.*":"R","a.b*":"W","a.b.c":"X","d":"R","d*":"X"}}`
	tools := []string{"a.x", "a.b", "a.bz", "a.b.c", "d", "dd", "e"}
	var first []policy.Decision
	for i := 0; i < 50; i++ {
		p := parseRoles(t, roles)
		var cur []policy.Decision
		for _, tl := range tools {
			cur = append(cur, p.Decide("r", tl, false))
		}
		if first == nil {
			first = cur
			continue
		}
		for j := range cur {
			if cur[j] != first[j] {
				t.Fatalf("parse %d: decision for %s changed: %+v vs %+v", i, tools[j], cur[j], first[j])
			}
		}
	}
	_ = sort.Strings
}

// M-D44 (2): RFC 8259 whitespace after the JSON value is allowed; any other
// trailing byte is malformed. (Interior whitespace is covered elsewhere.)
func TestTrailingWhitespaceRFC8259(t *testing.T) {
	for _, tail := range []string{" ", "\t", "\n", "\r", "\r\n", " \n\t\r ", strings.Repeat(" ", 4096)} {
		p, err := policy.Parse([]byte(validBase + tail))
		if err != nil {
			t.Fatalf("trailing %q rejected: %v (M-D44 allows RFC 8259 whitespace)", tail, err)
		}
		if p.Version != 2 || p.Tenant != "bank-a" {
			t.Fatalf("trailing %q changed the policy", tail)
		}
	}
	for _, tail := range []string{"\x00", "\v", "\f", " ", " ", " ", "\ufeff", "\x1c", "\x85", "x", ",", " ,", "\n{", "}", "0", "//", "/**/", " \x00", "\u180e"} {
		mustReject(t, "tail-"+fmt.Sprintf("%q", tail), "M-D44: only RFC 8259 whitespace may follow the value", validBase+tail)
	}
	// Leading garbage is not whitespace either.
	for _, head := range []string{"\x00", "\v", "\f", " ", "\ufeff"} {
		mustReject(t, "head-"+fmt.Sprintf("%q", head), "leading non-JSON-whitespace", head+validBase)
	}
}

// FuzzDecide: arbitrary role and tool strings against a fixed policy never
// panic, agree with the reference model, and safe mode is never wider (I3).
func FuzzDecide(f *testing.F) {
	roles := map[string]map[string]byte{
		"r": {"a.*": 'R', "a.b": 'W', "a.b.*": 'X', "c": 'R', "c*": 'W', "z-_.": 'X', "Q*": 'R'},
		"s": {"a.*": 'X'},
	}
	var parts []string
	for r, m := range roles {
		var es []string
		for p, c := range m {
			es = append(es, fmt.Sprintf("%q:%q", p, string(c)))
		}
		parts = append(parts, fmt.Sprintf("%q:{%s}", r, strings.Join(es, ",")))
	}
	p, err := policy.Parse([]byte(pl{roles: "{" + strings.Join(parts, ",") + "}"}.String()))
	if err != nil {
		f.Fatal(err)
	}
	m := model{roles: roles}
	for _, s := range []string{"a.b", "a.b.c", "a.", "c", "cc", "z-_.", "Qx", "a.b\x00", "", "r", "日本"} {
		f.Add("r", s)
	}
	f.Fuzz(func(t *testing.T, role, tool string) {
		for _, safe := range []bool{false, true} {
			d := p.Decide(role, tool, safe)
			wa, wc, wr := m.decide(role, tool, safe)
			if d.Allowed != wa || byte(d.Class) != wc || d.Rule != wr {
				t.Fatalf("role %q tool %q safe=%v: %+v vs model %v %c %q", role, tool, safe, d, wa, wc, wr)
			}
		}
		if p.Decide(role, tool, true).Allowed && !p.Decide(role, tool, false).Allowed {
			t.Fatal("safe mode wider than normal")
		}
		v := p.Visible(role, []string{tool}, false)
		if (len(v) == 1) != p.Decide(role, tool, false).Allowed {
			t.Fatal("Visible != Decide")
		}
	})
}
