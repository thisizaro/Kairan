package policy

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"strings"
	"testing"
)

// mustPolicy builds a policy whose roles are given as role -> pattern -> class.
func mustPolicy(t testing.TB, roles map[string]map[string]string) *Policy {
	t.Helper()
	rb, err := json.Marshal(roles)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse([]byte(good(map[string]string{"roles": string(rb)})))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return p
}

var sampleRoles = map[string]map[string]string{
	"sales": {
		"crm.read_*":      "R",
		"crm.update_deal": "W",
		"crm.read_secret": "X", // exact beats the shorter prefix
		"crm.*":           "W",
		"crm.read_priv*":  "X", // longer prefix beats crm.read_*
	},
	"engineer": {
		"github.*":            "R",
		"github.create_issue": "W",
		"ci.rerun":            "X",
	},
	"empty": {},
}

func TestDecide(t *testing.T) {
	p := mustPolicy(t, sampleRoles)
	tests := []struct {
		name       string
		role, tool string
		safe       bool
		want       Decision
	}{
		{"exact W", "sales", "crm.update_deal", false, Decision{true, ClassW, "crm.update_deal"}},
		{"exact beats every prefix", "sales", "crm.read_secret", false, Decision{true, ClassX, "crm.read_secret"}},
		{"longest prefix wins", "sales", "crm.read_private_notes", false, Decision{true, ClassX, "crm.read_priv*"}},
		{"shorter prefix when longer does not match", "sales", "crm.read_leads", false, Decision{true, ClassR, "crm.read_*"}},
		{"shortest prefix as fallback", "sales", "crm.delete_all", false, Decision{true, ClassW, "crm.*"}},
		{"prefix matches itself with empty tail", "sales", "crm.read_", false, Decision{true, ClassR, "crm.read_*"}},
		{"prefix without its dot-less stem does not match", "sales", "crm", false, Decision{}},
		{"prefix text must match from the start", "sales", "xcrm.read_leads", false, Decision{}},
		{"role isolation", "sales", "github.list_repos", false, Decision{}},
		{"other role", "engineer", "github.list_repos", false, Decision{true, ClassR, "github.*"}},
		{"X rule allows X tool", "engineer", "ci.rerun", false, Decision{true, ClassX, "ci.rerun"}},
		{"unknown role", "admin", "github.list_repos", false, Decision{}},
		{"empty role name", "", "github.list_repos", false, Decision{}},
		{"role names are case-sensitive", "Sales", "crm.update_deal", false, Decision{}},
		{"role with no rules", "empty", "crm.update_deal", false, Decision{}},
		{"unknown tool", "engineer", "shell.exec", false, Decision{}},
		{"empty tool", "engineer", "", false, Decision{}},
		{"tool names are case-sensitive", "engineer", "GitHub.list", false, Decision{}},
		{"exact rule is not a prefix", "engineer", "ci.rerun_all", false, Decision{}},
		{"exact rule is not a prefix of shorter", "engineer", "ci.reru", false, Decision{}},
		{"tool with bad characters is denied even under a prefix", "engineer", "github.é", false, Decision{}},
		{"tool with NUL is denied", "engineer", "github.a\x00b", false, Decision{}},
		{"tool with space is denied", "engineer", "github.a b", false, Decision{}},
		{"tool over 128 bytes is denied", "engineer", "github." + strings.Repeat("a", 122), false, Decision{}},
		{"tool at 128 bytes is allowed", "engineer", "github." + strings.Repeat("a", 121), false, Decision{true, ClassR, "github.*"}},

		// Safe mode (read_only): class R only. The decision still reports the matched rule.
		{"safe R allowed", "engineer", "github.list_repos", true, Decision{true, ClassR, "github.*"}},
		{"safe W blocked", "engineer", "github.create_issue", true, Decision{false, ClassW, "github.create_issue"}},
		{"safe X blocked", "engineer", "ci.rerun", true, Decision{false, ClassX, "ci.rerun"}},
		{"safe no match", "engineer", "shell.exec", true, Decision{}},
		{"safe unknown role", "admin", "github.list_repos", true, Decision{}},
		{"safe longest prefix is X, so blocked", "sales", "crm.read_private_notes", true, Decision{false, ClassX, "crm.read_priv*"}},
		{"safe longest prefix is R, so allowed", "sales", "crm.read_leads", true, Decision{true, ClassR, "crm.read_*"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Decide(tc.role, tc.tool, tc.safe)
			if got != tc.want {
				t.Fatalf("Decide(%q, %q, %v) = %+v, want %+v", tc.role, tc.tool, tc.safe, got, tc.want)
			}
		})
	}
}

// A W or X rule allows the tool in normal mode: the class labels the tool,
// it is not a lower bound on what the role may do (section 10.0).
func TestDecideAnyClassAllowsWhenEnforcing(t *testing.T) {
	p := mustPolicy(t, map[string]map[string]string{"a": {"r": "R", "w": "W", "x": "X"}})
	for _, c := range []struct {
		tool string
		want Class
	}{{"r", ClassR}, {"w", ClassW}, {"x", ClassX}} {
		d := p.Decide("a", c.tool, false)
		if !d.Allowed || d.Class != c.want {
			t.Errorf("%s: %+v", c.tool, d)
		}
		if safe := p.Decide("a", c.tool, true); safe.Allowed != (c.want == ClassR) {
			t.Errorf("%s safe: %+v", c.tool, safe)
		}
	}
}

func TestDecideNilAndZeroPolicyDeny(t *testing.T) {
	var nilP *Policy
	if d := nilP.Decide("a", "b", false); d != (Decision{}) {
		t.Fatalf("nil policy: %+v", d)
	}
	if d := (&Policy{}).Decide("a", "b", false); d != (Decision{}) {
		t.Fatalf("zero policy: %+v", d)
	}
	if v := nilP.Visible("a", []string{"b"}, false); len(v) != 0 {
		t.Fatalf("nil policy visible: %v", v)
	}
}

// An exact rule equal to a prefix rule's stem must win for that name only.
func TestDecideExactEqualToPrefixStem(t *testing.T) {
	p := mustPolicy(t, map[string]map[string]string{"a": {"x.": "W", "x.*": "R"}})
	if d := p.Decide("a", "x.", false); d != (Decision{true, ClassW, "x."}) {
		t.Fatalf("exact: %+v", d)
	}
	if d := p.Decide("a", "x.y", false); d != (Decision{true, ClassR, "x.*"}) {
		t.Fatalf("prefix: %+v", d)
	}
}

func TestVisible(t *testing.T) {
	p := mustPolicy(t, sampleRoles)
	tools := []string{"github.list", "crm.update_deal", "ci.rerun", "github.create_issue", "shell.exec", "crm.read_leads", "github.list"}
	tests := []struct {
		name string
		role string
		safe bool
		want []string
	}{
		{"engineer", "engineer", false, []string{"github.list", "ci.rerun", "github.create_issue", "github.list"}},
		{"engineer safe", "engineer", true, []string{"github.list", "github.list"}},
		{"sales", "sales", false, []string{"crm.update_deal", "crm.read_leads"}},
		{"sales safe", "sales", true, []string{"crm.read_leads"}},
		{"unknown role", "nobody", false, []string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := p.Visible(tc.role, tools, tc.safe)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if got := p.Visible("engineer", nil, false); got == nil || len(got) != 0 {
		t.Fatalf("nil input: want empty non-nil, got %#v", got)
	}
}

func TestVisibleDoesNotModifyInput(t *testing.T) {
	p := mustPolicy(t, sampleRoles)
	in := []string{"shell.exec", "github.list", "ci.rerun"}
	cp := append([]string(nil), in...)
	out := p.Visible("engineer", in, false)
	if !reflect.DeepEqual(in, cp) {
		t.Fatalf("input changed: %v", in)
	}
	if len(out) > 0 {
		out[0] = "mutated"
		if !reflect.DeepEqual(in, cp) {
			t.Fatalf("output aliases input: %v", in)
		}
	}
}

// reference is a slow, obviously correct matcher used as an oracle.
func reference(roles map[string]map[string]string, role, tool string, safe bool) Decision {
	rules, ok := roles[role]
	if !ok || !validName(tool) {
		return Decision{}
	}
	if c, ok := rules[tool]; ok {
		return finish(Decision{Class: Class(c[0]), Rule: tool}, safe)
	}
	best := ""
	for pat := range rules {
		if strings.HasSuffix(pat, "*") && strings.HasPrefix(tool, strings.TrimSuffix(pat, "*")) && len(pat) > len(best) {
			best = pat
		}
	}
	if best == "" {
		return Decision{}
	}
	return finish(Decision{Class: Class(rules[best][0]), Rule: best}, safe)
}

func finish(d Decision, safe bool) Decision {
	d.Allowed = !safe || d.Class == ClassR
	return d
}

// Property test: random policies and tools drawn from a tiny alphabet so
// that matches, near-misses and overlaps are common. Decide must equal the
// oracle, and Visible must be exactly the Decide-allowed tools in order.
func TestDecideAgainstReferenceAndVisibleConsistent(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alpha := []byte("ab._")
	word := func(max int) string {
		n := 1 + rng.Intn(max)
		b := make([]byte, n)
		for i := range b {
			b[i] = alpha[rng.Intn(len(alpha))]
		}
		return string(b)
	}
	classes := []string{"R", "W", "X"}
	for iter := 0; iter < 300; iter++ {
		roles := map[string]map[string]string{}
		for _, r := range []string{"r1", "r2"} {
			rules := map[string]string{}
			for n := rng.Intn(12); n > 0; n-- {
				pat := word(5)
				if rng.Intn(2) == 0 {
					pat += "*"
				}
				rules[pat] = classes[rng.Intn(3)]
			}
			roles[r] = rules
		}
		p := mustPolicy(t, roles)
		var tools []string
		for i := 0; i < 60; i++ {
			tools = append(tools, word(7))
		}
		tools = append(tools, "has space", "", "a\x00")
		for _, role := range []string{"r1", "r2", "r3"} {
			for _, safe := range []bool{false, true} {
				var want []string
				for _, tool := range tools {
					got := p.Decide(role, tool, safe)
					if ref := reference(roles, role, tool, safe); got != ref {
						t.Fatalf("iter %d role %s safe %v tool %q rules %v: got %+v want %+v", iter, role, safe, tool, roles[role], got, ref)
					}
					if got.Allowed {
						want = append(want, tool)
					}
				}
				if want == nil {
					want = []string{}
				}
				if vis := p.Visible(role, tools, safe); !reflect.DeepEqual(vis, want) {
					t.Fatalf("iter %d role %s safe %v: Visible %v != allowed %v", iter, role, safe, vis, want)
				}
			}
		}
	}
}

// Safe mode never widens: whatever Decide allows in safe mode it also allows
// in normal mode, with the same class.
func TestSafeModeNeverWiderThanEnforcing(t *testing.T) {
	p := mustPolicy(t, sampleRoles)
	for _, role := range []string{"sales", "engineer", "empty", "x"} {
		for _, tool := range []string{"crm.read_leads", "crm.update_deal", "github.a", "ci.rerun", "zzz", "crm.read_private"} {
			s, n := p.Decide(role, tool, true), p.Decide(role, tool, false)
			if s.Allowed && (!n.Allowed || s.Class != ClassR || n.Class != s.Class) {
				t.Errorf("%s %s: safe %+v normal %+v", role, tool, s, n)
			}
		}
	}
}

func FuzzDecide(f *testing.F) {
	roles := map[string]map[string]string{
		"a": {"x.*": "R", "x.y": "W", "x.y.*": "X", "pre*": "R", "exact": "W"},
		"b": {"-*": "R", "_a": "R"},
	}
	p := mustPolicy(f, roles)
	for _, s := range []string{"x.y", "x.", "x", "pre", "exact", "exac", "", "x.y.z", "\x00", "x.\xff", "-", "_a", "X.y", strings.Repeat("x", 300)} {
		f.Add("a", s, false)
		f.Add("b", s, true)
	}
	f.Add("", "x.y", false)
	f.Add("A", "x.y", false)
	f.Fuzz(func(t *testing.T, role, tool string, safe bool) {
		d := p.Decide(role, tool, safe)
		ref := reference(roles, role, tool, safe)
		if d != ref {
			t.Fatalf("Decide(%q, %q, %v) = %+v, oracle %+v", role, tool, safe, d, ref)
		}
		if d.Allowed && d.Rule == "" {
			t.Fatal("allowed with no matched rule")
		}
		if d.Allowed {
			// Never allowed unless a rule really matches.
			rule := d.Rule
			if rule != tool && !(strings.HasSuffix(rule, "*") && strings.HasPrefix(tool, strings.TrimSuffix(rule, "*"))) {
				t.Fatalf("allowed %q by non-matching rule %q", tool, rule)
			}
		}
		v := p.Visible(role, []string{tool}, safe)
		if (len(v) == 1) != d.Allowed {
			t.Fatalf("Visible disagrees with Decide for %q", tool)
		}
	})
}

// buildBig returns a policy with n rules in one role (a mix of exact names
// and prefixes across several namespaces) and a spread of tool names.
func buildBig(tb testing.TB, n int) (*Policy, []string) {
	tb.Helper()
	rules := map[string]string{}
	var tools []string
	classes := []string{"R", "W", "X"}
	for i := 0; len(rules) < n; i++ {
		ns := fmt.Sprintf("svc%d", i%40)
		switch i % 4 {
		case 0:
			rules[fmt.Sprintf("%s.read_%d_*", ns, i)] = "R"
			tools = append(tools, fmt.Sprintf("%s.read_%d_item", ns, i))
		case 1:
			rules[fmt.Sprintf("%s.op_%d", ns, i)] = classes[i%3]
			tools = append(tools, fmt.Sprintf("%s.op_%d", ns, i))
		case 2:
			rules[fmt.Sprintf("%s.group%d.*", ns, i)] = classes[(i+1)%3]
			tools = append(tools, fmt.Sprintf("%s.group%d.deep.tool", ns, i))
		default:
			rules[fmt.Sprintf("%s.x%d", ns, i)] = "W"
			tools = append(tools, fmt.Sprintf("%s.missing_%d", ns, i)) // no match
		}
	}
	// Policy limit is 1,024 patterns per role; stay within it.
	return mustPolicy(tb, map[string]map[string]string{"bench": rules}), tools
}

func TestBigPolicyDecides(t *testing.T) {
	p, tools := buildBig(t, 1000)
	allowed := 0
	for _, tool := range tools {
		if p.Decide("bench", tool, false).Allowed {
			allowed++
		}
	}
	if allowed == 0 || allowed == len(tools) {
		t.Fatalf("expected a mix, allowed %d of %d", allowed, len(tools))
	}
}

func BenchmarkDecide(b *testing.B) {
	p, tools := buildBig(b, 1000)
	b.ReportAllocs()
	b.ResetTimer()
	var sink Decision
	for i := 0; i < b.N; i++ {
		sink = p.Decide("bench", tools[i%len(tools)], i&1 == 1)
	}
	_ = sink
}

func TestDecideZeroAllocs(t *testing.T) {
	p, tools := buildBig(t, 1000)
	n := testing.AllocsPerRun(200, func() {
		for _, tool := range tools[:50] {
			_ = p.Decide("bench", tool, false)
		}
	})
	if n != 0 {
		t.Fatalf("Decide allocates: %v", n)
	}
}
