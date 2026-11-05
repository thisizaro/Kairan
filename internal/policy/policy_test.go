package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// good builds a valid payload; the pieces can be swapped per test case.
// A value of "-" removes the field.
func good(fields map[string]string) string {
	f := map[string]string{
		"tenant":     `"bank-a"`,
		"version":    `8`,
		"issued_at":  `"2026-11-05T09:00:00Z"`,
		"expires_at": `"2026-11-08T09:00:00Z"`,
		"default":    `"deny"`,
		"roles":      `{"sales":{"crm.read_*":"R","crm.update_deal":"W"},"engineer":{"github.*":"R","ci.rerun":"X"}}`,
	}
	for k, v := range fields {
		if v == "-" {
			delete(f, k)
		} else {
			f[k] = v
		}
	}
	var parts []string
	for _, k := range []string{"tenant", "version", "issued_at", "expires_at", "default", "roles"} {
		if v, ok := f[k]; ok {
			parts = append(parts, fmt.Sprintf("%q:%s", k, v))
		}
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func TestParseValid(t *testing.T) {
	p, err := Parse([]byte(good(nil)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Tenant != "bank-a" || p.Version != 8 {
		t.Fatalf("tenant/version: %q %d", p.Tenant, p.Version)
	}
	if want := time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC); !p.IssuedAt.Equal(want) || p.IssuedAt.Location() != time.UTC {
		t.Fatalf("issued_at %v", p.IssuedAt)
	}
	if want := time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC); !p.ExpiresAt.Equal(want) {
		t.Fatalf("expires_at %v", p.ExpiresAt)
	}
	sales, ok := p.roles["sales"]
	if !ok || len(sales.exact) != 1 || sales.exact["crm.update_deal"] != 'W' {
		t.Fatalf("sales rules: %+v", sales)
	}
	if len(sales.prefixes) != 1 || sales.prefixes[0].prefix != "crm.read_" || sales.prefixes[0].class != 'R' || sales.prefixes[0].pattern != "crm.read_*" {
		t.Fatalf("sales prefixes: %+v", sales.prefixes)
	}
}

func TestParseValidEdges(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{"empty roles", good(map[string]string{"roles": `{}`})},
		{"role without rules", good(map[string]string{"roles": `{"a":{}}`})},
		{"reordered fields", `{"roles":{},"default":"deny","expires_at":"2026-11-08T09:00:00Z","issued_at":"2026-11-05T09:00:00Z","version":1,"tenant":"t"}`},
		{"fractional seconds", good(map[string]string{"issued_at": `"2026-11-05T09:00:00.5Z"`})},
		{"max version", good(map[string]string{"version": `18446744073709551615`})},
		{"escaped value", good(map[string]string{"tenant": `"bank-a"`})},
		{"name 128 chars", good(map[string]string{"roles": `{"a":{"` + strings.Repeat("a", 128) + `":"R"}}`})},
		{"prefix 128 chars", good(map[string]string{"roles": `{"a":{"` + strings.Repeat("a", 128) + `*":"R"}}`})},
		{"upper case tool names", good(map[string]string{"roles": `{"a":{"CRM.Read":"R","crm.read":"W"}}`})},
		{"all chars", good(map[string]string{"roles": `{"a":{"aZ09_.-":"X","aZ09_.-*":"W"}}`})},
		{"exact and prefix same text", good(map[string]string{"roles": `{"a":{"x":"R","x*":"W"}}`})},
		{"space around", " \n" + good(nil) + " \n\t"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse([]byte(tc.payload)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseMalformed(t *testing.T) {
	roles := func(n int) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"r%d":{}`, i)
		}
		b.WriteString("}")
		return b.String()
	}
	pats := func(n int) string {
		var b strings.Builder
		b.WriteString(`{"a":{`)
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"t%d":"R"`, i)
		}
		b.WriteString("}}")
		return b.String()
	}
	R := func(s string) string { return good(map[string]string{"roles": s}) }
	F := func(k, v string) string { return good(map[string]string{k: v}) }
	ok := good(nil)
	deep := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)

	tests := []struct {
		name    string
		payload string
	}{
		// whole document
		{"empty", ``},
		{"whitespace", `   `},
		{"not json", `hello`},
		{"array", `[]`},
		{"null", `null`},
		{"string", `"x"`},
		{"truncated", ok[:len(ok)-1]},
		{"trailing second value", ok + `{"version":99}`},
		{"trailing second value after space", ok + ` {"version":99}`},
		{"trailing garbage", ok + `x`},
		{"trailing comma", `{"tenant":"a",}`},
		{"empty object", `{}`},
		{"utf8 bom", "\xef\xbb\xbf" + ok},
		{"too big", ok + strings.Repeat(" ", wire.MaxEnvelopeBytes)},

		// fields: missing, unknown, case, duplicates
		{"missing tenant", F("tenant", "-")},
		{"missing version", F("version", "-")},
		{"missing issued_at", F("issued_at", "-")},
		{"missing expires_at", F("expires_at", "-")},
		{"missing default", F("default", "-")},
		{"missing roles", F("roles", "-")},
		{"unknown field", strings.Replace(ok, "{", `{"extra":1,`, 1)},
		{"unknown field null", strings.Replace(ok, "{", `{"extra":null,`, 1)},
		{"Tenant", strings.Replace(ok, `"tenant"`, `"Tenant"`, 1)},
		{"TENANT", strings.Replace(ok, `"tenant"`, `"TENANT"`, 1)},
		{"Version", strings.Replace(ok, `"version"`, `"Version"`, 1)},
		{"Issued_At", strings.Replace(ok, `"issued_at"`, `"Issued_At"`, 1)},
		{"Expires_at", strings.Replace(ok, `"expires_at"`, `"Expires_at"`, 1)},
		{"Default", strings.Replace(ok, `"default"`, `"Default"`, 1)},
		{"Roles", strings.Replace(ok, `"roles"`, `"Roles"`, 1)},
		{"issuedat", strings.Replace(ok, `"issued_at"`, `"issuedat"`, 1)},
		{"trailing space in field", strings.Replace(ok, `"tenant"`, `"tenant "`, 1)},
		{"duplicate tenant", strings.Replace(ok, "{", `{"tenant":"bank-b",`, 1)},
		{"duplicate tenant same value", strings.Replace(ok, "{", `{"tenant":"bank-a",`, 1)},
		{"duplicate via escape", strings.Replace(ok, "{", `{"tenant":"bank-b",`, 1)},
		{"duplicate version", strings.Replace(ok, "{", `{"version":1,`, 1)},
		{"duplicate roles", strings.Replace(ok, "{", `{"roles":{},`, 1)},
		{"case variant plus real", strings.Replace(ok, "{", `{"Tenant":"bank-b",`, 1)},
		{"duplicate role", R(`{"a":{"x":"R"},"a":{"x":"X"}}`)},
		{"duplicate role same content", R(`{"a":{},"a":{}}`)},
		{"duplicate tool", R(`{"a":{"x":"R","x":"X"}}`)},
		{"duplicate tool same class", R(`{"a":{"x":"R","x":"R"}}`)},
		{"duplicate prefix", R(`{"a":{"x*":"R","x*":"X"}}`)},
		{"duplicate tool via escape", R(`{"a":{"x":"R","x":"X"}}`)},

		// types
		{"tenant number", F("tenant", `1`)},
		{"tenant null", F("tenant", `null`)},
		{"tenant object", F("tenant", `{}`)},
		{"tenant array", F("tenant", `["a"]`)},
		{"tenant empty", F("tenant", `""`)},
		{"tenant upper", F("tenant", `"Bank-A"`)},
		{"tenant underscore", F("tenant", `"bank_a"`)},
		{"tenant leading dash", F("tenant", `"-a"`)},
		{"tenant 64 chars", F("tenant", `"`+strings.Repeat("a", 64)+`"`)},
		{"version string", F("version", `"8"`)},
		{"version zero", F("version", `0`)},
		{"version negative", F("version", `-1`)},
		{"version float", F("version", `8.0`)},
		{"version exponent", F("version", `8e0`)},
		{"version fraction", F("version", `8.5`)},
		{"version overflow", F("version", `18446744073709551616`)},
		{"version null", F("version", `null`)},
		{"version bool", F("version", `true`)},
		{"version leading zero", F("version", `08`)},
		{"version plus", F("version", `+8`)},
		{"roles array", R(`[]`)},
		{"roles null", R(`null`)},
		{"roles string", R(`"x"`)},
		{"role is array", R(`{"a":[]}`)},
		{"role is null", R(`{"a":null}`)},
		{"role is string", R(`{"a":"R"}`)},
		{"class number", R(`{"a":{"x":1}}`)},
		{"class null", R(`{"a":{"x":null}}`)},
		{"class bool", R(`{"a":{"x":true}}`)},
		{"class object", R(`{"a":{"x":{}}}`)},
		{"class array", R(`{"a":{"x":["R"]}}`)},

		// time
		{"issued not string", F("issued_at", `1762333200`)},
		{"issued date only", F("issued_at", `"2026-11-05"`)},
		{"issued offset", F("issued_at", `"2026-11-05T10:00:00+01:00"`)},
		{"issued plus zero offset", F("issued_at", `"2026-11-05T09:00:00+00:00"`)},
		{"issued lower z", F("issued_at", `"2026-11-05T09:00:00z"`)},
		{"issued lower t", F("issued_at", `"2026-11-05t09:00:00Z"`)},
		{"issued space", F("issued_at", `"2026-11-05 09:00:00Z"`)},
		{"issued no zone", F("issued_at", `"2026-11-05T09:00:00"`)},
		{"issued month 13", F("issued_at", `"2026-13-05T09:00:00Z"`)},
		{"issued empty", F("issued_at", `""`)},
		{"issued null", F("issued_at", `null`)},
		{"expires bad", F("expires_at", `"tomorrow"`)},
		{"expires equals issued", F("expires_at", `"2026-11-05T09:00:00Z"`)},
		{"expires before issued", F("expires_at", `"2026-11-05T08:59:59Z"`)},
		{"expires before issued by sub-second", good(map[string]string{"issued_at": `"2026-11-05T09:00:00.5Z"`, "expires_at": `"2026-11-05T09:00:00.4Z"`})},

		// default
		{"default allow", F("default", `"allow"`)},
		{"default upper", F("default", `"DENY"`)},
		{"default title", F("default", `"Deny"`)},
		{"default empty", F("default", `""`)},
		{"default null", F("default", `null`)},
		{"default bool", F("default", `false`)},
		{"default padded", F("default", `"deny "`)},

		// classes
		{"class lower r", R(`{"a":{"x":"r"}}`)},
		{"class empty", R(`{"a":{"x":""}}`)},
		{"class RW", R(`{"a":{"x":"RW"}}`)},
		{"class Z", R(`{"a":{"x":"Z"}}`)},
		{"class allow", R(`{"a":{"x":"allow"}}`)},
		{"class padded", R(`{"a":{"x":"R "}}`)},

		// role names
		{"role empty", R(`{"":{}}`)},
		{"role upper", R(`{"Sales":{}}`)},
		{"role space", R(`{"a b":{}}`)},
		{"role dot", R(`{"a.b":{}}`)},
		{"role 64 chars", R(`{"` + strings.Repeat("a", 64) + `":{}}`)},
		{"role leading dash", R(`{"-a":{}}`)},

		// patterns
		{"bare star", R(`{"a":{"*":"R"}}`)},
		{"empty tool", R(`{"a":{"":"R"}}`)},
		{"double star", R(`{"a":{"x**":"R"}}`)},
		{"star then name", R(`{"a":{"x*y":"R"}}`)},
		{"leading star", R(`{"a":{"*x":"R"}}`)},
		{"middle star", R(`{"a":{"a*b*":"R"}}`)},
		{"star inside exact", R(`{"a":{"a.*.b":"R"}}`)},
		{"question mark", R(`{"a":{"x?":"R"}}`)},
		{"slash", R(`{"a":{"x/y":"R"}}`)},
		{"space", R(`{"a":{"x y":"R"}}`)},
		{"colon", R(`{"a":{"x:y":"R"}}`)},
		{"non ascii", R(`{"a":{"café":"R"}}`)},
		{"non ascii prefix", R(`{"a":{"café*":"R"}}`)},
		{"nul byte", R(`{"a":{"x\u0000":"R"}}`)},
		{"newline", R(`{"a":{"x\n":"R"}}`)},
		{"invalid utf8", "{\"tenant\":\"\xff\"}"},
		{"name 129 chars", R(`{"a":{"` + strings.Repeat("a", 129) + `":"R"}}`)},
		{"prefix 129 chars", R(`{"a":{"` + strings.Repeat("a", 129) + `*":"R"}}`)},

		// limits
		{"257 roles", R(roles(257))},
		{"1025 patterns", R(pats(1025))},

		// depth bombs
		{"deep nesting in unknown field", strings.Replace(ok, "{", `{"x":`+deep+",", 1)},
		{"deep nesting in class", R(`{"a":{"x":` + deep + `}}`)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := Parse([]byte(tc.payload))
			if err == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if p != nil {
				t.Fatal("non-nil policy with error")
			}
			if !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("error does not wrap wire.ErrInvalid: %v", err)
			}
		})
	}
}

func TestParseLimitsAtBoundary(t *testing.T) {
	var rs strings.Builder
	rs.WriteString("{")
	for i := 0; i < MaxRoles; i++ {
		if i > 0 {
			rs.WriteString(",")
		}
		fmt.Fprintf(&rs, `"r%d":{}`, i)
	}
	rs.WriteString("}")
	p, err := Parse([]byte(good(map[string]string{"roles": rs.String()})))
	if err != nil {
		t.Fatalf("256 roles: %v", err)
	}
	if len(p.roles) != MaxRoles {
		t.Fatalf("roles %d", len(p.roles))
	}

	var ps strings.Builder
	ps.WriteString(`{"a":{`)
	for i := 0; i < MaxPatterns; i++ {
		if i > 0 {
			ps.WriteString(",")
		}
		if i%2 == 0 {
			fmt.Fprintf(&ps, `"t%d":"R"`, i)
		} else {
			fmt.Fprintf(&ps, `"t%d*":"W"`, i)
		}
	}
	ps.WriteString("}}")
	p, err = Parse([]byte(good(map[string]string{"roles": ps.String()})))
	if err != nil {
		t.Fatalf("1024 patterns: %v", err)
	}
	if n := len(p.roles["a"].exact) + len(p.roles["a"].prefixes); n != MaxPatterns {
		t.Fatalf("rules %d", n)
	}
}

func TestPrefixesSortedLongestFirst(t *testing.T) {
	p, err := Parse([]byte(good(map[string]string{"roles": `{"a":{"a*":"R","a.b.c*":"X","a.b*":"W","b*":"R","a.c*":"R"}}`})))
	if err != nil {
		t.Fatal(err)
	}
	pre := p.roles["a"].prefixes
	if len(pre) != 5 {
		t.Fatalf("prefixes: %+v", pre)
	}
	for i := 1; i < len(pre); i++ {
		if len(pre[i-1].prefix) < len(pre[i].prefix) {
			t.Fatalf("not longest first: %+v", pre)
		}
	}
	if pre[0].prefix != "a.b.c" {
		t.Fatalf("order: %+v", pre)
	}
}

func TestErrorsLeakNoPayload(t *testing.T) {
	secret := "SECRET-TENANT-VALUE"
	for _, payload := range []string{
		good(map[string]string{"tenant": `"` + secret + `"`}),
		good(map[string]string{"roles": `{"` + secret + `":{}}`}),
		good(map[string]string{"roles": `{"a":{"` + secret + `":"Q"}}`}),
		good(map[string]string{"default": `"` + secret + `"`}),
		strings.Replace(good(nil), "{", `{"`+secret+`":1,`, 1),
	} {
		_, err := Parse([]byte(payload))
		if err == nil {
			t.Fatal("accepted")
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error echoes payload: %v", err)
		}
	}
}

// Golden envelopes from test/fixtures: the policy inside each must parse or
// fail as the case says. Signature and tenant cases belong to package trust;
// here only whether the policy bytes parse is checked.
func TestFixturePolicies(t *testing.T) {
	dir := filepath.Join("..", "..", "test", "fixtures")
	raw, err := os.ReadFile(filepath.Join(dir, "cases.json"))
	if err != nil {
		t.Fatalf("fixtures: %v", err)
	}
	var doc struct {
		Cases []struct {
			Name string `json:"name"`
			File string `json:"file"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	cases := doc.Cases
	if len(cases) == 0 {
		t.Fatal("cases.json: no cases")
	}
	// Policies that must fail strict parsing; all others must parse.
	bad := map[string]bool{
		"malformed-policy": true, "duplicate-role": true, "duplicate-tool": true,
		"case-variant-field": true, "trailing-bytes": true, "issued-after-expires": true,
	}
	seen := 0
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join(dir, c.File))
			if err != nil {
				t.Fatal(err)
			}
			var env struct {
				Payload []byte `json:"payload"`
			}
			if err := json.Unmarshal(b, &env); err != nil {
				t.Fatalf("envelope: %v", err)
			}
			p, err := Parse(env.Payload)
			if bad[c.Name] {
				seen++
				if err == nil {
					t.Fatalf("accepted: %+v", p)
				}
				if !errors.Is(err, wire.ErrInvalid) {
					t.Fatalf("not ErrInvalid: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("policy rejected: %v", err)
			}
			if p.Version == 0 || !p.ExpiresAt.After(p.IssuedAt) {
				t.Fatalf("bad parsed policy: %+v", p)
			}
		})
	}
	if seen != len(bad) {
		t.Fatalf("saw %d of %d expected-bad fixtures", seen, len(bad))
	}
}

func FuzzParse(f *testing.F) {
	seeds := []string{
		good(nil),
		good(map[string]string{"roles": `{}`}),
		`{}`, ``, `null`, `[]`, `{"tenant":`,
		good(nil) + `{"version":99}`,
		// duplicate keys, every level
		strings.Replace(good(nil), "{", `{"tenant":"bank-b",`, 1),
		strings.Replace(good(nil), "{", `{"tenant":"bank-b",`, 1),
		good(map[string]string{"roles": `{"a":{"x":"R"},"a":{"x":"X"}}`}),
		good(map[string]string{"roles": `{"a":{"x":"R","x":"X"}}`}),
		// case variants
		strings.Replace(good(nil), `"tenant"`, `"Tenant"`, 1),
		strings.Replace(good(nil), `"roles"`, `"ROLES"`, 1),
		strings.Replace(good(nil), "{", `{"Tenant":"bank-b",`, 1),
		// patterns and values
		good(map[string]string{"roles": `{"a":{"*":"R"}}`}),
		good(map[string]string{"roles": `{"a":{"x**":"R","y*z":"W","café":"X"}}`}),
		good(map[string]string{"default": `"allow"`}),
		good(map[string]string{"version": `1e3`}),
		good(map[string]string{"issued_at": `"2026-11-05T09:00:00+01:00"`}),
		good(map[string]string{"roles": `{"a":{"x":` + strings.Repeat("[", 50) + `}}`}),
		"{\"tenant\":\"\xff\"}",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := Parse(data)
		if err != nil {
			if p != nil {
				t.Fatal("policy with error")
			}
			if !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("error does not wrap ErrInvalid: %v", err)
			}
			return
		}
		// Anything accepted must satisfy every rule of 10.0.
		if !p.Tenant.Valid() || p.Version < 1 || !p.ExpiresAt.After(p.IssuedAt) {
			t.Fatalf("invalid policy accepted: %+v", p)
		}
		if p.IssuedAt.Location() != time.UTC || p.ExpiresAt.Location() != time.UTC {
			t.Fatal("not UTC")
		}
		if len(p.roles) > MaxRoles {
			t.Fatal("too many roles")
		}
		for name, r := range p.roles {
			if !wire.ID(name).Valid() {
				t.Fatalf("role %q", name)
			}
			if len(r.exact)+len(r.prefixes) > MaxPatterns {
				t.Fatal("too many patterns")
			}
			for tool, c := range r.exact {
				if !validName(tool) || !validClass(c) {
					t.Fatalf("tool %q %c", tool, c)
				}
			}
			for i, pr := range r.prefixes {
				if !validName(pr.prefix) || pr.pattern != pr.prefix+"*" || !validClass(pr.class) {
					t.Fatalf("prefix %+v", pr)
				}
				if i > 0 && len(r.prefixes[i-1].prefix) < len(pr.prefix) {
					t.Fatal("prefixes not longest first")
				}
			}
		}
		// Accepted bytes must be unambiguous: the standard decoder, which is
		// case-insensitive and keeps the last duplicate, must read the same
		// tenant and version as Parse.
		var std struct {
			Tenant  string `json:"tenant"`
			Version uint64 `json:"version"`
		}
		if err := json.Unmarshal(data, &std); err != nil {
			t.Fatalf("std decoder rejects accepted payload: %v", err)
		}
		if std.Tenant != string(p.Tenant) || std.Version != p.Version {
			t.Fatalf("decoders disagree: %+v vs %q %d", std, p.Tenant, p.Version)
		}
	})
}
