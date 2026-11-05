// Package policybreak holds black-box attack tests for policy.Parse (task T-01).
// Sources: ARCHITECTURE section 10.0 and the policy LLD, M-D12 as amended by
// M-D32, PRD I1/I3, test/fixtures, and the go doc of the policy package.
package policybreak

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

const validBase = `{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}}`

// pl builds a payload with each section overridable (raw JSON text).
type pl struct {
	tenant, version, issued, expires, def, roles string
}

func (p pl) String() string {
	d := pl{`"bank-a"`, `2`, `"2026-11-05T11:00:00Z"`, `"2026-11-08T11:00:00Z"`, `"deny"`, `{"sales":{"crm.read_*":"R"}}`}
	if p.tenant != "" {
		d.tenant = p.tenant
	}
	if p.version != "" {
		d.version = p.version
	}
	if p.issued != "" {
		d.issued = p.issued
	}
	if p.expires != "" {
		d.expires = p.expires
	}
	if p.def != "" {
		d.def = p.def
	}
	if p.roles != "" {
		d.roles = p.roles
	}
	return fmt.Sprintf(`{"tenant":%s,"version":%s,"issued_at":%s,"expires_at":%s,"default":%s,"roles":%s}`,
		d.tenant, d.version, d.issued, d.expires, d.def, d.roles)
}

func mustReject(t *testing.T, name, why, payload string) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC on %q (%s): %v", abbreviate(payload), why, r)
			}
		}()
		p, err := policy.Parse([]byte(payload))
		if err == nil {
			t.Fatalf("%s: accepted %q, want error wrapping wire.ErrInvalid", why, abbreviate(payload))
		}
		if p != nil {
			t.Fatalf("%s: error AND non-nil policy returned", why)
		}
		if !errors.Is(err, wire.ErrInvalid) {
			t.Fatalf("%s: error %v does not wrap wire.ErrInvalid", why, err)
		}
	})
}

func mustAccept(t *testing.T, name, why, payload string) *policy.Policy {
	t.Helper()
	var out *policy.Policy
	t.Run(name, func(t *testing.T) {
		p, err := policy.Parse([]byte(payload))
		if err != nil {
			t.Fatalf("%s: rejected %q: %v", why, abbreviate(payload), err)
		}
		out = p
	})
	return out
}

func abbreviate(s string) string {
	if len(s) > 160 {
		return s[:160] + "...(" + fmt.Sprint(len(s)) + " bytes)"
	}
	return s
}

func fixtureRoot() string {
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "fixtures")
}

// --- 1. Golden fixtures (test/fixtures) ---------------------------------

type fixtureCase struct {
	Name string `json:"name"`
	File string `json:"file"`
	Want string `json:"want"`
}

func TestFixturePayloadsParse(t *testing.T) {
	root := fixtureRoot()
	raw, err := os.ReadFile(filepath.Join(root, "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []fixtureCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// Fixtures whose payload is itself a policy-parse failure (section 10.0, M-D32).
	policyBad := map[string]bool{
		"duplicate-role": true, "duplicate-tool": true, "case-variant-field": true,
		"malformed-policy": true, "trailing-bytes": true, "issued-after-expires": true,
	}
	// tampered-payload carries one trailing space: M-D44 (2) allows RFC 8259
	// whitespace after the JSON value, so it must parse.
	skip := map[string]bool{}
	n := 0
	for _, c := range doc.Cases {
		c := c
		n++
		t.Run(c.Name, func(t *testing.T) {
			if skip[c.Name] {
				t.Skip("trailing whitespace behaviour not pinned by docs")
			}
			eb, err := os.ReadFile(filepath.Join(root, c.File))
			if err != nil {
				t.Fatal(err)
			}
			var env wire.Envelope
			if err := json.Unmarshal(eb, &env); err != nil {
				t.Fatal(err)
			}
			p, perr := policy.Parse(env.Payload)
			if policyBad[c.Name] {
				if perr == nil {
					t.Fatalf("fixture %s (want %q): Parse accepted a payload the golden vectors call malformed", c.Name, c.Want)
				}
				if !errors.Is(perr, wire.ErrInvalid) {
					t.Fatalf("error does not wrap wire.ErrInvalid: %v", perr)
				}
				return
			}
			if perr != nil {
				t.Fatalf("fixture %s: Parse rejected a well-formed policy: %v", c.Name, perr)
			}
			if p.Version == 0 || !p.Tenant.Valid() || !p.ExpiresAt.After(p.IssuedAt) {
				t.Fatalf("parsed policy has bad fields: %+v", p)
			}
		})
	}
	if n < 20 {
		t.Fatalf("only %d fixture cases found", n)
	}
}

func TestValidFieldsRoundTrip(t *testing.T) {
	// ARCH 10.0 example values come back exactly, in UTC.
	p := mustAccept(t, "valid", "section 10.0 example", validBase)
	if p == nil {
		return
	}
	if p.Tenant != "bank-a" || p.Version != 2 {
		t.Fatalf("tenant/version wrong: %+v", p)
	}
	wantI := time.Date(2026, 11, 5, 11, 0, 0, 0, time.UTC)
	wantE := time.Date(2026, 11, 8, 11, 0, 0, 0, time.UTC)
	if !p.IssuedAt.Equal(wantI) || !p.ExpiresAt.Equal(wantE) {
		t.Fatalf("times wrong: %v %v", p.IssuedAt, p.ExpiresAt)
	}
	if p.IssuedAt.Location() != time.UTC || p.ExpiresAt.Location() != time.UTC {
		t.Fatalf("times are not in UTC (doc: // UTC): %v %v", p.IssuedAt.Location(), p.ExpiresAt.Location())
	}
}

// --- 2. Structure, trailing data, garbage --------------------------------

func TestRejectGarbageShapes(t *testing.T) {
	cases := []struct{ name, in string }{
		{"empty", ""},
		{"whitespace-only", "   "},
		{"null", "null"},
		{"array", "[]"},
		{"string", `"x"`},
		{"number", "1"},
		{"empty-object", "{}"},
		{"bool", "true"},
		{"nul-byte", "\x00"},
		{"bom-prefix", "\xef\xbb\xbf" + validBase},
		{"utf16-bom", "\xff\xfe" + validBase},
		{"leading-garbage", "x" + validBase},
		{"trailing-second-object", validBase + `{"version":99}`},
		{"trailing-second-object-space", validBase + ` {"version":99}`},
		{"trailing-comma", validBase + ","},
		{"trailing-brace", validBase + "}"},
		{"trailing-x", validBase + "x"},
		{"trailing-nul", validBase + "\x00"},
		{"trailing-bom", validBase + "\xef\xbb\xbf"},
		{"two-docs-newline", validBase + "\n" + validBase},
		{"object-opened-not-closed", validBase[:len(validBase)-1]},
		{"comment", `/*c*/` + validBase},
		{"single-quotes", `{'tenant':'bank-a'}`},
		{"trailing-comma-inside", strings.Replace(validBase, `"W"}`, `"W",}`, 1)},
		{"missing-colon", strings.Replace(validBase, `"tenant":`, `"tenant"`, 1)},
		{"nan-version", pl{version: "NaN"}.String()},
		{"infinity-version", pl{version: "Infinity"}.String()},
		{"hex-version", pl{version: "0x2"}.String()},
		{"leading-zero-version", pl{version: "02"}.String()},
		{"plus-version", pl{version: "+2"}.String()},
	}
	for _, c := range cases {
		mustReject(t, c.name, "ARCH 10.0: strict; any trailing bytes / non-JSON is malformed", c.in)
	}
}

// Every proper prefix of a valid payload is incomplete JSON and must be refused.
func TestEveryTruncationRejected(t *testing.T) {
	for i := 0; i < len(validBase); i++ {
		_, err := policy.Parse([]byte(validBase[:i]))
		if err == nil {
			t.Fatalf("prefix of length %d accepted: %q", i, validBase[:i])
		}
		if !errors.Is(err, wire.ErrInvalid) {
			t.Fatalf("prefix %d: error does not wrap wire.ErrInvalid: %v", i, err)
		}
	}
}

// --- 3. Duplicate and case-variant keys (M-D32) --------------------------

func TestDuplicateAndCaseVariantKeys(t *testing.T) {
	why := "M-D32: duplicate key at any level / non-lowercase field name is malformed"
	rolesDup := `{"sales":{"crm.read_*":"R"},"sales":{"crm.*":"X"}}`
	toolDup := `{"sales":{"crm.read_*":"R","crm.read_*":"X"}}`
	cases := []struct{ name, in string }{
		{"dup-tenant-same-value", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","tenant":"bank-a",`, 1)},
		{"dup-tenant-diff-value", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","tenant":"city-b",`, 1)},
		{"dup-version", strings.Replace(validBase, `"version":2,`, `"version":2,"version":3,`, 1)},
		{"dup-default", strings.Replace(validBase, `"default":"deny",`, `"default":"deny","default":"deny",`, 1)},
		{"dup-roles-key-toplevel", validBase[:len(validBase)-1] + `,"roles":{}}`},
		{"dup-role", pl{roles: rolesDup}.String()},
		{"dup-tool", pl{roles: toolDup}.String()},
		{"dup-tool-same-class", pl{roles: `{"a":{"x.y":"R","x.y":"R"}}`}.String()},
		{"dup-tool-escaped-star", pl{roles: `{"a":{"crm.read_*":"R","crm.read_*":"X"}}`}.String()},
		{"dup-tool-escaped-dot", pl{roles: `{"a":{"crm.read":"R","crm.read":"X"}}`}.String()},
		{"dup-key-via-escape-tenant", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","tenant":"city-b",`, 1)},
		{"dup-key-via-escape-version", strings.Replace(validBase, `"version":2,`, `"version":2,"version":9,`, 1)},
		{"dup-role-via-escape", pl{roles: `{"sales":{"a":"R"},"sales":{"a":"X"}}`}.String()},
		{"case-Tenant", strings.Replace(validBase, `"tenant"`, `"Tenant"`, 1)},
		{"case-TENANT", strings.Replace(validBase, `"tenant"`, `"TENANT"`, 1)},
		{"case-Version", strings.Replace(validBase, `"version"`, `"Version"`, 1)},
		{"case-Issued_At", strings.Replace(validBase, `"issued_at"`, `"Issued_At"`, 1)},
		{"case-expires_AT", strings.Replace(validBase, `"expires_at"`, `"expires_AT"`, 1)},
		{"case-Default", strings.Replace(validBase, `"default"`, `"Default"`, 1)},
		{"case-Roles", strings.Replace(validBase, `"roles"`, `"Roles"`, 1)},
		{"case-and-lower-both", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","Tenant":"city-b",`, 1)},
		{"fold-long-s-roles", strings.Replace(validBase, `"roles"`, "\"roleſ\"", 1)},
		{"fold-long-s-issued", strings.Replace(validBase, `"issued_at"`, "\"iſsued_at\"", 1)},
		{"fold-long-s-escaped", strings.Replace(validBase, `"roles"`, `"roleſ"`, 1)},
		{"fold-kelvin-in-unknown", strings.Replace(validBase, `"tenant":"bank-a",`, "\"tenant\":\"bank-a\",\"Key\":1,", 1)},
		{"key-with-leading-space", strings.Replace(validBase, `"tenant"`, `" tenant"`, 1)},
		{"key-with-trailing-space", strings.Replace(validBase, `"tenant"`, `"tenant "`, 1)},
		{"key-trailing-nul", strings.Replace(validBase, `"tenant"`, `"tenant\u0000"`, 1)},
		{"unknown-field", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","extra":1,`, 1)},
		{"unknown-field-null", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","extra":null,`, 1)},
		{"unknown-field-nested", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","extra":{"a":[1,2,{"b":3}]},`, 1)},
		{"unknown-field-empty-name", strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","":1,`, 1)},
		{"missing-tenant", `{"version":2,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","default":"deny","roles":{"a":{"x":"R"}}}`},
		{"missing-version", `{"tenant":"bank-a","issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","default":"deny","roles":{"a":{"x":"R"}}}`},
		{"missing-issued", `{"tenant":"bank-a","version":2,"expires_at":"2026-11-08T11:00:00Z","default":"deny","roles":{"a":{"x":"R"}}}`},
		{"missing-expires", `{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T11:00:00Z","default":"deny","roles":{"a":{"x":"R"}}}`},
		{"missing-default", `{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","roles":{"a":{"x":"R"}}}`},
		{"missing-roles", `{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T11:00:00Z","expires_at":"2026-11-08T11:00:00Z","default":"deny"}`},
	}
	for _, c := range cases {
		mustReject(t, c.name, why, c.in)
	}
}

// An escaped spelling of a valid key decodes to the same name. Either outcome is
// defensible (strict bytes vs decoded name), but a silently different policy is not.
func TestEscapedKeySpellingNeverChangesMeaning(t *testing.T) {
	ref, err := policy.Parse([]byte(validBase))
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range []string{
		strings.Replace(validBase, `"tenant"`, `"tenant"`, 1),
		strings.Replace(validBase, `"version"`, `"version"`, 1),
		strings.Replace(validBase, `"default"`, `"default"`, 1),
		strings.Replace(validBase, `"deny"`, `"deny"`, 1),
		strings.Replace(validBase, `"bank-a"`, `"bank-a"`, 1),
	} {
		p, err := policy.Parse([]byte(in))
		if err != nil {
			continue // strict rejection is fine
		}
		if p.Tenant != ref.Tenant || p.Version != ref.Version || !p.IssuedAt.Equal(ref.IssuedAt) || !p.ExpiresAt.Equal(ref.ExpiresAt) {
			t.Fatalf("escaped spelling changed the policy: %q -> %+v vs %+v", in, p, ref)
		}
	}
}

// --- 4. Field value rules ------------------------------------------------

func TestTenantRule(t *testing.T) {
	why := "ARCH 10.0: tenant is a wire.ID"
	for name, tenant := range map[string]string{
		"empty": `""`, "upper": `"Bank-A"`, "underscore": `"bank_a"`, "dot": `"bank.a"`,
		"leading-dash": `"-bank"`, "len64": `"` + strings.Repeat("a", 64) + `"`,
		"space": `"bank a"`, "unicode": `"bänk"`, "null": `null`, "number": `1`, "array": `["bank-a"]`,
		"object": `{}`, "nul": `"bank\u0000a"`, "trailing-newline": `"bank-a\n"`, "bool": `true`,
	} {
		mustReject(t, "tenant-"+name, why, pl{tenant: tenant}.String())
	}
	mustAccept(t, "tenant-len63", why, pl{tenant: `"` + strings.Repeat("a", 63) + `"`}.String())
	mustAccept(t, "tenant-digit-first", why, pl{tenant: `"1a"`}.String())
	mustAccept(t, "tenant-single", why, pl{tenant: `"a"`}.String())
}

func TestVersionRule(t *testing.T) {
	why := "ARCH 10.0: version is an integer >= 1"
	for name, v := range map[string]string{
		"zero": "0", "negative": "-1", "negative-zero": "-0", "fraction": "1.5", "string": `"2"`,
		"null": "null", "bool": "true", "array": "[2]", "object": "{}",
		"uint64-overflow": "18446744073709551616", "huge-digits": strings.Repeat("9", 400),
		"exp-huge": "1e400", "neg-huge": "-1e400", "int64-neg-min": "-9223372036854775808",
	} {
		mustReject(t, "version-"+name, why, pl{version: v}.String())
	}
	mustAccept(t, "version-1", why, pl{version: "1"}.String())
	mustAccept(t, "version-int64-max", why+" (no silent wrap)", pl{version: "9223372036854775807"}.String())
	// 2^63 and uint64 max: either rejected or exactly represented, never wrapped.
	for _, c := range []struct {
		in   string
		want uint64
	}{{"9223372036854775808", 1 << 63}, {"18446744073709551615", ^uint64(0)}} {
		p, err := policy.Parse([]byte(pl{version: c.in}.String()))
		if err == nil && p.Version != c.want {
			t.Fatalf("version %s silently became %d", c.in, p.Version)
		}
	}
	// Integer-valued spellings: reject or return exactly 2, never anything else.
	for _, in := range []string{"2.0", "2e0", "0.2e1", "20e-1"} {
		p, err := policy.Parse([]byte(pl{version: in}.String()))
		if err == nil && p.Version != 2 {
			t.Fatalf("version %s parsed as %d", in, p.Version)
		}
	}
}

func TestTimeRules(t *testing.T) {
	why := "ARCH 10.0: issued_at/expires_at are RFC 3339 UTC; expires_at > issued_at"
	bad := map[string]string{
		"offset-plus9":     `"2026-11-05T20:00:00+09:00"`,
		"offset-minus":     `"2026-11-05T11:00:00-05:00"`,
		"no-zone":          `"2026-11-05T11:00:00"`,
		"date-only":        `"2026-11-05"`,
		"unix":             `1793876400`,
		"null":             `null`,
		"empty":            `""`,
		"space-sep":        `"2026-11-05 11:00:00Z"`,
		"bad-month":        `"2026-13-05T11:00:00Z"`,
		"feb-30":           `"2026-02-30T11:00:00Z"`,
		"hour-24":          `"2026-11-05T24:00:00Z"`,
		"min-60":           `"2026-11-05T11:60:00Z"`,
		"leap-sec-60":      `"2026-11-05T11:00:60Z"`,
		"year-10000":       `"10000-11-05T11:00:00Z"`,
		"trailing-space":   `"2026-11-05T11:00:00Z "`,
		"leading-space":    `" 2026-11-05T11:00:00Z"`,
		"trailing-newline": `"2026-11-05T11:00:00Z\n"`,
		"nul":              `"2026-11-05T11:00:00Z\u0000"`,
		"array":            `["2026-11-05T11:00:00Z"]`,
		"bool":             `true`,
		"short":            `"2026-11-05T11:00Z"`,
	}
	for name, v := range bad {
		mustReject(t, "issued-"+name, why, pl{issued: v}.String())
		mustReject(t, "expires-"+name, why, pl{expires: v}.String())
	}
	mustReject(t, "expires-equals-issued", why, pl{issued: `"2026-11-05T11:00:00Z"`, expires: `"2026-11-05T11:00:00Z"`}.String())
	mustReject(t, "expires-before-issued", why, pl{issued: `"2026-11-05T11:00:01Z"`, expires: `"2026-11-05T11:00:00Z"`}.String())
	mustReject(t, "expires-before-issued-by-year", why, pl{issued: `"2027-11-05T11:00:00Z"`, expires: `"2026-11-05T11:00:00Z"`}.String())
	mustAccept(t, "expires-one-second-after", why, pl{issued: `"2026-11-05T11:00:00Z"`, expires: `"2026-11-05T11:00:01Z"`}.String())
	mustReject(t, "offset-hides-order", why, pl{issued: `"2026-11-05T11:00:00Z"`, expires: `"2026-11-05T20:00:00+09:00"`}.String())
}

func TestDefaultRule(t *testing.T) {
	why := "ARCH 10.0: default must be exactly \"deny\" (I3: default deny)"
	for name, d := range map[string]string{
		"allow": `"allow"`, "Deny": `"Deny"`, "DENY": `"DENY"`, "deny-space": `"deny "`, "empty": `""`,
		"null": `null`, "true": `true`, "false": `false`, "array": `["deny"]`, "object": `{"deny":1}`, "number": `0`,
		"deny-nul": `"deny\u0000"`, "deny-newline": `"deny\n"`, "star": `"*"`, "R": `"R"`,
	} {
		mustReject(t, "default-"+name, why, pl{def: d}.String())
	}
}

// --- 5. Roles, patterns, classes, limits ---------------------------------

func TestClassRule(t *testing.T) {
	why := "ARCH 10.0: class is R, W or X"
	for name, c := range map[string]string{
		"lower-r": `"r"`, "lower-w": `"w"`, "lower-x": `"x"`, "empty": `""`, "RW": `"RW"`, "Y": `"Y"`,
		"A": `"A"`, "null": `null`, "number": `1`, "bool": `true`, "R-space": `"R "`, "array": `["R"]`,
		"allow": `"allow"`, "star": `"*"`, "R-nul": `"R\u0000"`, "unicode-R": "\"Ｒ\"", "object": `{}`,
	} {
		mustReject(t, "class-"+name, why, pl{roles: `{"a":{"x.y":` + c + `}}`}.String())
	}
	for _, c := range []string{"R", "W", "X"} {
		mustAccept(t, "class-"+c, why, pl{roles: `{"a":{"x.y":"` + c + `"}}`}.String())
	}
}

func TestPatternRule(t *testing.T) {
	why := "ARCH 10.0: exact name or non-empty prefix + single trailing *; bare * malformed; 1-128 chars of [A-Za-z0-9_.-]"
	bad := map[string]string{
		"bare-star": "*", "empty": "", "double-star": "a**", "star-only-double": "**", "mid-star": "a*b",
		"leading-star": "*a", "star-dot": "*.read", "space": "a b", "slash": "a/b", "colon": "a:b",
		"unicode-name": "ツール", "unicode-accent": "café", "fullwidth-star": "a＊",
		"len129": strings.Repeat("a", 129), "len200-star": strings.Repeat("a", 200) + "*",
		"nul": `a\u0000b`, "newline": `a\nb`, "tab": `a\tb`, "question": "a?", "bracket": "a[1]",
		"star-escaped-mid": `a*b`, "bare-star-escaped": `*`, "trailing-space": "a ", "leading-space": " a",
		"glob-brace": "a{b,c}", "backslash": `a\\b`, "percent": "a%2a", "plus": "a+",
	}
	for name, k := range bad {
		mustReject(t, "pattern-"+name, why, pl{roles: `{"a":{"` + k + `":"R"}}`}.String())
	}
	good := map[string]string{
		"exact": "crm.export", "prefix": "crm.*", "underscore-prefix": "crm.read_*", "dash": "a-b", "upper": "CRM.Read",
		"digits": "0123", "len128": strings.Repeat("a", 128), "single": "a", "dot-star": ".*", "dash-star": "-*", "under-star": "_*",
	}
	for name, k := range good {
		mustAccept(t, "pattern-ok-"+name, why, pl{roles: `{"a":{"` + k + `":"R"}}`}.String())
	}
	mustReject(t, "pattern-invalid-utf8", why, pl{roles: "{\"a\":{\"a\xff\":\"R\"}}"}.String())
	mustReject(t, "pattern-overlong-utf8", why, pl{roles: "{\"a\":{\"a\xc0\xaf\":\"R\"}}"}.String())
}

func TestRoleNameRule(t *testing.T) {
	why := "ARCH 10.0: role name follows the wire.ID pattern"
	bad := map[string]string{
		"empty": "", "upper": "Sales", "underscore": "sales_team", "dot": "sales.eu", "leading-dash": "-s",
		"len64": strings.Repeat("a", 64), "space": "a b", "unicode": "営業", "star": "*", "slash": "a/b",
	}
	for name, k := range bad {
		mustReject(t, "role-"+name, why, pl{roles: `{"` + k + `":{"x.y":"R"}}`}.String())
	}
	mustAccept(t, "role-len63", why, pl{roles: `{"` + strings.Repeat("a", 63) + `":{"x.y":"R"}}`}.String())
	mustAccept(t, "role-dash", why, pl{roles: `{"sales-eu-2":{"x.y":"R"}}`}.String())
	for name, r := range map[string]string{
		"roles-null": `null`, "roles-array": `[]`, "roles-string": `"x"`, "roles-number": `1`,
		"role-null": `{"a":null}`, "role-array": `{"a":[]}`, "role-string": `{"a":"R"}`, "role-number": `{"a":1}`,
		"role-array-of-pairs": `{"a":[["x","R"]]}`,
	} {
		mustReject(t, name, "roles must be object of role -> object of tool -> class", pl{roles: r}.String())
	}
}

func TestLimits(t *testing.T) {
	why := "ARCH 10.0: <= 256 roles, <= 1024 patterns per role"
	mkRoles := func(n int) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"r%d":{"t.x":"R"}`, i)
		}
		b.WriteString("}")
		return b.String()
	}
	mkPats := func(n int) string {
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
	if policy.MaxRoles != 256 || policy.MaxPatterns != 1024 || policy.MaxToolNameLen != 128 {
		t.Fatalf("exported limit constants differ from ARCH 10.0: %d %d %d", policy.MaxRoles, policy.MaxPatterns, policy.MaxToolNameLen)
	}
	mustAccept(t, "roles-255", why, pl{roles: mkRoles(255)}.String())
	mustAccept(t, "roles-256", why, pl{roles: mkRoles(256)}.String())
	mustReject(t, "roles-257", why, pl{roles: mkRoles(257)}.String())
	mustReject(t, "roles-5000", why, pl{roles: mkRoles(5000)}.String())
	mustAccept(t, "patterns-1023", why, pl{roles: mkPats(1023)}.String())
	mustAccept(t, "patterns-1024", why, pl{roles: mkPats(1024)}.String())
	mustReject(t, "patterns-1025", why, pl{roles: mkPats(1025)}.String())
	mustReject(t, "patterns-100000", why, pl{roles: mkPats(100000)}.String())
	// The limit is per role, not total.
	var b strings.Builder
	b.WriteString("{")
	for r := 0; r < 4; r++ {
		if r > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"r%d":`, r)
		b.WriteString(strings.TrimSuffix(strings.TrimPrefix(mkPats(1024), `{"a":`), `}`))
	}
	b.WriteString("}")
	mustAccept(t, "patterns-per-role-not-total", why, pl{roles: b.String()}.String())
}

// --- 6. Hostile size / nesting (isolated subprocess: a stack overflow is fatal) ---

func TestDeepNestingDoesNotCrash(t *testing.T) {
	if os.Getenv("POLICYBREAK_DEEP") == "1" {
		depth := 3_000_000
		shapes := map[string]string{
			"unknown-field-arrays":   `{"tenant":"bank-a","extra":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`,
			"unknown-field-objects":  `{"tenant":"bank-a","extra":` + strings.Repeat(`{"a":`, depth) + `1` + strings.Repeat("}", depth) + `}`,
			"roles-arrays":           `{"roles":` + strings.Repeat("[", depth) + `}`,
			"top-arrays":             strings.Repeat("[", depth),
			"role-objects":           `{"roles":{"a":` + strings.Repeat(`{"b":`, depth) + `1` + strings.Repeat("}", depth) + `}}`,
			"valid-prefix-then-deep": validBase[:len(validBase)-1] + `,"x":` + strings.Repeat("[", depth) + strings.Repeat("]", depth) + `}`,
		}
		for name, in := range shapes {
			if p, err := policy.Parse([]byte(in)); err == nil || p != nil {
				fmt.Printf("DEEP-ACCEPTED %s\n", name)
				os.Exit(3)
			}
		}
		fmt.Println("DEEP-OK")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDeepNestingDoesNotCrash$")
	cmd.Env = append(os.Environ(), "POLICYBREAK_DEEP=1")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		o := out.String()
		if err != nil || !strings.Contains(o, "DEEP-OK") {
			if len(o) > 1500 {
				o = o[:1500]
			}
			t.Fatalf("deeply nested hostile input crashed or was accepted (I3: never panics on garbage): %v\n%s", err, o)
		}
	case <-time.After(60 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("deeply nested input took > 60s (parser is super-linear: DoS)")
	}
}

func TestHugeInputsBounded(t *testing.T) {
	start := time.Now()
	huge := `{"tenant":"` + strings.Repeat("a", 64<<20) + `"}`
	if _, err := policy.Parse([]byte(huge)); err == nil {
		t.Fatal("huge tenant accepted")
	}
	huge2 := `{"tenant":"bank-a","version":` + strings.Repeat("1", 16<<20) + `}`
	if _, err := policy.Parse([]byte(huge2)); err == nil {
		t.Fatal("huge version accepted")
	}
	if d := time.Since(start); d > 90*time.Second {
		t.Fatalf("hostile large inputs took %v", d)
	}
}

// --- 7. I4: errors never echo payload ------------------------------------

func TestErrorsNeverEchoPayload(t *testing.T) {
	canary := "CANARY-SECRET-9f3a7c"
	mut := []string{
		strings.Replace(validBase, `"bank-a"`, `"`+canary+`"`, 1),
		strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","`+canary+`":1,`, 1),
		strings.Replace(validBase, `"deny"`, `"`+canary+`"`, 1),
		strings.Replace(validBase, `"sales"`, `"`+canary+`"`, 1),
		strings.Replace(validBase, `"crm.update_deal"`, `"`+canary+`!"`, 1),
		strings.Replace(validBase, `"crm.update_deal":"W"`, `"crm.update_deal":"`+canary+`"`, 1),
		strings.Replace(validBase, `"2026-11-05T11:00:00Z"`, `"`+canary+`"`, 1),
		strings.Replace(validBase, `"version":2`, `"version":"`+canary+`"`, 1),
		strings.Replace(validBase, `"tenant":"bank-a",`, `"tenant":"bank-a","tenant":"`+canary+`",`, 1),
		validBase + canary,
		strings.Replace(validBase, `"roles":{`, `"`+canary+`":{`, 1),
		canary,
		`{"` + canary + `"`,
	}
	for i, in := range mut {
		p, err := policy.Parse([]byte(in))
		if err == nil {
			t.Fatalf("case %d: unexpectedly accepted %q", i, abbreviate(in))
		}
		if p != nil {
			t.Fatalf("case %d: non-nil policy with error", i)
		}
		if strings.Contains(err.Error(), canary) || strings.Contains(fmt.Sprintf("%+v %#v", err, err), canary) {
			t.Fatalf("case %d: error echoes payload content (I4): %v", i, err)
		}
		if !errors.Is(err, wire.ErrInvalid) {
			t.Fatalf("case %d: not wire.ErrInvalid: %v", i, err)
		}
	}
}

// --- 8. Concurrency, determinism, input aliasing -------------------------

func TestConcurrentParseAndNoAliasing(t *testing.T) {
	done := make(chan struct{})
	for g := 0; g < 16; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				in := []byte(pl{version: fmt.Sprint(g*1000 + i + 1)}.String())
				p, err := policy.Parse(in)
				if err != nil {
					t.Errorf("parse: %v", err)
					return
				}
				for j := range in {
					in[j] = 'X'
				}
				if p.Version != uint64(g*1000+i+1) || p.Tenant != "bank-a" {
					t.Errorf("policy aliased caller buffer: %+v", p)
					return
				}
			}
		}(g)
	}
	for g := 0; g < 16; g++ {
		<-done
	}
}

func TestParseInputNotModified(t *testing.T) {
	in := []byte(validBase)
	cp := append([]byte(nil), in...)
	_, _ = policy.Parse(in)
	if !bytes.Equal(in, cp) {
		t.Fatal("Parse modified its input")
	}
	bad := []byte(`{"tenant":"x","tenant":"y"}`)
	cp = append([]byte(nil), bad...)
	_, _ = policy.Parse(bad)
	if !bytes.Equal(bad, cp) {
		t.Fatal("Parse modified its input on error path")
	}
}

// --- 9. Differential fuzz against encoding/json ---------------------------

// refStrict is an independent token-stream walk that reports duplicate keys and
// non-exact top-level field names, the two things encoding/json is lenient about.
func refStrict(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	type frame struct {
		obj  bool
		seen map[string]bool
		key  bool // expecting a key
	}
	var stack []frame
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				if len(stack) >= 8 {
					return false
				}
				stack = append(stack, frame{obj: v == '{', seen: map[string]bool{}, key: v == '{'})
			} else {
				stack = stack[:len(stack)-1]
				if n := len(stack); n > 0 && stack[n-1].obj {
					stack[n-1].key = true
				}
			}
		case string:
			if n := len(stack); n > 0 && stack[n-1].obj && stack[n-1].key {
				f := &stack[n-1]
				if f.seen[v] {
					return false
				}
				f.seen[v] = true
				f.key = false
				if n == 1 {
					switch v {
					case "tenant", "version", "issued_at", "expires_at", "default", "roles":
					default:
						return false
					}
				}
				continue
			}
			if n := len(stack); n > 0 && stack[n-1].obj {
				stack[n-1].key = true
			}
		default:
			if n := len(stack); n > 0 && stack[n-1].obj {
				stack[n-1].key = true
			}
		}
		if len(stack) == 0 {
			break
		}
	}
	return true
}

type stdPolicy struct {
	Tenant    string                       `json:"tenant"`
	Version   uint64                       `json:"version"`
	IssuedAt  time.Time                    `json:"issued_at"`
	ExpiresAt time.Time                    `json:"expires_at"`
	Default   string                       `json:"default"`
	Roles     map[string]map[string]string `json:"roles"`
}

func FuzzParseDifferential(f *testing.F) {
	seeds := []string{
		validBase,
		validBase + " ",
		`{}`, ``, `null`, `[]`,
		strings.Replace(validBase, `"tenant"`, `"Tenant"`, 1),
		strings.Replace(validBase, `"version":2,`, `"version":2,"version":3,`, 1),
		strings.Replace(validBase, `"roles"`, "\"roleſ\"", 1),
		strings.Replace(validBase, `"tenant"`, `"tenant"`, 1),
		pl{roles: `{"a":{"x":"R","x":"W"}}`}.String(),
		pl{roles: `{"a":{"*":"R"}}`}.String(),
		pl{roles: `{"a":{"x*":"R","x*":"W"}}`}.String(),
		pl{version: "1e0"}.String(),
		pl{version: "18446744073709551615"}.String(),
		pl{issued: `"2026-11-05T20:00:00+09:00"`}.String(),
		"\xef\xbb\xbf" + validBase,
	}
	root := fixtureRoot()
	if raw, err := os.ReadFile(filepath.Join(root, "cases.json")); err == nil {
		var doc struct {
			Cases []fixtureCase `json:"cases"`
		}
		if json.Unmarshal(raw, &doc) == nil {
			for _, c := range doc.Cases {
				if eb, err := os.ReadFile(filepath.Join(root, c.File)); err == nil {
					var env wire.Envelope
					if json.Unmarshal(eb, &env) == nil {
						seeds = append(seeds, string(env.Payload))
					}
				}
			}
		}
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := policy.Parse(data)
		if err != nil {
			if p != nil {
				t.Fatal("error with non-nil policy")
			}
			if !errors.Is(err, wire.ErrInvalid) {
				t.Fatalf("error does not wrap wire.ErrInvalid: %v", err)
			}
			return
		}
		// Accepted: valid JSON, strictly keyed, and encoding/json must agree.
		if !json.Valid(data) {
			t.Fatalf("accepted invalid JSON %q", data)
		}
		if bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
			t.Fatalf("accepted BOM")
		}
		if !refStrict(data) {
			t.Fatalf("accepted input with duplicate/unknown/case-variant keys: %q", data)
		}
		var sp stdPolicy
		d := json.NewDecoder(bytes.NewReader(data))
		d.DisallowUnknownFields()
		if err := d.Decode(&sp); err != nil {
			t.Fatalf("encoding/json rejects what Parse accepted: %v on %q", err, data)
		}
		if sp.Tenant != string(p.Tenant) || sp.Version != p.Version || !sp.IssuedAt.Equal(p.IssuedAt) || !sp.ExpiresAt.Equal(p.ExpiresAt) {
			t.Fatalf("differential mismatch on scalar fields: std=%+v parse=%+v", sp, p)
		}
		if sp.Default != "deny" || p.Version == 0 || !p.ExpiresAt.After(p.IssuedAt) || !p.Tenant.Valid() {
			t.Fatalf("accepted a policy violating section 10.0: %q", data)
		}
		if len(sp.Roles) > policy.MaxRoles {
			t.Fatalf("too many roles accepted")
		}
		for r, m := range sp.Roles {
			if !wire.ID(r).Valid() || len(m) > policy.MaxPatterns {
				t.Fatalf("bad role accepted: %q", r)
			}
			for k, c := range m {
				if c != "R" && c != "W" && c != "X" {
					t.Fatalf("bad class accepted: %q", c)
				}
				body := strings.TrimSuffix(k, "*")
				if k == "*" || len(k) == 0 || len(k) > 128 || strings.ContainsRune(body, '*') {
					t.Fatalf("bad pattern accepted: %q", k)
				}
				for _, ch := range body {
					if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '.' || ch == '-') {
						t.Fatalf("bad char in pattern accepted: %q", k)
					}
				}
			}
		}
		p2, err2 := policy.Parse(data)
		if err2 != nil || p2.Version != p.Version || p2.Tenant != p.Tenant {
			t.Fatalf("Parse is not deterministic")
		}
	})
}
