package policybreak

import (
	"strings"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// The exact example printed in ARCHITECTURE section 10.0, pretty-printed.
const archExample = `{
  "tenant": "bank-a",
  "version": 8,
  "issued_at": "2026-11-05T09:00:00Z",
  "expires_at": "2026-11-08T09:00:00Z",
  "default": "deny",
  "roles": {
    "sales":    { "crm.read_*": "R", "crm.update_deal": "W" },
    "engineer": { "github.*": "R", "github.create_issue": "W", "ci.rerun": "X" }
  }
}`

func TestArchitectureExampleParses(t *testing.T) {
	p := mustAccept(t, "arch-10.0-example", "ARCH 10.0 example must be a valid policy", archExample)
	if p == nil {
		return
	}
	if p.Tenant != "bank-a" || p.Version != 8 ||
		!p.IssuedAt.Equal(time.Date(2026, 11, 5, 9, 0, 0, 0, time.UTC)) ||
		!p.ExpiresAt.Equal(time.Date(2026, 11, 8, 9, 0, 0, 0, time.UTC)) {
		t.Fatalf("example parsed wrong: %+v", p)
	}
	// Interior whitespace of every JSON flavour is fine.
	mustAccept(t, "crlf-and-tabs", "JSON whitespace between tokens", strings.ReplaceAll(archExample, "\n", "\r\n\t"))
}

func TestTrailingWhitespaceIsNotAnAttackSurface(t *testing.T) {
	// Not pinned by the docs either way (T-D1 says nothing): the outcome must just
	// be a clean accept or a clean wire.ErrInvalid, never a different policy.
	for _, tail := range []string{"\n", " ", "\r\n", "\t", "\n\n"} {
		p, err := policy.Parse([]byte(validBase + tail))
		if err == nil && (p.Version != 2 || p.Tenant != "bank-a") {
			t.Fatalf("tail %q changed the policy: %+v", tail, p)
		}
	}
}

func TestPayloadOverEnvelopeCapIsMalformed(t *testing.T) {
	// T-D1 (accepted): a payload cannot exceed wire.MaxEnvelopeBytes. A valid policy
	// padded with insignificant whitespace past the cap must be refused.
	pad := strings.Repeat(" ", wire.MaxEnvelopeBytes)
	mustReject(t, "padded-past-cap", "T-D1: payload over wire.MaxEnvelopeBytes is malformed",
		"{"+pad+validBase[1:])
	// Same, with the extra bytes inside a role name list (many valid patterns).
	var b strings.Builder
	b.WriteString(`{"a":{`)
	for i := 0; b.Len() < wire.MaxEnvelopeBytes+1024; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"tool_number_` + strings.Repeat("x", 40) + itoa(i) + `":"R"`)
	}
	b.WriteString("}}")
	mustReject(t, "many-patterns-past-cap", "T-D1 cap or MaxPatterns, either way malformed",
		pl{roles: b.String()}.String())
}

func itoa(i int) string {
	const d = "0123456789"
	if i == 0 {
		return "0"
	}
	var s []byte
	for i > 0 {
		s = append([]byte{d[i%10]}, s...)
		i /= 10
	}
	return string(s)
}
