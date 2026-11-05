package main

import (
	"flag"
	"fmt"
	"time"

	"kairan/internal/policy"
	"kairan/internal/wire"
)

// cmdPolicyNew writes a policy payload template: default deny, one example
// role, valid from now for the given period (72h by default, PRD). The
// output is checked with policy.Parse before it is written. The admin edits
// the roles, then signs the file as it is; kairanctl never re-encodes it.
func cmdPolicyNew(args []string, s streams) error {
	fs := flag.NewFlagSet("policy new", flag.ContinueOnError)
	tenant := fs.String("tenant", "", "tenant ID (lowercase letters, digits, '-')")
	version := fs.Uint64("version", 1, "policy version (>= 1, must rise with every policy)")
	validity := fs.Duration("validity", 72*time.Hour, "how long the policy stays valid")
	out := fs.String("out", "", "file to create; default is standard output")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if !wire.ID(*tenant).Valid() {
		return fail("-tenant must be a valid tenant ID (lowercase letters, digits and '-')",
			"-tenant には有効なテナントID (小文字の英数字と '-') を指定してください")
	}
	if *version < 1 {
		return fail("-version must be at least 1", "-version は1以上にしてください")
	}
	if *validity < time.Second || *validity%time.Second != 0 {
		return fail("-validity must be a positive whole number of seconds, for example 72h",
			"-validity は1秒以上の整数秒で指定してください (例: 72h)")
	}
	issued := s.now().UTC().Truncate(time.Second)
	expires := issued.Add(*validity)
	payload := []byte(fmt.Sprintf(`{
  "tenant": %q,
  "version": %d,
  "issued_at": %q,
  "expires_at": %q,
  "default": "deny",
  "roles": {
    "example": { "notes.read": "R" }
  }
}
`, *tenant, *version, issued.Format(time.RFC3339), expires.Format(time.RFC3339)))
	if _, err := policy.Parse(payload); err != nil {
		return fail("these values do not make a valid policy (check -validity)",
			"この値では有効なポリシーになりません (-validity を確認してください)").because(err)
	}
	if *out == "" {
		_, err := s.out.Write(payload)
		return err
	}
	if err := createExclusive(*out, payload, 0o644); err != nil {
		return writeErr(err)
	}
	fmt.Fprintf(s.out, "wrote %s: edit the roles, then sign it with: kairanctl sign\n", *out)
	return nil
}
