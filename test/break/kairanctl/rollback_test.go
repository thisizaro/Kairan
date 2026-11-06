package kairanctlbreak

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/trust"
)

// T-D4: rollback = the same rules re-issued as a new, higher version with fresh
// validity, written as an UNSIGNED payload unless two different keys and
// -env-out are all given.

var rollbackRoles = `{"sales":{"crm.read_*":"R","crm.update_deal":"W","crm.export":"X"},"engineer":{"github.*":"R","ci.rerun":"X"}}`

func sameRules(t *testing.T, a, b *policy.Policy) {
	t.Helper()
	probes := []string{"crm.read_x", "crm.read_", "crm.update_deal", "crm.export", "crm.other", "github.x", "github.create", "ci.rerun", "ci.other", "nothing"}
	for _, role := range []string{"sales", "engineer", "nobody"} {
		for _, tool := range probes {
			for _, safe := range []bool{false, true} {
				if x, y := a.Decide(role, tool, safe), b.Decide(role, tool, safe); x != y {
					t.Fatalf("rollback changed the rules: %s/%s safe=%v: %+v vs %+v", role, tool, safe, x, y)
				}
			}
		}
	}
}

func TestRollbackKeepsRulesRaisesVersion(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	old := payload("bank-a", 3, rollbackRoles)
	writeFile(t, filepath.Join(d, "old.json"), old, 0o644)
	op, err := policy.Parse(old)
	if err != nil {
		t.Fatal(err)
	}

	r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "old.json", "-version", "9", "-out", "new.json", "-validity", "48h")
	if r.code != 0 {
		t.Fatalf("rollback: exit %d: %s%s", r.code, r.stdout, r.stderr)
	}
	nb, _ := os.ReadFile(filepath.Join(d, "new.json"))
	np, err := policy.Parse(nb)
	if err != nil {
		t.Fatalf("rollback wrote an invalid payload: %v", err)
	}
	if np.Tenant != op.Tenant || np.Version != 9 {
		t.Fatalf("tenant/version: %+v", np)
	}
	if np.ExpiresAt.Sub(np.IssuedAt) != 48*time.Hour {
		t.Fatalf("validity %v, want 48h", np.ExpiresAt.Sub(np.IssuedAt))
	}
	if d := time.Since(np.IssuedAt); d < -2*time.Minute || d > 2*time.Minute {
		t.Fatalf("issued_at %v is not fresh (J6: re-publish as a new policy)", np.IssuedAt)
	}
	sameRules(t, op, np)
	if strings.Contains(r.stdout+r.stderr, "signature") && !strings.Contains(strings.ToLower(r.stdout+r.stderr), "unsigned") && !strings.Contains(r.stdout+r.stderr, "not signed") {
		t.Logf("note: rollback output should say that the payload is unsigned: %s", r.stdout)
	}
	// Rollback from a signed envelope as the source works the same.
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "old.json", "-out", "oldenv.json")
	runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "oldenv.json", "-yes")
	r = runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "oldenv.json", "-version", "10", "-out", "new2.json")
	if r.code != 0 {
		t.Fatalf("rollback from envelope: %s%s", r.stdout, r.stderr)
	}
	nb2, _ := os.ReadFile(filepath.Join(d, "new2.json"))
	np2, err := policy.Parse(nb2)
	if err != nil || np2.Version != 10 {
		t.Fatalf("rollback from envelope: %v %+v", err, np2)
	}
	sameRules(t, op, np2)
}

func TestRollbackVersionMustRise(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	writeFile(t, filepath.Join(d, "old.json"), payload("bank-a", 5, rollbackRoles), 0o644)
	for _, v := range []string{"5", "4", "1", "0"} {
		out := "bad" + v + ".json"
		r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "old.json", "-version", v, "-out", out)
		if r.code == 0 {
			t.Fatalf("version %s <= old version 5 accepted (I2: versions only grow)", v)
		}
		if _, err := os.Stat(filepath.Join(d, out)); err == nil {
			t.Fatalf("version %s refused but %s written", v, out)
		}
	}
	for _, v := range []string{"-1", "x", "", "99999999999999999999999"} {
		r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "old.json", "-version", v, "-out", "weird.json")
		if r.code == 0 {
			t.Fatalf("version %q accepted", v)
		}
	}
	if r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "old.json", "-version", "6", "-out", "ok.json", "-validity", "0s"); r.code == 0 {
		t.Fatal("zero validity accepted")
	}
	if r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "old.json", "-version", "6", "-out", "ok.json", "-validity", "-1h"); r.code == 0 {
		t.Fatal("negative validity accepted")
	}
}

func TestRollbackRefusesBadSources(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	i, e := nowish()
	ts := `"issued_at":"` + i.Format(time.RFC3339) + `","expires_at":"` + e.Format(time.RFC3339) + `"`
	srcs := map[string]string{
		"dup-role":    `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{"s":{"a":"R"},"s":{"a.*":"X"}}}`,
		"case":        `{"Tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{}}`,
		"garbage":     `hello`,
		"empty":       ``,
		"trailing":    string(payload("bank-a", 2, rollbackRoles)) + `{}`,
		"env-no-body": `{"payloadType":"application/vnd.kairan.policy+json","payload":"","signatures":[]}`,
	}
	for n, c := range srcs {
		writeFile(t, filepath.Join(d, n+".json"), []byte(c), 0o644)
		out := n + ".out"
		r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", n+".json", "-version", "50", "-out", out)
		if r.code == 0 {
			t.Fatalf("%s: rollback accepted an invalid source", n)
		}
		if _, err := os.Stat(filepath.Join(d, out)); err == nil {
			t.Fatalf("%s: refused but wrote output", n)
		}
	}
	if r := runIn(t, bin, d, nil, "", "rollout", "rollback", "-from", "missing.json", "-version", "5", "-out", "x.json"); r.code == 0 {
		t.Fatal("missing source accepted")
	}
}

func TestRollbackSigningRules(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	writeFile(t, filepath.Join(d, "old.json"), payload("bank-a", 3, rollbackRoles), 0o644)
	base := []string{"rollout", "rollback", "-from", "old.json", "-version", "8"}

	// Only one key, or keys without -env-out, or same key twice: never a signed (let alone 1-sig) envelope.
	cases := map[string][]string{
		"one-key-with-env-out":     {"-out", "p1.json", "-key", a.keyFile, "-env-out", "e1.json"},
		"two-keys-no-env-out":      {"-out", "p2.json", "-key", a.keyFile, "-key2", b.keyFile},
		"same-key-twice":           {"-out", "p3.json", "-key", a.keyFile, "-key2", a.keyFile, "-env-out", "e3.json"},
		"key2-only":                {"-out", "p4.json", "-key2", b.keyFile, "-env-out", "e4.json"},
		"env-out-only":             {"-out", "p5.json", "-env-out", "e5.json"},
		"same-key-different-paths": {"-out", "p6.json", "-key", a.keyFile, "-key2", filepath.Join(d, ".", "alice.key"), "-env-out", "e6.json"},
	}
	for n, extra := range cases {
		r := runIn(t, bin, d, nil, "", append(append([]string{}, base...), extra...)...)
		_ = r
		for _, f := range []string{"e1.json", "e3.json", "e4.json", "e5.json", "e6.json"} {
			bs, err := os.ReadFile(filepath.Join(d, f))
			if err != nil {
				continue
			}
			var env struct {
				Signatures []json.RawMessage `json:"signatures"`
			}
			_ = json.Unmarshal(bs, &env)
			t.Errorf("%s: wrote envelope %s with %d signatures; only two different keys may sign (T-D4)", n, f, len(env.Signatures))
			os.Remove(filepath.Join(d, f))
		}
	}
	// Two different keys + -env-out: a real 2-of-N envelope for the new version.
	r := runIn(t, bin, d, nil, "", append(append([]string{}, base...), "-out", "pok.json", "-key", a.keyFile, "-key2", b.keyFile, "-env-out", "eok.json")...)
	if r.code != 0 {
		t.Fatalf("rollback with two keys: %s%s", r.stdout, r.stderr)
	}
	e := readEnv(t, filepath.Join(d, "eok.json"))
	pb, _ := os.ReadFile(filepath.Join(d, "pok.json"))
	if string(e.Payload) != string(pb) {
		t.Fatal("envelope payload is not the written payload file")
	}
	v, code, err := trust.Accept(e, rootFor("bank-a", a, b), 3, time.Now().Add(time.Minute), time.Minute)
	if code != "" || err != nil {
		t.Fatalf("rollback envelope rejected by trust.Accept: %q %v", code, err)
	}
	if v.Policy.Version != 8 || len(v.Signers) != 2 {
		t.Fatalf("%+v", v)
	}
	// The envelope never replaces the old one at a lower version: old v3 offered after v8 is refused (I2).
	// Loose key mode refused here too.
	loose := filepath.Join(d, "loose.key")
	writeFile(t, loose, []byte(a.seedHex+"\n"), 0o644)
	if r := runIn(t, bin, d, nil, "", append(append([]string{}, base...), "-out", "ploose.json", "-key", loose, "-key2", b.keyFile, "-env-out", "eloose.json")...); r.code == 0 {
		t.Fatal("rollback signed with a world-readable key file")
	}
	if _, err := os.Stat(filepath.Join(d, "eloose.json")); err == nil {
		t.Fatal("envelope written with a loose key")
	}
}
