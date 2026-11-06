package kairanctlbreak

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/policy"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

// --- helpers ---

type kp struct {
	name      string
	keyFile   string
	pubFile   string
	priv      ed25519.PrivateKey
	pub       ed25519.PublicKey
	seedHex   string
	stdoutLog string
}

func keygen(t *testing.T, bin, dir, name string) kp {
	t.Helper()
	r := runIn(t, bin, dir, nil, "", "keygen", "-name", name)
	if r.code != 0 {
		t.Fatalf("keygen %s: exit %d: %s%s", name, r.code, r.stdout, r.stderr)
	}
	sb, err := os.ReadFile(filepath.Join(dir, name+".key"))
	if err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(sb)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("%s.key is not a 64-hex seed (T-D3): %q", name, sb)
	}
	pk := ed25519.NewKeyFromSeed(seed)
	return kp{name: name, keyFile: filepath.Join(dir, name+".key"), pubFile: filepath.Join(dir, name+".pub"),
		priv: pk, pub: pk.Public().(ed25519.PublicKey), seedHex: strings.TrimSpace(string(sb)), stdoutLog: r.stdout + r.stderr}
}

func keyID(p ed25519.PublicKey) wire.Hash {
	s := sha256.Sum256(p)
	return wire.Hash(hex.EncodeToString(s[:]))
}

func rootFor(tenant string, ks ...kp) trust.Root {
	m := map[wire.Hash]ed25519.PublicKey{}
	for _, k := range ks {
		m[keyID(k.pub)] = k.pub
	}
	return trust.Root{Tenant: wire.ID(tenant), Keys: m, Threshold: 2}
}

func writeFile(t testing.TB, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, b, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readEnv(t testing.TB, path string) wire.Envelope {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := trust.DecodeEnvelope(b)
	if err != nil {
		t.Fatalf("%s is not a valid envelope: %v", path, err)
	}
	return e
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func nowish() (time.Time, time.Time) {
	n := time.Now().UTC().Truncate(time.Second)
	return n.Add(-time.Minute), n.Add(72 * time.Hour)
}

// payload builds a valid policy payload with the given raw roles JSON.
func payload(tenant string, version int, roles string) []byte {
	i, e := nowish()
	return []byte(`{"tenant":"` + tenant + `","version":` + itoa(version) + `,"issued_at":"` + i.Format(time.RFC3339) + `","expires_at":"` + e.Format(time.RFC3339) + `","default":"deny","roles":` + roles + `}`)
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

const stdRoles = `{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}`

// --- keygen (M-D37, T-D3) ---

func TestKeygenMode0600AndNoOverwrite(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	k := keygen(t, bin, d, "alice")

	fi, err := os.Stat(k.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode %v, want 0600 (M-D37)", fi.Mode().Perm())
	}
	pb, _ := os.ReadFile(k.pubFile)
	if strings.TrimSpace(string(pb)) != hex.EncodeToString(k.pub) {
		t.Fatalf("alice.pub %q does not match the private key", pb)
	}
	if strings.Contains(k.stdoutLog, k.seedHex) {
		t.Fatal("keygen printed the private seed")
	}
	if !strings.Contains(k.stdoutLog, string(keyID(k.pub))) {
		t.Logf("note: keygen does not print the key ID")
	}

	before, _ := os.ReadFile(k.keyFile)
	for i := 0; i < 3; i++ {
		r := runIn(t, bin, d, nil, "", "keygen", "-name", "alice")
		if r.code == 0 {
			t.Fatalf("keygen overwrote an existing key (exit 0) (M-D37)")
		}
	}
	after, _ := os.ReadFile(k.keyFile)
	if !bytes.Equal(before, after) {
		t.Fatal("existing private key content changed")
	}
}

func TestKeygenUmaskCannotWiden(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	// sh -c 'umask 0; exec kairanctl ...': a permissive umask must not give group/other access to the key.
	r := runShell(t, d, "umask 0; exec "+shq(bin)+" keygen -name loose")
	if r.code != 0 {
		t.Fatalf("keygen failed: %s%s", r.stdout, r.stderr)
	}
	fi, err := os.Stat(filepath.Join(d, "loose.key"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("with umask 0 the key has mode %v; group/other must never have access", fi.Mode().Perm())
	}
}

func TestKeygenRefusesSymlinkAndPartialOverwrite(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	victimDir := t.TempDir()
	victim := filepath.Join(victimDir, "victim")

	// 1. dangling symlink NAME.key -> victim: keygen must not write through it.
	if err := os.Symlink(victim, filepath.Join(d, "evil.key")); err != nil {
		t.Fatal(err)
	}
	r := runIn(t, bin, d, nil, "", "keygen", "-name", "evil")
	if r.code == 0 {
		t.Fatal("keygen succeeded over a symlinked key path")
	}
	if _, err := os.Lstat(victim); err == nil {
		t.Fatal("keygen wrote through the symlink to a file elsewhere (private key may land outside the dir)")
	}

	// 2. existing NAME.pub only: refuse, and leave no stray private key behind.
	writeFile(t, filepath.Join(d, "half.pub"), []byte("keep me\n"), 0o644)
	r = runIn(t, bin, d, nil, "", "keygen", "-name", "half")
	if r.code == 0 {
		t.Fatal("keygen overwrote an existing .pub (M-D37: refuses to overwrite an existing file)")
	}
	if got, _ := os.ReadFile(filepath.Join(d, "half.pub")); string(got) != "keep me\n" {
		t.Fatalf("existing .pub was modified: %q", got)
	}
	if _, err := os.Stat(filepath.Join(d, "half.key")); err == nil {
		t.Fatal("keygen left a new private key whose public half was refused (orphan key)")
	}
}

func TestKeygenIsRandomAndDirRespected(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	sub := filepath.Join(d, "keys")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	a := keygen(t, bin, d, "a")
	b := keygen(t, bin, d, "b")
	if a.seedHex == b.seedHex {
		t.Fatal("two keygens produced the same key")
	}
	r := runIn(t, bin, d, nil, "", "keygen", "-name", "c", "-dir", sub)
	if r.code != 0 {
		t.Fatalf("keygen -dir: %s%s", r.stdout, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(sub, "c.key")); err != nil {
		t.Fatal("key not written to -dir")
	}
	if _, err := os.Stat(filepath.Join(d, "c.key")); err == nil {
		t.Fatal("key also written to cwd")
	}
	// Bad names: no key may appear outside the dir.
	outside := t.TempDir()
	for _, n := range []string{"../escape", "a/b", "", ".", ".."} {
		runIn(t, bin, sub, nil, "", "keygen", "-name", n)
	}
	for _, p := range []string{filepath.Join(sub, "..", "escape.key"), filepath.Join(sub, "..", "escape.pub")} {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("keygen -name ../escape wrote %s outside -dir", p)
		}
	}
	_ = outside
}

// --- policy new ---

func TestPolicyNewProducesStrictValidPolicy(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	r := runIn(t, bin, d, nil, "", "policy", "new", "-tenant", "bank-a", "-version", "7", "-validity", "24h", "-out", "p.json")
	if r.code != 0 {
		t.Fatalf("policy new: %s%s", r.stdout, r.stderr)
	}
	b, _ := os.ReadFile(filepath.Join(d, "p.json"))
	p, err := policy.Parse(b)
	if err != nil {
		t.Fatalf("policy new wrote something policy.Parse rejects: %v\n%s", err, b)
	}
	if p.Tenant != "bank-a" || p.Version != 7 || p.ExpiresAt.Sub(p.IssuedAt) != 24*time.Hour {
		t.Fatalf("fields wrong: %+v", p)
	}
	// Default validity 72h (PRD section 7).
	r = runIn(t, bin, d, nil, "", "policy", "new", "-tenant", "bank-a")
	p2, err := policy.Parse([]byte(r.stdout))
	if err != nil {
		t.Fatalf("stdout payload rejected: %v\n%s", err, r.stdout)
	}
	if p2.ExpiresAt.Sub(p2.IssuedAt) != 72*time.Hour || p2.Version != 1 {
		t.Fatalf("defaults wrong: %+v", p2)
	}
	// Bad inputs must be refused, never produce a file.
	bad := [][]string{
		{"-tenant", ""}, {"-tenant", "Bank-A"}, {"-tenant", "bank a"}, {"-tenant", "-x"}, {"-tenant", strings.Repeat("a", 64)},
		{"-tenant", "bank-a", "-version", "0"}, {"-tenant", "bank-a", "-version", "-1"}, {"-tenant", "bank-a", "-version", "1.5"},
		{"-tenant", "bank-a", "-validity", "0s"}, {"-tenant", "bank-a", "-validity", "-1h"}, {"-tenant", "bank-a", "-validity", "x"},
		{"-tenant", `bank-a","default":"allow`},
	}
	for i, a := range bad {
		out := "bad" + itoa(i) + ".json"
		r := runIn(t, bin, d, nil, "", append(append([]string{"policy", "new"}, a...), "-out", out)...)
		if r.code == 0 {
			t.Fatalf("policy new %v accepted", a)
		}
		if _, err := os.Stat(filepath.Join(d, out)); err == nil {
			t.Fatalf("policy new %v refused but left %s behind", a, out)
		}
	}
}

// --- sign ---

func TestSignKeepsExactBytesAndVerifies(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	// Odd but valid formatting: escapes in names, odd spacing, trailing whitespace, key order.
	p := payload("bank-a", 4, `{ "s\u0061les" :  { "crm.read_\u002a":"R" ,"crm.\u0075pdate_deal" : "W" } }`)
	p = append(p, "\n\n  \t\n"...)
	writeFile(t, filepath.Join(d, "p.json"), p, 0o644)
	r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "p.json", "-out", "e.json")
	if r.code != 0 {
		t.Fatalf("sign: %s%s", r.stdout, r.stderr)
	}
	e := readEnv(t, filepath.Join(d, "e.json"))
	if !bytes.Equal(e.Payload, p) {
		t.Fatalf("signed payload differs from the file: sign must not re-encode (PRD Envelope)\nfile: %q\nenv:  %q", p, e.Payload)
	}
	if len(e.Signatures) != 1 || e.PayloadType != wire.PayloadTypePolicy {
		t.Fatalf("envelope shape: %+v", e)
	}
	if !ed25519.Verify(a.pub, trust.PAE(e.PayloadType, e.Payload), e.Signatures[0].Sig) || e.Signatures[0].KeyID != keyID(a.pub) {
		t.Fatal("signature does not verify over the DSSE PAE / key ID wrong (M-D2)")
	}
	if !strings.Contains(r.stdout, sha(p)) {
		t.Logf("note: sign output does not show the payload hash")
	}
	if strings.Contains(r.stdout+r.stderr, a.seedHex) {
		t.Fatal("sign printed key material")
	}
	// Second signature via approve keeps the exact bytes and the full envelope passes trust.Accept.
	r = runIn(t, bin, d, nil, "yes\n", "approve", "-key", b.keyFile, "-in", "e.json", "-trusted", a.pubFile)
	if r.code != 0 {
		t.Fatalf("approve: %s%s", r.stdout, r.stderr)
	}
	e = readEnv(t, filepath.Join(d, "e.json"))
	if !bytes.Equal(e.Payload, p) {
		t.Fatal("approve changed the signed bytes")
	}
	i, _ := nowish()
	v, code, err := trust.Accept(e, rootFor("bank-a", a, b), 3, i.Add(2*time.Minute), time.Minute)
	if code != "" || err != nil {
		t.Fatalf("sign+approve envelope rejected by trust.Accept: %q %v", code, err)
	}
	if v.Hash != wire.Hash(sha(p)) {
		t.Fatal("hash is not over the exact bytes")
	}
	// The escaped spelling in the file means the same enforced rule once parsed.
	if d := v.Policy.Decide("sales", "crm.read_x", false); !d.Allowed || d.Rule != "crm.read_*" {
		t.Fatalf("decode of escaped names: %+v", d)
	}
}

func TestSignRefusals(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a := keygen(t, bin, d, "alice")
	good := payload("bank-a", 2, stdRoles)
	writeFile(t, filepath.Join(d, "good.json"), good, 0o644)

	i, e := nowish()
	ts := `"issued_at":"` + i.Format(time.RFC3339) + `","expires_at":"` + e.Format(time.RFC3339) + `"`
	badPayloads := map[string]string{
		"duplicate-role":  `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{"s":{"a":"R"},"s":{"a.*":"X"}}}`,
		"duplicate-tool":  `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{"s":{"a":"R","a":"X"}}}`,
		"duplicate-field": `{"tenant":"bank-a","tenant":"city-b","version":2,` + ts + `,"default":"deny","roles":{}}`,
		"case-variant":    `{"Tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{}}`,
		"default-allow":   `{"tenant":"bank-a","version":2,` + ts + `,"default":"allow","roles":{}}`,
		"bare-star":       `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{"s":{"*":"X"}}}`,
		"trailing-object": string(good) + ` {"version":99}`,
		"empty":           ``,
		"not-json":        `hello`,
		"unknown-field":   `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{},"extra":1}`,
		"escape-in-role":  `{"tenant":"bank-a","version":2,` + ts + `,"default":"deny","roles":{"\u001b[31mred":{"a":"R"}}}`,
		"version-zero":    `{"tenant":"bank-a","version":0,` + ts + `,"default":"deny","roles":{}}`,
		"expires-before":  `{"tenant":"bank-a","version":2,"issued_at":"2026-11-08T00:00:00Z","expires_at":"2026-11-05T00:00:00Z","default":"deny","roles":{}}`,
		"leading-bom":     "\ufeff" + string(good),
		"trailing-nul":    string(good) + "\x00",
	}
	for n, p := range badPayloads {
		writeFile(t, filepath.Join(d, n+".json"), []byte(p), 0o644)
		out := n + ".env"
		r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", n+".json", "-out", out)
		if r.code == 0 {
			t.Fatalf("%s: sign accepted an invalid payload (T-D3: sign runs policy.Parse first)", n)
		}
		if _, err := os.Stat(filepath.Join(d, out)); err == nil {
			t.Fatalf("%s: refused but left an envelope", n)
		}
		if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
			t.Fatalf("%s: output contains an escape character", n)
		}
	}

	// Key hygiene (T-D3): group/other-accessible key files are refused, as are non-regular files.
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604, 0o660, 0o666, 0o604, 0o601, 0o610, 0o602, 0o620} {
		kf := filepath.Join(d, "loose.key")
		writeFile(t, kf, []byte(a.seedHex+"\n"), mode)
		out := "loose-" + itoa(int(mode)) + ".env"
		r := runIn(t, bin, d, nil, "", "sign", "-key", kf, "-in", "good.json", "-out", out)
		if r.code == 0 {
			t.Fatalf("sign used a key file with mode %v (T-D3: refuse group/other-accessible keys)", mode)
		}
		if _, err := os.Stat(filepath.Join(d, out)); err == nil {
			t.Fatalf("mode %v refused but envelope written", mode)
		}
		if strings.Contains(r.stdout+r.stderr, a.seedHex) {
			t.Fatal("key material printed")
		}
	}
	// Garbage key contents.
	for n, c := range map[string]string{"short": "abcd\n", "nothex": strings.Repeat("zz", 32) + "\n", "empty": "", "pubkey-hex-too-long": strings.Repeat("ab", 64) + "\n"} {
		kf := filepath.Join(d, n+".key")
		writeFile(t, kf, []byte(c), 0o600)
		if r := runIn(t, bin, d, nil, "", "sign", "-key", kf, "-in", "good.json", "-out", n+".env"); r.code == 0 {
			t.Fatalf("sign accepted key file %s", n)
		}
	}
	// -out is never overwritten (T-D3).
	writeFile(t, filepath.Join(d, "exists.env"), []byte("precious"), 0o644)
	if r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "good.json", "-out", "exists.env"); r.code == 0 {
		t.Fatal("sign overwrote an existing -out file")
	}
	if got, _ := os.ReadFile(filepath.Join(d, "exists.env")); string(got) != "precious" {
		t.Fatalf("existing -out was modified: %q", got)
	}
	// Symlink -out must not write through it.
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.Symlink(victim, filepath.Join(d, "link.env"))
	if r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "good.json", "-out", "link.env"); r.code == 0 {
		if _, err := os.Lstat(victim); err == nil {
			t.Fatal("sign wrote through a symlinked -out")
		}
	}
	// Missing args are usage errors, not crashes.
	for _, args := range [][]string{{"sign"}, {"sign", "-key", a.keyFile}, {"sign", "-in", "good.json"}, {"sign", "-key", "nope.key", "-in", "good.json", "-out", "x.env"}, {"sign", "-key", a.keyFile, "-in", "nope.json", "-out", "x.env"}} {
		r := runIn(t, bin, d, nil, "", args...)
		if r.code == 0 || strings.Contains(r.stderr, "panic") || strings.Contains(r.stderr, "goroutine ") {
			t.Fatalf("%v: exit %d, stderr %q", args, r.code, r.stderr)
		}
	}
}

// --- approve (M-D32, T-D3) ---

func TestApproveShowsRenderedPolicyNotRawText(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	// Valid policy whose raw text spells names with escapes and carries a decoy
	// comment-like string inside a tool name's neighbour; the approver must see
	// what is enforced: the decoded role and the decoded wildcard.
	raw := payload("bank-a", 5, `{"s\u0061les":{"crm.read_\u002a":"R","crm.\u0075pdate_deal":"W"},"\u0065ngineer":{"ci.rerun":"X"}}`)
	writeFile(t, filepath.Join(d, "p.json"), raw, 0o644)
	if r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "p.json", "-out", "e.json"); r.code != 0 {
		t.Fatalf("sign: %s%s", r.stdout, r.stderr)
	}
	r := runIn(t, bin, d, nil, "yes\n", "approve", "-key", b.keyFile, "-in", "e.json")
	if r.code != 0 {
		t.Fatalf("approve: %s%s", r.stdout, r.stderr)
	}
	out := r.stdout
	for _, want := range []string{"bank-a", "sales", "crm.read_*", "crm.update_deal", "engineer", "ci.rerun", sha(raw)} {
		if !strings.Contains(out, want) {
			t.Errorf("approve output lacks %q (M-D32: rendered policy + payload hash)\n%s", want, out)
		}
	}
	for _, leak := range []string{`\u0061`, `\u002a`, `\u0075`, `\u0065`, `"tenant"`, `{"s`} {
		if strings.Contains(out, leak) {
			t.Errorf("approve output contains raw text %q: M-D32 says never the raw document\n%s", leak, out)
		}
	}
	// Class letters must be visible per tool.
	if !strings.Contains(out, "X") || !strings.Contains(out, "W") {
		t.Errorf("classes not shown")
	}
}

func TestApproveRefusesWithoutTypedYes(t *testing.T) {
	bin := buildCtl(t)
	for _, in := range []string{"", "\n", "no\n", "n\n", "NO\n", "ye\n", "yess\n", " \n", "yes", "y\n", "No, yes\n", "\x00yes\n", "q\nyes\n"} {
		d := t.TempDir()
		a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
		writeFile(t, filepath.Join(d, "p.json"), payload("bank-a", 2, stdRoles), 0o644)
		runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "p.json", "-out", "e.json")
		before, _ := os.ReadFile(filepath.Join(d, "e.json"))
		r := runIn(t, bin, d, nil, in, "approve", "-key", b.keyFile, "-in", "e.json")
		after, _ := os.ReadFile(filepath.Join(d, "e.json"))
		if in == "yes" {
			// EOF right after "yes" without newline is an answer of "yes"; either outcome is defensible.
			continue
		}
		if r.code == 0 || !bytes.Equal(before, after) {
			t.Fatalf("stdin %q: approve signed without a typed 'yes' (exit %d)", in, r.code)
		}
	}
}

func TestApproveRefusals(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b, c, out := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob"), keygen(t, bin, d, "carol"), keygen(t, bin, d, "mallory")
	writeFile(t, filepath.Join(d, "p.json"), payload("bank-a", 2, stdRoles), 0o644)
	if r := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "p.json", "-out", "e1.json"); r.code != 0 {
		t.Fatalf("sign: %s%s", r.stdout, r.stderr)
	}
	e1, _ := os.ReadFile(filepath.Join(d, "e1.json"))

	unchanged := func(t *testing.T, name string, r result) {
		t.Helper()
		got, _ := os.ReadFile(filepath.Join(d, "e1.json"))
		if r.code == 0 {
			t.Fatalf("%s: approve succeeded", name)
		}
		if !bytes.Equal(got, e1) {
			t.Fatalf("%s: refused but e1.json was modified", name)
		}
		if strings.ContainsRune(r.stdout+r.stderr, 0x1b) {
			t.Fatalf("%s: escape character in output", name)
		}
	}
	t.Run("same-key-again", func(t *testing.T) {
		unchanged(t, "same key", runIn(t, bin, d, nil, "yes\n", "approve", "-key", a.keyFile, "-in", "e1.json", "-yes"))
	})
	t.Run("same-key-after-approval-in-out-file", func(t *testing.T) {
		if r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e1.json", "-out", "e2.json", "-yes"); r.code != 0 {
			t.Fatalf("approve -out: %s%s", r.stdout, r.stderr)
		}
		got, _ := os.ReadFile(filepath.Join(d, "e1.json"))
		if !bytes.Equal(got, e1) {
			t.Fatal("approve -out modified -in")
		}
		e2 := readEnv(t, filepath.Join(d, "e2.json"))
		if len(e2.Signatures) != 2 {
			t.Fatalf("e2 has %d sigs", len(e2.Signatures))
		}
		// bob again on e2: refused
		if r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e2.json", "-out", "e3.json", "-yes"); r.code == 0 {
			t.Fatal("same key signed twice via a chain (four-eyes bypass)")
		}
		if _, err := os.Stat(filepath.Join(d, "e3.json")); err == nil {
			t.Fatal("refusal left e3.json")
		}
		// -out never overwrites.
		if r := runIn(t, bin, d, nil, "", "approve", "-key", c.keyFile, "-in", "e2.json", "-out", "e2.json", "-yes"); r.code == 0 {
			t.Fatal("approve -out overwrote an existing file")
		}
		if r := runIn(t, bin, d, nil, "", "approve", "-key", c.keyFile, "-in", "e1.json", "-out", "e2.json", "-yes"); r.code == 0 {
			t.Fatal("approve -out overwrote e2.json")
		}
		if r, _ := os.ReadFile(filepath.Join(d, "e2.json")); len(readEnvBytes(t, r).Signatures) != 2 {
			t.Fatal("e2.json changed")
		}
	})
	t.Run("loose-key-mode", func(t *testing.T) {
		kf := filepath.Join(d, "loose2.key")
		writeFile(t, kf, []byte(b.seedHex+"\n"), 0o644)
		unchanged(t, "loose key", runIn(t, bin, d, nil, "", "approve", "-key", kf, "-in", "e1.json", "-yes"))
	})
	t.Run("trusted-rejects-unknown-signer", func(t *testing.T) {
		// existing signer is alice; -trusted lists only mallory
		unchanged(t, "alice not in -trusted", runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e1.json", "-yes", "-trusted", out.pubFile))
	})
	t.Run("trusted-accepts-known-signer", func(t *testing.T) {
		if r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e1.json", "-out", "ok.json", "-yes", "-trusted", a.pubFile+","+hex.EncodeToString(c.pub)); r.code != 0 {
			t.Fatalf("approve with correct -trusted failed: %s%s", r.stdout, r.stderr)
		}
	})
	t.Run("trusted-key-id-instead-of-pubkey", func(t *testing.T) {
		unchanged(t, "key id as -trusted", runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e1.json", "-yes", "-trusted", string(keyID(a.pub))))
	})
	t.Run("trusted-garbage", func(t *testing.T) {
		unchanged(t, "garbage -trusted", runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "e1.json", "-yes", "-trusted", "nope.pub,zz"))
	})
	t.Run("forged-existing-signature-with-trusted", func(t *testing.T) {
		e := readEnv(t, filepath.Join(d, "e1.json"))
		e.Signatures[0].Sig[3] ^= 1
		bs, _ := json.Marshal(e)
		writeFile(t, filepath.Join(d, "forged.json"), bs, 0o644)
		r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "forged.json", "-yes", "-trusted", a.pubFile, "-out", "forged-out.json")
		if r.code == 0 {
			t.Fatal("approve -trusted signed an envelope whose existing signature is forged")
		}
		if _, err := os.Stat(filepath.Join(d, "forged-out.json")); err == nil {
			t.Fatal("output written")
		}
	})
	t.Run("mislabeled-existing-signature-with-trusted", func(t *testing.T) {
		// alice's signature carrying carol's key ID: must not count as carol.
		e := readEnv(t, filepath.Join(d, "e1.json"))
		e.Signatures[0].KeyID = keyID(c.pub)
		bs, _ := json.Marshal(e)
		writeFile(t, filepath.Join(d, "mislabel.json"), bs, 0o644)
		r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "mislabel.json", "-yes", "-trusted", c.pubFile, "-out", "mislabel-out.json")
		if r.code == 0 {
			t.Fatal("approve -trusted accepted a mislabeled signature")
		}
	})
	t.Run("wrong-payload-type", func(t *testing.T) {
		e := readEnv(t, filepath.Join(d, "e1.json"))
		e.PayloadType = "text/plain"
		bs, _ := json.Marshal(e)
		writeFile(t, filepath.Join(d, "pt.json"), bs, 0o644)
		if r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "pt.json", "-yes", "-out", "pt-out.json"); r.code == 0 {
			t.Fatal("approve signed an envelope with a foreign payloadType")
		}
	})
	t.Run("invalid-policy-inside-envelope", func(t *testing.T) {
		for n, pb := range map[string]string{
			"dup": `{"tenant":"bank-a","tenant":"x","version":2,"issued_at":"2026-11-05T00:00:00Z","expires_at":"2026-11-08T00:00:00Z","default":"deny","roles":{}}`,
			"esc": `{"tenant":"bank-a","version":2,"issued_at":"2026-11-05T00:00:00Z","expires_at":"2026-11-08T00:00:00Z","default":"deny","roles":{"\u001b]0;pwned\u0007":{"a":"R"}}}`,
		} {
			env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(pb)}
			trust.Sign(&env, a.priv)
			bs, _ := json.Marshal(env)
			writeFile(t, filepath.Join(d, n+".json"), bs, 0o644)
			r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", n+".json", "-yes", "-out", n+"-out.json")
			if r.code == 0 {
				t.Fatalf("%s: approve signed an envelope with an invalid policy (approver would see raw/ambiguous bytes)", n)
			}
			if strings.ContainsRune(r.stdout+r.stderr, 0x1b) || strings.ContainsRune(r.stdout+r.stderr, 7) {
				t.Fatalf("%s: terminal control character in output", n)
			}
		}
	})
	t.Run("eight-signatures-already", func(t *testing.T) {
		pb := payload("bank-a", 2, stdRoles)
		env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: pb}
		for i := 0; i < 8; i++ {
			_, pk, _ := ed25519.GenerateKey(nil)
			trust.Sign(&env, pk)
		}
		bs, _ := json.Marshal(env)
		writeFile(t, filepath.Join(d, "eight.json"), bs, 0o644)
		r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "eight.json", "-yes", "-out", "eight-out.json")
		if r.code == 0 {
			if e := readEnv(t, filepath.Join(d, "eight-out.json")); len(e.Signatures) > wire.MaxSignatures {
				t.Fatalf("approve produced an envelope with %d signatures (> wire.MaxSignatures)", len(e.Signatures))
			}
		}
	})
	t.Run("garbage-inputs", func(t *testing.T) {
		for n, c := range map[string]string{"empty": "", "null": "null", "arr": "[]", "trunc": string(e1[:len(e1)/2]), "trailing": string(e1) + "{}", "unknown": strings.Replace(string(e1), "{", `{"x":1,`, 1)} {
			writeFile(t, filepath.Join(d, "g-"+n+".json"), []byte(c), 0o644)
			r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "g-"+n+".json", "-yes", "-out", "g-"+n+"-out.json")
			if r.code == 0 || strings.Contains(r.stderr, "panic") || strings.Contains(r.stderr, "goroutine ") {
				t.Fatalf("%s: exit %d stderr %q", n, r.code, r.stderr)
			}
		}
	})
	t.Run("in-place-replace-keeps-mode-and-is-complete", func(t *testing.T) {
		writeFile(t, filepath.Join(d, "inplace.json"), e1, 0o600)
		r := runIn(t, bin, d, nil, "", "approve", "-key", b.keyFile, "-in", "inplace.json", "-yes")
		if r.code != 0 {
			t.Fatalf("approve in place: %s%s", r.stdout, r.stderr)
		}
		e := readEnv(t, filepath.Join(d, "inplace.json"))
		if len(e.Signatures) != 2 {
			t.Fatalf("in-place result has %d signatures", len(e.Signatures))
		}
		if entries, _ := filepath.Glob(filepath.Join(d, "inplace.json*")); len(entries) != 1 {
			t.Fatalf("temp files left behind: %v", entries)
		}
		for _, m := range []string{"bob.key"} {
			_ = m
		}
	})
}

func readEnvBytes(t testing.TB, b []byte) wire.Envelope {
	t.Helper()
	e, err := trust.DecodeEnvelope(b)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestApproveNeverPrintsKeyMaterial(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	writeFile(t, filepath.Join(d, "p.json"), payload("bank-a", 2, stdRoles), 0o644)
	r1 := runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "p.json", "-out", "e.json")
	r2 := runIn(t, bin, d, nil, "yes\n", "approve", "-key", b.keyFile, "-in", "e.json")
	r3 := runIn(t, bin, d, nil, "yes\n", "approve", "-key", b.keyFile, "-in", "e.json")
	for _, r := range []result{r1, r2, r3} {
		for _, secret := range []string{a.seedHex, b.seedHex} {
			if strings.Contains(r.stdout+r.stderr, secret) {
				t.Fatal("private seed appeared in output")
			}
		}
	}
}

// T-D3: sign and approve refuse non-regular key files. A FIFO must be refused,
// not opened (opening blocks forever); a directory is refused too.
func TestKeyFileMustBeRegular(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a := keygen(t, bin, d, "alice")
	writeFile(t, filepath.Join(d, "good.json"), payload("bank-a", 2, stdRoles), 0o644)
	runIn(t, bin, d, nil, "", "sign", "-key", a.keyFile, "-in", "good.json", "-out", "e.json")
	fifo := filepath.Join(d, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("environment: mkfifo: %v", err)
	}
	for _, kf := range []string{d, fifo, "/dev/null", "/dev/zero"} {
		kf := kf
		base := strings.NewReplacer("/", "_").Replace(kf)
		t.Run("sign/"+filepath.Base(kf), func(t *testing.T) {
			t.Parallel()
			if r := runIn(t, bin, d, nil, "", "sign", "-key", kf, "-in", "good.json", "-out", "x-"+filepath.Base(base)+".env"); r.code == 0 {
				t.Fatalf("sign accepted non-regular key file %s", kf)
			}
		})
		t.Run("approve/"+filepath.Base(kf), func(t *testing.T) {
			t.Parallel()
			if r := runIn(t, bin, d, nil, "yes\n", "approve", "-key", kf, "-in", "e.json", "-out", "y-"+filepath.Base(base)+".env", "-yes"); r.code == 0 {
				t.Fatalf("approve accepted non-regular key file %s", kf)
			}
		})
	}
}

// M-D32 spirit: an envelope file with a duplicate or case-variant "payload"
// key can show one thing to a reader and mean another to a parser. Whatever
// approve displays and signs must be one and the same set of bytes.
func TestApproveDisplayedPayloadIsTheSignedPayload(t *testing.T) {
	bin := buildCtl(t)
	d := t.TempDir()
	a, b := keygen(t, bin, d, "alice"), keygen(t, bin, d, "bob")
	benign := payload("bank-a", 2, `{"sales":{"crm.read_*":"R"}}`)
	evil := payload("bank-a", 2, `{"sales":{"crm.*":"X"}}`)
	mkEnv := func(p []byte) string {
		e := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: p}
		trust.Sign(&e, a.priv)
		bs, _ := json.Marshal(e)
		return string(bs)
	}
	benignEnv := mkEnv(benign)
	b64 := func(p []byte) string { bs, _ := json.Marshal(p); return string(bs) }
	variants := map[string]string{
		"dup-payload-benign-first": strings.Replace(benignEnv, `"payload":`, `"payload":`+b64(benign)+`,"payload":`+b64(evil)+`,"x":`, 1),
		"dup-payload-evil-first":   strings.Replace(benignEnv, `"payload":`, `"payload":`+b64(evil)+`,"payload":`, 1),
		"case-variant-payload":     strings.Replace(benignEnv, `"payload":`, `"Payload":`+b64(evil)+`,"payload":`, 1),
	}
	for n, content := range variants {
		writeFile(t, filepath.Join(d, n+".json"), []byte(content), 0o644)
		r := runIn(t, bin, d, nil, "yes\n", "approve", "-key", b.keyFile, "-in", n+".json", "-out", n+".out")
		if r.code != 0 {
			continue // refusing an ambiguous envelope is the safest outcome
		}
		out := readEnv(t, filepath.Join(d, n+".out"))
		if !strings.Contains(r.stdout, sha(out.Payload)) {
			t.Fatalf("%s: the hash shown to the approver is not the hash of the payload that was signed\nshown:\n%s\nsigned payload sha: %s", n, r.stdout, sha(out.Payload))
		}
		last := out.Signatures[len(out.Signatures)-1]
		if !ed25519.Verify(b.pub, trust.PAE(out.PayloadType, out.Payload), last.Sig) {
			t.Fatalf("%s: the new signature does not cover the output payload", n)
		}
		ob, _ := os.ReadFile(filepath.Join(d, n+".out"))
		if strings.Count(string(ob), `"payload"`) != 1 {
			t.Fatalf("%s: output envelope still carries a duplicate payload key", n)
		}
		if strings.Contains(r.stdout, "crm.*") != bytes.Contains(out.Payload, []byte(`"crm.*"`)) {
			t.Fatalf("%s: approver was shown rules that differ from the signed payload", n)
		}
	}
}
