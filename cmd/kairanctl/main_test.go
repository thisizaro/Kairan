package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode"

	"kairan/internal/policy"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

var testNow = time.Date(2026, 11, 5, 9, 0, 0, 123456789, time.UTC)

// ctl runs kairanctl in-process and returns exit code, stdout and stderr.
func ctl(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, streams{
		in:  strings.NewReader(stdin),
		out: &out,
		err: &errb,
		now: func() time.Time { return testNow },
	})
	return code, out.String(), errb.String()
}

// fixtureKey copies a TEST-ONLY seed into dir as <name>.key (mode 0600) and
// returns the path and the public key.
func fixtureKey(t *testing.T, dir, fixture, name string) (string, ed25519.PublicKey) {
	t.Helper()
	seed, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "TEST-ONLY-"+fixture+".seed"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+".key")
	if err := os.WriteFile(path, seed, 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(seed)))
	if err != nil {
		t.Fatal(err)
	}
	return path, ed25519.NewKeyFromSeed(raw).Public().(ed25519.PublicKey)
}

// rawPayload is valid but deliberately not in canonical form (odd spacing,
// reversed field order), so a re-encoding would change its bytes.
const rawPayload = "{ \"roles\" :  {\"sales\": {\"crm.update_deal\":\"W\", \"crm.read_*\":\"R\"}},\n" +
	"  \"default\":\"deny\", \"expires_at\":\"2026-11-08T09:00:00Z\", \"issued_at\":\"2026-11-05T09:00:00Z\",\n" +
	"  \"version\":8, \"tenant\":\"bank-a\" }\n"

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readEnvelope(t *testing.T, path string) wire.Envelope {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	env, err := trust.DecodeEnvelope(b)
	if err != nil {
		t.Fatalf("envelope does not decode: %v", err)
	}
	return env
}

func verifies(env wire.Envelope, sigIdx int, pub ed25519.PublicKey) bool {
	return ed25519.Verify(pub, trust.PAE(env.PayloadType, env.Payload), env.Signatures[sigIdx].Sig)
}

// hasBoth reports whether stderr carries an English "error" line and Japanese text (J7).
func hasBoth(s string) bool {
	jp := false
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
			jp = true
		}
	}
	return jp && strings.Contains(s, "error:")
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"bogus"}, {"policy"}, {"policy", "bogus"}, {"keygen"}, {"sign"}, {"approve"}, {"keygen", "-nope"}} {
		code, out, errb := ctl(t, "", args...)
		if code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
		if out != "" || errb == "" {
			t.Errorf("%v: stdout %q stderr %q", args, out, errb)
		}
	}
	if code, out, _ := ctl(t, "", "help"); code != 0 || !strings.Contains(out, "keygen") {
		t.Errorf("help: exit %d, out %q", code, out)
	}
}

func TestKeygen(t *testing.T) {
	dir := t.TempDir()
	code, out, errb := ctl(t, "", "keygen", "-name", "alice", "-dir", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	keyPath, pubPath := filepath.Join(dir, "alice.key"), filepath.Join(dir, "alice.pub")
	st, err := os.Stat(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("private key mode %v, want 0600", st.Mode().Perm())
	}
	seedHex, _ := os.ReadFile(keyPath)
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedHex)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("key file is not a hex seed: %v", err)
	}
	pubHex, _ := os.ReadFile(pubPath)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	if strings.TrimSpace(string(pubHex)) != hex.EncodeToString(pub) {
		t.Error(".pub does not match the private key")
	}
	if strings.Contains(out+errb, strings.TrimSpace(string(seedHex))) {
		t.Error("private key material was printed")
	}
	if !strings.Contains(out, string(trust.KeyID(pub))) || !strings.Contains(out, hex.EncodeToString(pub)) {
		t.Errorf("output should show key ID and public key, got %q", out)
	}
	// Two runs give two different keys.
	if code, _, _ := ctl(t, "", "keygen", "-name", "bob", "-dir", dir); code != 0 {
		t.Fatal("second keygen failed")
	}
	other, _ := os.ReadFile(filepath.Join(dir, "bob.key"))
	if string(other) == string(seedHex) {
		t.Error("two keygen runs produced the same key")
	}
}

func TestKeygenRefusals(t *testing.T) {
	dir := t.TempDir()
	if code, _, e := ctl(t, "", "keygen", "-name", "alice", "-dir", dir); code != 0 {
		t.Fatal(e)
	}
	keyPath := filepath.Join(dir, "alice.key")
	before, _ := os.ReadFile(keyPath)

	// Overwrite refused, file untouched.
	code, _, errb := ctl(t, "", "keygen", "-name", "alice", "-dir", dir)
	if code != 1 || !hasBoth(errb) {
		t.Errorf("overwrite: exit %d, stderr %q", code, errb)
	}
	if after, _ := os.ReadFile(keyPath); string(after) != string(before) {
		t.Error("existing key was modified")
	}

	// A stray .pub alone also blocks, and no .key is created.
	writeFile(t, filepath.Join(dir, "carol.pub"), "x")
	if code, _, _ = ctl(t, "", "keygen", "-name", "carol", "-dir", dir); code != 1 {
		t.Errorf("existing .pub: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "carol.key")); err == nil {
		t.Error("a .key was created next to an existing .pub")
	}

	// A symlink at the target is not followed.
	target := filepath.Join(dir, "elsewhere")
	writeFile(t, target, "keep")
	if err := os.Symlink(target, filepath.Join(dir, "dave.key")); err != nil {
		t.Fatal(err)
	}
	if code, _, _ = ctl(t, "", "keygen", "-name", "dave", "-dir", dir); code != 1 {
		t.Errorf("symlink: exit %d", code)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Error("symlink target was written")
	}

	// Names that could escape the directory or hide a file.
	for _, name := range []string{"", "../x", "a/b", ".hidden", "a b", "a\x00b", strings.Repeat("a", 65)} {
		if code, _, errb := ctl(t, "", "keygen", "-name", name, "-dir", dir); code != 1 && code != 2 {
			t.Errorf("name %q accepted (exit %d, %s)", name, code, errb)
		}
	}
	// Missing directory.
	if code, _, _ := ctl(t, "", "keygen", "-name", "eve", "-dir", filepath.Join(dir, "nope")); code != 1 {
		t.Errorf("missing dir: exit %d", code)
	}
}

func TestPolicyNew(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "payload.json")
	code, _, errb := ctl(t, "", "policy", "new", "-tenant", "bank-a", "-out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	b, _ := os.ReadFile(out)
	p, err := policy.Parse(b)
	if err != nil {
		t.Fatalf("template does not parse: %v\n%s", err, b)
	}
	if p.Tenant != "bank-a" || p.Version != 1 {
		t.Errorf("tenant %q version %d", p.Tenant, p.Version)
	}
	if got := p.ExpiresAt.Sub(p.IssuedAt); got != 72*time.Hour {
		t.Errorf("validity %v, want 72h", got)
	}
	if !p.IssuedAt.Equal(testNow.Truncate(time.Second)) {
		t.Errorf("issued_at %v, want the clock at whole seconds", p.IssuedAt)
	}
	if !strings.Contains(string(b), `"default": "deny"`) {
		t.Error("template is not default deny")
	}
	if p.Decide("nobody", "any.tool", false).Allowed {
		t.Error("unknown role allowed")
	}

	// Flags, and stdout when -out is omitted.
	code, stdout, errb := ctl(t, "", "policy", "new", "-tenant", "acme", "-version", "9", "-validity", "24h")
	if code != 0 {
		t.Fatal(errb)
	}
	p, err = policy.Parse([]byte(stdout))
	if err != nil || p.Version != 9 || p.ExpiresAt.Sub(p.IssuedAt) != 24*time.Hour {
		t.Errorf("flags not honoured: %v %+v", err, p)
	}

	// Refusals.
	for _, tc := range [][]string{
		{"policy", "new", "-out", filepath.Join(dir, "x.json")},                               // no tenant
		{"policy", "new", "-tenant", "Bad_Tenant"},                                            // bad tenant
		{"policy", "new", "-tenant", "bank-a", "-version", "0"},                               // version < 1
		{"policy", "new", "-tenant", "bank-a", "-validity", "0s"},                             // not positive
		{"policy", "new", "-tenant", "bank-a", "-validity", "-1h"},                            // negative
		{"policy", "new", "-tenant", "bank-a", "-validity", "soon"},                           // not a duration
		{"policy", "new", "-tenant", "bank-a", "-out", out},                                   // overwrite
		{"policy", "new", "-tenant", "bank-a", "-out", filepath.Join(dir, "no", "such", "f")}, // missing dir
	} {
		before, _ := os.ReadFile(out)
		code, so, errb := ctl(t, "", tc...)
		if code == 0 {
			t.Errorf("%v accepted", tc)
		}
		if so != "" || !hasBoth(errb) && code == 1 {
			t.Errorf("%v: stdout %q stderr %q", tc, so, errb)
		}
		if after, _ := os.ReadFile(out); string(after) != string(before) {
			t.Errorf("%v modified the existing file", tc)
		}
	}
}

func TestSign(t *testing.T) {
	dir := t.TempDir()
	key, pub := fixtureKey(t, dir, "admin-a", "a")
	in, out := filepath.Join(dir, "payload.json"), filepath.Join(dir, "env.json")
	writeFile(t, in, rawPayload)

	code, stdout, errb := ctl(t, "", "sign", "-key", key, "-in", in, "-out", out)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	env := readEnvelope(t, out)
	if env.PayloadType != wire.PayloadTypePolicy {
		t.Errorf("payload type %q", env.PayloadType)
	}
	if string(env.Payload) != rawPayload {
		t.Errorf("payload bytes changed:\n%q\nwant\n%q", env.Payload, rawPayload)
	}
	if len(env.Signatures) != 1 || env.Signatures[0].KeyID != trust.KeyID(pub) || !verifies(env, 0, pub) {
		t.Errorf("bad signature block: %+v", env.Signatures)
	}
	if err := env.ValidateShape(); err != nil {
		t.Error(err)
	}
	sum := sha256.Sum256([]byte(rawPayload))
	if !strings.Contains(stdout, hex.EncodeToString(sum[:])) {
		t.Errorf("sign should print the policy hash, got %q", stdout)
	}
	if strings.Contains(stdout+errb, strings.TrimSpace(readFile(t, key))) {
		t.Error("private key material was printed")
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSignRefusals(t *testing.T) {
	dir := t.TempDir()
	key, _ := fixtureKey(t, dir, "admin-a", "a")
	good := filepath.Join(dir, "good.json")
	writeFile(t, good, rawPayload)

	loose := filepath.Join(dir, "loose.key")
	writeFile(t, loose, readFile(t, key))
	if err := os.Chmod(loose, 0o640); err != nil {
		t.Fatal(err)
	}
	garbage := filepath.Join(dir, "garbage.key")
	if err := os.WriteFile(garbage, []byte("not a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	short := filepath.Join(dir, "short.key")
	if err := os.WriteFile(short, []byte("abcd\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dup := filepath.Join(dir, "dup.json")
	writeFile(t, dup, strings.Replace(rawPayload, `"tenant":"bank-a"`, `"tenant":"bank-a","tenant":"evil"`, 1))
	unknown := filepath.Join(dir, "unknown.json")
	writeFile(t, unknown, strings.Replace(rawPayload, `"version":8`, `"version":8,"extra":1`, 1))
	notjson := filepath.Join(dir, "notjson.json")
	writeFile(t, notjson, "hello")
	empty := filepath.Join(dir, "empty.json")
	writeFile(t, empty, "")
	existing := filepath.Join(dir, "existing.json")
	writeFile(t, existing, "keep")
	huge := filepath.Join(dir, "huge.json")
	writeFile(t, huge, strings.Repeat(" ", wire.MaxEnvelopeBytes+1))

	tests := []struct {
		name string
		args []string
	}{
		{"key mode too open", []string{"-key", loose, "-in", good, "-out", filepath.Join(dir, "o1")}},
		{"key missing", []string{"-key", filepath.Join(dir, "none.key"), "-in", good, "-out", filepath.Join(dir, "o2")}},
		{"key garbage", []string{"-key", garbage, "-in", good, "-out", filepath.Join(dir, "o3")}},
		{"key short", []string{"-key", short, "-in", good, "-out", filepath.Join(dir, "o4")}},
		{"payload missing", []string{"-key", key, "-in", filepath.Join(dir, "none.json"), "-out", filepath.Join(dir, "o5")}},
		{"payload duplicate key", []string{"-key", key, "-in", dup, "-out", filepath.Join(dir, "o6")}},
		{"payload unknown field", []string{"-key", key, "-in", unknown, "-out", filepath.Join(dir, "o7")}},
		{"payload not json", []string{"-key", key, "-in", notjson, "-out", filepath.Join(dir, "o8")}},
		{"payload empty", []string{"-key", key, "-in", empty, "-out", filepath.Join(dir, "o9")}},
		{"payload huge", []string{"-key", key, "-in", huge, "-out", filepath.Join(dir, "o10")}},
		{"out exists", []string{"-key", key, "-in", good, "-out", existing}},
		{"no out", []string{"-key", key, "-in", good}},
		{"no key", []string{"-in", good, "-out", filepath.Join(dir, "o11")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, so, errb := ctl(t, "", append([]string{"sign"}, tc.args...)...)
			if code == 0 {
				t.Fatalf("accepted; stdout %q", so)
			}
			if code == 1 && !hasBoth(errb) {
				t.Errorf("error not readable in both languages: %q", errb)
			}
			// No envelope written.
			for i, a := range tc.args {
				if a == "-out" && tc.args[i+1] != existing {
					if _, err := os.Stat(tc.args[i+1]); err == nil {
						t.Error("an envelope was written")
					}
				}
			}
			if readFile(t, existing) != "keep" {
				t.Error("existing file modified")
			}
		})
	}
}

// signedBy makes an envelope over payload signed by the given fixtures.
func signedBy(t *testing.T, dir, payload string, fixtures ...string) (string, []ed25519.PublicKey) {
	t.Helper()
	in := filepath.Join(dir, "payload.json")
	writeFile(t, in, payload)
	path := filepath.Join(dir, "env.json")
	var pubs []ed25519.PublicKey
	for i, f := range fixtures {
		key, pub := fixtureKey(t, dir, f, f)
		pubs = append(pubs, pub)
		if i == 0 {
			if code, _, e := ctl(t, "", "sign", "-key", key, "-in", in, "-out", path); code != 0 {
				t.Fatal(e)
			}
			continue
		}
		if code, _, e := ctl(t, "", "approve", "-yes", "-key", key, "-in", path); code != 0 {
			t.Fatal(e)
		}
	}
	return path, pubs
}

func TestApprove(t *testing.T) {
	dir := t.TempDir()
	envPath, pubs := signedBy(t, dir, rawPayload, "admin-a")
	keyB, pubB := fixtureKey(t, dir, "admin-b", "b")

	code, out, errb := ctl(t, "yes\n", "approve", "-key", keyB, "-in", envPath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	env := readEnvelope(t, envPath)
	if string(env.Payload) != rawPayload {
		t.Error("payload bytes changed by approve")
	}
	if len(env.Signatures) != 2 {
		t.Fatalf("%d signatures", len(env.Signatures))
	}
	if !verifies(env, 0, pubs[0]) || !verifies(env, 1, pubB) {
		t.Error("signatures do not verify")
	}
	if env.Signatures[0].KeyID == env.Signatures[1].KeyID {
		t.Error("same key twice")
	}

	// What the approver saw: parsed rendering and the hash, never the raw text.
	p, _ := policy.Parse([]byte(rawPayload))
	if !strings.Contains(out, p.Render()) {
		t.Errorf("output lacks the rendered policy:\n%s", out)
	}
	sum := sha256.Sum256([]byte(rawPayload))
	if !strings.Contains(out, hex.EncodeToString(sum[:])) {
		t.Error("output lacks the policy hash")
	}
	for _, frag := range []string{`"roles" :`, `"default":"deny"`, "{ \"roles\"", `"W", "crm`} {
		if strings.Contains(out, frag) {
			t.Errorf("raw payload text %q shown to the approver", frag)
		}
	}
	if !strings.Contains(out, string(trust.KeyID(pubB))) {
		t.Error("output should name the approving key ID")
	}

	// The result passes the real verifier with a 2-of-2 root.
	root := trust.Root{Tenant: "bank-a", Threshold: 2, Keys: map[wire.Hash]ed25519.PublicKey{
		trust.KeyID(pubs[0]): pubs[0], trust.KeyID(pubB): pubB,
	}}
	if _, c, err := trust.Verify(env, root); err != nil {
		t.Errorf("trust.Verify: %v (%s)", err, c)
	}
}

func TestApproveInteractive(t *testing.T) {
	for _, tc := range []struct {
		name, stdin string
		signs       bool
	}{
		{"yes", "yes\n", true},
		{"yes no newline", "yes", true},
		{"YES padded", "  yes \r\n", true},
		{"no", "no\n", false},
		{"y", "y\n", false},
		{"empty", "\n", false},
		{"eof", "", false},
		{"yes later", "maybe\nyes\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			envPath, _ := signedBy(t, dir, rawPayload, "admin-a")
			keyB, _ := fixtureKey(t, dir, "admin-b", "b")
			before := readFile(t, envPath)
			code, out, errb := ctl(t, tc.stdin, "approve", "-key", keyB, "-in", envPath)
			if tc.signs {
				if code != 0 {
					t.Fatalf("exit %d: %s", code, errb)
				}
				return
			}
			if code != 1 || !hasBoth(errb) {
				t.Errorf("exit %d, stderr %q", code, errb)
			}
			if readFile(t, envPath) != before {
				t.Error("envelope modified without confirmation")
			}
			// The approver still saw the policy before being refused.
			if !strings.Contains(out, "tenant:  bank-a") {
				t.Error("policy was not shown before the prompt")
			}
		})
	}
}

func TestApproveRefusals(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := signedBy(t, dir, rawPayload, "admin-a")
	keyA := filepath.Join(dir, "admin-a.key")
	keyB, _ := fixtureKey(t, dir, "admin-b", "b")
	pristine := readFile(t, envPath)

	loose := filepath.Join(dir, "loose.key")
	writeFile(t, loose, readFile(t, keyB))
	if err := os.Chmod(loose, 0o666); err != nil {
		t.Fatal(err)
	}

	// Envelopes built by hand: bad payloads, wrong type, no signatures.
	mk := func(name string, edit func(*wire.Envelope)) string {
		env := readEnvelope(t, envPath)
		edit(&env)
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		writeFile(t, p, string(b))
		return p
	}
	malformed := mk("malformed.json", func(e *wire.Envelope) { e.Payload = []byte(`{"tenant":"bank-a"}`) })
	dupKey := mk("dupkey.json", func(e *wire.Envelope) {
		e.Payload = []byte(strings.Replace(rawPayload, `"tenant":"bank-a"`, `"tenant":"bank-a","tenant":"x"`, 1))
	})
	wrongType := mk("type.json", func(e *wire.Envelope) { e.PayloadType = "text/plain" })
	noSigs := mk("nosigs.json", func(e *wire.Envelope) { e.Signatures = nil })
	full := mk("full.json", func(e *wire.Envelope) {
		for len(e.Signatures) < wire.MaxSignatures {
			e.Signatures = append(e.Signatures, wire.Signature{KeyID: wire.Hash(strings.Repeat("ab", 32)), Sig: make([]byte, wire.SignatureSize)})
		}
	})
	junk := filepath.Join(dir, "junk.json")
	writeFile(t, junk, "{not json")
	trailing := filepath.Join(dir, "trailing.json")
	writeFile(t, trailing, pristine+" {}")

	tests := []struct {
		name string
		args []string
		file string // the file that must stay untouched
	}{
		{"same key twice", []string{"-key", keyA, "-in", envPath}, envPath},
		{"key mode too open", []string{"-key", loose, "-in", envPath}, envPath},
		{"key missing", []string{"-key", filepath.Join(dir, "none.key"), "-in", envPath}, envPath},
		{"envelope missing", []string{"-key", keyB, "-in", filepath.Join(dir, "none.json")}, ""},
		{"envelope junk", []string{"-key", keyB, "-in", junk}, junk},
		{"envelope trailing data", []string{"-key", keyB, "-in", trailing}, trailing},
		{"malformed payload", []string{"-key", keyB, "-in", malformed}, malformed},
		{"duplicate-key payload", []string{"-key", keyB, "-in", dupKey}, dupKey},
		{"wrong payload type", []string{"-key", keyB, "-in", wrongType}, wrongType},
		{"no first signature", []string{"-key", keyB, "-in", noSigs}, noSigs},
		{"already 8 signatures", []string{"-key", keyB, "-in", full}, full},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var before string
			if tc.file != "" {
				before = readFile(t, tc.file)
			}
			code, _, errb := ctl(t, "yes\n", append([]string{"approve", "-yes"}, tc.args...)...)
			if code != 1 {
				t.Fatalf("exit %d, want 1; stderr %q", code, errb)
			}
			if !hasBoth(errb) {
				t.Errorf("error not readable in both languages: %q", errb)
			}
			if tc.file != "" && readFile(t, tc.file) != before {
				t.Error("envelope modified on refusal")
			}
		})
	}
	if readFile(t, envPath) != pristine {
		t.Error("original envelope changed")
	}

	// -out must not overwrite an existing file either.
	existing := filepath.Join(dir, "existing.json")
	writeFile(t, existing, "keep")
	if code, _, _ := ctl(t, "", "approve", "-yes", "-key", keyB, "-in", envPath, "-out", existing); code != 1 {
		t.Errorf("-out onto existing file: exit %d", code)
	}
	if readFile(t, existing) != "keep" {
		t.Error("existing -out file modified")
	}
}

func TestApproveOut(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := signedBy(t, dir, rawPayload, "admin-a")
	keyB, _ := fixtureKey(t, dir, "admin-b", "b")
	before := readFile(t, envPath)
	out := filepath.Join(dir, "two.json")
	if code, _, e := ctl(t, "", "approve", "-yes", "-key", keyB, "-in", envPath, "-out", out); code != 0 {
		t.Fatal(e)
	}
	if readFile(t, envPath) != before {
		t.Error("-in changed although -out was given")
	}
	if n := len(readEnvelope(t, out).Signatures); n != 2 {
		t.Errorf("%d signatures in -out", n)
	}
}

// Three distinct approvers are allowed (threshold may exceed 2).
func TestApproveThird(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := signedBy(t, dir, rawPayload, "admin-a", "admin-b", "admin-c")
	if n := len(readEnvelope(t, envPath).Signatures); n != 3 {
		t.Errorf("%d signatures, want 3", n)
	}
}

// An in-place approve must leave no temporary files behind.
func TestApproveNoLeftovers(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "work")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	envPath, _ := signedBy(t, sub, rawPayload, "admin-a")
	keyB, _ := fixtureKey(t, sub, "admin-b", "b")
	before, _ := os.ReadDir(sub)
	if code, _, e := ctl(t, "", "approve", "-yes", "-key", keyB, "-in", envPath); code != 0 {
		t.Fatal(e)
	}
	after, _ := os.ReadDir(sub)
	if len(before) != len(after) {
		t.Errorf("directory listing changed: %d -> %d entries", len(before), len(after))
	}
}

// Full journey with freshly generated keys, as an operator would run it.
func TestJourney(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"alice", "bob"} {
		if code, _, e := ctl(t, "", "keygen", "-name", n, "-dir", dir); code != 0 {
			t.Fatal(e)
		}
	}
	payload := filepath.Join(dir, "payload.json")
	env := filepath.Join(dir, "env.json")
	for _, args := range [][]string{
		{"policy", "new", "-tenant", "bank-a", "-version", "3", "-out", payload},
		{"sign", "-key", filepath.Join(dir, "alice.key"), "-in", payload, "-out", env},
		{"approve", "-yes", "-key", filepath.Join(dir, "bob.key"), "-in", env},
	} {
		if code, _, e := ctl(t, "", args...); code != 0 {
			t.Fatalf("%v: %s", args, e)
		}
	}
	read := func(n string) ed25519.PublicKey {
		raw, err := hex.DecodeString(strings.TrimSpace(readFile(t, filepath.Join(dir, n+".pub"))))
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	a, b := read("alice"), read("bob")
	root := trust.Root{Tenant: "bank-a", Threshold: 2, Keys: map[wire.Hash]ed25519.PublicKey{trust.KeyID(a): a, trust.KeyID(b): b}}
	now := testNow.Add(time.Hour)
	v, c, err := trust.Accept(readEnvelope(t, env), root, 2, now, time.Minute)
	if err != nil {
		t.Fatalf("trust.Accept: %v (%s)", err, c)
	}
	if v.Policy.Version != 3 {
		t.Errorf("version %d", v.Policy.Version)
	}
}
