package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode"

	"kairan/internal/trust"
)

// pubFile copies a TEST-ONLY public key fixture into dir.
func pubFile(t *testing.T, dir, fixture string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "test", "fixtures", "TEST-ONLY-"+fixture+".pub"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, fixture+".pub")
	writeFile(t, p, string(b))
	return p
}

func hasJapanese(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
			return true
		}
	}
	return false
}

func TestApproveWarnsWhenNotVerifying(t *testing.T) {
	dir := t.TempDir()
	envPath, _ := signedBy(t, dir, rawPayload, "admin-a")
	keyB, _ := fixtureKey(t, dir, "admin-b", "b")
	code, _, errb := ctl(t, "", "approve", "-yes", "-key", keyB, "-in", envPath)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(errb, "warning:") || !strings.Contains(errb, "-trusted") || !hasJapanese(errb) {
		t.Errorf("stderr lacks a bilingual warning that existing signatures were not verified: %q", errb)
	}
}

func TestApproveTrusted(t *testing.T) {
	dir := t.TempDir()
	pubA := pubFile(t, dir, "admin-a")
	pubC := pubFile(t, dir, "admin-c")
	hexA := strings.TrimSpace(readFile(t, pubA))

	for _, tc := range []struct {
		name, trusted string
	}{
		{"pub file", pubA},
		{"inline hex", hexA},
		{"list with extra keys", pubC + "," + pubA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			envPath, _ := signedBy(t, d, rawPayload, "admin-a")
			keyB, _ := fixtureKey(t, d, "admin-b", "b")
			code, out, errb := ctl(t, "", "approve", "-yes", "-trusted", tc.trusted, "-key", keyB, "-in", envPath)
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errb)
			}
			if strings.Contains(errb, "warning:") {
				t.Errorf("warned although -trusted was given: %q", errb)
			}
			if !strings.Contains(out, "verified") {
				t.Errorf("output should say existing signatures were verified:\n%s", out)
			}
			if n := len(readEnvelope(t, envPath).Signatures); n != 2 {
				t.Errorf("%d signatures, want 2", n)
			}
		})
	}
}

func TestApproveTrustedRefusals(t *testing.T) {
	dir := t.TempDir()
	pubA := pubFile(t, dir, "admin-a")
	pubC := pubFile(t, dir, "admin-c")

	t.Run("signature from an untrusted key", func(t *testing.T) {
		d := t.TempDir()
		envPath, _ := signedBy(t, d, rawPayload, "outsider")
		keyB, _ := fixtureKey(t, d, "admin-b", "b")
		before := readFile(t, envPath)
		code, _, errb := ctl(t, "", "approve", "-yes", "-trusted", pubA, "-key", keyB, "-in", envPath)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("exit %d, stderr %q", code, errb)
		}
		if readFile(t, envPath) != before {
			t.Error("envelope modified despite refusal")
		}
	})
	t.Run("invalid signature", func(t *testing.T) {
		d := t.TempDir()
		envPath, _ := signedBy(t, d, rawPayload, "admin-a")
		env := readEnvelope(t, envPath)
		env.Signatures[0].Sig[0] ^= 1
		b, _ := json.Marshal(env)
		writeFile(t, envPath, string(b))
		keyB, _ := fixtureKey(t, d, "admin-b", "b")
		before := readFile(t, envPath)
		code, _, errb := ctl(t, "", "approve", "-yes", "-trusted", pubA, "-key", keyB, "-in", envPath)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("exit %d, stderr %q", code, errb)
		}
		if readFile(t, envPath) != before {
			t.Error("envelope modified despite refusal")
		}
	})
	t.Run("payload changed after signing", func(t *testing.T) {
		d := t.TempDir()
		envPath, _ := signedBy(t, d, rawPayload, "admin-a")
		env := readEnvelope(t, envPath)
		env.Payload = []byte(strings.Replace(rawPayload, `"W"`, `"X"`, 1))
		b, _ := json.Marshal(env)
		writeFile(t, envPath, string(b))
		keyB, _ := fixtureKey(t, d, "admin-b", "b")
		code, _, errb := ctl(t, "", "approve", "-yes", "-trusted", pubA, "-key", keyB, "-in", envPath)
		if code != 1 || !hasBoth(errb) {
			t.Errorf("exit %d, stderr %q", code, errb)
		}
	})
	t.Run("bad -trusted values", func(t *testing.T) {
		d := t.TempDir()
		envPath, pubs := signedBy(t, d, rawPayload, "admin-a")
		keyB, _ := fixtureKey(t, d, "admin-b", "b")
		keyID := string(trust.KeyID(pubs[0]))
		garbage := filepath.Join(d, "garbage.pub")
		writeFile(t, garbage, "not a key\n")
		for name, val := range map[string]string{
			"missing file":     filepath.Join(d, "nope.pub"),
			"garbage file":     garbage,
			"short hex":        "abcd",
			"key id not a key": keyID,
			"empty item":       pubA + ",",
			"empty":            "",
			"blank":            "  ",
			"garbage in list":  pubC + "," + garbage,
			"too many items":   strings.Repeat(pubC+",", 40) + pubC,
		} {
			code, _, errb := ctl(t, "", "approve", "-yes", "-trusted", val, "-key", keyB, "-in", envPath)
			if code == 0 || !hasBoth(errb) {
				t.Errorf("%s: exit %d, stderr %q", name, code, errb)
			}
		}
		if n := len(readEnvelope(t, envPath).Signatures); n != 1 {
			t.Errorf("%d signatures after refusals, want 1", n)
		}
	})
}
