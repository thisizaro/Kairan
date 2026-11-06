package trustbreak

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func envJSON(t testing.TB, e wire.Envelope) string {
	t.Helper()
	return string(mustJSON(e))
}

// DecodeEnvelope contract (doc): one JSON value, <= MaxEnvelopeBytes, no unknown
// fields, no trailing data, bare sentinel errors that do not echo input.
func TestDecodeEnvelopeHostileInput(t *testing.T) {
	k := loadKeys(t)
	e := signed(goodPayload(), k.a, k.b)
	good := envJSON(t, e)
	const canary = "CANARY-DEC-91ab"

	rows := []struct {
		name, in string
		want     error // nil = must decode
	}{
		{"good", good, nil},
		{"good-trailing-newline", good + "\n", nil},
		{"good-trailing-spaces", good + "  \t\r\n", nil},
		{"good-leading-ws", " \n" + good, nil},
		{"trailing-second-object", good + good, wire.ErrBodyInvalid},
		{"trailing-garbage", good + "x", wire.ErrBodyInvalid},
		{"trailing-nul", good + "\x00", wire.ErrBodyInvalid},
		{"trailing-comma", good + ",", wire.ErrBodyInvalid},
		{"trailing-empty-object", good + "{}", wire.ErrBodyInvalid},
		{"trailing-bom", good + "\ufeff", wire.ErrBodyInvalid},
		{"leading-bom", "\ufeff" + good, wire.ErrBodyInvalid},
		{"empty", "", wire.ErrBodyInvalid},
		{"whitespace-only", "   ", wire.ErrBodyInvalid},
		{"array", "[]", wire.ErrBodyInvalid},
		{"array-of-envelope", "[" + good + "]", wire.ErrBodyInvalid},
		{"string", `"x"`, wire.ErrBodyInvalid},
		{"number", `1`, wire.ErrBodyInvalid},
		{"truncated", good[:len(good)-1], wire.ErrBodyInvalid},
		{"unknown-field", strings.Replace(good, "{", `{"extra":1,`, 1), wire.ErrBodyInvalid},
		{"unknown-field-nested-in-sig", strings.Replace(good, `"keyid"`, `"zz":"`+canary+`","keyid"`, 1), wire.ErrBodyInvalid},
		{"payload-not-base64", `{"payloadType":"` + wire.PayloadTypePolicy + `","payload":"!!!!","signatures":[]}`, wire.ErrBodyInvalid},
		{"payload-base64url", `{"payloadType":"` + wire.PayloadTypePolicy + `","payload":"-_-_","signatures":[]}`, wire.ErrBodyInvalid},
		{"payload-number", `{"payloadType":"x","payload":5,"signatures":[]}`, wire.ErrBodyInvalid},
		{"payload-object", `{"payloadType":"x","payload":{},"signatures":[]}`, wire.ErrBodyInvalid},
		{"payloadType-number", `{"payloadType":5,"payload":"","signatures":[]}`, wire.ErrBodyInvalid},
		{"signatures-object", `{"payloadType":"x","payload":"","signatures":{}}`, wire.ErrBodyInvalid},
		{"sig-keyid-number", `{"payloadType":"x","payload":"","signatures":[{"keyid":1,"sig":""}]}`, wire.ErrBodyInvalid},
		{"invalid-utf8-in-type", "{\"payloadType\":\"\xff\xfe\",\"payload\":\"\",\"signatures\":[]}", nil}, // std lib substitutes U+FFFD; must then fail Verify
		{"deep-nesting-in-unknown", `{"a":` + strings.Repeat("[", 100000) + strings.Repeat("]", 100000) + `}`, wire.ErrBodyInvalid},
	}
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			defer func() {
				if x := recover(); x != nil {
					t.Fatalf("PANIC: %v", x)
				}
			}()
			env, err := trust.DecodeEnvelope([]byte(r.in))
			if r.want == nil {
				if err != nil {
					t.Fatalf("rejected: %v", err)
				}
				// Whatever decoded must never verify unless it is the genuine envelope.
				if r.name != "good" && !strings.HasPrefix(r.name, "good-") {
					if _, code, _ := trust.Verify(env, k.root()); code == "" {
						t.Fatalf("junk envelope verified")
					}
				}
				return
			}
			if err != r.want {
				t.Fatalf("err = %v, want exactly %v (bare sentinel)", err, r.want)
			}
			if env.Payload != nil || env.Signatures != nil || env.PayloadType != "" {
				t.Fatalf("error returned with a partially filled envelope: %+v", env)
			}
			if strings.Contains(err.Error(), canary) {
				t.Fatal("error echoes input")
			}
		})
	}
}

// Size boundary: MaxEnvelopeBytes exact is allowed, one more is ErrBodyTooLarge,
// including when the excess is trailing whitespace.
func TestDecodeEnvelopeSizeLimit(t *testing.T) {
	k := loadKeys(t)
	good := envJSON(t, signed(goodPayload(), k.a, k.b))
	pad := wire.MaxEnvelopeBytes - len(good)
	exact := good + strings.Repeat(" ", pad)
	if len(exact) != wire.MaxEnvelopeBytes {
		t.Fatal("bad test construction")
	}
	if _, err := trust.DecodeEnvelope([]byte(exact)); err != nil {
		t.Fatalf("exactly %d bytes rejected: %v", wire.MaxEnvelopeBytes, err)
	}
	if _, err := trust.DecodeEnvelope([]byte(exact + " ")); err != wire.ErrBodyTooLarge {
		t.Fatalf("limit+1 bytes: err %v, want wire.ErrBodyTooLarge", err)
	}
	if _, err := trust.DecodeEnvelope(bytes.Repeat([]byte("a"), wire.MaxEnvelopeBytes*4)); err != wire.ErrBodyTooLarge {
		t.Fatalf("4x limit: err %v, want wire.ErrBodyTooLarge", err)
	}
	// A real envelope whose payload is 256 KiB: JSON is larger than the cap (base64 + framing).
	big := signed(bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes), k.a, k.b)
	if _, err := trust.DecodeEnvelope(mustJSON(big)); err != wire.ErrBodyTooLarge {
		t.Fatalf("envelope with 256KiB payload: err %v, want wire.ErrBodyTooLarge", err)
	}
	// Too large wins over invalid (a 300 KiB garbage body is "too large", not "invalid").
	if _, err := trust.DecodeEnvelope(append([]byte("{"), bytes.Repeat([]byte("x"), wire.MaxEnvelopeBytes+10)...)); err != wire.ErrBodyTooLarge {
		t.Fatalf("garbage over limit: err %v, want ErrBodyTooLarge", err)
	}
}

// DecodeEnvelope must return the exact bytes: round trip equals encoding/json
// and Verify succeeds on a decoded golden file (signatures cover decoded bytes).
func TestDecodeRoundTripKeepsSignedBytes(t *testing.T) {
	k := loadKeys(t)
	for _, p := range [][]byte{
		goodPayload(),
		append(goodPayload(), '\n'),
		[]byte(strings.Replace(string(goodPayload()), "sales", "s\\u0061les", 1)), // escape inside the signed JSON must stay an escape
	} {
		e := signed(p, k.a, k.b)
		d, err := trust.DecodeEnvelope(mustJSON(e))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(d.Payload, p) {
			t.Fatal("decoded payload differs from signed bytes")
		}
		if !reflect.DeepEqual(d.Signatures, e.Signatures) || d.PayloadType != e.PayloadType {
			t.Fatal("decoded envelope differs")
		}
		expectAccept(t, "decoded", d, k.root(), 1, now, skew)
	}
	// "null" is valid JSON and std decodes it to the zero value: that envelope must be rejected, never accepted.
	d, err := trust.DecodeEnvelope([]byte("null"))
	if err == nil {
		if _, code, verr := trust.Verify(d, k.root()); code == "" || verr == nil {
			t.Fatal("null envelope verified")
		}
	}
}

// Base64 differentials: a payload encoded with embedded newlines or without
// padding must either be refused or decode to the same bytes the signer signed
// (never to different ones that still verify).
func TestDecodeBase64Variants(t *testing.T) {
	k := loadKeys(t)
	p := goodPayload()
	e := signed(p, k.a, k.b)
	std := b64(p)
	variants := map[string]string{
		"newline-inside":  std[:10] + "\n" + std[10:],
		"crlf-inside":     std[:10] + "\r\n" + std[10:],
		"unpadded":        strings.TrimRight(std, "="),
		"space-inside":    std[:10] + " " + std[10:],
		"url-alphabet":    strings.NewReplacer("+", "-", "/", "_").Replace(std),
		"extra-padding":   std + "==",
		"nonzero-padbits": flipLastB64(std),
	}
	for n, v := range variants {
		raw := strings.Replace(envJSON(t, e), `"payload":"`+std+`"`, `"payload":"`+v+`"`, 1)
		if raw == envJSON(t, e) && v != std {
			t.Fatalf("%s: replacement failed", n)
		}
		d, err := trust.DecodeEnvelope([]byte(raw))
		if err != nil {
			continue // refused: fine
		}
		if bytes.Equal(d.Payload, p) {
			continue // same bytes: harmless
		}
		if _, code, _ := trust.Verify(d, k.root()); code == "" {
			t.Fatalf("%s: decoded to different bytes and still verified", n)
		}
	}
}

func flipLastB64(s string) string {
	// Change the last data character before padding so the unused bits are non-zero.
	trim := strings.TrimRight(s, "=")
	pads := s[len(trim):]
	if pads == "" {
		return s
	}
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alpha, trim[len(trim)-1])
	return trim[:len(trim)-1] + string(alpha[(last+1)%64]) + pads
}

// Doc ambiguity Q-D3: the docs say "strict decoding" for the envelope but only
// spell out duplicate/case-variant rules for the policy payload (M-D32). The std
// decoder keeps the last duplicate and matches case-insensitively. Both are
// recorded here as informational: the outcome must at least be consistent.
func TestDecodeEnvelopeDuplicateAndCaseVariantKeys(t *testing.T) {
	k := loadKeys(t)
	g := signed(goodPayload(), k.a, k.b)
	one := signed(goodPayload(), k.a)
	good := envJSON(t, g)
	rows := map[string]string{
		"dup-signatures-valid-first": strings.Replace(good, `"signatures":`, `"signatures":`+string(mustJSON(g.Signatures))+`,"signatures":`, 1),
		"dup-signatures-weak-last":   strings.Replace(good, `"signatures":`, `"signatures":`+string(mustJSON(g.Signatures))+`,"signatures":`+string(mustJSON(one.Signatures))+`,"x":`, 1),
		"dup-payload":                strings.Replace(good, `"payload":`, `"payload":"`+b64([]byte("{}"))+`","payload":`, 1),
		"dup-type":                   strings.Replace(good, `"payloadType":`, `"payloadType":"text/plain","payloadType":`, 1),
		"case-payload":               strings.Replace(good, `"payload":`, `"PAYLOAD":`, 1),
		"case-sigs":                  strings.Replace(good, `"signatures":`, `"Signatures":`, 1),
		"case-type":                  strings.Replace(good, `"payloadType":`, `"payloadtype":`, 1),
		"case-keyid":                 strings.Replace(good, `"keyid":`, `"KeyID":`, 1),
	}
	for n, raw := range rows {
		d, err := trust.DecodeEnvelope([]byte(raw))
		if err != nil {
			t.Logf("%s: refused (%v)", n, err)
			continue // strict refusal is the safest answer
		}
		t.Logf("%s: ACCEPTED by DecodeEnvelope", n)
		// If accepted by the decoder, what Verify sees must be what a stock decoder sees.
		var std wire.Envelope
		if json.Unmarshal([]byte(raw), &std) != nil {
			t.Fatalf("%s: DecodeEnvelope accepts what encoding/json refuses", n)
		}
		if !bytes.Equal(d.Payload, std.Payload) || d.PayloadType != std.PayloadType || len(d.Signatures) != len(std.Signatures) {
			t.Fatalf("%s: DecodeEnvelope and encoding/json disagree (parser differential)", n)
		}
		// And the proxy's decision about it must be the decision for the final values, i.e. never a pass with fewer than 2 distinct sigs.
		if _, code, _ := trust.Verify(d, k.root()); code == "" && len(d.Signatures) < 2 {
			t.Fatalf("%s: verified with %d signatures", n, len(d.Signatures))
		}
	}
}

// Every golden file must decode without error, and decoding is stable
// (marshal + decode yields the same envelope).
func TestDecodeGoldenFilesStable(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(fixtureRoot(), "envelopes", "*.json"))
	if err != nil || len(files) != 24 {
		t.Fatalf("golden files: %d, %v", len(files), err)
	}
	for _, f := range files {
		raw, _ := os.ReadFile(f)
		d, err := trust.DecodeEnvelope(raw)
		if err != nil {
			t.Fatalf("%s: %v", filepath.Base(f), err)
		}
		d2, err := trust.DecodeEnvelope(mustJSON(d))
		if err != nil || !reflect.DeepEqual(d, d2) {
			t.Fatalf("%s: decode not stable: %v", filepath.Base(f), err)
		}
	}
}

// Hostile payload sizes and shapes under a valid signature: never a panic, never a pass.
func TestSignedHostilePayloads(t *testing.T) {
	k := loadKeys(t)
	root := k.root()
	huge := bytes.Repeat([]byte("a"), 16<<20)
	rows := map[string][]byte{
		"16MiB-garbage":        huge,
		"over-envelope-cap-ws": append(goodPayload(), bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes)...),
		"deep-array":           []byte(strings.Repeat("[", 1<<20)),
		"deep-object":          []byte(strings.Repeat(`{"a":`, 200000)),
		"nul-bytes":            bytes.Repeat([]byte{0}, 1000),
		"one-byte":             []byte("{"),
		"json-null":            []byte("null"),
		"empty-object":         []byte("{}"),
		"invalid-utf8":         []byte("{\"tenant\":\"\xff\"}"),
	}
	for n, p := range rows {
		n, p := n, p
		t.Run(n, func(t *testing.T) {
			e := signed(p, k.a, k.b)
			v, code, err := trust.Accept(e, root, 1, now, skew)
			if code != wire.ErrMalformed || err == nil || v.Policy != nil {
				t.Fatalf("code %q err %v; want malformed", code, err)
			}
		})
	}
}
