package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"kairan/internal/policy"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

func policyHash(payload []byte) wire.Hash {
	sum := sha256.Sum256(payload)
	return wire.Hash(hex.EncodeToString(sum[:]))
}

// parsePayload runs the strict parser. The parser's own message is not
// shown: it never echoes payload content, and a fixed message is enough.
func parsePayload(payload []byte) (*policy.Policy, *cliError) {
	p, err := policy.Parse(payload)
	if err != nil {
		return nil, fail("the policy payload is not valid and will not be signed (it must follow the policy format exactly: no unknown, missing or duplicate fields)",
			"ポリシーの内容が不正なため署名しません (形式に厳密に従う必要があります: 未知・不足・重複するフィールドは不可)").because(err)
	}
	return p, nil
}

// encodeEnvelope renders env as JSON and checks it fits the envelope limit.
func encodeEnvelope(env wire.Envelope) ([]byte, *cliError) {
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return nil, fail("cannot encode the envelope", "エンベロープを作成できません")
	}
	b = append(b, '\n')
	if len(b) > wire.MaxEnvelopeBytes {
		return nil, fail("the signed envelope would be larger than the 256 KiB limit",
			"署名済みエンベロープが上限 (256 KiB) を超えます")
	}
	return b, nil
}

// cmdSign creates an envelope holding the exact bytes of the payload file and
// one signature over PAE(payloadType, payload). The payload is validated with
// policy.Parse first and is never re-encoded.
func cmdSign(args []string, s streams) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "private key file (from keygen)")
	in := fs.String("in", "", "policy payload file")
	out := fs.String("out", "", "envelope file to create")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" || *out == "" {
		return usageErr("-key, -in and -out are all required", "-key, -in, -out はすべて必要です")
	}
	priv, cerr := loadKey(*keyPath)
	if cerr != nil {
		return cerr
	}
	payload, cerr := readInput(*in)
	if cerr != nil {
		return cerr
	}
	pol, cerr := parsePayload(payload)
	if cerr != nil {
		return cerr
	}
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: payload}
	trust.Sign(&env, priv)
	data, cerr := encodeEnvelope(env)
	if cerr != nil {
		return cerr
	}
	if err := createExclusive(*out, data, 0o644); err != nil {
		return writeErr(err)
	}
	fmt.Fprintf(s.out, "signed tenant %s version %d\n", pol.Tenant, pol.Version)
	fmt.Fprintf(s.out, "policy hash: %s\n", policyHash(payload))
	fmt.Fprintf(s.out, "signer:      %s\n", env.Signatures[0].KeyID)
	fmt.Fprintf(s.out, "wrote %s (1 signature; a second admin must run: kairanctl approve)\n", *out)
	return nil
}

// cmdApprove adds a signature to an envelope after the approver has seen what
// will be enforced (M-D32): the policy as policy.Parse understood it, plus
// its hash, never the raw text. It refuses if the key already signed, if the
// payload does not parse, or if the approver does not type "yes" (unless -yes).
func cmdApprove(args []string, s streams) error {
	fs := flag.NewFlagSet("approve", flag.ContinueOnError)
	keyPath := fs.String("key", "", "approver's private key file (from keygen)")
	in := fs.String("in", "", "envelope file to approve")
	out := fs.String("out", "", "write the result to a new file instead of updating -in")
	yes := fs.Bool("yes", false, "do not ask for confirmation (scripts and tests)")
	trustedSpec := fs.String("trusted", "", "check the existing signatures first: comma-separated public key files (NAME.pub) or hex public keys")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" {
		return usageErr("-key and -in are required", "-key と -in は必須です")
	}
	trustedGiven := false
	fs.Visit(func(f *flag.Flag) { trustedGiven = trustedGiven || f.Name == "trusted" })
	var trusted *trustedSet
	if trustedGiven {
		var terr *cliError
		if trusted, terr = loadTrusted(*trustedSpec); terr != nil {
			return terr
		}
	}
	priv, cerr := loadKey(*keyPath)
	if cerr != nil {
		return cerr
	}
	raw, cerr := readInput(*in)
	if cerr != nil {
		return cerr
	}
	env, err := trust.DecodeEnvelope(raw)
	if err != nil {
		return fail("the envelope file is not a valid envelope", "エンベロープのファイルが不正です").because(err)
	}
	if err := env.ValidateShape(); err != nil {
		return fail("the envelope has the wrong shape (payload type, payload or signatures)",
			"エンベロープの形式が不正です (種別・内容・署名)").because(err)
	}
	pol, cerr := parsePayload(env.Payload)
	if cerr != nil {
		return cerr
	}
	me := trust.KeyID(priv.Public().(ed25519.PublicKey))
	for _, sg := range env.Signatures {
		if sg.KeyID == me {
			return fail("this key has already signed this envelope; a second signature must come from a different key",
				"この鍵は既にこのエンベロープに署名しています。2つ目の署名は別の鍵で行ってください")
		}
	}
	if len(env.Signatures) >= wire.MaxSignatures {
		return fail("the envelope already has the maximum number of signatures", "署名数が上限に達しています")
	}

	if trusted != nil {
		if cerr := trusted.verifyExisting(env); cerr != nil {
			return cerr
		}
	}

	// Show exactly what will be enforced: the parsed policy and its hash.
	fmt.Fprintf(s.out, "%s\n", strings.TrimRight(pol.Render(), "\n"))
	fmt.Fprintf(s.out, "\npolicy hash: %s\n", policyHash(env.Payload))
	if trusted != nil {
		fmt.Fprintf(s.out, "signatures so far (verified against -trusted): %d\n", len(env.Signatures))
	} else {
		fmt.Fprintf(s.out, "signatures so far (not verified here): %d\n", len(env.Signatures))
		fmt.Fprint(s.err, "warning: the existing signatures were not verified; use -trusted <public keys> to check them before signing\n"+
			"警告: 既存の署名は検証されていません。署名の前に -trusted <公開鍵> で確認できます\n")
	}
	for _, sg := range env.Signatures {
		fmt.Fprintf(s.out, "  signed by key %s\n", sg.KeyID)
	}
	fmt.Fprintf(s.out, "you will sign as key %s\n", me)
	if !*yes {
		fmt.Fprint(s.out, "Type 'yes' to sign this policy: ")
		line, _ := bufio.NewReader(io.LimitReader(s.in, 64)).ReadString('\n')
		fmt.Fprintln(s.out)
		if strings.TrimSpace(line) != "yes" {
			return fail("not confirmed; nothing was signed", "確認されなかったため、署名していません")
		}
	}

	trust.Sign(&env, priv)
	data, cerr := encodeEnvelope(env)
	if cerr != nil {
		return cerr
	}
	if *out != "" {
		if err := createExclusive(*out, data, 0o644); err != nil {
			return writeErr(err)
		}
		fmt.Fprintf(s.out, "wrote %s (%d signatures)\n", *out, len(env.Signatures))
		return nil
	}
	if err := replaceFile(*in, data); err != nil {
		return fail("cannot update the envelope file: "+reason(err), "エンベロープのファイルを更新できません: "+reasonJa(err)).because(err)
	}
	fmt.Fprintf(s.out, "updated %s (%d signatures)\n", *in, len(env.Signatures))
	return nil
}
