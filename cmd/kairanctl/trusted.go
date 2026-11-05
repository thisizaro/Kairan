package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// maxTrustedKeys bounds a -trusted list; an envelope holds at most
// wire.MaxSignatures signatures, so a few more than that is plenty.
const maxTrustedKeys = 32

// trustedSet is the public keys an administrator names with -trusted.
type trustedSet struct {
	keys map[wire.Hash]ed25519.PublicKey // key ID -> key
	hex  map[string]bool                 // the hex strings given inline, to explain a common mistake
}

// loadTrusted parses a comma-separated list of public keys. Each item is a
// file holding one hex public key (the NAME.pub that keygen wrote) or the 64
// hex characters themselves. A key ID is not enough: a signature can only be
// checked against the public key.
func loadTrusted(spec string) (*trustedSet, *cliError) {
	bad := func(en, ja string) (*trustedSet, *cliError) { return nil, fail(en, ja) }
	items := strings.Split(spec, ",")
	if len(items) > maxTrustedKeys {
		return bad("-trusted lists too many keys", "-trusted の鍵が多すぎます")
	}
	ts := &trustedSet{keys: map[wire.Hash]ed25519.PublicKey{}, hex: map[string]bool{}}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			return bad("-trusted has an empty item (use a comma-separated list of public key files or hex public keys)",
				"-trusted に空の項目があります (公開鍵ファイルまたは16進公開鍵をカンマ区切りで指定してください)")
		}
		text := item
		if !isHexKey(item) {
			b, err := readBounded(item, 1024)
			switch {
			case errors.Is(err, errNotRegular):
				return bad("a -trusted file is not a regular file", "-trusted のファイルが通常のファイルではありません")
			case errors.Is(err, errTooBig):
				return bad("a -trusted file is not a public key file", "-trusted のファイルが公開鍵ファイルではありません")
			case err != nil:
				return bad("cannot read a -trusted file: "+reason(err), "-trusted のファイルを読めません: "+reasonJa(err))
			}
			text = strings.TrimSpace(string(b))
		} else {
			ts.hex[item] = true
		}
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return bad("-trusted must name public keys: a file written by keygen (NAME.pub) or 64 hex characters (a key ID is not enough to check a signature)",
				"-trusted には公開鍵を指定してください: keygen が作る NAME.pub ファイル、または16進数64文字 (鍵IDでは署名を検証できません)")
		}
		pub := ed25519.PublicKey(raw)
		ts.keys[trust.KeyID(pub)] = pub
	}
	return ts, nil
}

func isHexKey(s string) bool {
	if len(s) != 2*ed25519.PublicKeySize {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// verifyExisting checks every signature already on env: each must come from
// a key in ts and be valid over the exact payload bytes.
func (ts *trustedSet) verifyExisting(env wire.Envelope) *cliError {
	msg := trust.PAE(env.PayloadType, env.Payload)
	for _, sg := range env.Signatures {
		pub, ok := ts.keys[sg.KeyID]
		if !ok {
			if ts.hex[string(sg.KeyID)] {
				return fail("an existing signature names key "+string(sg.KeyID)+", which looks like a key ID: -trusted needs the public key, not the key ID",
					"既存の署名の鍵 "+string(sg.KeyID)+" は鍵IDのようです: -trusted には鍵IDではなく公開鍵が必要です")
			}
			return fail("an existing signature is from key "+string(sg.KeyID)+", which is not in -trusted; nothing was signed",
				"既存の署名の鍵 "+string(sg.KeyID)+" は -trusted にありません。署名していません")
		}
		if len(sg.Sig) != ed25519.SignatureSize || !ed25519.Verify(pub, msg, sg.Sig) {
			return fail("an existing signature from key "+string(sg.KeyID)+" is not valid for this payload; nothing was signed",
				"鍵 "+string(sg.KeyID)+" の既存の署名がこの内容に対して無効です。署名していません")
		}
	}
	return nil
}
