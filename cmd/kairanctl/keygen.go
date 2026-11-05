package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"

	"kairan/internal/trust"
)

// keyNameRE keeps NAME a plain file name: no separators, no leading dot.
var keyNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)

// cmdKeygen creates NAME.key (private, mode 0600) and NAME.pub. It refuses
// to touch an existing file (M-D37) and never prints the private key.
func cmdKeygen(args []string, s streams) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	name := fs.String("name", "", "key name; files are NAME.key and NAME.pub")
	dir := fs.String("dir", ".", "directory to write into")
	if err := parseFlags(fs, args, s); err != nil {
		return err
	}
	if *name == "" {
		return usageErr("-name is required", "-name が必要です")
	}
	if !keyNameRE.MatchString(*name) {
		return fail("key name may contain only letters, digits, '_', '.' and '-' (up to 64, not starting with a symbol)",
			"鍵の名前に使えるのは英数字と _ . - のみです (64文字まで、記号で始められません)")
	}
	if st, err := os.Stat(*dir); err != nil || !st.IsDir() {
		return fail("output directory does not exist", "出力先のディレクトリがありません")
	}
	keyPath := filepath.Join(*dir, *name+".key")
	pubPath := filepath.Join(*dir, *name+".pub")
	for _, p := range []string{keyPath, pubPath} {
		if _, err := os.Lstat(p); err == nil {
			return fail("refusing to overwrite an existing file: "+filepath.Base(p),
				"既存のファイルは上書きしません: "+filepath.Base(p))
		}
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fail("cannot generate a key", "鍵を生成できません")
	}
	if err := createExclusive(keyPath, []byte(hex.EncodeToString(priv.Seed())+"\n"), 0o600); err != nil {
		return writeErr(err)
	}
	pubHex := hex.EncodeToString(pub)
	if err := createExclusive(pubPath, []byte(pubHex+"\n"), 0o644); err != nil {
		os.Remove(keyPath)
		return writeErr(err)
	}
	fmt.Fprintf(s.out, "wrote %s (private key, mode 0600: keep it on this machine only)\n", keyPath)
	fmt.Fprintf(s.out, "wrote %s (public key: share this)\n", pubPath)
	fmt.Fprintf(s.out, "key id:     %s\n", trust.KeyID(pub))
	fmt.Fprintf(s.out, "public key: %s\n", pubHex)
	return nil
}

// writeErr turns a file-creation error into a bilingual failure.
func writeErr(err error) *cliError {
	if errors.Is(err, fs.ErrExist) {
		return fail("refusing to overwrite an existing file", "既存のファイルは上書きしません").because(err)
	}
	return fail("cannot write output file: "+reason(err), "出力ファイルを書けません: "+reasonJa(err)).because(err)
}
