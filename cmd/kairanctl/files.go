package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"kairan/internal/wire"
)

// readBounded reads a whole file of at most limit bytes.
func readBounded(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, errTooBig
	}
	return b, nil
}

var errTooBig = errors.New("file too large")

// readInput reads a payload or envelope file (at most wire.MaxEnvelopeBytes).
func readInput(path string) ([]byte, *cliError) {
	b, err := readBounded(path, wire.MaxEnvelopeBytes)
	switch {
	case errors.Is(err, errTooBig):
		return nil, fail("input file is larger than the 256 KiB limit", "入力ファイルが上限 (256 KiB) を超えています")
	case err != nil:
		return nil, fail("cannot read input file: "+reason(err), "入力ファイルを読めません: "+reasonJa(err))
	}
	return b, nil
}

// createExclusive writes data to a new file; it never overwrites or follows
// a symbolic link at path. On a failed write the partial file is removed.
func createExclusive(path string, data []byte, perm fs.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(path)
		return err
	}
	return nil
}

// replaceFile atomically replaces path with data, keeping the old mode.
func replaceFile(path string, data []byte) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kairanctl-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			tmp.Close()
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(st.Mode().Perm()); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// loadKey reads a private key file: a hex ed25519 seed (as written by
// keygen). Like ssh, it refuses a file that other users can read or write.
// Errors say what is wrong with the file and never include its content.
func loadKey(path string) (ed25519.PrivateKey, *cliError) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fail("cannot open key file: "+reason(err), "鍵ファイルを開けません: "+reasonJa(err))
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fail("cannot read key file: "+reason(err), "鍵ファイルを読めません: "+reasonJa(err))
	}
	if !st.Mode().IsRegular() {
		return nil, fail("key file is not a regular file", "鍵ファイルが通常のファイルではありません")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fail("key file permissions are too open; run: chmod 600 <key file>",
			"鍵ファイルの権限が緩すぎます。chmod 600 <鍵ファイル> を実行してください")
	}
	b, err := io.ReadAll(io.LimitReader(f, 1024))
	if err != nil {
		return nil, fail("cannot read key file: "+reason(err), "鍵ファイルを読めません: "+reasonJa(err))
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fail("key file is not a kairanctl private key (expected 64 hex characters)",
			"鍵ファイルが kairanctl の秘密鍵ではありません (16進数64文字が必要です)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// reason gives a short English cause for a file error without echoing paths.
func reason(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "no such file or directory"
	case errors.Is(err, fs.ErrExist):
		return "file already exists"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	}
	return "I/O error"
}

func reasonJa(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "ファイルまたはディレクトリがありません"
	case errors.Is(err, fs.ErrExist):
		return "ファイルが既に存在します"
	case errors.Is(err, fs.ErrPermission):
		return "権限がありません"
	}
	return "入出力エラー"
}
