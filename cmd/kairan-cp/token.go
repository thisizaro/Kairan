package main

import (
	"io"
	"os"
	"strings"
	"syscall"
)

const (
	envTokenFile = "KCP_ADMIN_TOKEN_FILE"
	envToken     = "KCP_ADMIN_TOKEN"

	minTokenBytes = 16
	maxTokenBytes = 256
	maxTokenFile  = 4096
)

// adminToken finds the admin token. The sources, in order: the file named by
// -admin-token-file, the file named by KCP_ADMIN_TOKEN_FILE, the value of
// KCP_ADMIN_TOKEN. There is no flag that carries the token itself, because a
// command line is visible to every user of the machine. A token file must be
// a regular file readable by its owner only (chmod 600 or 400); it is opened
// without blocking, so a FIFO is refused instead of waited on.
func adminToken(flagFile string, getenv func(string) string) (string, *cliError) {
	var raw string
	switch {
	case flagFile != "":
		b, cerr := readTokenFile(flagFile)
		if cerr != nil {
			return "", cerr
		}
		raw = b
	case strings.TrimSpace(getenv(envTokenFile)) != "":
		b, cerr := readTokenFile(strings.TrimSpace(getenv(envTokenFile)))
		if cerr != nil {
			return "", cerr
		}
		raw = b
	default:
		raw = getenv(envToken)
	}
	tok := strings.TrimSpace(raw)
	if tok == "" {
		return "", msg("no admin token: use -admin-token-file, "+envTokenFile+" or "+envToken,
			"管理トークンがありません。-admin-token-file、"+envTokenFile+"、"+envToken+" のいずれかで指定してください")
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] < 0x21 || tok[i] > 0x7e {
			return "", msg("the admin token has spaces or non-printable characters", "管理トークンに空白または表示できない文字があります")
		}
	}
	switch {
	case len(tok) < minTokenBytes:
		return "", msg("the admin token is too short (at least 16 characters)", "管理トークンが短すぎます (16 文字以上)")
	case len(tok) > maxTokenBytes:
		return "", msg("the admin token is too large (at most 256 characters)", "管理トークンが大きすぎます (256 文字まで)")
	}
	return tok, nil
}

func readTokenFile(path string) (string, *cliError) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", tokenFileErr(err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", tokenFileErr(err)
	}
	if !st.Mode().IsRegular() {
		return "", msg("admin token file: not a regular file", "管理トークンファイル: 通常のファイルではありません")
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", msg("admin token file permissions are too open; run chmod 600 on it", "管理トークンファイルの権限が緩すぎます。chmod 600 を実行してください")
	}
	b, err := io.ReadAll(io.LimitReader(f, maxTokenFile+1))
	if err != nil {
		return "", tokenFileErr(err)
	}
	if len(b) > maxTokenFile {
		return "", msg("the admin token file is too large", "管理トークンファイルが大きすぎます")
	}
	return string(b), nil
}

func tokenFileErr(err error) *cliError {
	return osMsg("admin token file", "管理トークンファイル", err)
}
