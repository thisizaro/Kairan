package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

	"kairan/internal/proxy/agent"
	"kairan/internal/proxy/applylog"
)

// What a message may say about a failure (M-D65). The error of a library or of
// the OS can hold a configured path or value ("open /etc/x: permission
// denied"), so no message uses err.Error(). A message names the config field
// and gives the error class:
//
//   - the English line gets errText: the system's own reason (the errno text,
//     which has no path) or the class name;
//   - the Japanese line gets errClassJa: a Japanese phrase for the class, never
//     library text.
//
// What the person typed is echoed only through esc. A source-scan test
// (messages_test.go) fails any message that skips these rules.

// errClass is the kind of failure.
type errClass int

const (
	classOther errClass = iota
	classNotFound
	classPermission
	classAddrInUse
	classIsDir
	classNotRegular
	classTooLarge
)

// classify puts err into a class.
func classify(err error) errClass {
	switch {
	case err == nil:
		return classOther
	case errors.Is(err, fs.ErrNotExist):
		return classNotFound
	case errors.Is(err, fs.ErrPermission):
		return classPermission
	case errors.Is(err, syscall.EADDRINUSE):
		return classAddrInUse
	case errors.Is(err, syscall.EISDIR):
		return classIsDir
	case errors.Is(err, agent.ErrNotRegular):
		return classNotRegular
	case errors.Is(err, agent.ErrTooLarge), errors.Is(err, syscall.EFBIG), errors.Is(err, syscall.E2BIG):
		return classTooLarge
	}
	return classOther
}

func (c errClass) en() string {
	switch c {
	case classNotFound:
		return "not found"
	case classPermission:
		return "permission denied"
	case classAddrInUse:
		return "address already in use"
	case classIsDir:
		return "is a directory"
	case classNotRegular:
		return "not a regular file"
	case classTooLarge:
		return "too large"
	}
	return "other error"
}

func (c errClass) ja() string {
	switch c {
	case classNotFound:
		return "見つかりません"
	case classPermission:
		return "権限がありません"
	case classAddrInUse:
		return "アドレスは既に使用中です"
	case classIsDir:
		return "ディレクトリです"
	case classNotRegular:
		return "通常のファイルではありません"
	case classTooLarge:
		return "大きすぎます"
	}
	return "その他のエラーです"
}

// errClassJa is the Japanese phrase for the class of err.
func errClassJa(err error) string {
	if errors.Is(err, agent.ErrNoPEM) {
		return "PEM 証明書が含まれていません"
	}
	return classify(err).ja()
}

// errText is the English reason for err: the system's own text for an errno
// (such as "address already in use"; an errno has no path), the class name, or
// the fixed text of an errors.New of ours. It never holds a path or a value.
func errText(err error) string {
	var en syscall.Errno
	switch {
	case err == nil:
		return "no error"
	case errors.Is(err, agent.ErrNoPEM):
		return "holds no PEM certificate"
	case errors.Is(err, applylog.ErrChain):
		return "the hash chain is broken"
	case errors.Is(err, applylog.ErrMalformed):
		return "an entry is malformed"
	case errors.Is(err, applylog.ErrTruncated):
		return "the last line is truncated"
	case errors.Is(err, applylog.ErrChanged):
		return "the file changed since the last append"
	case errors.As(err, &en):
		return en.Error()
	}
	if c := classify(err); c != classOther {
		return c.en()
	}
	// An error made by errors.New in our own packages has fixed text. Anything
	// that wraps another error, or comes from elsewhere, might hold a value.
	if fmt.Sprintf("%T", err) == "*errors.errorString" && errors.Unwrap(err) == nil {
		return err.Error()
	}
	return classOther.en()
}

// maxEcho is the most bytes of typed text that a message repeats.
const maxEcho = 128

// esc makes typed text safe to put in a message: printable ASCII stays, every
// other byte (control bytes, ESC, a newline, non-ASCII, a backslash) becomes
// \xNN, and the result is cut to maxEcho bytes with "...". The message stays
// one line of ASCII however hostile the input.
func esc(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		part := string(c)
		if c < 0x20 || c >= 0x7f || c == '\\' {
			part = fmt.Sprintf(`\x%02x`, c)
		}
		if b.Len()+len(part) > maxEcho {
			b.WriteString("...")
			break
		}
		b.WriteString(part)
	}
	return b.String()
}
