package main

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"

	"kairan/internal/cp/store"
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
// What the person typed (a flag name, a field name of the config) is echoed
// only through esc. A source-scan test (messages_test.go) fails any message
// that skips these rules.

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
	case errors.Is(err, errNotRegular):
		return classNotRegular
	case errors.Is(err, errTooBig), errors.Is(err, syscall.EFBIG), errors.Is(err, syscall.E2BIG):
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
func errClassJa(err error) string { return classify(err).ja() }

// errText is the English reason for err: the system's own text for an errno
// (such as "address already in use"; an errno has no path) or the class name.
// It never holds a path or a value.
func errText(err error) string {
	var en syscall.Errno
	switch {
	case err == nil:
		return "no error"
	case errors.As(err, &en):
		return en.Error()
	}
	return classify(err).en()
}

// osMsg is a failure with a cause: the English line adds the reason (errText)
// and the Japanese line the class (errClassJa). Neither holds a path or a
// value, and the Japanese line holds no library text (M-D65).
func osMsg(en, ja string, err error) *cliError {
	return msg(en+": "+errText(err), ja+": "+errClassJa(err))
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

// oneLine makes sure a message cannot start a second line or carry a control
// byte, whatever was put into it.
func oneLine(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			b.WriteString(fmt.Sprintf(`\x%02x`, c))
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// corruptFile is the name of the damaged state file that store.ErrCorrupt
// reports (a name inside the data directory, not the configured path).
func corruptFile(err error) string {
	return strings.TrimPrefix(err.Error(), store.ErrCorrupt.Error()+": ")
}
