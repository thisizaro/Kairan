package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Q-D32, Q-D33, Q-D34 (M-D65): no message names a configured path or value,
// typed text is echoed escaped and bounded, and the Japanese line holds no raw
// library error text.

// libraryWords are English words of the Go library and the OS. They may be on
// the English line; never on the Japanese line.
var libraryWords = []string{
	"bind:", "permission denied", "no such file", "no such host", "address already in use",
	"is a directory", "not a directory", "file exists", "too many", "invalid argument",
	"mkdir", "open ", "lookup", "dial", "operation not", "connection refused", "read ", "write ",
}

// requireClean checks one English/Japanese pair (after any log lines) against
// the three rules. root is a string that must not appear anywhere.
func requireClean(t *testing.T, name, errOut string, mustNotHave ...string) (en, ja string) {
	t.Helper()
	_, rest := logLines(errOut)
	// a command-line error is followed by the usage text; cut it
	text := strings.Join(rest, "\n")
	if i := strings.Index(text, "usage:"); i >= 0 {
		text = text[:i]
	}
	en, ja = pairOf(t, name, text)
	for _, bad := range mustNotHave {
		if bad != "" && strings.Contains(errOut, bad) {
			t.Errorf("%s: output holds %q:\n%s", name, bad, errOut)
		}
	}
	for _, word := range libraryWords {
		if strings.Contains(ja, word) {
			t.Errorf("%s: the Japanese line holds library text %q:\n%s", name, word, ja)
		}
	}
	return en, ja
}

func TestStartupErrorsNameNoConfiguredPathAndJapaneseHasNoLibraryText(t *testing.T) {
	const marker = "zqmarker"
	w := newWorld(t)
	type tc struct {
		name   string
		setup  func(w2 *world) // changes the config or the disk
		code   int
		jaWant string // a Japanese phrase for the error class
	}
	file := func(w2 *world, name string) string {
		p := filepath.Join(w2.dir, name)
		if err := os.WriteFile(p, []byte("not a certificate"), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cases := []tc{
		{"data_dir under a file", func(w2 *world) {
			w2.cfg["data_dir"] = filepath.Join(file(w2, "afile"), marker+"-data")
		}, 1, ""},
		{"ca_file missing", func(w2 *world) {
			w2.cfg["ca_file"] = filepath.Join(w2.dir, marker+"-ca.pem")
		}, 2, "見つかりません"},
		{"ca_file a directory", func(w2 *world) {
			d := filepath.Join(w2.dir, marker+"-cadir")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			w2.cfg["ca_file"] = d
		}, 2, "通常のファイルではありません"},
		{"ca_file not PEM", func(w2 *world) {
			w2.cfg["ca_file"] = file(w2, marker+"-ca.pem")
		}, 2, "PEM"},
		{"decisions.log is a directory", func(w2 *world) {
			d := filepath.Join(w2.cfg["data_dir"].(string), decisionLogFile)
			if err := os.MkdirAll(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}, 1, "ディレクトリ"},
		{"data_dir not writable", func(w2 *world) {
			if os.Geteuid() == 0 {
				t.Skip("root can write anywhere")
			}
			ro := filepath.Join(w2.dir, marker+"-ro")
			if err := os.Mkdir(ro, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(ro, 0o700) })
			w2.cfg["data_dir"] = filepath.Join(ro, marker+"-data")
		}, 1, "権限"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w2 := newWorld(t)
			c.setup(w2)
			code, errOut := w.execute("-config", w2.writeConfig())
			if code != c.code {
				t.Errorf("code %d, want %d\n%s", code, c.code, errOut)
			}
			dataDir, _ := w2.cfg["data_dir"].(string)
			caFile, _ := w2.cfg["ca_file"].(string)
			_, ja := requireClean(t, c.name, errOut, marker, w2.dir, dataDir, caFile, "TestStartup")
			if c.jaWant != "" && !strings.Contains(ja, c.jaWant) {
				t.Errorf("Japanese line lacks %q:\n%s", c.jaWant, ja)
			}
		})
	}

	t.Run("config path", func(t *testing.T) {
		dir := filepath.Join(w.dir, marker)
		fifo := filepath.Join(w.dir, marker+".fifo")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		for name, c := range map[string]struct{ p, ja string }{
			"missing":    {filepath.Join(w.dir, marker+"-none.json"), "見つかりません"},
			"directory":  {dir, "通常のファイルではありません"},
			"fifo":       {fifo, "通常のファイルではありません"},
			"under file": {filepath.Join(file(w, "cfgfile"), marker), ""},
		} {
			code, errOut := w.execute("-config", c.p)
			if code != 2 {
				t.Errorf("%s: code %d\n%s", name, code, errOut)
			}
			_, ja := requireClean(t, name, errOut, marker, w.dir)
			if c.ja != "" && !strings.Contains(ja, c.ja) {
				t.Errorf("%s: Japanese line lacks %q:\n%s", name, c.ja, ja)
			}
		}
	})

	t.Run("listen address in use", func(t *testing.T) {
		r := w.start()
		defer r.stop(t)
		w2 := newWorld(t)
		w2.cfg["listen"] = r.addr
		code, errOut := w.execute("-config", w2.writeConfig())
		if code != 1 {
			t.Errorf("code %d\n%s", code, errOut)
		}
		en, ja := requireClean(t, "listen", errOut, r.addr, w2.dir)
		if !strings.Contains(en, "address already in use") {
			t.Errorf("the English line lost the system's reason:\n%s", en)
		}
		if !strings.Contains(ja, "アドレス") || !strings.Contains(ja, "使用中") {
			t.Errorf("Japanese line lacks the address-in-use phrase:\n%s", ja)
		}
	})
}

func TestEchoedCommandLineIsEscapedAndBounded(t *testing.T) {
	w := newWorld(t)
	long := strings.Repeat("a", 30000)
	cases := map[string][]string{
		"newline in flag":  {"-bogus\nkairan-proxy: error: forged"},
		"newline then ja":  {"-x\nkairan-proxy: エラー: forged"},
		"escape in flag":   {"-\x1b[2Jred"},
		"carriage return":  {"-a\rb"},
		"nul and DEL":      {"-a\x00b\x7fc"},
		"invalid utf8":     {"-\xff\xfe\xc3"},
		"non-ASCII flag":   {"-日本語"},
		"huge flag name":   {"-" + long},
		"huge config path": {"-config", long},
		"huge both":        {"-config", long, "-" + long},
	}
	for name, args := range cases {
		code, errOut := w.execute(args...)
		if code != 2 {
			t.Errorf("%s: code %d", name, code)
		}
		if len(errOut) > 2000 {
			t.Errorf("%s: %d bytes of output for a bad command line", name, len(errOut))
		}
		for i := 0; i < len(errOut); i++ {
			c := errOut[i]
			if c == 0x1b || c == '\r' || c == 0 || c == 0x7f || (c < 0x20 && c != '\n') {
				t.Errorf("%s: raw control byte %#x in the output", name, c)
				break
			}
		}
		var nEn, nJa int
		for _, l := range strings.Split(errOut, "\n") {
			if strings.HasPrefix(l, "kairan-proxy: error: ") {
				nEn++
			}
			if strings.HasPrefix(l, "kairan-proxy: エラー: ") {
				nJa++
			}
		}
		if nEn != 1 || nJa != 1 {
			t.Errorf("%s: %d English and %d Japanese error lines:\n%s", name, nEn, nJa, errOut)
		}
		en, _ := requireClean(t, name, errOut)
		if !isASCII(en) {
			t.Errorf("%s: English line is not ASCII", name)
		}
		if strings.Contains(name, "huge") && !strings.Contains(errOut, "...") && !strings.Contains(name, "path") {
			t.Errorf("%s: no ellipsis:\n%s", name, errOut)
		}
	}
}

func TestEsc(t *testing.T) {
	long := strings.Repeat("a", 500)
	cases := []struct{ in, want string }{
		{"-config", "-config"},
		{"a\nb", `a\x0ab`},
		{"\x1b[0m", `\x1b[0m`},
		{`a\b`, `a\x5cb`},
		{"\xff", `\xff`},
		{"é", `\xc3\xa9`},
		{"", ""},
		{long, strings.Repeat("a", 128) + "..."},
		{strings.Repeat("\n", 100), strings.Repeat(`\x0a`, 32) + "..."},
		{strings.Repeat("a", 127) + "\n", strings.Repeat("a", 127) + "..."},
		{strings.Repeat("a", 128), strings.Repeat("a", 128)},
	}
	for _, c := range cases {
		if got := esc(c.in); got != c.want {
			t.Errorf("esc(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestClassifyAndTexts(t *testing.T) {
	type c struct {
		err  error
		en   string
		ja   string
		name string
	}
	pe := func(e error) error { return &os.PathError{Op: "open", Path: "/zq/secret", Err: e} }
	for _, tc := range []c{
		{pe(syscall.ENOENT), "no such file or directory", "見つかりません", "not found"},
		{pe(syscall.EACCES), "permission denied", "権限がありません", "permission"},
		{pe(syscall.EADDRINUSE), "address already in use", "アドレスは既に使用中です", "address in use"},
		{pe(syscall.EISDIR), "is a directory", "ディレクトリです", "is a directory"},
		{pe(syscall.ENOTDIR), "not a directory", "その他", "other with errno"},
		{pe(syscall.EFBIG), "file too large", "大きすぎます", "too big"},
	} {
		en, ja := errText(tc.err), errClassJa(tc.err)
		if !strings.Contains(en, tc.en) || strings.Contains(en, "/zq") {
			t.Errorf("%s: English %q", tc.name, en)
		}
		if !strings.Contains(ja, tc.ja) || !hasJapanese(ja) || !isASCIIFree(ja) {
			t.Errorf("%s: Japanese %q", tc.name, ja)
		}
	}
}

// isASCIIFree is true when s holds no ASCII letters (so no library word).
func isASCIIFree(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' {
			return false
		}
	}
	return true
}
