package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Q-D36, Q-D37, Q-D38 (M-D65): no message names a configured path or value,
// typed text is echoed escaped and bounded, and the Japanese line holds no raw
// library error text. Every message is one English line and one Japanese line.

// libraryWords are English words of the Go library and the OS. They may be on
// the English line; never on the Japanese line.
var libraryWords = []string{
	"bind:", "permission denied", "no such file", "no such host", "address already in use",
	"is a directory", "not a directory", "file exists", "too many", "invalid argument",
	"mkdir", "open ", "lookup", "dial", "operation not", "connection refused", "read ", "write ",
	"store:",
}

// pairOf returns the English and Japanese error line of errOut, and fails
// unless there is exactly one of each.
func pairOf(t *testing.T, name, errOut string) (en, ja string) {
	t.Helper()
	var nEn, nJa int
	for _, l := range strings.Split(errOut, "\n") {
		switch {
		case strings.HasPrefix(l, "kairan-cp: error: "):
			nEn++
			en = l
		case strings.HasPrefix(l, "kairan-cp: エラー: "):
			nJa++
			ja = l
		}
	}
	if nEn != 1 || nJa != 1 {
		t.Errorf("%s: %d English and %d Japanese error lines:\n%s", name, nEn, nJa, errOut)
	}
	return en, ja
}

// requireClean checks one run's stderr against the three rules. mustNotHave
// lists strings (a path, a marker) that must not appear anywhere.
func requireClean(t *testing.T, name, errOut string, mustNotHave ...string) (en, ja string) {
	t.Helper()
	en, ja = pairOf(t, name, errOut)
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
	if strings.Contains(en, "store: open") || strings.Contains(errOut, "store: open") {
		t.Errorf("%s: library text 'store: open' in:\n%s", name, errOut)
	}
	return en, ja
}

func noControlBytes(t *testing.T, name, s string) {
	t.Helper()
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x1b || c == '\r' || c == 0 || c == 0x7 || c == 0x7f || (c < 0x20 && c != '\n') {
			t.Errorf("%s: raw control byte %#x in the output", name, c)
			return
		}
	}
}

func TestStartupErrorsNameNoConfiguredPathAndJapaneseHasNoLibraryText(t *testing.T) {
	const marker = "zqmarker"
	tokenEnv := func(h *harness) []string { return []string{envTokenFile + "=" + h.token} }
	type tc struct {
		name   string
		setup  func(h *harness) []string // changes the config or the disk; returns args
		code   int
		jaWant string // a Japanese phrase for the error class
	}
	cfgArgs := func(h *harness) []string { return []string{"-config", h.write()} }
	cases := []tc{
		{"data_dir under a file", func(h *harness) []string {
			f := filepath.Join(h.dir, "afile")
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.cfg["data_dir"] = filepath.Join(f, marker+"-data")
			return cfgArgs(h)
		}, 1, ""},
		{"data_dir not writable", func(h *harness) []string {
			if os.Geteuid() == 0 {
				t.Skip("root can write anywhere")
			}
			ro := filepath.Join(h.dir, marker+"-ro")
			if err := os.Mkdir(ro, 0o500); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Chmod(ro, 0o700) })
			h.cfg["data_dir"] = filepath.Join(ro, marker+"-data")
			return cfgArgs(h)
		}, 1, "権限"},
		{"config missing", func(h *harness) []string {
			return []string{"-config", filepath.Join(h.dir, marker+"-none.json")}
		}, 2, "見つかりません"},
		{"config is a directory", func(h *harness) []string {
			d := filepath.Join(h.dir, marker+"-dir")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", d}
		}, 2, "通常のファイルではありません"},
		{"config is a fifo", func(h *harness) []string {
			f := filepath.Join(h.dir, marker+".fifo")
			if err := syscall.Mkfifo(f, 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", f}
		}, 2, "通常のファイルではありません"},
		{"config under a file", func(h *harness) []string {
			f := filepath.Join(h.dir, "cfgfile")
			if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", filepath.Join(f, marker)}
		}, 2, ""},
		{"config not readable", func(h *harness) []string {
			if os.Geteuid() == 0 {
				t.Skip("root can read anything")
			}
			p := h.write()
			if err := os.Chmod(p, 0); err != nil {
				t.Fatal(err)
			}
			return []string{"-config", p}
		}, 2, "権限"},
		{"token file missing", func(h *harness) []string {
			return append(cfgArgs(h), "-admin-token-file", filepath.Join(h.dir, marker+"-token"))
		}, 2, "見つかりません"},
		{"token file is a directory", func(h *harness) []string {
			d := filepath.Join(h.dir, marker+"-tokdir")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			return append(cfgArgs(h), "-admin-token-file", d)
		}, 2, "通常のファイルではありません"},
		{"tls files missing", func(h *harness) []string {
			delete(h.cfg, "allow_plaintext")
			h.cfg["tls_cert_file"] = filepath.Join(h.dir, marker+"-cert.pem")
			h.cfg["tls_key_file"] = filepath.Join(h.dir, marker+"-key.pem")
			return cfgArgs(h)
		}, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			args := c.setup(h)
			code, out, errOut := runBin(t, h, tokenEnv(h), args...)
			if code != c.code || out != "" {
				t.Errorf("code %d (want %d) stdout %q\n%s", code, c.code, out, errOut)
			}
			dataDir, _ := h.cfg["data_dir"].(string)
			_, ja := requireClean(t, c.name, errOut, marker, h.dir, dataDir)
			if c.jaWant != "" && !strings.Contains(ja, c.jaWant) {
				t.Errorf("Japanese line lacks %q:\n%s", c.jaWant, ja)
			}
			noControlBytes(t, c.name, errOut)
		})
	}

	t.Run("data_dir error names the field", func(t *testing.T) {
		h := newHarness(t)
		f := filepath.Join(h.dir, "afile")
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		h.cfg["data_dir"] = filepath.Join(f, "d")
		_, _, errOut := runBin(t, h, tokenEnv(h), "-config", h.write())
		en, ja := requireClean(t, "data_dir", errOut, f)
		if !strings.Contains(en, "data_dir") || !strings.Contains(ja, "data_dir") {
			t.Errorf("messages do not name data_dir:\n%s", errOut)
		}
	})

	t.Run("listen address in use", func(t *testing.T) {
		h := newHarness(t)
		first := h.start("-config", h.write())
		defer first.stop()
		h2 := newHarness(t)
		h2.cfg["listen"] = first.addr
		code, _, errOut := runBin(t, h2, tokenEnv(h2), "-config", h2.write())
		if code != 1 {
			t.Errorf("code %d\n%s", code, errOut)
		}
		en, ja := requireClean(t, "listen", errOut, first.addr, h2.dir)
		if !strings.Contains(en, "address already in use") {
			t.Errorf("the English line lost the system's reason:\n%s", en)
		}
		if !strings.Contains(ja, "アドレス") || !strings.Contains(ja, "使用中") {
			t.Errorf("Japanese line lacks the address-in-use phrase:\n%s", ja)
		}
	})
}

func TestEchoedCommandLineIsEscapedAndBounded(t *testing.T) {
	h := newHarness(t)
	cfg := h.write()
	env := []string{envTokenFile + "=" + h.token}
	long := strings.Repeat("a", 30000)
	cases := map[string][]string{
		"newline in flag":    {"-config", cfg, "-bogus\nkairan-cp: error: forged"},
		"newline then ja":    {"-config", cfg, "-x\nkairan-cp: エラー: forged"},
		"escape in flag":     {"-config", cfg, "-\x1b[2Jred"},
		"bell in flag":       {"-config", cfg, "-a\ab"},
		"carriage return":    {"-config", cfg, "-a\rb"},
		"DEL":                {"-config", cfg, "-a\x7fc"},
		"invalid utf8":       {"-config", cfg, "-\xff\xfe\xc3"},
		"non-ASCII flag":     {"-config", cfg, "-日本語"},
		"huge flag name":     {"-config", cfg, "-" + long},
		"flag lacks a value": {"-config", cfg, "-admin-token-file"},
		"backslash flag":     {"-config", cfg, `-a\nb`},
	}
	for name, args := range cases {
		code, out, errOut := runBin(t, h, env, args...)
		if code != 2 || out != "" {
			t.Errorf("%s: code %d stdout %q", name, code, out)
		}
		if len(errOut) > 2000 {
			t.Errorf("%s: %d bytes of output for a bad command line", name, len(errOut))
		}
		noControlBytes(t, name, errOut)
		en, _ := requireClean(t, name, errOut)
		if !isASCII(en) {
			t.Errorf("%s: English line is not ASCII", name)
		}
		if strings.Contains(name, "huge") && !strings.Contains(errOut, "...") {
			t.Errorf("%s: no ellipsis:\n%s", name, errOut)
		}
	}
	// a typed flag name is still shown, escaped
	_, _, errOut := runBin(t, h, env, "-config", cfg, "-bogus\x1b[2J")
	if !strings.Contains(errOut, `unknown flag: -bogus\x1b[2J`) || !strings.Contains(errOut, `未知のフラグです: -bogus\x1b[2J`) {
		t.Errorf("escaped flag name missing:\n%s", errOut)
	}
}

func TestEchoedConfigFieldNamesAreEscapedAndBounded(t *testing.T) {
	long := strings.Repeat("a", 30000)
	cases := map[string]string{
		"unknown field ESC":    `{"listen":"127.0.0.1:0","\u001b[2Jhostile":1}`,
		"unknown field bell":   `{"listen":"127.0.0.1:0","a\u0007b":1}`,
		"unknown field newl":   `{"listen":"127.0.0.1:0","x\nkairan-cp: error: forged":1}`,
		"unknown field newlja": `{"listen":"127.0.0.1:0","x\nkairan-cp: エラー: forged":1}`,
		"unknown field huge":   `{"listen":"127.0.0.1:0","` + long + `":1}`,
		"unknown non-ASCII":    `{"listen":"127.0.0.1:0","日本語":1}`,
		"upper case ESC":       `{"listen":"127.0.0.1:0","\u001b[2JA":1}`,
		"upper case newline":   `{"listen":"127.0.0.1:0","A\nB":1}`,
		"repeated field ESC":   `{"\u001b[2Jx":1,"\u001b[2Jx":2}`,
		"repeated field huge":  `{"` + long + `":1,"` + long + `":2}`,
		"wrong type nested":    `{"listen":"127.0.0.1:0","tenants":{"a\u001bb":5}}`,
		"wrong type enroll":    `{"listen":"127.0.0.1:0","enrollments":[{"proxy_id":5}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			p := filepath.Join(h.dir, "bad.json")
			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			code, out, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", p)
			if code != 2 || out != "" {
				t.Errorf("code %d stdout %q\n%s", code, out, errOut)
			}
			if len(errOut) > 1500 {
				t.Errorf("%d bytes of output", len(errOut))
			}
			noControlBytes(t, name, errOut)
			en, _ := requireClean(t, name, errOut)
			if !isASCII(en) {
				t.Errorf("English line is not ASCII: %q", en)
			}
			if strings.Contains(name, "huge") && !strings.Contains(errOut, "...") {
				t.Errorf("no ellipsis:\n%.300s", errOut)
			}
		})
	}
	// a field name is still shown, escaped
	h := newHarness(t)
	p := filepath.Join(h.dir, "bad.json")
	if err := os.WriteFile(p, []byte(`{"listen":"127.0.0.1:0","\u001b[2jx":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", p)
	if !strings.Contains(errOut, `unknown field: \x1b[2jx`) || !strings.Contains(errOut, `未知のフィールドです: \x1b[2jx`) {
		t.Errorf("escaped field name missing:\n%s", errOut)
	}
}

func TestCorruptStateFileNameIsEscaped(t *testing.T) {
	h := newHarness(t)
	d := filepath.Join(h.dir, "data", "envelopes", "bank-a")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "00000000000000000001.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write())
	requireClean(t, "corrupt", errOut, h.dir)
	noControlBytes(t, "corrupt", errOut)
}

func TestEsc(t *testing.T) {
	long := strings.Repeat("a", 500)
	cases := []struct{ in, want string }{
		{"-config", "-config"},
		{"a\nb", `a\x0ab`},
		{"\x1b[0m", `\x1b[0m`},
		{"\a", `\x07`},
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

func FuzzEsc(f *testing.F) {
	for _, s := range []string{"", "a", "\x1b[2J", "a\nb", "日本語", "\xff\xfe", strings.Repeat("\n", 200)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := esc(s)
		if len(got) > maxEcho+3 {
			t.Fatalf("%d bytes", len(got))
		}
		for i := 0; i < len(got); i++ {
			if got[i] < 0x20 || got[i] >= 0x7f {
				t.Fatalf("byte %#x in %q", got[i], got)
			}
		}
	})
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
		{errNotRegular, "not a regular file", "通常のファイルではありません", "not regular"},
		{errTooBig, "too large", "大きすぎます", "too large"},
		{os.ErrInvalid, "other error", "その他", "other"},
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
