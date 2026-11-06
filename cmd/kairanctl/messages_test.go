package main

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// M-D65 (Q-D33, Q-D34, Q-D39): the flag package speaks English only and echoes
// what was typed. Every flag failure of every subcommand is one English line
// and one Japanese line, never repeats a typed value, repeats a typed flag
// name only escaped and cut to 128 bytes, and -h prints a bilingual usage.

// subcommands lists the 11 subcommands with a flag that takes a value, flags
// that parse a typed value (bad values go here) and a boolean flag, if any.
var subcommands = []struct {
	args    []string
	valFlag string   // takes a string value
	typed   []string // flags whose value is a number or a duration
	boolean []string // boolean flags
	flags   []string // every flag; each must be in the usage
}{
	{[]string{"keygen"}, "-name", nil, nil, []string{"name", "dir"}},
	{[]string{"policy", "new"}, "-tenant", []string{"-version", "-validity"}, nil, []string{"tenant", "version", "validity", "out"}},
	{[]string{"sign"}, "-key", nil, nil, []string{"key", "in", "out"}},
	{[]string{"approve"}, "-key", nil, []string{"-yes"}, []string{"key", "in", "out", "yes", "trusted"}},
	{[]string{"publish"}, "-in", nil, []string{"-allow-plaintext"}, []string{"url", "ca-file", "token-file", "allow-plaintext", "in"}},
	{[]string{"rollout", "start"}, "-tenant", []string{"-version", "-canary-dwell"}, []string{"-allow-plaintext"}, []string{"url", "ca-file", "token-file", "allow-plaintext", "tenant", "version", "canary-dwell"}},
	{[]string{"rollout", "status"}, "-tenant", nil, []string{"-allow-plaintext"}, []string{"url", "ca-file", "token-file", "allow-plaintext", "tenant"}},
	{[]string{"rollout", "rollback"}, "-from", []string{"-version", "-validity"}, nil, []string{"from", "version", "validity", "out", "key", "key2", "env-out"}},
	{[]string{"fleet"}, "-tenant", nil, []string{"-allow-plaintext"}, []string{"url", "ca-file", "token-file", "allow-plaintext", "tenant"}},
	{[]string{"evidence", "export"}, "-applylog", nil, []string{"-allow-plaintext"}, []string{"url", "ca-file", "token-file", "allow-plaintext", "tenant", "proxy", "out", "applylog"}},
	{[]string{"verify-applylog"}, "-in", nil, nil, []string{"in"}},
}

// checkFlagFailure applies the rules to one failing run. wantName, if not
// empty, is a string the English line must hold (the escaped flag name).
func checkFlagFailure(t *testing.T, what string, code int, out, errb string, wantName string) {
	t.Helper()
	if code != 2 {
		t.Errorf("%s: exit %d, want 2", what, code)
	}
	if out != "" {
		t.Errorf("%s: standard output %q", what, out)
	}
	if !utf8.ValidString(errb) {
		t.Errorf("%s: stderr is not UTF-8", what)
	}
	for _, c := range errb {
		if (c < 0x20 && c != '\n') || c == 0x7f || (c >= 0x80 && c < 0xa0) {
			t.Errorf("%s: raw control character %U in stderr", what, c)
			break
		}
	}
	lines := strings.Split(strings.TrimSuffix(errb, "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "error: ") || !strings.HasPrefix(lines[1], "エラー: ") {
		t.Errorf("%s: stderr does not start with an English and a Japanese line:\n%.400s", what, errb)
		return
	}
	if hasJapanese(lines[0]) || !hasJapanese(lines[1]) {
		t.Errorf("%s: wrong languages:\n%.400s", what, errb)
	}
	if len(lines) > 2 && lines[2] != "" {
		t.Errorf("%s: text after the pair is not separated by a blank line:\n%.400s", what, errb)
	}
	for _, ln := range lines[2:] {
		if strings.HasPrefix(ln, "error: ") || strings.HasPrefix(ln, "エラー: ") {
			t.Errorf("%s: a second error line %.100q", what, ln)
		}
	}
	for _, bad := range []string{"CANARYVAL", "flag provided", "invalid value", "invalid boolean", "parse error", "bad flag syntax"} {
		if strings.Contains(errb, bad) {
			t.Errorf("%s: stderr holds %q:\n%.400s", what, bad, errb)
		}
	}
	for _, ln := range lines[:2] {
		if len(ln) > 128+200 {
			t.Errorf("%s: a message line is %d bytes", what, len(ln))
		}
	}
	if wantName != "" && !strings.Contains(lines[0], wantName) {
		t.Errorf("%s: English line lacks %q:\n%.400s", what, wantName, lines[0])
	}
	if len(lines) > 3 && !strings.HasPrefix(lines[3], "kairanctl:") {
		t.Errorf("%s: usage does not follow the pair: %.100q", what, lines[3])
	}
}

func TestFlagErrorsAreEnglishJapanesePairs(t *testing.T) {
	long := strings.Repeat("x", 30*1024)
	for _, sc := range subcommands {
		name := strings.Join(sc.args, " ")
		with := func(extra ...string) []string { return append(append([]string{}, sc.args...), extra...) }
		type tc struct {
			what string
			args []string
			name string // wanted in the English line
		}
		cases := []tc{
			{"unknown flag", with("-CANARYFLAG"), "-CANARYFLAG"},
			{"double dash", with("--CANARYFLAG"), "-CANARYFLAG"},
			{"unknown flag with value", with("-bogus=CANARYVAL"), "-bogus"},
			{"newline in name", with("-a\nerror: forged"), `\x0a`},
			{"escape in name", with("-\x1b[2JCANARYFLAG"), `\x1b`},
			{"bell and NUL in name", with("-a\x07\x00b"), `\x07\x00`},
			{"non-printable UTF-8", with("-a\u202eb\xff"), `\x`},
			{"missing value", with(sc.valFlag), strings.TrimPrefix(sc.valFlag, "-")},
			{"bad syntax", with("---CANARYVAL"), ""},
			{"bad syntax equals", with("-=CANARYVAL"), ""},
			{"30 KB flag name", with("-" + long), "..."},
		}
		for _, f := range sc.typed {
			cases = append(cases,
				tc{"bad value " + f, with(f, "CANARYVAL"), ""},
				tc{"control bytes in value " + f, with(f, "x\x1b[2J\nerror: forged CANARYVAL"), ""},
				tc{"negative " + f, with(f, "-5"), ""},
				tc{"30 KB value " + f, with(f, "CANARYVAL"+long), ""},
			)
		}
		for _, f := range sc.boolean {
			cases = append(cases, tc{"bad bool " + f, with(f + "=CANARYVAL"), ""})
		}
		for _, c := range cases {
			t.Run(name+"/"+c.what, func(t *testing.T) {
				code, out, errb := ctl(t, "", c.args...)
				checkFlagFailure(t, name+": "+c.what, code, out, errb, c.name)
				if strings.Contains(c.what, "30 KB value") && len(errb) > 8192 {
					t.Errorf("typed value echoed unbounded (%d bytes)", len(errb))
				}
			})
		}
	}
}

func TestEscapeAndCut(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abc", "abc"},
		{"a\nb", `a\x0ab`},
		{"a\x1bb", `a\x1bb`},
		{`a\b`, `a\x5cb`},
		{"é", `\xc3\xa9`},
		{"a\x7f", `a\x7f`},
		{strings.Repeat("a", 128), strings.Repeat("a", 128)},
		{strings.Repeat("a", 129), strings.Repeat("a", 128) + "..."},
		{strings.Repeat("\n", 40), strings.Repeat(`\x0a`, 32) + "..."},
	} {
		if got := esc(tc.in); got != tc.want {
			t.Errorf("esc(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHelpPrintsBilingualUsagePerSubcommand(t *testing.T) {
	for _, sc := range subcommands {
		name := strings.Join(sc.args, " ")
		for _, h := range []string{"-h", "-help", "--help"} {
			t.Run(name+" "+h, func(t *testing.T) {
				code, out, errb := ctl(t, "", append(append([]string{}, sc.args...), h)...)
				if code != 0 {
					t.Errorf("exit %d, want 0", code)
				}
				if errb != "" {
					t.Errorf("stderr %q", errb)
				}
				lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
				if len(lines) < 4 || !strings.HasPrefix(lines[0], "kairanctl: usage: kairanctl "+name) || !strings.HasPrefix(lines[1], "kairanctl: 使い方: kairanctl "+name) {
					t.Fatalf("usage does not open with an English and a Japanese line:\n%s", out)
				}
				if hasJapanese(lines[0]) {
					t.Errorf("English usage line holds Japanese: %q", lines[0])
				}
				seen := map[string]bool{}
				for i, ln := range lines {
					if !strings.HasPrefix(ln, "  -") {
						continue
					}
					f := strings.Fields(ln)[0][1:]
					seen[f] = true
					if i+2 >= len(lines) || !strings.HasPrefix(lines[i+1], "        ") || !strings.HasPrefix(lines[i+2], "        ") ||
						hasJapanese(lines[i+1]) || !hasJapanese(lines[i+2]) {
						t.Errorf("flag -%s: no English line then Japanese line after it:\n%s", f, out)
					}
				}
				for _, f := range sc.flags {
					if !seen["-"+f] && !seen[f] {
						t.Errorf("flag -%s is not in the usage:\n%s", f, out)
					}
				}
				if len(seen) != len(sc.flags) {
					t.Errorf("usage lists %d flags, want %d:\n%s", len(seen), len(sc.flags), out)
				}
			})
		}
	}
}

// A flag error is followed by the usage of that subcommand, so that the person
// sees which flags exist, in both languages.
func TestFlagErrorShowsSubcommandUsage(t *testing.T) {
	for _, sc := range subcommands {
		name := strings.Join(sc.args, " ")
		_, _, errb := ctl(t, "", append(append([]string{}, sc.args...), "-nope")...)
		if !strings.Contains(errb, "\nkairanctl: usage: kairanctl "+name) || !strings.Contains(errb, "使い方: kairanctl "+name) {
			t.Errorf("%s: no usage after the error:\n%s", name, errb)
		}
	}
}

func TestHelpDoesNotEchoLaterArguments(t *testing.T) {
	code, out, errb := ctl(t, "", "keygen", "-h", "-CANARYFLAG")
	if code != 0 || strings.Contains(out+errb, "CANARYFLAG") {
		t.Errorf("exit %d, out %q err %q", code, out, errb)
	}
}
