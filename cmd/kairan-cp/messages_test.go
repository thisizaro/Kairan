package main

import (
	"bufio"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every message for a person is in English and in Japanese (package doc,
// M-D61, Q-D25). These tests enumerate the message paths: the source scan
// finds any path that skips the bilingual helpers, and the process tests run
// the real binary through the paths that print.

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func TestEveryLogEventIsBilingual(t *testing.T) {
	if len(events) < 6 {
		t.Fatalf("only %d events listed", len(events))
	}
	for _, ev := range events {
		if ev.en == "" || !isASCII(ev.en) {
			t.Errorf("english text %q is empty or not English", ev.en)
		}
		if !hasJapanese(ev.ja) {
			t.Errorf("event %q has no Japanese text: %q", ev.en, ev.ja)
		}
	}
}

func TestUsageTextIsBilingual(t *testing.T) {
	for _, want := range []string{"usage:", "使い方:", "path of the control plane config file", "設定ファイル", "管理トークン", "then exit", "終了"} {
		if !strings.Contains(usageText, want) {
			t.Errorf("usage text lacks %q", want)
		}
	}
}

// literals returns the string literals found anywhere inside e.
func literals(e ast.Expr) []string {
	var out []string
	ast.Inspect(e, func(n ast.Node) bool {
		if bl, ok := n.(*ast.BasicLit); ok && bl.Kind == token.STRING {
			if s, err := strconv.Unquote(bl.Value); err == nil {
				out = append(out, s)
			}
		}
		return true
	})
	return out
}

// japaneseArg is true when e holds a Japanese literal or names a Japanese
// string (a parameter called ja, or ending in Ja).
func japaneseArg(e ast.Expr) bool {
	for _, s := range literals(e) {
		if hasJapanese(s) {
			return true
		}
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && (id.Name == "ja" || strings.HasSuffix(id.Name, "Ja")) {
			found = true
		}
		return true
	})
	return found
}

func englishArg(e ast.Expr) bool {
	for _, s := range literals(e) {
		if !isASCII(s) {
			return false
		}
	}
	return true
}

func TestEveryMessagePathInTheSourceIsBilingual(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	// helpers that take (english, japanese) string pairs, by argument index
	pairs := map[string][][2]int{
		"msg":           {{0, 1}},
		"fail":          {{0, 1}},
		"readSmallFile": {{2, 3}, {4, 5}},
	}
	// the only functions allowed to write to stdout or stderr
	printers := map[string]bool{"report": true, "run": true}
	calls := map[string]int{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				pos := fset.Position(call.Pos()).String()
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if ps, ok := pairs[fn.Name]; ok && !(fn.Name == "msg" && fd.Name.Name == "msg") {
						for _, p := range ps {
							if len(call.Args) <= p[1] {
								t.Errorf("%s: %s call without a Japanese text", pos, fn.Name)
								continue
							}
							calls[fn.Name]++
							if !englishArg(call.Args[p[0]]) {
								t.Errorf("%s: %s: English text holds Japanese or other non-ASCII", pos, fn.Name)
							}
							if !japaneseArg(call.Args[p[1]]) {
								t.Errorf("%s: %s: no Japanese text", pos, fn.Name)
							}
						}
					}
					if fn.Name == "panic" || fn.Name == "println" || fn.Name == "print" {
						t.Errorf("%s: %s writes an English-only message", pos, fn.Name)
					}
				case *ast.SelectorExpr:
					x, _ := fn.X.(*ast.Ident)
					if x == nil {
						return true
					}
					switch {
					case x.Name == "log" || x.Name == "slog":
						switch fn.Sel.Name {
						case "Debug", "Info", "Warn", "Error", "Log", "DebugContext", "InfoContext", "WarnContext", "ErrorContext", "Fatal", "Fatalf", "Fatalln", "Panic", "Printf", "Println", "Print":
							if fd.Name.Name != "say" {
								t.Errorf("%s: %s.%s outside say: log lines must go through say(log, level, event)", pos, x.Name, fn.Sel.Name)
							}
						}
					case x.Name == "fmt" && strings.HasPrefix(fn.Sel.Name, "Print"):
						t.Errorf("%s: fmt.%s writes to stdout", pos, fn.Sel.Name)
					case x.Name == "fmt" && strings.HasPrefix(fn.Sel.Name, "Fprint"):
						calls["Fprint"]++
						if !printers[fd.Name.Name] {
							t.Errorf("%s: fmt.%s in %s: only %v may print", pos, fn.Sel.Name, fd.Name.Name, printers)
						}
						// a literal format must carry both languages; a variable must be usageText
						if len(call.Args) >= 2 {
							a := call.Args[1]
							if id, ok := a.(*ast.Ident); ok {
								if id.Name != "usageText" {
									t.Errorf("%s: fmt.%s prints %s, not a checked bilingual text", pos, fn.Sel.Name, id.Name)
								}
							} else if !japaneseArg(a) {
								t.Errorf("%s: fmt.%s prints no Japanese text", pos, fn.Sel.Name)
							}
						}
					case x.Name == "os" && (fn.Sel.Name == "Exit") && fd.Name.Name != "main":
						t.Errorf("%s: os.Exit outside main", pos)
					}
				}
				return true
			})
			// os.Stderr / os.Stdout may only be handed over in main
			ast.Inspect(fd, func(n ast.Node) bool {
				if se, ok := n.(*ast.SelectorExpr); ok {
					if x, ok := se.X.(*ast.Ident); ok && x.Name == "os" && (se.Sel.Name == "Stderr" || se.Sel.Name == "Stdout") && fd.Name.Name != "main" {
						t.Errorf("%s: os.%s used outside main", fset.Position(se.Pos()), se.Sel.Name)
					}
				}
				return true
			})
		}
	}
	// the scan must really see the code it guards
	if calls["msg"] < 40 || calls["fail"] < 10 || calls["readSmallFile"] == 0 || calls["Fprint"] < 3 {
		t.Errorf("the scan saw too little code: %v", calls)
	}
}

// logLines returns the JSON log lines of stderr; any other line is returned
// in rest.
func logLines(t *testing.T, stderr string) (recs []map[string]any, rest []string) {
	t.Helper()
	sc := bufio.NewScanner(strings.NewReader(stderr))
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) == nil {
			recs = append(recs, rec)
		} else if sc.Text() != "" {
			rest = append(rest, sc.Text())
		}
	}
	return recs, rest
}

func requireBilingualLog(t *testing.T, stderr string) map[string]map[string]any {
	t.Helper()
	recs, rest := logLines(t, stderr)
	if len(rest) != 0 {
		t.Errorf("stderr has lines that are not log records: %q", rest)
	}
	byMsg := map[string]map[string]any{}
	for _, r := range recs {
		m, _ := r["msg"].(string)
		ja, _ := r["msg_ja"].(string)
		if !hasJapanese(ja) {
			t.Errorf("log line %q has no Japanese text (msg_ja): %v", m, r)
		}
		if !isASCII(m) {
			t.Errorf("msg %q is not English", m)
		}
		byMsg[m] = r
	}
	return byMsg
}

func TestStartupWarningsAndLogsAreBilingual(t *testing.T) {
	h := newHarness(t)
	h.cfg["metrics_listen"] = "0.0.0.0:0"
	p := h.start("-config", h.write())
	if err := p.stop(); err != nil {
		t.Fatalf("exit: %v\n%s", err, p.stderr.String())
	}
	by := requireBilingualLog(t, p.stderr.String())
	for _, ev := range []event{evMetricsOpen, evPlaintext, evListening, evShuttingDown, evStopped} {
		r, ok := by[ev.en]
		if !ok {
			t.Errorf("no log line %q in:\n%s", ev.en, p.stderr.String())
			continue
		}
		if r["msg_ja"] != ev.ja {
			t.Errorf("%q: Japanese text %v, want %q", ev.en, r["msg_ja"], ev.ja)
		}
	}
	// the two warnings are at warn level
	for _, ev := range []event{evMetricsOpen, evPlaintext} {
		if by[ev.en]["level"] != "WARN" {
			t.Errorf("%q: level %v", ev.en, by[ev.en]["level"])
		}
	}
}

func TestCommandLineErrorsAreBilingual(t *testing.T) {
	h := newHarness(t)
	env := []string{envTokenFile + "=" + h.token}
	cfg := h.write()
	cases := map[string]struct {
		args   []string
		code   int
		enWant string
		jaWant string
	}{
		"unknown flag":     {[]string{"-config", cfg, "-bogus"}, 2, "unknown flag: -bogus", "未知のフラグです: -bogus"},
		"flag lacks value": {[]string{"-config"}, 2, "flag needs an argument: -config", "フラグに引数が必要です: -config"},
		"bad bool":         {[]string{"-config", cfg, "-check=perhaps"}, 2, "a flag has an invalid value", "フラグの値が正しくありません"},
		"extra argument":   {[]string{"-config", cfg, "extra"}, 2, "unexpected argument", "余分な引数があります"},
		"no config":        {[]string{}, 2, "-config is required", "-config は必須です"},
		"token as a flag":  {[]string{"-config", cfg, "-admin-token", testAdmin}, 2, "unknown flag: -admin-token", "未知のフラグです: -admin-token"},
		"help":             {[]string{"-h"}, 0, "usage: kairan-cp", "使い方: kairan-cp"},
		"help long":        {[]string{"-help"}, 0, "usage: kairan-cp", "使い方: kairan-cp"},
	}
	for name, c := range cases {
		code, out, errOut := runBin(t, h, env, c.args...)
		if code != c.code || out != "" {
			t.Errorf("%s: code %d (want %d) stdout %q", name, code, c.code, out)
		}
		if !strings.Contains(errOut, c.enWant) || !strings.Contains(errOut, c.jaWant) {
			t.Errorf("%s: want %q and %q in:\n%s", name, c.enWant, c.jaWant, errOut)
		}
		if strings.Contains(errOut, "perhaps") || strings.Contains(errOut, testAdmin) {
			t.Errorf("%s: stderr repeats a value:\n%s", name, errOut)
		}
		// the flag package's own English-only wording must not leak out
		for _, bad := range []string{"flag provided but not defined", "invalid boolean value", "parse error", "Usage of "} {
			if strings.Contains(errOut, bad) {
				t.Errorf("%s: English-only flag text %q in:\n%s", name, bad, errOut)
			}
		}
		if code == 2 && (!strings.Contains(errOut, "kairan-cp: error: ") || !strings.Contains(errOut, "kairan-cp: エラー: ")) {
			t.Errorf("%s: error not in both languages:\n%s", name, errOut)
		}
	}
}

// -check, every error path in the config and token files, and the startup
// failures: each stderr message is a pair of lines, English then Japanese.
func TestEveryFailureIsAnEnglishJapanesePair(t *testing.T) {
	h := newHarness(t)
	env := []string{envTokenFile + "=" + h.token}
	h.cfg["listen"] = "nonsense"
	cfg := h.write()
	for _, args := range [][]string{{"-config", cfg}, {"-config", cfg, "-check"}, {"-config", filepath.Join(h.dir, "none.json")}} {
		code, _, errOut := runBin(t, h, env, args...)
		if code != 2 {
			t.Fatalf("%v: code %d", args, code)
		}
		lines := strings.Split(strings.TrimSpace(errOut), "\n")
		if len(lines) != 2 || !strings.HasPrefix(lines[0], "kairan-cp: error: ") || !strings.HasPrefix(lines[1], "kairan-cp: エラー: ") || !hasJapanese(lines[1]) {
			t.Errorf("%v: not an English/Japanese pair:\n%s", args, errOut)
		}
	}
	// the good -check line
	h = newHarness(t)
	code, out, errOut := runBin(t, h, []string{envTokenFile + "=" + h.token}, "-config", h.write(), "-check")
	if code != 0 || errOut != "" || !strings.Contains(out, "config ok") || !strings.Contains(out, "設定は正常です") {
		t.Errorf("-check: %d %q %q", code, out, errOut)
	}
}
