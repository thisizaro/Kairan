package main

import (
	"bufio"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Every message for a person is in English and in Japanese (PRD J7, M-D62).
// These tests list the message paths: the source scan finds any path that
// skips the bilingual helpers, and the execute tests run the program's own
// exit path (the same code main uses) through the paths that print.

func hasJapanese(s string) bool {
	for _, r := range s {
		if r >= 0x3040 && r <= 0x9fff {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func TestEveryLogEventIsBilingual(t *testing.T) {
	if len(events) < 8 {
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
	for _, want := range []string{"usage:", "使い方:", "path to proxy.json", "のパス", "offline signed bundle", "オフライン", "-import"} {
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
// string (an identifier called ja, or ending in Ja).
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
		"msg":        {{0, 1}},
		"usageMsg":   {{0, 1}},
		"cmdLineMsg": {{0, 1}},
		"osMsg":      {{0, 1}},
		"osUsageMsg": {{0, 1}},
		"bad":        {{1, 2}},
	}
	// M-D65: no message holds a configured path or value, or library text.
	// err.Error() is allowed only where the text is made safe or is the flag
	// package's own (its flag name is echoed through esc).
	errorCallers := map[string]bool{"errText": true, "flagError": true}
	// the helpers that turn an err into the two lines (errText, errClassJa)
	causeHelpers := map[string]bool{"osMsg": true, "osUsageMsg": true}
	// identifiers that hold a configured path, address, token or other value
	valueNames := map[string]bool{
		"path": true, "file": true, "dir": true, "cfgPath": true, "importPath": true, "DataDir": true,
		"CAFile": true, "Listen": true, "MetricsListen": true, "Token": true, "addr": true, "reason": true,
		"CP": true, "Upstream": true, "APIKeys": true, "ProxyID": true, "Tenant": true,
	}
	// the only functions allowed to write to stdout or stderr
	printers := map[string]bool{"report": true, "run": true, "runLocal": true, "importBundle": true}
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
					if ps, ok := pairs[fn.Name]; ok && fd.Name.Name != fn.Name {
						for _, p := range ps {
							if len(call.Args) <= p[1] {
								t.Errorf("%s: %s call without a Japanese text", pos, fn.Name)
								continue
							}
							calls[fn.Name]++
							for _, arg := range []ast.Expr{call.Args[p[0]], call.Args[p[1]]} {
								ast.Inspect(arg, func(n ast.Node) bool {
									switch n := n.(type) {
									case *ast.Ident:
										if valueNames[n.Name] {
											t.Errorf("%s: %s: a message names a configured value (%s)", pos, fn.Name, n.Name)
										}
									case *ast.CallExpr:
										if se, ok := n.Fun.(*ast.SelectorExpr); ok && se.Sel.Name == "Error" {
											t.Errorf("%s: %s: err.Error() in a message: use osMsg(en, ja, err)", pos, fn.Name)
										}
									}
									return true
								})
							}
							if !causeHelpers[fd.Name.Name] {
								ast.Inspect(call.Args[p[1]], func(n ast.Node) bool {
									if id, ok := n.(*ast.Ident); ok && (id.Name == "err" || id.Name == "reason") {
										t.Errorf("%s: %s: the Japanese text holds %s: library text must not reach the Japanese line", pos, fn.Name, id.Name)
									}
									return true
								})
							}
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
					if fn.Sel.Name == "Error" && len(call.Args) == 0 && !errorCallers[fd.Name.Name] {
						t.Errorf("%s: .Error() in %s: error text can hold a path or a value; use errText(err)", pos, fd.Name.Name)
					}
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
					case x.Name == "os" && fn.Sel.Name == "Exit" && fd.Name.Name != "main":
						t.Errorf("%s: os.Exit outside main", pos)
					case x.Name == "fmt" && fn.Sel.Name == "Errorf":
						t.Errorf("%s: fmt.Errorf makes an English-only error: use msg(en, ja)", pos)
					case x.Name == "errors" && fn.Sel.Name == "New":
						t.Errorf("%s: errors.New makes an English-only error: use msg(en, ja)", pos)
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
	if calls["msg"] < 8 || calls["usageMsg"] < 8 || calls["osMsg"] < 8 || calls["osUsageMsg"] < 4 ||
		calls["cmdLineMsg"] < 6 || calls["bad"] < 25 || calls["Fprint"] < 3 {
		t.Errorf("the scan saw too little code: %v", calls)
	}
}

// logLines returns the JSON log lines of stderr; any other line is returned
// in rest.
func logLines(stderr string) (recs []map[string]any, rest []string) {
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
	recs, rest := logLines(stderr)
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

func TestStartupAndShutdownLogsAreBilingual(t *testing.T) {
	w := newWorld(t)
	w.cfg["metrics_listen"] = "127.0.0.1:0"
	var pubs []string
	for _, n := range []string{"admin-a", "admin-b"} {
		b, err := os.ReadFile("../../test/fixtures/TEST-ONLY-" + n + ".pub")
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, strings.TrimSpace(string(b)))
	}
	w.cfg["trusted_keys"] = pubs
	r := w.start()
	if err := r.stop(t); err != nil {
		t.Fatalf("stop: %v\n%s", err, r.stderr.String())
	}
	out := r.stderr.String()
	by := requireBilingualLog(t, out)
	for _, ev := range []event{evBooted, evLocalListener, evListening, evTestOnlyKey, evShuttingDown, evStopped} {
		rec, ok := by[ev.en]
		if !ok {
			t.Errorf("no log line %q in:\n%s", ev.en, out)
			continue
		}
		if rec["msg_ja"] != ev.ja {
			t.Errorf("%q: Japanese text %v, want %q", ev.en, rec["msg_ja"], ev.ja)
		}
	}
	// the English wording that log matchers use is unchanged
	if !strings.HasPrefix(evTestOnlyKey.en, "TEST-ONLY KEY TRUSTED") || by[evTestOnlyKey.en]["level"] != "WARN" {
		t.Errorf("test-only key warning: %v", by[evTestOnlyKey.en])
	}
}

func TestCorruptHighWaterAndTamperedApplyLogWarningsAreBilingual(t *testing.T) {
	w := newWorld(t)
	data := w.cfg["data_dir"].(string)
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "apply.log"), []byte("garbage that is not a log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "highwater"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := w.start()
	r.stop(t)
	by := requireBilingualLog(t, r.stderr.String())
	for _, ev := range []event{evApplyLogBad, evHighWaterCorrupt} {
		if rec, ok := by[ev.en]; !ok || rec["msg_ja"] != ev.ja {
			t.Errorf("%q: %v in:\n%s", ev.en, rec, r.stderr.String())
		}
	}
}

// execute runs the program the way main does, without exiting the process.
func (w *world) execute(args ...string) (code int, stderr string) {
	var out syncBuf
	code = execute(w.t.Context(), args, &out)
	return code, out.String()
}

func TestCommandLineErrorsAreBilingual(t *testing.T) {
	w := newWorld(t)
	cfg := w.writeConfig()
	cases := map[string]struct {
		args   []string
		code   int
		enWant string
		jaWant string
	}{
		"unknown flag":     {[]string{"-config", cfg, "-bogus"}, 2, "unknown flag: -bogus", "未知のフラグです: -bogus"},
		"flag lacks value": {[]string{"-config"}, 2, "flag needs an argument: -config", "フラグに引数が必要です: -config"},
		"import no value":  {[]string{"-config", cfg, "-import"}, 2, "flag needs an argument: -import", "フラグに引数が必要です: -import"},
		"empty import":     {[]string{"-config", cfg, "-import", ""}, 2, "-import needs a file name", "-import にはファイル名が必要です"},
		"extra argument":   {[]string{"-config", cfg, "extra"}, 2, "unexpected argument", "余分な引数があります"},
		"no config":        {[]string{}, 2, "-config is required", "-config は必須です"},
		"help":             {[]string{"-h"}, 0, "usage: kairan-proxy", "使い方: kairan-proxy"},
		"help long":        {[]string{"-help"}, 0, "usage: kairan-proxy", "使い方: kairan-proxy"},
	}
	for name, c := range cases {
		code, errOut := w.execute(c.args...)
		if code != c.code {
			t.Errorf("%s: code %d (want %d)\n%s", name, code, c.code, errOut)
		}
		if !strings.Contains(errOut, c.enWant) || !strings.Contains(errOut, c.jaWant) {
			t.Errorf("%s: want %q and %q in:\n%s", name, c.enWant, c.jaWant, errOut)
		}
		// the flag package's own English-only wording must not leak out
		for _, bad := range []string{"flag provided but not defined", "invalid boolean value", "parse error", "Usage of ", "invalid value"} {
			if strings.Contains(errOut, bad) {
				t.Errorf("%s: English-only flag text %q in:\n%s", name, bad, errOut)
			}
		}
		if code == 2 && (!strings.Contains(errOut, "kairan-proxy: error: ") || !strings.Contains(errOut, "kairan-proxy: エラー: ")) {
			t.Errorf("%s: error not in both languages:\n%s", name, errOut)
		}
		if !strings.Contains(errOut, "使い方:") || !strings.Contains(errOut, "usage:") {
			t.Errorf("%s: no usage text:\n%s", name, errOut)
		}
	}
}

// pairOf checks that stderr is exactly one English line and one Japanese line
// with the given prefixes, and returns them.
func pairOf(t *testing.T, name, errOut string) (en, ja string) {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "kairan-proxy: error: ") || !strings.HasPrefix(lines[1], "kairan-proxy: エラー: ") || !hasJapanese(lines[1]) || !isASCII(lines[0]) {
		t.Errorf("%s: not an English/Japanese pair:\n%s", name, errOut)
		return "", ""
	}
	return lines[0], lines[1]
}

// Every way a config can be wrong gives the English line and the Japanese
// line, exit status 2, and never the value that was wrong.
func TestConfigErrorsAreAnEnglishJapanesePair(t *testing.T) {
	const secret = "enroll-token-xyz"
	w := newWorld(t)
	cases := map[string]func(c map[string]any){
		"tenant":            func(c map[string]any) { c["tenant"] = "Bad Tenant" },
		"proxy id":          func(c map[string]any) { delete(c, "proxy_id") },
		"token":             func(c map[string]any) { c["token"] = "" },
		"cp url missing":    func(c map[string]any) { delete(c, "cp_url") },
		"cp url relative":   func(c map[string]any) { c["cp_url"] = "no-host" },
		"cp url userinfo":   func(c map[string]any) { c["cp_url"] = "https://u:" + secret + "@host" },
		"cp url query":      func(c map[string]any) { c["cp_url"] = "https://host/?k=" + secret },
		"cp url scheme":     func(c map[string]any) { c["cp_url"] = "ftp://host" },
		"cp url plaintext":  func(c map[string]any) { c["allow_plaintext"] = false },
		"keys none":         func(c map[string]any) { c["trusted_keys"] = []string{} },
		"keys not hex":      func(c map[string]any) { c["trusted_keys"] = []string{secret, secret} },
		"keys twice":        func(c map[string]any) { k := c["trusted_keys"].([]string); c["trusted_keys"] = []string{k[0], k[0]} },
		"threshold missing": func(c map[string]any) { delete(c, "threshold") },
		"threshold one":     func(c map[string]any) { c["threshold"] = 1 },
		"threshold high":    func(c map[string]any) { c["threshold"] = 9 },
		"skew syntax":       func(c map[string]any) { c["skew"] = "soon" },
		"skew range":        func(c map[string]any) { c["skew"] = "6m" },
		"safe mode":         func(c map[string]any) { c["safe_mode"] = "allow_all" },
		"listen missing":    func(c map[string]any) { delete(c, "listen") },
		"listen syntax":     func(c map[string]any) { c["listen"] = "nonsense" },
		"listen port":       func(c map[string]any) { c["listen"] = "127.0.0.1:http" },
		"metrics syntax":    func(c map[string]any) { c["metrics_listen"] = "nonsense" },
		"metrics port":      func(c map[string]any) { c["metrics_listen"] = "127.0.0.1:http" },
		"metrics same":      func(c map[string]any) { c["metrics_listen"] = "127.0.0.1:9999"; c["listen"] = "127.0.0.1:9999" },
		"upstream missing":  func(c map[string]any) { delete(c, "upstream") },
		"upstream scheme":   func(c map[string]any) { c["upstream"] = "ftp://host" },
		"api keys none":     func(c map[string]any) { delete(c, "api_keys") },
		"api keys bad":      func(c map[string]any) { c["api_keys"] = map[string]string{secret + " x": "sales"} },
		"data dir":          func(c map[string]any) { c["data_dir"] = "" },
		"unknown field":     func(c map[string]any) { c["surprise"] = true },
		"wrong type":        func(c map[string]any) { c["threshold"] = secret },
		"ca file":           func(c map[string]any) { c["ca_file"] = "/nonexistent/ca.pem" },
	}
	for name, mod := range cases {
		w2 := newWorld(t)
		mod(w2.cfg)
		code, errOut := w.execute("-config", w2.writeConfig())
		if code != 2 {
			t.Errorf("%s: code %d\n%s", name, code, errOut)
		}
		pairOf(t, name, errOut)
		if strings.Contains(errOut, secret) {
			t.Errorf("%s: stderr repeats a value:\n%s", name, errOut)
		}
	}
	// the file itself: missing, a directory, too large, not JSON, not an
	// object, two values, duplicate key, case variant, too deep
	raw := map[string][]byte{
		"not json":      []byte("{{{"),
		"not object":    []byte("[1]"),
		"trailing data": []byte(`{} {}`),
		"duplicate key": []byte(`{"tenant":"a","tenant":"b"}`),
		"nested dup":    []byte(`{"api_keys":{"a":"x","a":"y"}}`),
		"unknown key":   []byte(`{"Tenant":"a"}`),
		"too deep":      []byte(`{"api_keys":{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":{}}}}}}}}}}`),
		"too deep list": []byte(`{"trusted_keys":[[[[[[[[[1]]]]]]]]]}`),
		"too large":     []byte(strings.Repeat(" ", maxConfigBytes+1)),
		"truncated":     []byte(`{"tenant":`),
		"empty":         nil,
	}
	for name, data := range raw {
		p := filepath.Join(w.dir, "raw.json")
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
		code, errOut := w.execute("-config", p)
		if code != 2 {
			t.Errorf("%s: code %d\n%s", name, code, errOut)
		}
		pairOf(t, name, errOut)
	}
	fifo := filepath.Join(w.dir, "cfg.fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, p := range map[string]string{"missing": filepath.Join(w.dir, "none.json"), "directory": w.dir, "fifo": fifo} {
		code, errOut := w.execute("-config", p)
		if code != 2 {
			t.Errorf("%s: code %d\n%s", name, code, errOut)
		}
		pairOf(t, name, errOut)
	}
}

// Failures after the config is accepted (exit status 1) are pairs too.
func TestStartupFailuresAreAnEnglishJapanesePair(t *testing.T) {
	w := newWorld(t)
	r := w.start()
	// listen address already taken
	w2 := newWorld(t)
	w2.cfg["listen"] = r.addr
	code, errOut := w.execute("-config", w2.writeConfig())
	if code != 1 {
		t.Errorf("listen taken: code %d\n%s", code, errOut)
	}
	requirePairAfterLogs(t, "listen taken", errOut)
	r.stop(t)

	// data_dir is a file
	w3 := newWorld(t)
	file := filepath.Join(w3.dir, "afile")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	w3.cfg["data_dir"] = file
	code, errOut = w.execute("-config", w3.writeConfig())
	if code != 1 && code != 2 {
		t.Errorf("data_dir file: code %d\n%s", code, errOut)
	}
	requirePairAfterLogs(t, "data_dir file", errOut)

	// the data directory in use
	old := lockWait
	lockWait = 50 * time.Millisecond
	defer func() { lockWait = old }()
	w4 := newWorld(t)
	r4 := w4.start()
	w4.cfg["listen"] = "127.0.0.1:0"
	code, errOut = w.execute("-config", w4.writeConfig())
	if code != 1 || !strings.Contains(errOut, "the data directory is in use") || !strings.Contains(errOut, "データディレクトリ") {
		t.Errorf("in use: code %d\n%s", code, errOut)
	}
	requirePairAfterLogs(t, "in use", errOut)
	r4.stop(t)
}

// requirePairAfterLogs finds the English/Japanese error pair at the end of
// stderr, ignoring JSON log lines before it.
func requirePairAfterLogs(t *testing.T, name, errOut string) {
	t.Helper()
	_, rest := logLines(errOut)
	pairOf(t, name, strings.Join(rest, "\n"))
}

// The import result, accepted or rejected, is an English line and a Japanese
// line, and nothing from the bundle is printed.
func TestImportMessagesAreEnglishJapanesePairs(t *testing.T) {
	w := newWorld(t)
	cfg := w.writeConfig()
	good := w.bundleFile("good.json", w.bundle("bank-a", 3, 48*time.Hour, w.keys[0], w.keys[1]))
	code, errOut := w.execute("-config", cfg, "-import", good)
	if code != 0 {
		t.Fatalf("import: code %d\n%s", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(errOut), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "kairan-proxy: imported policy version 3") || !isASCII(lines[0]) ||
		!strings.HasPrefix(lines[1], "kairan-proxy: ") || !hasJapanese(lines[1]) || !strings.Contains(lines[1], "3") {
		t.Errorf("import result is not an English line and a Japanese line:\n%s", errOut)
	}
	// each rejection, with a payload word that must not come back
	rejects := map[string]string{
		"unsigned":      w.bundleFile("r1.json", w.bundle("bank-a", 4, time.Hour)),
		"one signature": w.bundleFile("r2.json", w.bundle("bank-a", 4, time.Hour, w.keys[0])),
		"wrong tenant":  w.bundleFile("r3.json", w.bundle("bank-b", 4, time.Hour, w.keys[0], w.keys[1])),
		"old version":   good,
		"expired":       w.bundleFile("r4.json", w.bundle("bank-a", 5, -30*time.Minute, w.keys[0], w.keys[1])),
		"garbage":       w.file("r5.json", []byte("crm.export enroll-token-xyz")),
		"missing":       filepath.Join(w.dir, "none.json"),
		"directory":     w.dir,
	}
	for name, f := range rejects {
		code, errOut := w.execute("-config", cfg, "-import", f)
		if code != 1 {
			t.Errorf("%s: code %d\n%s", name, code, errOut)
		}
		requirePairAfterLogs(t, name, errOut)
		for _, leak := range []string{"crm.export", "enroll-token-xyz", "crm.read_"} {
			if strings.Contains(errOut, leak) {
				t.Errorf("%s: stderr repeats %q:\n%s", name, leak, errOut)
			}
		}
	}
}
