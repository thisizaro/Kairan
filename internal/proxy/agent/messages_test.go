package agent

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// The agent's log lines are messages for a person: English in msg, Japanese in
// msg_ja (PRD J7, M-D62).

func hasJapanese(s string) bool {
	for _, r := range s {
		if r >= 0x3040 && r <= 0x9fff {
			return true
		}
	}
	return false
}

func TestEveryAgentEventIsBilingual(t *testing.T) {
	if len(events) < 15 {
		t.Fatalf("only %d events listed", len(events))
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if ev.en == "" || !hasJapanese(ev.ja) {
			t.Errorf("event %q / %q is not English plus Japanese", ev.en, ev.ja)
		}
		for i := 0; i < len(ev.en); i++ {
			if ev.en[i] >= 0x80 {
				t.Errorf("english text %q is not English", ev.en)
				break
			}
		}
		if seen[ev.en] {
			t.Errorf("event %q listed twice", ev.en)
		}
		seen[ev.en] = true
	}
}

// Any log call outside say is an English-only message.
func TestEveryAgentLogCallGoesThroughSay(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	said := 0
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
				pos := fset.Position(call.Pos())
				switch fn := call.Fun.(type) {
				case *ast.Ident:
					if fn.Name == "say" && fd.Name.Name != "say" {
						said++
						if len(call.Args) < 3 {
							t.Errorf("%s: say without an event", pos)
						} else if id, ok := call.Args[2].(*ast.Ident); !ok || !strings.HasPrefix(id.Name, "ev") {
							t.Errorf("%s: say must be given a named event (evXxx)", pos)
						}
					}
				case *ast.SelectorExpr:
					switch fn.Sel.Name {
					case "Debug", "Info", "Warn", "Error", "Log", "DebugContext", "InfoContext", "WarnContext", "ErrorContext":
						if fd.Name.Name == "say" {
							return true
						}
						switch x := fn.X.(type) {
						case *ast.Ident:
							if x.Name == "log" || x.Name == "slog" {
								t.Errorf("%s: %s.%s outside say: use say(log, level, event)", pos, x.Name, fn.Sel.Name)
							}
						case *ast.SelectorExpr:
							if x.Sel.Name == "log" {
								t.Errorf("%s: .log.%s outside say: use say(a.log, level, event)", pos, fn.Sel.Name)
							}
						}
					}
				}
				return true
			})
		}
	}
	if said < 14 {
		t.Errorf("the scan saw only %d say calls", said)
	}
}
