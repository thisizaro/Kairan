package kairan

// Architecture rules from docs/ARCHITECTURE.md (PLAN O-06), checked on every
// `make ci` by reading the import lists and selector expressions of all Go
// files under internal/ and cmd/:
//
//	R1  internal/cp/... and internal/proxy/... never import each other.
//	R2  Core packages do no I/O: no net, os, files, logging or shell packages.
//	R3  Core packages never read the clock directly (time.Now, time.Sleep, ...).
//	R4  internal/wire and internal/clock import no kairan package.
//	R5  Nothing imports kairan/cmd/...
//	R6  Standard library only: any import with a dot in its first element fails.
//
// Test files are exempt from R2 and R3 only.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

const module = "kairan"

var corePkgs = []string{
	"internal/policy",
	"internal/trust",
	"internal/cp/fleet",
	"internal/cp/rollout",
	"internal/proxy/state",
}

var coreForbiddenImports = []string{
	"net", "os", "io/fs", "io/ioutil", "path/filepath", "syscall", "log", "database/sql", "crypto/rand",
	module + "/internal/obs",
	module + "/internal/cp/api", module + "/internal/cp/store", module + "/internal/cp/web",
	module + "/internal/proxy/enforce", module + "/internal/proxy/agent",
	module + "/internal/proxy/store", module + "/internal/proxy/applylog",
}

var forbiddenTimeFuncs = map[string]bool{
	"Now": true, "Since": true, "Until": true, "Sleep": true, "After": true,
	"AfterFunc": true, "Tick": true, "NewTimer": true, "NewTicker": true,
}

// under reports whether path equals prefix or lies below it.
func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}

func isCore(dir string) bool {
	for _, c := range corePkgs {
		if dir == c {
			return true
		}
	}
	return false
}

// checkFile returns rule violations for one parsed file in package dir
// (slash-separated, relative to the module root).
func checkFile(dir, name string, f *ast.File) []string {
	var out []string
	bad := func(rule, msg string) { out = append(out, rule+" "+dir+"/"+name+": "+msg) }
	isTest := strings.HasSuffix(name, "_test.go")
	core := isCore(dir) && !isTest
	timeName := ""

	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		switch {
		case under(dir, "internal/cp") && under(path, module+"/internal/proxy"),
			under(dir, "internal/proxy") && under(path, module+"/internal/cp"):
			bad("R1", "imports "+path+" (cp and proxy talk only through wire over HTTP)")
		}
		if core {
			for _, p := range coreForbiddenImports {
				if under(path, p) {
					bad("R2", "core package imports "+path+" (core does no I/O)")
				}
			}
		}
		if (dir == "internal/wire" || dir == "internal/clock") && under(path, module) {
			bad("R4", "imports "+path+" (wire and clock depend on nothing in kairan)")
		}
		if under(path, module+"/cmd") {
			bad("R5", "imports "+path+" (nothing imports cmd)")
		}
		if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
			bad("R6", "imports "+path+" (stdlib only; add a dependency only with a decision)")
		}
		if path == "time" {
			switch {
			case imp.Name == nil:
				timeName = "time"
			case imp.Name.Name == ".":
				if core {
					bad("R3", "dot-imports time")
				}
			case imp.Name.Name != "_":
				timeName = imp.Name.Name
			}
		}
	}

	if core && timeName != "" {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == timeName && forbiddenTimeFuncs[sel.Sel.Name] {
				bad("R3", "uses time."+sel.Sel.Name+" (take now as an argument or use internal/clock)")
			}
			return true
		})
	}
	return out
}

func TestArchitecture(t *testing.T) {
	fset := token.NewFileSet()
	files := 0
	for _, root := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(p, ".go") {
				return err
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			files++
			for _, v := range checkFile(filepath.ToSlash(filepath.Dir(p)), filepath.Base(p), f) {
				t.Error(v)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("checked %d files", files)
}

// The checker must catch what it claims to catch, even while most packages
// are still empty.
func TestArchRulesCatchViolations(t *testing.T) {
	cases := []struct {
		dir, name, src string
		want           string // rule ID expected, "" = clean
	}{
		{"internal/cp/api", "a.go", `package api; import _ "kairan/internal/proxy/enforce"`, "R1"},
		{"internal/proxy/agent", "a.go", `package agent; import _ "kairan/internal/cp/store"`, "R1"},
		{"internal/cp/api", "a_test.go", `package api; import _ "kairan/internal/proxy/state"`, "R1"},
		{"internal/policy", "p.go", `package policy; import _ "os"`, "R2"},
		{"internal/trust", "t.go", `package trust; import _ "net/http"`, "R2"},
		{"internal/cp/fleet", "f.go", `package fleet; import _ "log/slog"`, "R2"},
		{"internal/proxy/state", "s.go", `package state; import _ "kairan/internal/proxy/store"`, "R2"},
		{"internal/cp/rollout", "r.go", `package rollout; import "time"; func f() { _ = time.Now() }`, "R3"},
		{"internal/policy", "p.go", `package policy; import t "time"; var x = t.Since`, "R3"},
		{"internal/trust", "t.go", `package trust; import . "time"; var x Duration`, "R3"},
		{"internal/wire", "w.go", `package wire; import _ "kairan/internal/clock"`, "R4"},
		{"internal/clock", "c.go", `package clock; import _ "kairan/internal/wire"`, "R4"},
		{"internal/cp/api", "a.go", `package api; import _ "kairan/cmd/kairanctl"`, "R5"},
		{"internal/policy", "p.go", `package policy; import _ "github.com/x/y"`, "R6"},
		{"internal/policy", "p_test.go", `package policy; import _ "golang.org/x/z"`, "R6"},

		// Allowed.
		{"internal/policy", "p_test.go", `package policy; import ("os"; "time"); var _ = os.Args; var x = time.Now`, ""},
		{"internal/trust", "t.go", `package trust; import ("crypto/ed25519"; "time"; "kairan/internal/wire"); var _ ed25519.PublicKey; var d time.Duration; var _ wire.Hash`, ""},
		{"internal/cp/rollout", "r.go", `package rollout; import "time"; func f(now time.Time) time.Time { return now.Add(time.Second) }`, ""},
		{"internal/cp/api", "a.go", `package api; import ("net/http"; "os"; "time"; "kairan/internal/wire"); var _ = http.MethodGet; var _ = os.Args; var _ = time.Now; var _ wire.ID`, ""},
		{"internal/proxy/enforce", "e.go", `package enforce; import _ "kairan/internal/proxy/state"`, ""},
		{"cmd/kairan-cp", "main.go", `package main; import (_ "kairan/internal/cp/api"; _ "kairan/internal/proxy/state")`, ""},
	}
	for _, c := range cases {
		f, err := parser.ParseFile(token.NewFileSet(), c.name, c.src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("%s/%s: %v", c.dir, c.name, err)
		}
		got := checkFile(c.dir, c.name, f)
		switch {
		case c.want == "" && len(got) > 0:
			t.Errorf("%s/%s: want clean, got %v", c.dir, c.name, got)
		case c.want != "" && (len(got) == 0 || !strings.HasPrefix(got[0], c.want+" ")):
			t.Errorf("%s/%s: want %s, got %v", c.dir, c.name, c.want, got)
		}
	}
}
