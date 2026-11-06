// Package kairanctlbreak holds black-box attack tests for the kairanctl
// binary (tasks T-05, T-06). It only builds and runs the program. Sources:
// ARCHITECTURE kairanctl LLD, M-D31, M-D32, M-D37, M-D45, T-D3, T-D4.
package kairanctlbreak

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  string
	skipMsg   string
)

// buildCtl returns the kairanctl binary: KAIRANCTL_BIN first (make break sets
// it), then a build from KAIRANCTL_SRC_DIR, then a build by import path.
// It builds at most once. In a checkout that has the
// program (main, after the lane merges) it builds the package by import path.
// Lane Q's worktree is sparse and has no program sources: there the build is
// pointed at another checkout with KAIRANCTL_SRC_DIR (a module root); with
// neither, the tests skip loudly rather than pass.
func buildCtl(t testing.TB) string {
	t.Helper()
	buildOnce.Do(func() {
		if b := os.Getenv("KAIRANCTL_BIN"); b != "" {
			if _, err := os.Stat(b); err != nil {
				buildErr = "KAIRANCTL_BIN is set but unusable: " + err.Error()
				return
			}
			builtBin = b
			return
		}
		dir, err := os.MkdirTemp("", "kairanctl-break-")
		if err != nil {
			buildErr = err.Error()
			return
		}
		builtDir = dir
		bin := filepath.Join(dir, "kairanctl")
		args := []string{"build", "-o", bin}
		if src := os.Getenv("KAIRANCTL_SRC_DIR"); src != "" {
			args = append([]string{"build", "-C", src, "-o", bin}, "kairan/cmd/kairanctl")
		} else {
			args = append(args, "kairan/cmd/kairanctl")
		}
		out, err := exec.Command("go", args...).CombinedOutput()
		if err != nil {
			if bytes.Contains(out, []byte("is not in std")) || bytes.Contains(out, []byte("no required module provides")) {
				skipMsg = "kairanctl sources are not in this checkout (sparse lane Q); set KAIRANCTL_SRC_DIR=<checkout with the program>: " + string(out)
				return
			}
			buildErr = string(out)
			return
		}
		builtBin = bin
	})
	if skipMsg != "" {
		t.Skip(skipMsg)
	}
	if buildErr != "" {
		t.Fatalf("build failed: %s", buildErr)
	}
	return builtBin
}

// builtDir is the temp dir buildCtl created (empty when KAIRANCTL_BIN was used); TestMain removes it so that
// repeated runs do not fill /tmp with binaries.
var builtDir string

func TestMain(m *testing.M) {
	code := m.Run()
	if builtDir != "" {
		_ = os.RemoveAll(builtDir)
	}
	os.Exit(code)
}

type result struct {
	code           int
	stdout, stderr string
}

// run executes the binary with a minimal clean environment plus env, a
// scratch working dir, optional stdin and a 20s timeout.
func run(t testing.TB, bin string, env []string, stdin string, args ...string) result {
	t.Helper()
	return runIn(t, bin, t.TempDir(), env, stdin, args...)
}

func runIn(t testing.TB, bin, dir string, env []string, stdin string, args ...string) result {
	t.Helper()
	return runTimeout(t, bin, dir, env, stdin, 20*time.Second, args...)
}

func runTimeout(t testing.TB, bin, dir string, env []string, stdin string, limit time.Duration, args ...string) result {
	t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LANG=C"}, env...)
	cmd.Stdin = bytes.NewBufferString(stdin)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(limit):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("kairanctl %v hung >%v", args, limit)
	}
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return result{code: code, stdout: so.String(), stderr: se.String()}
}

func shq(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// runShell runs a /bin/sh snippet in dir with the same clean environment.
func runShell(t testing.TB, dir, script string) result {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", script)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "LANG=C"}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	_ = cmd.Run()
	code := 0
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	return result{code: code, stdout: so.String(), stderr: se.String()}
}
