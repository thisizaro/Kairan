// Package kairancpbreak holds black-box attack tests for the kairan-cp binary (task C-07). It only runs
// the program named by CP_BIN. Sources: ARCHITECTURE kairan-cp LLD, M-D54, C-D9, C-D10, M-D52, invariants I3 and I4.
package kairancpbreak

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// cpBin returns the binary named by CP_BIN (set by make break or the Overseer). The only allowed skip
// (M-D52) is a binary that is not available; the guard hooks forbid lane Q to build it from source paths.
func cpBin(t testing.TB) string {
	t.Helper()
	b := os.Getenv("CP_BIN")
	if b == "" {
		t.Skip("CP_BIN is not set: no binary to attack")
	}
	if _, err := os.Stat(b); err != nil {
		t.Fatalf("CP_BIN is set but unusable: %v", err)
	}
	return b
}

type result struct {
	code           int
	stdout, stderr string
}

func (r result) all() string { return r.stdout + r.stderr }

// run executes the binary with a clean environment plus env and a 20 s limit.
func run(t testing.TB, env []string, args ...string) result {
	t.Helper()
	bin := cpBin(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + cmd.Dir, "LANG=C"}, env...)
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("binary %v did not exit within 20s (stderr %q)", args, se.String())
	}
	return result{cmd.ProcessState.ExitCode(), so.String(), se.String()}
}

// server is a running binary.
type server struct {
	t    testing.TB
	cmd  *exec.Cmd
	out  *lockedBuf
	done chan struct{}
	code int
}

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func start(t testing.TB, env []string, args ...string) *server {
	t.Helper()
	bin := cpBin(t)
	cmd := exec.Command(bin, args...)
	cmd.Dir = t.TempDir()
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "HOME=" + cmd.Dir, "LANG=C"}, env...)
	s := &server{t: t, cmd: cmd, out: &lockedBuf{}, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = s.out, s.out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	go func() {
		_ = cmd.Wait()
		s.code = cmd.ProcessState.ExitCode()
		close(s.done)
	}()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			_ = cmd.Process.Kill()
			<-s.done
		}
	})
	return s
}

func (s *server) waitExit(d time.Duration) (int, bool) {
	select {
	case <-s.done:
		return s.code, true
	case <-time.After(d):
		return 0, false
	}
}

func (s *server) signal(sig syscall.Signal) { _ = s.cmd.Process.Signal(sig) }

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}
