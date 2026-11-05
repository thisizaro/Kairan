package applylogbreak

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/proxy/applylog"
)

// Doc: "if the write fails the partial line is cut off again before the error
// is returned" and "On any error the log is as before" (ARCH section 8: disk
// full or write fails -> old state stays). Injected with RLIMIT_FSIZE in a child
// process so the limit and the ignored SIGXFSZ cannot touch other tests.
func TestDiskFullLeavesLogAsBefore(t *testing.T) {
	if os.Getenv("APPLYLOGBREAK_FSIZE") == "1" {
		signal.Ignore(syscall.SIGXFSZ)
		p := os.Getenv("APPLYLOGBREAK_PATH")
		clk := clock.NewFake(start)
		l, err := applylog.Open(p, clk)
		if err != nil {
			fmt.Println("FAIL open:", err)
			os.Exit(1)
		}
		for i := 1; i <= 2; i++ {
			clk.Advance(time.Second)
			if _, err := l.Append(entryN(i)); err != nil {
				fmt.Println("FAIL setup append:", err)
				os.Exit(1)
			}
		}
		before, _ := os.ReadFile(p)
		seq0, head0 := l.Head()
		v0, h0 := l.LastApplied()

		// A line is ~200 bytes; allow only 100 more bytes in the file.
		var old syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old)
		lim := syscall.Rlimit{Cur: uint64(len(before)) + 100, Max: old.Max}
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
			fmt.Println("FAIL setrlimit:", err)
			os.Exit(1)
		}
		clk.Advance(time.Second)
		_, aerr := l.Append(entryN(3))
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
		if aerr == nil {
			fmt.Println("FAIL: Append reported success although the write was cut short")
			os.Exit(1)
		}
		after, _ := os.ReadFile(p)
		if !bytes.Equal(before, after) {
			fmt.Printf("FAIL: file changed after failed Append: %d -> %d bytes (partial line left behind)\n", len(before), len(after))
			os.Exit(1)
		}
		if s, h := l.Head(); s != seq0 || h != head0 {
			fmt.Println("FAIL: Head moved after failed Append")
			os.Exit(1)
		}
		if v, h := l.LastApplied(); v != v0 || h != h0 {
			fmt.Println("FAIL: LastApplied moved after failed Append")
			os.Exit(1)
		}
		// Space is back: the log keeps working and stays a single clean chain.
		clk.Advance(time.Second)
		e, err := l.Append(entryN(3))
		if err != nil {
			fmt.Println("FAIL: Append after recovery:", err)
			os.Exit(1)
		}
		if e.Seq != 3 {
			fmt.Println("FAIL: seq after recovery =", e.Seq)
			os.Exit(1)
		}
		final, _ := os.ReadFile(p)
		if _, n, err := applylog.Verify(bytes.NewReader(final)); err != nil || n != 3 {
			fmt.Println("FAIL: verify after recovery:", n, err)
			os.Exit(1)
		}
		_ = l.Close()
		l2, err := applylog.Open(p, clk)
		if err != nil {
			fmt.Println("FAIL: reopen after recovery:", err)
			os.Exit(1)
		}
		_ = l2.Close()
		fmt.Println("DISKFULL-OK")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDiskFullLeavesLogAsBefore$")
	cmd.Env = append(os.Environ(), "APPLYLOGBREAK_FSIZE=1", "APPLYLOGBREAK_PATH="+filepath.Join(t.TempDir(), "apply.log"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DISKFULL-OK") {
		t.Fatalf("disk-full injection failed (err=%v):\n%s", err, out)
	}
}

func TestReadOnlyFileRefusesToOpenForAppend(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores file modes")
	}
	b, _ := build(t, 2)
	p := filepath.Join(t.TempDir(), "apply.log")
	if err := os.WriteFile(p, b, 0o400); err != nil {
		t.Fatal(err)
	}
	l, err := applylog.Open(p, clock.NewFake(start))
	if err == nil {
		// If Open succeeds, an Append must not silently report success.
		_, aerr := l.Append(entryN(3))
		_ = l.Close()
		if aerr == nil {
			t.Fatal("Append reported success on a read-only file")
		}
	}
	after, _ := os.ReadFile(p)
	if !bytes.Equal(after, b) {
		t.Fatal("read-only log was modified")
	}
}

func TestLastAppliedAfterReopenWithTrailingRejections(t *testing.T) {
	l, p, clk := newLog(t)
	add := func(e applylog.Entry) {
		clk.Advance(time.Second)
		if _, err := l.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	// Only rejections so far: nothing was ever applied.
	add(applylog.Entry{From: 0, To: 3, Hash: hx(3), Result: "threshold_not_met"})
	add(applylog.Entry{From: 0, To: 0, Result: "malformed"})
	if v, h := l.LastApplied(); v != 0 || h != "" {
		t.Fatalf("LastApplied with only rejections = %d %q", v, h)
	}
	_ = l.Close()
	l, err := applylog.Open(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	if v, h := l.LastApplied(); v != 0 || h != "" {
		t.Fatalf("after reopen, LastApplied with only rejections = %d %q", v, h)
	}
	add(applylog.Entry{From: 0, To: 5, Hash: hx(5)})
	add(applylog.Entry{From: 5, To: 4, Hash: hx(4), Result: "version_not_newer"})
	add(applylog.Entry{From: 5, To: 9, Hash: hx(9), Result: "expired"})
	_ = l.Close()
	l, err = applylog.Open(p, clk)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if v, h := l.LastApplied(); v != 5 || h != hx(5) {
		t.Fatalf("after reopen, LastApplied = %d %q, want 5 / hx(5): rejections must not count", v, h)
	}
	if s, _ := l.Head(); s != 5 {
		t.Fatalf("Head seq = %d, want 5", s)
	}
}

func TestAppendRacingClose(t *testing.T) {
	l, p, clk := newLog(t)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := 0; i < 200; i++ {
				clk.Advance(time.Millisecond)
				_, _ = l.Append(entryN(i + 1))
			}
		}()
	}
	time.Sleep(5 * time.Millisecond)
	_ = l.Close()
	for g := 0; g < 8; g++ {
		<-done
	}
	b, _ := os.ReadFile(p)
	if _, _, err := applylog.Verify(bytes.NewReader(b)); err != nil {
		t.Fatalf("log invalid after Close raced with Append: %v", err)
	}
}
