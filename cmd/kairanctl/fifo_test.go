package main

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// ctlTimeout runs ctl but fails the test instead of hanging if the command
// does not return (a FIFO nobody writes to blocks a plain open forever).
func ctlTimeout(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	type res struct {
		code     int
		out, err string
	}
	ch := make(chan res, 1)
	go func() {
		var out, errb strings.Builder
		code := run(args, streams{
			in:  strings.NewReader(""),
			out: &out,
			err: &errb,
			now: func() time.Time { return testNow },
		})
		ch <- res{code, out.String(), errb.String()}
	}()
	select {
	case r := <-ch:
		return r.code, r.out, r.err
	case <-time.After(3 * time.Second):
		t.Fatalf("kairanctl %s hangs on a FIFO", args[0])
		return 0, "", ""
	}
}

func TestFilesThatAreNotRegularAreRefusedNotWaitedOn(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	key, _ := fixtureKey(t, dir, "admin-a", "a")
	payload := filepath.Join(dir, "p.json")
	writeFile(t, payload, rawPayload)
	envPath, _ := signedBy(t, dir, rawPayload, "admin-a")
	// A symlink to a FIFO must be refused as well.
	link := filepath.Join(dir, "link")
	if err := syscall.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
	}{
		{"sign key", []string{"sign", "-key", fifo, "-in", payload, "-out", filepath.Join(dir, "o1.json")}},
		{"sign key via symlink", []string{"sign", "-key", link, "-in", payload, "-out", filepath.Join(dir, "o1b.json")}},
		{"sign in", []string{"sign", "-key", key, "-in", fifo, "-out", filepath.Join(dir, "o2.json")}},
		{"approve key", []string{"approve", "-yes", "-key", fifo, "-in", envPath, "-out", filepath.Join(dir, "o3.json")}},
		{"approve in", []string{"approve", "-yes", "-key", key, "-in", fifo, "-out", filepath.Join(dir, "o4.json")}},
		{"approve trusted", []string{"approve", "-yes", "-key", key, "-in", envPath, "-trusted", fifo, "-out", filepath.Join(dir, "o5.json")}},
		{"publish in", []string{"publish", "-url", "http://127.0.0.1:1", "-allow-plaintext", "-in", fifo}},
		{"rollback from", []string{"rollout", "rollback", "-from", fifo, "-version", "9", "-out", filepath.Join(dir, "o6.json")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errs := ctlTimeout(t, tc.args...)
			if code == 0 {
				t.Fatalf("exit 0, want a refusal\n%s", out)
			}
			if !strings.Contains(errs, "regular file") || !strings.Contains(errs, "通常のファイル") {
				t.Fatalf("message does not say (in both languages) that the file is not a regular file: %q", errs)
			}
		})
	}
}

func TestTokenFileFIFORefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "token")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("no FIFOs here: %v", err)
	}
	envPath, _ := twoSigned(t, dir)
	code, _, errs := ctlTimeout(t, "publish", "-url", "http://127.0.0.1:1", "-allow-plaintext", "-in", envPath, "-token-file", fifo)
	if code == 0 || !strings.Contains(errs, "regular file") || !strings.Contains(errs, "通常のファイル") {
		t.Fatalf("code %d, stderr %q", code, errs)
	}
}
