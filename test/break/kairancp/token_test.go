package kairancpbreak

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Admin token handling (ARCHITECTURE kairan-cp LLD, M-D54, C-D10): by file, KCP_ADMIN_TOKEN_FILE or
// KCP_ADMIN_TOKEN; never a flag value; the token file is a regular file with mode 0600/0400, opened
// non-blocking; the admin token must differ from every proxy token.

func cfgFile(t testing.TB) string {
	t.Helper()
	d := t.TempDir()
	p := filepath.Join(d, "cp.json")
	if err := os.WriteFile(p, baseCfg(t, d).bytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTokenSources(t *testing.T) {
	cp := cfgFile(t)
	tf := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tf, []byte(adminTok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  []string
		args []string
		want int
	}{
		{"flag file", nil, []string{"-config", cp, "-check", "-admin-token-file", tf}, 0},
		{"env file", []string{"KCP_ADMIN_TOKEN_FILE=" + tf}, []string{"-config", cp, "-check"}, 0},
		{"env value", []string{"KCP_ADMIN_TOKEN=" + adminTok}, []string{"-config", cp, "-check"}, 0},
		{"no token at all", nil, []string{"-config", cp, "-check"}, 2},
		{"env value empty", []string{"KCP_ADMIN_TOKEN="}, []string{"-config", cp, "-check"}, 2},
		{"env file points nowhere", []string{"KCP_ADMIN_TOKEN_FILE=" + tf + ".none"}, []string{"-config", cp, "-check"}, 2},
		{"flag file points nowhere", nil, []string{"-config", cp, "-check", "-admin-token-file", tf + ".none"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := run(t, c.env, c.args...)
			noPanic(t, r)
			if r.code != c.want {
				t.Fatalf("exit %d, want %d: %s", r.code, c.want, clip(r.all()))
			}
			if strings.Contains(r.all(), adminTok) {
				t.Errorf("admin token appears in the output: %q", clip(r.all()))
			}
		})
	}
}

// A token file is a regular file with mode 0600 or 0400; anything readable by others is refused (C-D10).
func TestTokenFileModes(t *testing.T) {
	cp := cfgFile(t)
	for _, c := range []struct {
		mode os.FileMode
		want int
	}{
		{0o600, 0}, {0o400, 0},
		{0o640, 2}, {0o644, 2}, {0o660, 2}, {0o666, 2}, {0o604, 2}, {0o602, 2}, {0o777, 2}, {0o444, 2},
	} {
		t.Run(c.mode.String(), func(t *testing.T) {
			tf := filepath.Join(t.TempDir(), "tok")
			if err := os.WriteFile(tf, []byte(adminTok), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(tf, c.mode); err != nil {
				t.Fatal(err)
			}
			r := run(t, nil, "-config", cp, "-check", "-admin-token-file", tf)
			if r.code != c.want {
				t.Fatalf("mode %v: exit %d, want %d: %s", c.mode, r.code, c.want, clip(r.all()))
			}
			if strings.Contains(r.all(), adminTok) {
				t.Errorf("token echoed")
			}
		})
	}
}

// Non-regular token files must be refused without hanging (opened non-blocking).
func TestTokenFileMustBeRegular(t *testing.T) {
	cp := cfgFile(t)
	t.Run("directory", func(t *testing.T) {
		d := t.TempDir()
		_ = os.Chmod(d, 0o700)
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", d); r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
	})
	t.Run("fifo with no writer", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "fifo")
		if err := syscall.Mkfifo(p, 0o600); err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		r := run(t, nil, "-config", cp, "-check", "-admin-token-file", p)
		if r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
		if time.Since(start) > 5*time.Second {
			t.Errorf("took %v: the open must not block", time.Since(start))
		}
	})
	t.Run("/dev/zero", func(t *testing.T) {
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", "/dev/zero"); r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
	})
	t.Run("/dev/null", func(t *testing.T) {
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", "/dev/null"); r.code != 2 {
			t.Fatalf("exit %d: %s", r.code, clip(r.all()))
		}
	})
	// Kubernetes mounts secrets as symlinks into ..data/, so a symlink to a regular 0600 file must work
	// (the k3d deployment needs it); the mode that counts is the target's.
	t.Run("symlink to a 0600 file is accepted", func(t *testing.T) {
		d := t.TempDir()
		real := filepath.Join(d, "real")
		_ = os.WriteFile(real, []byte(adminTok), 0o600)
		ln := filepath.Join(d, "link")
		_ = os.Symlink(real, ln)
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", ln); r.code != 0 {
			t.Errorf("exit %d: %s", r.code, clip(r.all()))
		}
	})
	t.Run("symlink to a 0644 file is refused", func(t *testing.T) {
		d := t.TempDir()
		real := filepath.Join(d, "real")
		_ = os.WriteFile(real, []byte(adminTok), 0o600)
		_ = os.Chmod(real, 0o644)
		ln := filepath.Join(d, "link")
		_ = os.Symlink(real, ln)
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", ln); r.code != 2 {
			t.Errorf("exit %d, want 2: %s", r.code, clip(r.all()))
		}
	})
	t.Run("dangling symlink", func(t *testing.T) {
		ln := filepath.Join(t.TempDir(), "link")
		_ = os.Symlink(ln+".none", ln)
		if r := run(t, nil, "-config", cp, "-check", "-admin-token-file", ln); r.code != 2 {
			t.Errorf("exit %d, want 2", r.code)
		}
	})
}

// Token content: empty, blank, NUL, embedded newlines, huge.
func TestTokenFileContent(t *testing.T) {
	cp := cfgFile(t)
	cases := []struct {
		name, body string
		want       int
	}{
		{"empty", "", 2},
		{"only newline", "\n", 2},
		{"only spaces", "      \n", 2},
		{"trailing newline is trimmed", adminTok + "\n", 0},
		{"trailing CRLF is trimmed", adminTok + "\r\n", 0},
		{"two lines", adminTok + "\nsecond-line-0123456789\n", 2},
		{"NUL inside", adminTok[:10] + "\x00" + adminTok[10:], 2},
		{"control characters", adminTok + "\x1b[2J", 2},
		{"non-ASCII", "ADMIN-TOKEN-é-0123456789abcdef", 2},
		{"spaces inside", "ADMIN TOKEN 0123456789 abcdef", 2},
		{"single character", "a", 2},
		{"1 MiB", strings.Repeat("A", 1<<20), 2},
		{"20 MiB", strings.Repeat("A", 20<<20), 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tf := filepath.Join(t.TempDir(), "tok")
			if err := os.WriteFile(tf, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			r := run(t, nil, "-config", cp, "-check", "-admin-token-file", tf)
			noPanic(t, r)
			if r.code != c.want {
				t.Fatalf("exit %d, want %d: %s", r.code, c.want, clip(r.all()))
			}
			if len(c.body) >= 8 && len(c.body) < 1000 && strings.Contains(r.all(), strings.TrimSpace(c.body)) {
				t.Errorf("token content echoed: %q", clip(r.all()))
			}
		})
	}
}

// C-D10: the admin token must differ from every proxy token. The config holds only digests, so the check is
// by digest: an admin token whose SHA-256 equals an enrollment digest is refused, and is not printed.
func TestAdminTokenEqualToProxyTokenIsRefused(t *testing.T) {
	cp := cfgFile(t)
	for _, id := range []string{"p1", "p2", "c1", "q1"} {
		tf := filepath.Join(t.TempDir(), "tok")
		if err := os.WriteFile(tf, []byte(tokOf(id)), 0o600); err != nil {
			t.Fatal(err)
		}
		r := run(t, nil, "-config", cp, "-check", "-admin-token-file", tf)
		if r.code != 2 {
			t.Errorf("admin token equal to proxy %s's token: exit %d, want 2: %s", id, r.code, clip(r.all()))
		}
		if strings.Contains(r.all(), tokOf(id)) {
			t.Errorf("token echoed")
		}
	}
	// the same through the environment
	r := run(t, []string{"KCP_ADMIN_TOKEN=" + tokOf("p1")}, "-config", cp, "-check")
	if r.code != 2 {
		t.Errorf("env admin token equal to a proxy token: exit %d, want 2", r.code)
	}
}

// With the check mode the server must never start: -check on a good config binds no port and creates no data.
func TestCheckDoesNotBindOrWrite(t *testing.T) {
	d := t.TempDir()
	data := filepath.Join(d, "data-should-not-exist")
	port := freePort(t)
	c := baseCfg(t, data).with(t, "listen", port)
	f := writeFiles(t, c.bytes(t), adminTok)
	hold, err := listen(port)
	if err != nil {
		t.Fatal(err)
	}
	defer hold.Close()
	// the port is taken: a -check that tried to bind would fail with exit 1
	r := run(t, nil, "-config", f.cfgPath, "-admin-token-file", f.tokPath, "-check")
	if r.code != 0 {
		t.Fatalf("-check bound the listener or failed on a busy port: exit %d: %s", r.code, clip(r.all()))
	}
	if _, err := os.Stat(data); err == nil {
		t.Errorf("-check created the data directory")
	}
}

var _ = exec.Command
