package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const goodToken = "0123456789abcdef-admin-token"

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func writeToken(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "admin.token")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAdminTokenSources(t *testing.T) {
	file := writeToken(t, goodToken+"\n", 0o600)
	other := writeToken(t, "another-token-0123456789", 0o400)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		flag string
		env  map[string]string
		want string
	}{
		{"flag file", file, nil, goodToken},
		{"env file", "", map[string]string{envTokenFile: file}, goodToken},
		{"env value", "", map[string]string{envToken: "  " + goodToken + " \n"}, goodToken},
		{"flag beats env file", other, map[string]string{envTokenFile: file}, "another-token-0123456789"},
		{"env file beats env value", "", map[string]string{envTokenFile: file, envToken: "zzzzzzzzzzzzzzzzzzzz"}, goodToken},
		{"read-only 0400 file", other, nil, "another-token-0123456789"},
		{"symlink to a 0600 file (mounted secret)", link, nil, goodToken},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, cerr := adminToken(tc.flag, envOf(tc.env))
			if cerr != nil || got != tc.want {
				t.Fatalf("got %q, %v", got, cerr)
			}
		})
	}
}

func TestAdminTokenRefusals(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		flag string
		env  map[string]string
		want string
	}{
		{"none", "", nil, "no admin token"},
		{"env value blank", "", map[string]string{envToken: "  \n"}, "no admin token"},
		{"empty file", writeToken(t, "\n", 0o600), nil, "no admin token"},
		{"group readable", writeToken(t, goodToken, 0o640), nil, "chmod 600"},
		{"world readable", writeToken(t, goodToken, 0o644), nil, "chmod 600"},
		{"world writable", writeToken(t, goodToken, 0o602), nil, "chmod 600"},
		{"directory", dir, nil, "not a regular file"},
		{"fifo (must not hang)", fifo, nil, "not a regular file"},
		{"missing", filepath.Join(dir, "nope"), nil, "no such file"},
		{"too short", writeToken(t, "short-token", 0o600), nil, "too short"},
		{"too long", writeToken(t, strings.Repeat("a", 300), 0o600), nil, "too large"},
		{"space inside", writeToken(t, "aaaaaaaaaaaaaaaa bbbbbbbb", 0o600), nil, "spaces or non-printable"},
		{"control char", writeToken(t, "aaaaaaaaaaaaaaaa\x1bbbbbbb", 0o600), nil, "spaces or non-printable"},
		{"non-ascii", writeToken(t, "aaaaaaaaaaaaaaaaé", 0o600), nil, "spaces or non-printable"},
		{"env value too short", "", map[string]string{envToken: "abc"}, "too short"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			done := make(chan struct{})
			var tok string
			var cerr *cliError
			go func() { tok, cerr = adminToken(tc.flag, envOf(tc.env)); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("adminToken hung")
			}
			if cerr == nil {
				t.Fatalf("accepted %q", tok)
			}
			if !strings.Contains(cerr.en, tc.want) {
				t.Errorf("en = %q, want %q", cerr.en, tc.want)
			}
			if !hasJapanese(cerr.ja) {
				t.Errorf("ja = %q", cerr.ja)
			}
			if strings.Contains(cerr.en+cerr.ja, goodToken) {
				t.Error("message echoes the token")
			}
		})
	}
}
