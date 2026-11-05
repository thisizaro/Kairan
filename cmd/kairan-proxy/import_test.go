package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"kairan/internal/proxy/applylog"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

var japanese = regexp.MustCompile(`[\p{Hiragana}\p{Katakana}\p{Han}]`)

// bundle builds an envelope for tenant tn, signed by signers.
func (w *world) bundle(tn string, version uint64, ttl time.Duration, signers ...ed25519.PrivateKey) wire.Envelope {
	now := time.Now().UTC()
	p := fmt.Sprintf(`{"tenant":%q,"version":%d,"issued_at":%q,"expires_at":%q,"default":"deny","roles":{"sales":{"crm.read_*":"R","crm.update_deal":"W"}}}`,
		tn, version, now.Add(-3*time.Hour).Format(time.RFC3339), now.Add(ttl).Format(time.RFC3339))
	env := wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(p), Signatures: []wire.Signature{}}
	for _, k := range signers {
		trust.Sign(&env, k)
	}
	return env
}

func (w *world) file(name string, data []byte) string {
	w.t.Helper()
	p := filepath.Join(w.dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		w.t.Fatal(err)
	}
	return p
}

func (w *world) bundleFile(name string, env wire.Envelope) string {
	w.t.Helper()
	b, err := json.Marshal(env)
	if err != nil {
		w.t.Fatal(err)
	}
	return w.file(name, b)
}

// runImport runs kairan-proxy -config .. -import file in-process.
func (w *world) runImport(file string) (string, error) {
	var out syncBuf
	err := run(w.t.Context(), []string{"-config", w.writeConfig(), "-import", file}, &out, func(string) { w.t.Fatal("import started the proxy") })
	return out.String(), err
}

func (w *world) policyFile() string { return filepath.Join(w.cfg["data_dir"].(string), "policy.json") }

func (w *world) applyEntries() []applylog.Entry {
	w.t.Helper()
	f, err := os.Open(filepath.Join(w.cfg["data_dir"].(string), "apply.log"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		w.t.Fatal(err)
	}
	defer f.Close()
	es, err := applylog.Read(f)
	if err != nil {
		w.t.Fatal(err)
	}
	return es
}

// A good bundle is applied offline, survives into a started proxy, and is in
// the apply log (PRD J3).
func TestImportAppliesAndProxyEnforcesIt(t *testing.T) {
	w := newWorld(t)
	f := w.bundleFile("good.json", w.bundle("bank-a", 3, 48*time.Hour, w.keys[0], w.keys[1]))
	out, err := w.runImport(f)
	if err != nil {
		t.Fatalf("import: %v\n%s", err, out)
	}
	if !strings.Contains(out, "3") || !japanese.MatchString(out) {
		t.Fatalf("message is not bilingual or lacks the version: %q", out)
	}
	es := w.applyEntries()
	if len(es) != 1 || es[0].To != 3 || es[0].From != 0 || es[0].Result != "" {
		t.Fatalf("apply log = %+v", es)
	}
	// A proxy started afterwards (control plane has nothing newer) enforces it.
	r := w.start()
	if reached, body := w.call(r, "key-sales-123", "crm.read_contact"); !reached {
		t.Fatalf("read tool denied after import: %s", body)
	}
	if reached, _ := w.call(r, "key-sales-123", "crm.export"); reached {
		t.Fatal("tool outside the policy reached the upstream")
	}
	r.stop(t)
	// Importing the same version again is an old version.
	_, err = w.runImport(f)
	if err == nil || errors.Is(err, errUsage) {
		t.Fatalf("repeat: %v", err)
	}
}

// The S5 cases and more: nothing is applied, nothing is saved, the message is
// in both languages, and the exit status is the runtime one (1), not usage.
func TestImportRejections(t *testing.T) {
	tests := []struct {
		name string
		make func(w *world) string
		want string // English reason fragment
	}{
		{"unsigned", func(w *world) string { return w.bundleFile("b.json", w.bundle("bank-a", 3, time.Hour)) }, "malformed"},
		{"one signature", func(w *world) string { return w.bundleFile("b.json", w.bundle("bank-a", 3, time.Hour, w.keys[0])) }, "signatures"},
		{"same key twice", func(w *world) string {
			return w.bundleFile("b.json", w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[0]))
		}, "signatures"},
		{"untrusted keys", func(w *world) string {
			return w.bundleFile("b.json", w.bundle("bank-a", 3, time.Hour, seed("x"), seed("y")))
		}, "signatures"},
		{"wrong tenant", func(w *world) string {
			return w.bundleFile("b.json", w.bundle("bank-b", 3, time.Hour, w.keys[0], w.keys[1]))
		}, "tenant"},
		{"expired", func(w *world) string {
			return w.bundleFile("b.json", w.bundle("bank-a", 3, -30*time.Minute, w.keys[0], w.keys[1]))
		}, "expired"},
		{"corrupted payload", func(w *world) string {
			e := w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1])
			e.Payload = []byte(strings.Replace(string(e.Payload), `"version":3`, `"version":4`, 1))
			return w.bundleFile("b.json", e)
		}, "signatures"},
		{"truncated file", func(w *world) string {
			b, _ := json.Marshal(w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1]))
			return w.file("b.json", b[:len(b)/2])
		}, "malformed"},
		{"garbage", func(w *world) string { return w.file("b.json", []byte("\x00\xff not json")) }, "malformed"},
		{"empty file", func(w *world) string { return w.file("b.json", nil) }, "malformed"},
		{"duplicate key", func(w *world) string {
			b, _ := json.Marshal(w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1]))
			return w.file("b.json", []byte(strings.Replace(string(b), `{"payloadType"`, `{"payloadType":"x","payloadType"`, 1)))
		}, "malformed"},
		{"oversize file", func(w *world) string {
			return w.file("b.json", []byte(strings.Repeat(" ", wire.MaxEnvelopeBytes+1)))
		}, "too large"},
		{"fifo", func(w *world) string {
			p := filepath.Join(w.dir, "b.fifo")
			if err := syscall.Mkfifo(p, 0o600); err != nil {
				t.Skip("no fifo:", err)
			}
			return p
		}, "regular file"},
		{"directory", func(w *world) string { return w.dir }, "regular file"},
		{"missing file", func(w *world) string { return filepath.Join(w.dir, "nope.json") }, "cannot read"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			f := tc.make(w)
			done := make(chan struct{})
			var out string
			var err error
			go func() { out, err = w.runImport(f); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("import hung")
			}
			if err == nil || errors.Is(err, errUsage) {
				t.Fatalf("err = %v", err)
			}
			msg := err.Error() + out
			if !strings.Contains(msg, tc.want) || !japanese.MatchString(msg) {
				t.Fatalf("message lacks %q or Japanese: %q", tc.want, msg)
			}
			if _, statErr := os.Stat(w.policyFile()); statErr == nil {
				t.Fatal("a policy was saved")
			}
			for _, e := range w.applyEntries() {
				if e.Result == "" {
					t.Fatalf("an apply was logged: %+v", e)
				}
			}
			r := w.start()
			defer r.stop(t)
			if reached, _ := w.call(r, "key-sales-123", "crm.read_contact"); reached {
				t.Fatal("a call was allowed: something was applied")
			}
		})
	}
}

// A rejected bundle does not disturb the policy in force, and an old version
// is the rollback case (I2).
func TestImportOldVersionKeepsPolicy(t *testing.T) {
	w := newWorld(t)
	if out, err := w.runImport(w.bundleFile("v5.json", w.bundle("bank-a", 5, time.Hour, w.keys[0], w.keys[1]))); err != nil {
		t.Fatalf("v5: %v %s", err, out)
	}
	before, _ := os.ReadFile(w.policyFile())
	_, err := w.runImport(w.bundleFile("v3.json", w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1])))
	if err == nil || !strings.Contains(err.Error(), "newer") || !japanese.MatchString(err.Error()) {
		t.Fatalf("err = %v", err)
	}
	after, _ := os.ReadFile(w.policyFile())
	if string(before) != string(after) {
		t.Fatal("policy file changed")
	}
	es := w.applyEntries()
	if len(es) != 2 || es[0].To != 5 || es[1].Result != wire.ErrNotNewer || es[1].From != 5 {
		t.Fatalf("apply log = %+v", es)
	}
	r := w.start()
	if reached, _ := w.call(r, "key-sales-123", "crm.read_contact"); !reached {
		t.Fatal("v5 is no longer in force")
	}
}

// An apply log that fails verification stops an import: nothing is applied
// into a tampered data directory.
func TestImportIntoTamperedDataDir(t *testing.T) {
	w := newWorld(t)
	if err := os.MkdirAll(w.cfg["data_dir"].(string), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.cfg["data_dir"].(string), "apply.log"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := w.runImport(w.bundleFile("good.json", w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1])))
	if err == nil || errors.Is(err, errUsage) || !japanese.MatchString(err.Error()+out) {
		t.Fatalf("err = %v, out = %q", err, out)
	}
	if _, statErr := os.Stat(w.policyFile()); statErr == nil {
		t.Fatal("a policy was saved")
	}
}

func TestImportUsage(t *testing.T) {
	w := newWorld(t)
	f := w.bundleFile("good.json", w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1]))
	for name, args := range map[string][]string{
		"no config":     {"-import", f},
		"empty import":  {"-config", w.writeConfig(), "-import", ""},
		"extra arg":     {"-config", w.writeConfig(), "-import", f, "extra"},
		"import no arg": {"-config", w.writeConfig(), "-import"},
	} {
		t.Run(name, func(t *testing.T) {
			var out syncBuf
			err := run(t.Context(), args, &out, func(string) { t.Fatal("started") })
			if err == nil || !errors.Is(err, errUsage) {
				t.Fatalf("err = %v", err)
			}
		})
	}
	// A bad config stops an import before the data directory is touched.
	w.cfg["threshold"] = 1
	out, err := w.runImport(f)
	if err == nil || !errors.Is(err, errUsage) {
		t.Fatalf("err = %v %s", err, out)
	}
	if _, statErr := os.Stat(w.cfg["data_dir"].(string)); statErr == nil {
		t.Fatal("data directory created")
	}
}

// The data directory belongs to one process: an import cannot run beside a
// proxy that has it open (two writers would break the apply log chain), and a
// second proxy cannot start on it.
func TestDataDirIsLocked(t *testing.T) {
	old := lockWait
	lockWait = 50 * time.Millisecond
	defer func() { lockWait = old }()

	w := newWorld(t)
	r := w.start()
	f := w.bundleFile("good.json", w.bundle("bank-a", 3, time.Hour, w.keys[0], w.keys[1]))
	out, err := w.runImport(f)
	if err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), "in use") || !japanese.MatchString(err.Error()+out) {
		t.Fatalf("import beside a running proxy: %v", err)
	}
	if es := w.applyEntries(); len(es) != 0 {
		t.Fatalf("apply log changed: %+v", es)
	}
	w.cfg["listen"] = "127.0.0.1:0"
	var out2 syncBuf
	err = run(t.Context(), []string{"-config", w.writeConfig()}, &out2, func(string) { t.Fatal("second proxy started") })
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second proxy: %v", err)
	}
	r.stop(t)
	// Released on stop.
	if out, err := w.runImport(f); err != nil {
		t.Fatalf("after stop: %v %s", err, out)
	}
}
