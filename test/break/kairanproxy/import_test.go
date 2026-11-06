package kairanproxybreak

// Break pass for P-11: kairan-proxy -config C -import FILE (offline import of a signed bundle, PRD J3).
// Sources: the kairan-proxy command doc (Offline import, The data directory is locked, Exit status), PRD J3,
// THREATS #1 and #3 (same trust.Accept as a policy from the control plane), ARCHITECTURE S5 (0 applied), I1-I3,
// the golden envelopes in test/fixtures (cases.json).
//
// Contract checked: exit 0 applied, 1 rejected or unreadable, 2 usage or config. A rejected bundle applies nothing,
// leaves policy.json byte for byte as it was, leaves the apply log a valid chain that only grew, and nothing from the
// bundle is printed. No network, no serving.

import (
	"bytes"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode"

	"kairan/internal/proxy/applylog"
	"kairan/internal/trust"
	"kairan/internal/wire"
)

const impCanary = "IMPORTCANARY-77aa31"

type imp struct {
	t   *testing.T
	dir string
	cp  *fakeCP
	cfg pcfg
}

func newImp(t *testing.T) *imp {
	t.Helper()
	cp := newCP(t)
	dir := filepath.Join(t.TempDir(), "data")
	return &imp{t: t, dir: dir, cp: cp, cfg: baseCfg(t, dir, cp.url(), "http://127.0.0.1:9/mcp", freePort(t))}
}

func (e *imp) bundle(raw []byte) string {
	e.t.Helper()
	p := filepath.Join(e.t.TempDir(), "bundle.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func envJSON(env wire.Envelope) []byte {
	b, _ := json.Marshal(env)
	return b
}

func (e *imp) run(path string, extra ...string) (int, string) {
	e.t.Helper()
	return runOnce(e.t, e.cfg.bytes(), nil, append([]string{"-import", path}, extra...)...)
}

// apply imports env and requires success.
func (e *imp) apply(env wire.Envelope) {
	e.t.Helper()
	code, out := e.run(e.bundle(envJSON(env)))
	if code != 0 {
		e.t.Fatalf("import of a valid bundle: exit %d: %s", code, clip(out))
	}
}

type snapshot struct {
	policy    []byte
	hasPolicy bool
	mtime     time.Time
	log       []byte
	others    []string
}

func (e *imp) snap() snapshot {
	var s snapshot
	if b, err := os.ReadFile(filepath.Join(e.dir, "policy.json")); err == nil {
		s.policy, s.hasPolicy = b, true
		if st, err := os.Stat(filepath.Join(e.dir, "policy.json")); err == nil {
			s.mtime = st.ModTime()
		}
	}
	s.log, _ = os.ReadFile(filepath.Join(e.dir, "apply.log"))
	ents, _ := os.ReadDir(e.dir)
	for _, d := range ents {
		switch d.Name() {
		case "policy.json", "apply.log", "kairan.lock", "highwater", "decisions.log":
		default:
			s.others = append(s.others, d.Name())
		}
	}
	sort.Strings(s.others)
	return s
}

// verifiedLog reads a log that must verify. A log that fails to verify is not "unchanged": it is reported.
func verifiedLog(t testing.TB, raw []byte) (uint64, []applylog.Entry) {
	t.Helper()
	ents, err := applylog.Read(bytes.NewReader(raw))
	if err != nil {
		t.Errorf("apply log does not verify: %v", err)
	}
	var v uint64
	for _, x := range ents {
		if x.Result == "" {
			v = x.To
		}
	}
	return v, ents
}

func hasJP(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana, unicode.Han) {
			return true
		}
	}
	return false
}

// reject runs the import and checks everything a rejection promises. wantEntry: the apply log must gain an
// entry with a reason (the doc lists these causes: unsigned, one signature, old version, wrong tenant, expired,
// corrupted, not an envelope).
func (e *imp) reject(name string, bundlePath string, wantEntry bool) string {
	e.t.Helper()
	before := e.snap()
	reqs := len(e.cp.all())
	code, out := e.run(bundlePath)
	after := e.snap()
	if code != 1 {
		e.t.Errorf("%s: exit %d, want 1: %s", name, code, clip(out))
	}
	if after.hasPolicy != before.hasPolicy || !bytes.Equal(after.policy, before.policy) || !after.mtime.Equal(before.mtime) {
		e.t.Errorf("%s: the stored policy changed (present %v -> %v)", name, before.hasPolicy, after.hasPolicy)
	}
	if strings.Join(after.others, ",") != strings.Join(before.others, ",") {
		e.t.Errorf("%s: files appeared or went in the data dir: %v -> %v", name, before.others, after.others)
	}
	vb, eb := verifiedLog(e.t, before.log)
	if !bytes.HasPrefix(after.log, before.log) {
		e.t.Errorf("%s: the apply log was rewritten, not appended to", name)
	}
	va, ea := verifiedLog(e.t, after.log)
	if va != vb {
		e.t.Errorf("%s: the applied version moved %d -> %d (I1)", name, vb, va)
	}
	if len(ea) >= len(eb) {
		for _, x := range ea[len(eb):] {
			if x.Result == "" {
				e.t.Errorf("%s: a rejected bundle logged as applied: %+v", name, x)
			}
		}
	}
	if wantEntry && (len(ea) <= len(eb) || ea[len(ea)-1].Result == "") {
		e.t.Errorf("%s: no rejection entry with a reason in the apply log (%d -> %d entries)", name, len(eb), len(ea))
	}
	if len(e.cp.all()) != reqs {
		e.t.Errorf("%s: the import used the network", name)
	}
	if strings.Contains(out, impCanary) || strings.Contains(out, token) || strings.Contains(out, keySales) {
		e.t.Errorf("%s: output echoes bundle or secret content: %s", name, clip(out))
	}
	if !hasJP(out) {
		e.t.Errorf("%s: result not in Japanese as well: %s", name, clip(out))
	}
	return out
}

func signedBy(t testing.TB, payload []byte, who ...string) wire.Envelope {
	var ks []keyPair
	for _, w := range who {
		ks = append(ks, key(t, w))
	}
	return envelopeOf(payload, ks...)
}

func good(t testing.TB, version uint64) wire.Envelope {
	return signedBy(t, validPolicy(version), "admin-a", "admin-b")
}

// ---- the happy path and what follows it ----

func TestImportApplies(t *testing.T) {
	e := newImp(t)
	env := good(t, 3)
	code, out := e.run(e.bundle(envJSON(env)))
	if code != 0 {
		t.Fatalf("exit %d: %s", code, clip(out))
	}
	if !hasJP(out) {
		t.Errorf("result not bilingual: %s", clip(out))
	}
	if strings.Contains(out, token) || strings.Contains(out, keySales) {
		t.Errorf("secret in output")
	}
	if st, err := os.Stat(e.dir); err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Errorf("data dir: %v %v", st, err)
	}
	if st, err := os.Stat(filepath.Join(e.dir, "policy.json")); err != nil || st.Mode().Perm()&0o077 != 0 {
		t.Errorf("policy.json: %v %v", st, err)
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, "apply.log"))
	v, ents := verifiedLog(t, raw)
	if v != 3 || len(ents) != 1 || ents[0].Hash != hashOf(env.Payload) || ents[0].From != 0 {
		t.Errorf("apply log %+v (applied %d), want one applied entry for v3 with the payload hash", ents, v)
	}
	if len(e.cp.all()) != 0 {
		t.Errorf("the import used the network: %d requests", len(e.cp.all()))
	}
	// a proxy that starts afterwards enforces the imported policy from disk, control plane down
	l := &life{t: t, dir: e.dir, cp: e.cp, up: newUpstream(t)}
	l.start("http://"+freePort(t), nil, nil)
	if !allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Fatalf("a proxy started after the import does not enforce it: %s", l.p.out.String())
	}
	if allowed(l.p.call(keySales, callBody("admin.shutdown", `{}`))) || allowed(l.p.call(keyIntrn, callBody("crm.read_contact", `{}`))) {
		t.Errorf("imported policy allows more than it says (I3)")
	}
	ls := l.decisions()
	if last := ls[len(ls)-1]; !strings.Contains(last, string(hashOf(env.Payload))) {
		t.Errorf("decision after import is not stamped with the imported policy hash (I5): %s", last)
	}
	l.stop()

	// replaying the same bundle is a rollback replay (THREATS #3): rejected, store unchanged
	e.reject("same bundle again", e.bundle(envJSON(env)), true)
	// a higher version applies after it, and the chain continues
	e.apply(good(t, 4))
	raw, _ = os.ReadFile(filepath.Join(e.dir, "apply.log"))
	if v, ents := verifiedLog(t, raw); v != 4 || len(ents) < 3 {
		t.Errorf("v4 after v3: applied %d, %d entries", v, len(ents))
	}
}

func TestImportNeedsNoServing(t *testing.T) {
	e := newImp(t)
	// the MCP port and the metrics port are taken: an import must not try to bind them
	l1, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l1.Close()
	l2, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l2.Close()
	e.cfg = e.cfg.with("listen", l1.Addr().String()).with("metrics_listen", l2.Addr().String())
	e.apply(good(t, 1))
	// an unreachable control plane URL changes nothing
	e.cfg = e.cfg.with("cp_url", "http://127.0.0.1:9")
	e.apply(good(t, 2))
}

// ---- the S5 rejection set ----

func TestImportRejectsLikeS5(t *testing.T) {
	a := key(t, "admin-a")
	now := time.Now()
	valid := func(v uint64) []byte { return validPolicy(v) }

	twice := envelopeOf(valid(9), a)
	trust.Sign(&twice, a.priv)
	tampered := signedBy(t, valid(9), "admin-a", "admin-b")
	tampered.Payload = bytes.Replace(tampered.Payload, []byte("crm.update_deal"), []byte("crm.update_dxal"), 1)
	flipped := signedBy(t, valid(9), "admin-a", "admin-b")
	flipped.Signatures[0].Sig[3] ^= 1
	mislabeled := signedBy(t, valid(9), "admin-a", "admin-b")
	mislabeled.Signatures[1].KeyID = mislabeled.Signatures[0].KeyID
	wrongType := signedBy(t, valid(9), "admin-a", "admin-b")
	wrongType.PayloadType = "application/json"
	many := signedBy(t, valid(9), "admin-a", "admin-b")
	for i := 0; i < 9; i++ {
		many.Signatures = append(many.Signatures, many.Signatures[i%2])
	}
	withCanary := policyDoc(tenant, 9, now.Add(-time.Hour), now.Add(time.Hour))
	withCanary = bytes.Replace(withCanary, []byte(`"help.*"`), []byte(`"help.`+impCanary+`.*"`), 1)

	cases := []struct {
		name  string
		env   wire.Envelope
		entry bool
	}{
		{"unsigned", envelopeOf(valid(9)), true},
		{"one signature", envelopeOf(valid(9), a), true},
		{"one trusted and an outsider", signedBy(t, valid(9), "admin-a", "outsider"), true},
		{"two outsiders", signedBy(t, valid(9), "outsider"), true},
		{"the same key twice", twice, true},
		{"payload edited after signing", tampered, true},
		{"signature bit flipped", flipped, true},
		{"key id of another signature", mislabeled, true},
		{"wrong payload type", wrongType, true},
		{"empty payload", signedBy(t, nil, "admin-a", "admin-b"), true},
		{"payload is not a policy", signedBy(t, []byte(`{"tenant":"bank-a"}`), "admin-a", "admin-b"), true},
		{"payload is not JSON", signedBy(t, []byte(impCanary), "admin-a", "admin-b"), true},
		{"more signatures than allowed, all repeats", many, true},
		{"wrong tenant", signedBy(t, policyDoc("bank-b", 9, now.Add(-time.Hour), now.Add(time.Hour)), "admin-a", "admin-b"), true},
		{"expired an hour ago", signedBy(t, policyDoc(tenant, 9, now.Add(-48*time.Hour), now.Add(-time.Hour)), "admin-a", "admin-b"), true},
		{"expired long ago", signedBy(t, policyDoc(tenant, 9, now.Add(-480*time.Hour), now.Add(-240*time.Hour)), "admin-a", "admin-b"), true},
		{"expires before it was issued", signedBy(t, policyDoc(tenant, 9, now.Add(time.Hour), now.Add(-time.Hour)), "admin-a", "admin-b"), true},
		{"version 0", signedBy(t, valid(0), "admin-a", "admin-b"), true},
		{"unknown tool pattern with canary only in the policy", signedBy(t, bytes.Replace(withCanary, []byte(`"deny"`), []byte(`"permit"`), 1), "admin-a", "admin-b"), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newImp(t)
			e.apply(good(t, 5)) // a policy is in force; it must stay
			e.reject(c.name, e.bundle(envJSON(c.env)), c.entry)
		})
	}
	t.Run("on a fresh data dir nothing is created", func(t *testing.T) {
		e := newImp(t)
		e.reject("unsigned on fresh", e.bundle(envJSON(envelopeOf(valid(1)))), true)
		if _, err := os.Stat(filepath.Join(e.dir, "policy.json")); err == nil {
			t.Errorf("policy.json exists after a rejected first import")
		}
	})
}

// Version rule (I2): not newer than anything applied is refused, however it is signed.
func TestImportVersionMustRise(t *testing.T) {
	for _, v := range []uint64{1, 4, 5} {
		t.Run(("v" + string(rune('0'+v))), func(t *testing.T) {
			e := newImp(t)
			e.apply(good(t, 5))
			e.reject("version not above 5", e.bundle(envJSON(good(t, v))), true)
		})
	}
	t.Run("rollback after a rejected-then-higher history", func(t *testing.T) {
		e := newImp(t)
		e.apply(good(t, 2))
		e.reject("unsigned 3", e.bundle(envJSON(envelopeOf(validPolicy(3)))), true)
		e.apply(good(t, 3)) // a rejected 3 does not burn the number 3
		e.reject("old 2", e.bundle(envJSON(good(t, 2))), true)
	})
	t.Run("a rejected high version does not raise the bar", func(t *testing.T) {
		e := newImp(t)
		e.apply(good(t, 2))
		e.reject("unsigned 99", e.bundle(envJSON(envelopeOf(validPolicy(99)))), true)
		e.apply(good(t, 3))
	})
}

// The wall clock set back: the high-water mark keeps an expired policy expired (M-D30), same as for a
// policy that came from the control plane.
func TestImportUsesEffectiveNow(t *testing.T) {
	e := newImp(t)
	e.apply(good(t, 1))
	hw := filepath.Join(e.dir, "highwater")
	future := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339Nano)
	if err := os.WriteFile(hw, []byte(future+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// valid for 24 h by the wall clock, expired by the high-water mark
	e.reject("expired at effective_now", e.bundle(envJSON(good(t, 2))), true)
}

// ---- hostile files ----

func TestImportRejectsMalformedBundles(t *testing.T) {
	env := good(t, 9)
	s := string(envJSON(env))
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		t.Fatalf("envelope JSON %q", clip(s))
	}
	inner := s[1 : len(s)-1]
	cases := map[string]string{
		"empty file":                       "",
		"whitespace only":                  " \n\t ",
		"null":                             "null",
		"array":                            "[" + s + "]",
		"string":                           `"` + impCanary + `"`,
		"number":                           "7",
		"empty object":                     "{}",
		"garbage with canary":              impCanary + " not json",
		"truncated envelope":               s[:len(s)/2],
		"envelope cut one byte short":      s[:len(s)-1],
		"duplicate payloadType":            `{"payloadType":"x",` + inner + `}`,
		"duplicate payload key":            `{"payload":"` + impCanary + `",` + inner + `}`,
		"duplicate signatures key":         `{"signatures":[],` + inner + `}`,
		"duplicate key inside a signature": strings.Replace(s, `{"keyid":`, `{"keyid":"00","keyid":`, 1),
		"case-variant payload":             `{` + inner + `,"Payload":"` + impCanary + `"}`,
		"case-variant payloadType":         `{` + inner + `,"PAYLOADTYPE":"x"}`,
		"case-variant signatures":          `{` + inner + `,"Signatures":[]}`,
		"unknown field":                    `{` + inner + `,"extra":"` + impCanary + `"}`,
		"unknown field in a signature":     strings.Replace(s, `{"keyid":`, `{"x":"`+impCanary+`","keyid":`, 1),
		"trailing garbage":                 s + impCanary,
		"trailing second object":           s + "\n" + s,
		"trailing empty object":            s + "{}",
		"byte order mark":                  "\xef\xbb\xbf" + s,
		"NUL after the object":             s + "\x00",
		"NUL inside":                       strings.Replace(s, "payloadType", "payload\x00Type", 1),
		"signatures null":                  `{"payloadType":"application/vnd.kairan.policy+json","payload":"e30=","signatures":null}`,
		"payload not base64":               `{"payloadType":"application/vnd.kairan.policy+json","payload":"!!` + impCanary + `","signatures":[]}`,
		"payload a number":                 `{"payloadType":"application/vnd.kairan.policy+json","payload":5,"signatures":[]}`,
		"deeply nested":                    strings.Repeat("[", 100000) + strings.Repeat("]", 100000),
		"huge number":                      `{"payloadType":"x","payload":"e30=","signatures":[],"n":` + strings.Repeat("9", 5000) + `}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			e := newImp(t)
			e.apply(good(t, 5))
			e.reject(name, e.bundle([]byte(content)), true)
		})
	}
}

func TestImportRefusesNonRegularAndOversizeFiles(t *testing.T) {
	d := t.TempDir()
	valid := envJSON(good(t, 9))
	over := append(append([]byte(nil), valid...), bytes.Repeat([]byte(" "), wire.MaxEnvelopeBytes+1-len(valid))...)
	if len(over) != wire.MaxEnvelopeBytes+1 {
		t.Fatalf("setup: %d", len(over))
	}
	sparse := func(name string, size int64) string {
		p := filepath.Join(d, name)
		f, err := os.Create(p)
		if err != nil {
			t.Fatal(err)
		}
		f.Truncate(size)
		f.Close()
		return p
	}
	fifo := filepath.Join(d, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	// a writer that never writes: opening for read without O_NONBLOCK would hang forever
	link := filepath.Join(d, "link.json")
	if err := os.Symlink(filepath.Join(d, "nope.json"), link); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"FIFO (must not hang)":                     fifo,
		"directory":                                d,
		"missing file":                             filepath.Join(d, "nope.json"),
		"dangling symlink":                         link,
		"/dev/null":                                "/dev/null",
		"/dev/zero (endless)":                      "/dev/zero",
		"/dev/urandom (endless)":                   "/dev/urandom",
		"valid envelope padded to MaxEnvelope+1":   e2file(t, d, "over.json", over),
		"300 KiB of garbage":                       e2file(t, d, "300k.json", bytes.Repeat([]byte("A"), 300<<10)),
		"64 MiB sparse":                            sparse("64m.json", 64<<20),
		"1 GiB sparse":                             sparse("1g.json", 1<<30),
		"empty path component (relative, missing)": "no/such/dir/bundle.json",
	}
	for name, path := range cases {
		t.Run(name, func(t *testing.T) {
			e := newImp(t)
			e.apply(good(t, 5))
			start := time.Now()
			e.reject(name, path, false)
			if d := time.Since(start); d > 12*time.Second {
				t.Errorf("took %v", d)
			}
		})
	}
}

func e2file(t testing.TB, dir, name string, b []byte) string {
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The golden envelopes: every case the trust package must reject is rejected by -import too, with the
// applied version set to the case's `have`, and nothing changes.
func TestImportGoldenRejections(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Name string `json:"name"`
			File string `json:"file"`
			Have uint64 `json:"have"`
			Want string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, c := range doc.Cases {
		if c.Want == "" {
			continue // accepted at the fixtures' fixed time; the wall clock here decides, so no assertion
		}
		n++
		t.Run(c.Name, func(t *testing.T) {
			b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", c.File))
			if err != nil {
				t.Fatal(err)
			}
			e := newImp(t)
			if c.Have > 0 {
				e.apply(good(t, c.Have))
			}
			e.reject(c.Name+" ("+c.Want+")", e.bundle(b), true)
		})
	}
	if n < 10 {
		t.Fatalf("only %d golden rejection cases", n)
	}
}

// ---- the apply log ----

func TestImportApplyLogIsADirectory(t *testing.T) {
	t.Run("apply.log is a directory", func(t *testing.T) {
		e := newImp(t)
		os.MkdirAll(filepath.Join(e.dir, "apply.log"), 0o700)
		code, out := e.run(e.bundle(envJSON(good(t, 1))))
		if code != 1 {
			t.Errorf("exit %d, want 1: %s", code, clip(out))
		}
		if _, err := os.Stat(filepath.Join(e.dir, "policy.json")); err == nil {
			t.Errorf("a policy was stored without a usable apply log")
		}
	})
}

// ---- the lock ----

func TestImportBesideARunningProxyIsRefused(t *testing.T) {
	l := newLife(t, "")
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	before, _ := os.ReadFile(l.policyFile())
	cfg := baseCfg(t, l.dir, l.cp.url(), l.up.srv.URL+"/mcp", freePort(t))
	bp := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(bp, envJSON(good(t, 2)), 0o600)
	start := time.Now()
	code, out := runOnce(t, cfg.bytes(), nil, "-import", bp)
	took := time.Since(start)
	if code != 1 {
		t.Errorf("exit %d, want 1 (data directory in use): %s", code, clip(out))
	}
	if took > 12*time.Second {
		t.Errorf("waited %v for the lock; the doc says up to 5 s", took)
	}
	if !strings.Contains(strings.ToLower(out), "in use") {
		t.Errorf("no 'in use' message: %s", clip(out))
	}
	after, _ := os.ReadFile(l.policyFile())
	if !bytes.Equal(before, after) {
		t.Errorf("the import changed the policy under a running proxy")
	}
	// the running proxy is unchanged and still enforces v1
	if !allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Errorf("running proxy no longer enforcing")
	}
	// the lock goes with the process: after the proxy stops, the import works
	l.stop()
	code, out = runOnce(t, cfg.bytes(), nil, "-import", bp)
	if code != 0 {
		t.Errorf("after the proxy stopped: exit %d: %s", code, clip(out))
	}
}

func TestImportLockGoneAfterKill(t *testing.T) {
	l := newLife(t, "")
	l.offer(1, "admin-a", "admin-b")
	l.start("", nil, nil)
	l.waitAllowed()
	l.p.signal(syscall.SIGKILL)
	l.p.waitExit(5 * time.Second)
	cfg := baseCfg(t, l.dir, l.cp.url(), l.up.srv.URL+"/mcp", freePort(t))
	bp := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(bp, envJSON(good(t, 2)), 0o600)
	start := time.Now()
	code, out := runOnce(t, cfg.bytes(), nil, "-import", bp)
	if code != 0 || time.Since(start) > 4*time.Second {
		t.Errorf("a dead process left the data dir locked: exit %d after %v: %s", code, time.Since(start), clip(out))
	}
}

// Two imports at once on one data dir: the lock serialises them; the chain stays valid; the higher version wins
// whatever the order.
func TestImportTwoAtOnce(t *testing.T) {
	e := newImp(t)
	e.apply(good(t, 1))
	p2 := e.bundle(envJSON(good(t, 2)))
	p3 := e.bundle(envJSON(good(t, 3)))
	var wg sync.WaitGroup
	codes := make([]int, 2)
	for i, p := range []string{p2, p3} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], _ = runOnce(t, e.cfg.bytes(), nil, "-import", p)
		}()
	}
	wg.Wait()
	for _, c := range codes {
		if c != 0 && c != 1 {
			t.Errorf("exit codes %v", codes)
		}
	}
	if codes[1] != 0 {
		t.Errorf("the v3 import must always succeed: %v", codes)
	}
	raw, _ := os.ReadFile(filepath.Join(e.dir, "apply.log"))
	v, _ := verifiedLog(t, raw)
	if v != 3 {
		t.Errorf("applied %d after two imports, want 3", v)
	}
	l := &life{t: t, dir: e.dir, cp: e.cp, up: newUpstream(t)}
	l.start("http://"+freePort(t), nil, nil)
	if !allowed(l.p.call(keySales, callBody("crm.read_contact", `{}`))) {
		t.Errorf("proxy does not enforce after two concurrent imports: %s", l.p.out.String())
	}
}

// ---- usage and config ----

func TestImportUsageAndConfigErrors(t *testing.T) {
	e := newImp(t)
	bp := e.bundle(envJSON(good(t, 1)))
	t.Run("-import without a value", func(t *testing.T) {
		code, out := runOnce(t, e.cfg.bytes(), nil, "-import")
		if code != 2 {
			t.Errorf("exit %d, want 2: %s", code, clip(out))
		}
	})
	t.Run("-import with an empty value must not start serving", func(t *testing.T) {
		code, out := runOnce(t, e.cfg.bytes(), nil, "-import", "")
		if code != 2 && code != 1 {
			t.Errorf("exit %d (0 or -1 means it did something else): %s", code, clip(out))
		}
	})
	t.Run("extra argument", func(t *testing.T) {
		code, out := runOnce(t, e.cfg.bytes(), nil, "-import", bp, "extra")
		if code == 0 || code == -1 {
			t.Errorf("exit %d: %s", code, clip(out))
		}
	})
	t.Run("unknown flag", func(t *testing.T) {
		code, _ := runOnce(t, e.cfg.bytes(), nil, "-import", bp, "-nope")
		if code != 2 {
			t.Errorf("exit %d, want 2", code)
		}
	})
	for name, c := range map[string]pcfg{
		"threshold 1":         e.cfg.with("threshold", 1),
		"skew over 5m":        e.cfg.with("skew", "6m"),
		"bad safe_mode":       e.cfg.with("safe_mode", "open"),
		"bad key":             e.cfg.with("trusted_keys", []string{"zz", "yy"}),
		"missing data_dir":    e.cfg.with("data_dir", nil),
		"missing trusted_key": e.cfg.with("trusted_keys", nil),
	} {
		t.Run("config: "+name, func(t *testing.T) {
			code, out := runOnce(t, c.bytes(), nil, "-import", bp)
			if code != 2 {
				t.Errorf("exit %d, want 2: %s", code, clip(out))
			}
			if _, err := os.Stat(filepath.Join(e.dir, "policy.json")); err == nil {
				t.Errorf("a bundle was imported under a bad config")
			}
		})
	}
	t.Run("no -config", func(t *testing.T) {
		b := bin(t)
		p := startRaw(t, b, []string{"-import", bp})
		if code, ok := p.waitExit(10 * time.Second); !ok || code != 2 {
			t.Errorf("exit %d (exited %v), want 2: %s", code, ok, clip(p.out.String()))
		}
	})
	t.Run("the trust root is the config, not the bundle", func(t *testing.T) {
		// a config that trusts only the outsider and one more key: the admin-signed bundle is not trusted
		ee := newImp(t)
		ee.cfg = ee.cfg.with("trusted_keys", []string{key(t, "outsider").pub, key(t, "admin-c").pub})
		ee.reject("signed by keys outside this proxy's config", ee.bundle(envJSON(good(t, 1))), true)
	})
}
