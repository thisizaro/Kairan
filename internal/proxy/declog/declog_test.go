package declog_test

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/policy"
	"kairan/internal/proxy/declog"
	"kairan/internal/proxy/enforce"
	"kairan/internal/wire"
)

var (
	hashA = wire.Hash(strings.Repeat("a", 64))
	hashB = wire.Hash(strings.Repeat("b", 64))
	t0    = time.Date(2026, 11, 5, 10, 0, 0, 0, time.UTC)
)

func rec(i int) enforce.Record {
	return enforce.Record{Time: t0.Add(time.Duration(i) * time.Second), Role: "reader", Tool: fmt.Sprintf("notes.read%d", i),
		Allowed: i%2 == 0, Class: policy.ClassR, Version: uint64(i), Hash: hashA, State: wire.StateEnforcing}
}

type counter struct {
	mu sync.Mutex
	m  map[string]int
}

func (c *counter) Inc(n string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.m == nil {
		c.m = map[string]int{}
	}
	c.m[n]++
}

func (c *counter) get(n string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[n]
}

// readAll returns every record from path.N ... path.1, path, oldest first,
// failing the test on any line that is not strictly valid.
func readAll(t *testing.T, path string) []enforce.Record {
	t.Helper()
	var files []string
	for i := 100; i >= 1; i-- {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err == nil {
			files = append(files, p)
		}
	}
	files = append(files, path)
	var out []enforce.Record
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) == 0 {
			continue
		}
		if b[len(b)-1] != '\n' {
			t.Fatalf("%s does not end in a newline", f)
		}
		for _, l := range bytes.SplitAfter(b[:len(b)-1], []byte("\n")) {
			l = append(bytes.TrimSuffix(l, []byte("\n")), '\n')
			r, err := declog.Decode(l)
			if err != nil {
				t.Fatalf("%s: bad line %q: %v", f, l, err)
			}
			out = append(out, r)
		}
	}
	return out
}

func TestOpenWritesAppendOnlyJSONLines0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	l, err := declog.Open(path, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Record(rec(i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	got := readAll(t, path)
	if len(got) != 5 {
		t.Fatalf("got %d records", len(got))
	}
	for i, r := range got {
		if r.Tool != fmt.Sprintf("notes.read%d", i) || r.Version != uint64(i) {
			t.Fatalf("record %d = %+v", i, r)
		}
	}

	// Reopen: appends, does not truncate.
	l, err = declog.Open(path, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(5)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	if n := len(readAll(t, path)); n != 6 {
		t.Fatalf("after reopen got %d records, want 6", n)
	}
}

func TestOpenTightensLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := declog.Open(path, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
}

func TestOpenRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "decisions.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if l, err := declog.Open(link, declog.Options{}); err == nil {
		l.Close()
		t.Fatal("Open followed a symlink")
	}
}

func TestOpenFailsInMissingDirectory(t *testing.T) {
	if _, err := declog.Open(filepath.Join(t.TempDir(), "nope", "d.log"), declog.Options{}); err == nil {
		t.Fatal("Open succeeded in a missing directory")
	}
}

// A crash can leave a half line at the end. The next record must not be glued
// to it: it starts on a fresh line, and the torn line stays a separate,
// invalid line that readers can skip.
func TestOpenSeparatesTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	if err := os.WriteFile(path, []byte(`{"time":"2026-11-05T10:00`), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := declog.Open(path, declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(1)); err != nil {
		t.Fatal(err)
	}
	_ = l.Close()
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %q", lines)
	}
	if _, err := declog.Decode([]byte(lines[1])); err != nil {
		t.Fatalf("new record is not a clean line: %v", err)
	}
}

type failWriter struct {
	fail atomic.Bool
	buf  bytes.Buffer
	mu   sync.Mutex
}

func (w *failWriter) Write(p []byte) (int, error) {
	if w.fail.Load() {
		return 0, errors.New("injected: no space left on device")
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func TestRecordReturnsWriteError(t *testing.T) {
	w := &failWriter{}
	m := &counter{}
	l := declog.New(w, m)
	if err := l.Record(rec(1)); err != nil {
		t.Fatal(err)
	}
	w.fail.Store(true)
	if err := l.Record(rec(2)); err == nil {
		t.Fatal("Record hid a failed write")
	}
	if m.get(declog.MetricWriteErrors) != 1 {
		t.Fatalf("write error counter = %d, want 1", m.get(declog.MetricWriteErrors))
	}
	w.fail.Store(false)
	if err := l.Record(rec(3)); err != nil {
		t.Fatalf("Log did not recover: %v", err)
	}
	if m.get(declog.MetricWriteErrors) != 1 {
		t.Fatal("counter moved on success")
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil } // short with nil error: a lying writer

func TestRecordShortWriteIsAnError(t *testing.T) {
	if err := declog.New(shortWriter{}, nil).Record(rec(1)); err == nil {
		t.Fatal("short write reported as success")
	}
}

func TestRecordRejectsBadRecordAndCounts(t *testing.T) {
	m := &counter{}
	w := &failWriter{}
	l := declog.New(w, m)
	r := rec(1)
	r.Tool = `notes.read {"query":"secret"}`
	if err := l.Record(r); err == nil {
		t.Fatal("free text accepted")
	}
	if w.buf.Len() != 0 {
		t.Fatalf("something was written: %q", w.buf.String())
	}
	if m.get(declog.MetricWriteErrors) != 1 {
		t.Fatal("rejection not counted")
	}
}

func TestRecordAfterClose(t *testing.T) {
	l, err := declog.Open(filepath.Join(t.TempDir(), "d.log"), declog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(1)); err == nil {
		t.Fatal("Record after Close succeeded")
	}
}

func TestRotationKeepsNFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	one, _ := os.CreateTemp(dir, "probe")
	probe := declog.New(one, nil)
	_ = probe.Record(rec(10))
	st, _ := one.Stat()
	lineLen := st.Size()
	one.Close()

	const maxLines = 3
	l, err := declog.Open(path, declog.Options{MaxBytes: lineLen*maxLines + 10, Keep: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 10; i < 10+40; i++ {
		if err := l.Record(rec(i)); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	var names []string
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "decisions.log") {
			names = append(names, e.Name())
			fi, _ := e.Info()
			if fi.Size() > lineLen*maxLines+10 {
				t.Errorf("%s is %d bytes, over the cap", e.Name(), fi.Size())
			}
			if fi.Mode().Perm() != 0o600 {
				t.Errorf("%s mode %v", e.Name(), fi.Mode().Perm())
			}
		}
	}
	sort.Strings(names)
	if want := []string{"decisions.log", "decisions.log.1", "decisions.log.2"}; strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("files = %v, want %v", names, want)
	}
	got := readAll(t, path)
	// Newest records survive, in order, without gaps.
	if last := got[len(got)-1]; last.Tool != "notes.read49" {
		t.Fatalf("last = %+v", last)
	}
	for i := 1; i < len(got); i++ {
		if got[i].Version != got[i-1].Version+1 {
			t.Fatalf("gap or reorder at %d: %d then %d", i, got[i-1].Version, got[i].Version)
		}
	}
	if len(got) < maxLines+1 {
		t.Fatalf("only %d records kept", len(got))
	}
}

func TestRotationFailureDeniesAndRecovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "decisions.log")
	m := &counter{}
	l, err := declog.Open(path, declog.Options{MaxBytes: 300, Keep: 3, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// path.1 is a non-empty directory: renaming the log onto it must fail.
	blocker := path + ".3" // the oldest slot (Keep is 3): removing it must fail
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	var failed int
	for i := 0; i < 10; i++ {
		if err := l.Record(rec(i)); err != nil {
			failed++
		}
	}
	if failed == 0 {
		t.Fatal("rotation failure was never reported")
	}
	if m.get(declog.MetricRotateErrors) == 0 {
		t.Fatal("rotation failure not counted")
	}
	// Every call that returned nil must really be on disk, and the main file
	// must not have grown past the cap while rotation was stuck.
	if st, _ := os.Stat(path); st != nil && st.Size() > 300 {
		t.Fatalf("log grew to %d bytes while rotation failed", st.Size())
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	if err := l.Record(rec(99)); err != nil {
		t.Fatalf("no recovery after the blocker was removed: %v", err)
	}
	got := readAll(t, path)
	if got[len(got)-1].Version != 99 {
		t.Fatalf("last = %+v", got[len(got)-1])
	}
}

func TestConcurrentRecordsAllLandIntact(t *testing.T) {
	path := filepath.Join(t.TempDir(), "decisions.log")
	l, err := declog.Open(path, declog.Options{MaxBytes: 4096, Keep: 1000})
	if err != nil {
		t.Fatal(err)
	}
	const workers, per = 16, 100
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r := rec(0)
				r.Role = fmt.Sprintf("w%d", w)
				r.Version = uint64(i)
				if err := l.Record(r); err != nil {
					t.Error(err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, r := range readAll(t, path) {
		seen[fmt.Sprintf("%s/%d", r.Role, r.Version)]++
	}
	if len(seen) != workers*per {
		t.Fatalf("distinct records = %d, want %d", len(seen), workers*per)
	}
	for k, n := range seen {
		if n != 1 {
			t.Fatalf("%s written %d times", k, n)
		}
	}
}

// Disk full, injected with RLIMIT_FSIZE in a child process so the limit and
// the ignored SIGXFSZ cannot touch other tests (same method as lane Q's
// applylog test). A failed Record must return an error, and it must not
// leave half a line behind.
func TestDiskFullFailsRecordAndLeavesNoPartialLine(t *testing.T) {
	if os.Getenv("DECLOG_FSIZE") == "1" {
		signal.Ignore(syscall.SIGXFSZ)
		path := os.Getenv("DECLOG_PATH")
		m := &counter{}
		l, err := declog.Open(path, declog.Options{Metrics: m})
		if err != nil {
			fmt.Println("FAIL open:", err)
			os.Exit(1)
		}
		for i := 0; i < 3; i++ {
			if err := l.Record(rec(i)); err != nil {
				fmt.Println("FAIL setup record:", err)
				os.Exit(1)
			}
		}
		before, _ := os.ReadFile(path)
		var old syscall.Rlimit
		_ = syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old)
		lim := syscall.Rlimit{Cur: uint64(len(before)) + 50, Max: old.Max} // less than one more line
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
			fmt.Println("FAIL setrlimit:", err)
			os.Exit(1)
		}
		rerr := l.Record(rec(3))
		_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
		if rerr == nil {
			fmt.Println("FAIL: Record reported success although the disk was full")
			os.Exit(1)
		}
		after, _ := os.ReadFile(path)
		if !bytes.Equal(before, after) {
			fmt.Printf("FAIL: partial line left behind: %d -> %d bytes\n", len(before), len(after))
			os.Exit(1)
		}
		if m.get(declog.MetricWriteErrors) != 1 {
			fmt.Println("FAIL: write error not counted")
			os.Exit(1)
		}
		if err := l.Record(rec(4)); err != nil {
			fmt.Println("FAIL: no recovery when space came back:", err)
			os.Exit(1)
		}
		_ = l.Close()
		final, _ := os.ReadFile(path)
		if n := bytes.Count(final, []byte("\n")); n != 4 {
			fmt.Println("FAIL: lines =", n)
			os.Exit(1)
		}
		fmt.Println("DISKFULL-OK")
		os.Exit(0)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestDiskFullFailsRecordAndLeavesNoPartialLine$")
	cmd.Env = append(os.Environ(), "DECLOG_FSIZE=1", "DECLOG_PATH="+filepath.Join(t.TempDir(), "decisions.log"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "DISKFULL-OK") {
		t.Fatalf("disk-full injection failed (err=%v):\n%s", err, out)
	}
}

// ---- with enforce -----------------------------------------------------------

func mustPolicy(t testing.TB, version int, readerTools string) *policy.Policy {
	t.Helper()
	p, err := policy.Parse([]byte(fmt.Sprintf(`{"tenant":"bank-a","version":%d,"issued_at":"2026-11-05T09:00:00Z","expires_at":"2026-11-08T09:00:00Z","default":"deny","roles":{"reader":{%s}}}`, version, readerTools)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type e2eRig struct {
	srv      *httptest.Server
	h        *enforce.Holder
	upstream atomic.Int64
}

func newE2E(t *testing.T, dl enforce.DecisionLog, m enforce.Metrics) *e2eRig {
	t.Helper()
	r := &e2eRig{h: &enforce.Holder{}}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.upstream.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = b
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"upstream ran it"}]}}`)
	}))
	t.Cleanup(up.Close)
	u, _ := url.Parse(up.URL)
	h := enforce.New(enforce.Config{Upstream: u, APIKeys: map[string]string{"key-reader": "reader"}}, r.h, dl,
		clock.NewFake(t0), m)
	r.srv = httptest.NewServer(h)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *e2eRig) call(t testing.TB, id int, tool string) string {
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{"q":"SECRET-ARGUMENT"}}}`, id, tool)
	req, _ := http.NewRequest("POST", r.srv.URL+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer key-reader")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Errorf("call: %v", err)
		return ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// A log that cannot store the decision denies the call; the upstream never
// hears of it (M-D33 item 3, I5).
func TestLogFailureDeniesCallAndNothingReachesUpstream(t *testing.T) {
	w := &failWriter{}
	m := &counter{}
	dl := declog.New(w, m)
	r := newE2E(t, dl, m)
	r.h.Store(&enforce.Active{Policy: mustPolicy(t, 1, `"notes.read":"R"`), Hash: hashA, State: wire.StateEnforcing})

	if got := r.call(t, 1, "notes.read"); !strings.Contains(got, "upstream ran it") {
		t.Fatalf("healthy log: %s", got)
	}
	w.fail.Store(true)
	if got := r.call(t, 2, "notes.read"); strings.Contains(got, "upstream ran it") {
		t.Fatalf("call went through although its decision could not be logged: %s", got)
	}
	if n := r.upstream.Load(); n != 1 {
		t.Fatalf("upstream saw %d calls, want 1", n)
	}
	if m.get(declog.MetricWriteErrors) != 1 {
		t.Fatalf("declog counter = %d", m.get(declog.MetricWriteErrors))
	}
	w.fail.Store(false)
	if got := r.call(t, 3, "notes.read"); !strings.Contains(got, "upstream ran it") {
		t.Fatalf("no recovery: %s", got)
	}
}

// The race the PLAN names: many concurrent calls while the Holder swaps
// between two policies, through the real file log with rotation. Every line
// on disk must carry a (version, hash, allowed) that the policy of that
// version really decides for that tool, and no line may carry arguments.
func TestAtomicSwapRaceEndToEndThroughFileLog(t *testing.T) {
	p1 := mustPolicy(t, 1, `"notes.read":"R","crm.read_*":"R"`)
	p2 := mustPolicy(t, 2, `"crm.read_*":"R"`)
	pols := map[uint64]struct {
		p *policy.Policy
		h wire.Hash
	}{1: {p1, hashA}, 2: {p2, hashB}}
	a1 := &enforce.Active{Policy: p1, Hash: hashA, State: wire.StateEnforcing}
	a2 := &enforce.Active{Policy: p2, Hash: hashB, State: wire.StateEnforcing}

	path := filepath.Join(t.TempDir(), "decisions.log")
	m := &counter{}
	dl, err := declog.Open(path, declog.Options{MaxBytes: 8 << 10, Keep: 1000, Metrics: m})
	if err != nil {
		t.Fatal(err)
	}
	r := newE2E(t, dl, m)
	r.h.Store(a1)

	stop := make(chan struct{})
	var swapper sync.WaitGroup
	swapper.Add(1)
	go func() {
		defer swapper.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				r.h.Store(a2)
			} else {
				r.h.Store(a1)
			}
		}
	}()

	tools := []string{"notes.read", "crm.read_deal", "crm.export", "unknown_tool"}
	const workers, per = 8, 80
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				r.call(t, w*1000+i, tools[(w+i)%len(tools)])
			}
		}(w)
	}
	wg.Wait()
	close(stop)
	swapper.Wait()
	if err := dl.Close(); err != nil {
		t.Fatal(err)
	}

	got := readAll(t, path)
	if len(got) != workers*per {
		t.Fatalf("log has %d lines, want %d (one per call)", len(got), workers*per)
	}
	seen := map[uint64]int{}
	for _, rc := range got {
		ref, ok := pols[rc.Version]
		if !ok || rc.Hash != ref.h {
			t.Fatalf("line names an unknown (version, hash): %+v", rc)
		}
		d := ref.p.Decide(rc.Role, rc.Tool, false)
		if rc.Allowed != d.Allowed || rc.Class != d.Class || rc.State != wire.StateEnforcing {
			t.Fatalf("line disagrees with policy v%d: logged %+v, policy says %+v", rc.Version, rc, d)
		}
		seen[rc.Version]++
	}
	t.Logf("lines per version: %v", seen)
	for _, f := range mustGlob(t, path+"*") {
		b, _ := os.ReadFile(f)
		if bytes.Contains(b, []byte("SECRET-ARGUMENT")) {
			t.Fatalf("%s contains call arguments", f)
		}
	}
	if m.get(declog.MetricWriteErrors) != 0 || m.get(declog.MetricRotateErrors) != 0 {
		t.Fatalf("unexpected log errors: %v", m.m)
	}
}

func mustGlob(t *testing.T, pat string) []string {
	t.Helper()
	m, err := filepath.Glob(pat)
	if err != nil || len(m) == 0 {
		t.Fatalf("glob %s: %v %v", pat, m, err)
	}
	return m
}
