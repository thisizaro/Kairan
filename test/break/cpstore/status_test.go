package cpstorebreak

import (
	"fmt"
	"math"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"kairan/internal/cp/fleet"
	"kairan/internal/cp/store"
	"kairan/internal/wire"
)

func sameLast(a, b fleet.Last) bool {
	return a.Group == b.Group && a.SeenAt.Equal(b.SeenAt) && reflect.DeepEqual(a.Report, b.Report)
}

func TestRecordStatusRoundTripSortedAndTenantIsolated(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	want := map[wire.ID]fleet.Last{}
	for i, id := range []wire.ID{"p3", "p1", "p2", "p10"} {
		l := last("main", rep("bank-a", id, withSeq(uint64(i+1), 100), withCounters(1, 2, 3), withAnchor(uint64(i+1)), withErr(wire.ErrThreshold, 9)), t0.Add(time.Duration(i)*time.Second))
		if err := s.RecordStatus(l); err != nil {
			t.Fatal(err)
		}
		want[id] = l
	}
	other := last("main", rep("city-b", "p1"), t0)
	if err := s.RecordStatus(other); err != nil {
		t.Fatal(err)
	}
	for round, st := range []store.Store{s, open(t, dir)} {
		got, err := st.Fleet("bank-a")
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 4 {
			t.Fatalf("round %d: %d proxies, want 4 (tenant leak?)", round, len(got))
		}
		ids := []string{}
		for _, g := range got {
			ids = append(ids, string(g.Report.ProxyID))
			if g.Report.Tenant != "bank-a" {
				t.Fatalf("round %d: foreign tenant row %+v", round, g)
			}
			if w := want[g.Report.ProxyID]; !sameLast(g, w) {
				// after a reopen only heartbeat-only fields may lag; these reports are all new proxies
				t.Fatalf("round %d: %s = %+v, want %+v", round, g.Report.ProxyID, g, w)
			}
		}
		if !sort.StringsAreSorted(ids) {
			t.Fatalf("round %d: Fleet not sorted by proxy ID: %v", round, ids)
		}
		gb, _ := st.Fleet("city-b")
		if len(gb) != 1 || !sameLast(gb[0], other) {
			t.Fatalf("round %d: city-b = %+v", round, gb)
		}
		if ge, err := st.Fleet("nobody"); err != nil || len(ge) != 0 {
			t.Fatalf("unknown tenant: %v %v", ge, err)
		}
	}
}

// LLD: "Values going in and out are copies." LastError is a pointer in the wire type.
func TestStatusCopyIsolation(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	in := last("main", rep("bank-a", "p1", withErr(wire.ErrThreshold, 5)), t0)
	if err := s.RecordStatus(in); err != nil {
		t.Fatal(err)
	}
	in.Report.LastError.Code = wire.ErrExpired // caller mutates through its own pointer
	in.Report.LastError.Version = 99
	got, _ := s.Fleet("bank-a")
	if got[0].Report.LastError == nil || got[0].Report.LastError.Code != wire.ErrThreshold || got[0].Report.LastError.Version != 5 {
		t.Fatalf("store aliases the caller's LastError: %+v", got[0].Report.LastError)
	}
	got[0].Report.LastError.Code = wire.ErrPersist // caller mutates what it got back
	got[0].Group = "mutated"
	again, _ := s.Fleet("bank-a")
	if len(again) != 1 || again[0].Report.LastError.Code != wire.ErrThreshold || again[0].Group != "main" {
		t.Fatalf("store aliases the Fleet result: %+v", again)
	}
	// heartbeat path (kept in memory) must copy too
	hb := last("main", rep("bank-a", "p1", withErr(wire.ErrThreshold, 5), withSeq(2, 10)), t0.Add(10*time.Second))
	if err := s.RecordStatus(hb); err != nil {
		t.Fatal(err)
	}
	hb.Report.LastError.Code = wire.ErrMalformed
	again, _ = s.Fleet("bank-a")
	if again[0].Report.LastError.Code != wire.ErrThreshold {
		t.Fatal("heartbeat path aliases the caller's LastError")
	}
	tl, _ := s.Timeline("bank-a")
	if len(tl) == 0 {
		t.Fatal("no timeline")
	}
	tl[0].Version = 12345
	tl2, _ := s.Timeline("bank-a")
	if tl2[0].Version == 12345 {
		t.Fatal("Timeline result aliases internal state")
	}
}

// M-D41 / C-D3: timeline entry per (version, hash) period, with the log anchor.
func TestTimelineEntriesAndAnchor(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	rec := func(sec int, opts ...repOpt) {
		t.Helper()
		l := last("main", rep("bank-a", "p1", opts...), t0.Add(time.Duration(sec)*time.Second))
		if err := s.RecordStatus(l); err != nil {
			t.Fatal(err)
		}
	}
	rec(0, withState(wire.StateDenyAll), withVersion(0), withSeq(1, 1)) // deny-all period (version 0)
	rec(10, withVersion(1), withSeq(2, 11), withAnchor(1))              // v1 applied
	rec(20, withVersion(1), withSeq(3, 21), withAnchor(1))              // heartbeat
	rec(30, withVersion(1), withSeq(4, 31), withAnchor(2))              // rejected envelope appended to the log: anchor moves
	rec(40, withVersion(2), withSeq(5, 41), withAnchor(3))              // v2
	rec(50, withVersion(2), withSeq(1, 0), withAnchor(3))               // restart, same version: no new entry
	rec(60, withVersion(2), withHash(hx("tampered-content")), withSeq(2, 10), withAnchor(3))
	rec(70, withVersion(1), withSeq(3, 20), withAnchor(3)) // version went down (a bug elsewhere): still an entry, never merged

	check := func(name string, tl []wire.TimelineEntry, exactLast bool) {
		t.Helper()
		type k struct {
			v uint64
			h wire.Hash
		}
		wantKeys := []k{{0, ""}, {1, hx("policy-1")}, {2, hx("policy-2")}, {2, hx("tampered-content")}, {1, hx("policy-1")}}
		if len(tl) != len(wantKeys) {
			t.Fatalf("%s: %d entries, want %d: %+v", name, len(tl), len(wantKeys), tl)
		}
		for i, e := range tl {
			if e.ProxyID != "p1" || e.Version != wantKeys[i].v || e.PolicyHash != wantKeys[i].h {
				t.Fatalf("%s: entry %d = %+v, want %v", name, i, e, wantKeys[i])
			}
			if e.FirstSeenUnixMs > e.LastSeenUnixMs {
				t.Fatalf("%s: entry %d first %d > last %d", name, i, e.FirstSeenUnixMs, e.LastSeenUnixMs)
			}
		}
		first := func(sec int) int64 { return t0.Add(time.Duration(sec) * time.Second).UnixMilli() }
		for i, sec := range []int{0, 10, 40, 60, 70} {
			if tl[i].FirstSeenUnixMs != first(sec) {
				t.Fatalf("%s: entry %d FirstSeen %d, want %d", name, i, tl[i].FirstSeenUnixMs, first(sec))
			}
		}
		// anchors: the latest report seen while the entry was current (M-D41)
		wantAnchor := []uint64{0, 2, 3, 3, 3}
		for i, e := range tl {
			if e.LogSeq != wantAnchor[i] {
				t.Fatalf("%s: entry %d LogSeq %d, want %d", name, i, e.LogSeq, wantAnchor[i])
			}
			if (e.LogSeq == 0) != (e.LogHead == "") {
				t.Fatalf("%s: entry %d seq/head do not go together: %+v", name, i, e)
			}
			if e.LogSeq > 0 && e.LogHead != hx(fmt.Sprintf("head-%d", e.LogSeq)) {
				t.Fatalf("%s: entry %d head %q does not belong to seq %d", name, i, e.LogHead, e.LogSeq)
			}
		}
		if exactLast {
			if tl[1].LastSeenUnixMs != first(30) {
				t.Fatalf("%s: v1 LastSeen %d, want %d (heartbeats extend the entry)", name, tl[1].LastSeenUnixMs, first(30))
			}
			if tl[2].LastSeenUnixMs != first(50) {
				t.Fatalf("%s: v2 LastSeen %d, want %d (restart must not split the entry)", name, tl[2].LastSeenUnixMs, first(50))
			}
		}
	}
	tl, err := s.Timeline("bank-a")
	if err != nil {
		t.Fatal(err)
	}
	check("memory", tl, true)
	// crash right now: everything but heartbeat freshness must be on disk
	tl2, err := open(t, dir).Timeline("bank-a")
	if err != nil {
		t.Fatal(err)
	}
	check("after-reopen", tl2, false)
	if f, _ := open(t, dir).Fleet("bank-a"); len(f) != 1 || f[0].Report.AppliedVersion != 1 || f[0].Report.LogSeq != 3 {
		t.Fatalf("fleet after reopen: %+v", f)
	}
}

func TestTimelineSortedByProxyThenSeen(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	at := t0
	for round := uint64(1); round <= 3; round++ {
		for _, id := range []wire.ID{"p9", "p1", "p5"} {
			at = at.Add(time.Second)
			if err := s.RecordStatus(last("main", rep("bank-a", id, withVersion(round), withSeq(round, round)), at)); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, st := range []store.Store{s, open(t, dir)} {
		tl, _ := st.Timeline("bank-a")
		if len(tl) != 9 {
			t.Fatalf("%d entries, want 9", len(tl))
		}
		for i := 1; i < len(tl); i++ {
			a, b := tl[i-1], tl[i]
			if a.ProxyID > b.ProxyID || a.ProxyID == b.ProxyID && a.Version >= b.Version {
				t.Fatalf("order wrong at %d: %+v then %+v", i, a, b)
			}
		}
		if tt, _ := st.Timeline("city-b"); len(tt) != 0 {
			t.Fatalf("tenant leak in timeline: %+v", tt)
		}
	}
}

// Same proxy ID in two tenants must be two proxies.
func TestSameProxyIDInTwoTenants(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	_ = s.RecordStatus(last("main", rep("bank-a", "p1", withVersion(1)), t0))
	_ = s.RecordStatus(last("main", rep("city-b", "p1", withVersion(7)), t0))
	for _, st := range []store.Store{s, open(t, dir)} {
		a, _ := st.Fleet("bank-a")
		b, _ := st.Fleet("city-b")
		if len(a) != 1 || a[0].Report.AppliedVersion != 1 || len(b) != 1 || b[0].Report.AppliedVersion != 7 {
			t.Fatalf("tenants mixed: %+v / %+v", a, b)
		}
	}
}

// ---- heartbeat coalescing property (C-D3, M-D41): never lose a version/state/anchor/error change ----

func importantEqual(a, b fleet.Last) bool {
	return a.Group == b.Group && a.Report.Tenant == b.Report.Tenant && a.Report.ProxyID == b.Report.ProxyID &&
		a.Report.State == b.Report.State && a.Report.AppliedVersion == b.Report.AppliedVersion &&
		a.Report.PolicyHash == b.Report.PolicyHash && a.Report.LogSeq == b.Report.LogSeq && a.Report.LogHead == b.Report.LogHead &&
		reflect.DeepEqual(a.Report.LastError, b.Report.LastError)
}

func TestHeartbeatCoalescingNeverLosesImportantChanges(t *testing.T) {
	codes := []wire.ErrorCode{wire.ErrThreshold, wire.ErrExpired, wire.ErrNotNewer, wire.ErrMalformed, wire.ErrPersist, wire.ErrClockUntrusted}
	for seed := int64(1); seed <= 25; seed++ {
		rng := rand.New(rand.NewSource(seed))
		root, dir := sandbox(t)
		s := open(t, dir)
		proxies := []wire.ID{"p1", "p2", "p3"}
		cur := map[wire.ID]fleet.Last{}
		for _, p := range proxies {
			cur[p] = last("main", rep("bank-a", p, withSeq(1, 0)), t0)
		}
		at := t0
		var memTimelineOps int
		_ = memTimelineOps
		for step := 0; step < 70; step++ {
			p := proxies[rng.Intn(len(proxies))]
			l := cur[p]
			// deep copy report pointer so the model stays independent of the store
			if l.Report.LastError != nil {
				e := *l.Report.LastError
				l.Report.LastError = &e
			}
			at = at.Add(10 * time.Second)
			l.SeenAt = at
			r := &l.Report
			r.Seq++
			r.UptimeSeconds += 10
			kind := rng.Intn(11)
			mustSeq, mustSeen := false, false
			switch kind {
			case 0, 1, 2: // heartbeat
				r.Counters.CallsAllowed++
			case 3: // new version
				withVersion(r.AppliedVersion + 1)(r)
				if r.State != wire.StateEnforcing && r.State != wire.StateSafeMode {
					r.State = wire.StateEnforcing
				}
				withAnchor(r.LogSeq + 1)(r)
			case 4: // state change
				if r.AppliedVersion > 0 {
					if r.State == wire.StateEnforcing {
						r.State = wire.StateSafeMode
					} else {
						r.State = wire.StateEnforcing
					}
				}
			case 5: // error set
				r.LastError = &wire.ApplyError{Code: codes[rng.Intn(len(codes))], Version: uint64(rng.Intn(5))}
			case 6: // error cleared
				r.LastError = nil
			case 7: // anchor only
				withAnchor(r.LogSeq + 1)(r)
			case 8: // restart
				r.Seq, r.UptimeSeconds = 1, 0
				r.Counters = wire.Counters{}
				mustSeq = true
			case 9: // group change
				if l.Group == "main" {
					l.Group = "canary"
				} else {
					l.Group = "main"
				}
			case 10: // wall clock of the CP steps back
				l.SeenAt = at.Add(-time.Hour)
				mustSeen = l.SeenAt.Before(cur[p].SeenAt) // only a real step back relative to the stored report
			}
			if err := s.RecordStatus(l); err != nil {
				t.Fatalf("seed %d step %d: %v", seed, step, err)
			}
			cur[p] = l

			// 1. memory: exactly the latest report (including heartbeat-only fields)
			mem, err := s.Fleet("bank-a")
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range mem {
				if w := cur[m.Report.ProxyID]; !sameLast(m, w) {
					t.Fatalf("seed %d step %d (kind %d): memory for %s = %+v, want %+v", seed, step, kind, m.Report.ProxyID, m, w)
				}
			}
			// 2. crash now: copy the directory as it is on disk
			crash := t.TempDir() + "/crash"
			copyTree(t, dir, crash)
			s2, err := store.OpenFiles(crash)
			if err != nil {
				t.Fatalf("seed %d step %d: state dir after crash does not open: %v", seed, step, err)
			}
			disk, _ := s2.Fleet("bank-a")
			byID := map[wire.ID]fleet.Last{}
			for _, d := range disk {
				byID[d.Report.ProxyID] = d
			}
			d, ok := byID[p]
			if !ok {
				t.Fatalf("seed %d step %d (kind %d): proxy %s missing after crash", seed, step, kind, p)
			}
			if !importantEqual(d, l) {
				t.Fatalf("seed %d step %d (kind %d): LOST a change that must be written through.\n disk: %+v\n want: %+v", seed, step, kind, d, l)
			}
			if mustSeq && (d.Report.Seq != l.Report.Seq || d.Report.UptimeSeconds != l.Report.UptimeSeconds) {
				t.Fatalf("seed %d step %d: restart (Seq/uptime decrease) not written: disk seq=%d up=%d", seed, step, d.Report.Seq, d.Report.UptimeSeconds)
			}
			if mustSeen && !d.SeenAt.Equal(l.SeenAt) {
				t.Fatalf("seed %d step %d: clock step back not written: disk %v want %v", seed, step, d.SeenAt, l.SeenAt)
			}
			// other proxies: still important-equal to their own latest
			for id, w := range cur {
				if id == p {
					continue
				}
				if got, ok := byID[id]; ok && !importantEqual(got, w) {
					t.Fatalf("seed %d step %d: other proxy %s regressed on disk: %+v vs %+v", seed, step, id, got, w)
				}
			}
			// 3. timeline: same (proxy, version, hash) sequence, anchor of the current entry
			tlMem, _ := s.Timeline("bank-a")
			tlDisk, _ := s2.Timeline("bank-a")
			if len(tlMem) != len(tlDisk) {
				t.Fatalf("seed %d step %d (kind %d): timeline has %d entries in memory but %d after crash", seed, step, kind, len(tlMem), len(tlDisk))
			}
			for i := range tlMem {
				a, b := tlMem[i], tlDisk[i]
				if a.ProxyID != b.ProxyID || a.Version != b.Version || a.PolicyHash != b.PolicyHash || a.FirstSeenUnixMs != b.FirstSeenUnixMs {
					t.Fatalf("seed %d step %d: timeline[%d] memory %+v disk %+v", seed, step, i, a, b)
				}
				if a.LogSeq != b.LogSeq || a.LogHead != b.LogHead {
					// the entry for the proxy that just changed must have its anchor on disk
					if a.ProxyID == p {
						t.Fatalf("seed %d step %d: anchor of the current entry lost: memory seq=%d disk seq=%d", seed, step, a.LogSeq, b.LogSeq)
					}
				}
			}
			_ = root
		}
	}
}

// A heartbeat flood must not rewrite files every time (M7: 1,000 proxies x 10s). Black-box:
// observe file modification counts by content, not by timing.
func TestHeartbeatsDoNotRewriteTheFileEveryTime(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	if err := s.RecordStatus(last("main", rep("bank-a", "p1", withSeq(1, 1)), t0)); err != nil {
		t.Fatal(err)
	}
	path := findFile(t, dir, "fleet", "bank-a", "p1")
	readInode := func() (uint64, int64) {
		info, err := os_Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		return inodeOf(info), info.Size()
	}
	ino0, _ := readInode()
	rewrites := 0
	for i := 1; i <= 200; i++ {
		l := last("main", rep("bank-a", "p1", withSeq(uint64(i+1), uint64(i)*10+1), withCounters(uint64(i), 0, 0)), t0.Add(time.Duration(i)*time.Second))
		if err := s.RecordStatus(l); err != nil {
			t.Fatal(err)
		}
		if ino, _ := readInode(); ino != ino0 {
			rewrites++
			ino0 = ino
		}
	}
	// C-D3: at most one flush per 30s of reports; 200s of heartbeats is at most ~7 flushes.
	// (Allow slack: whichever clock the store uses, 200 rewrites is the fsync storm the design avoids.)
	if rewrites > 20 {
		t.Fatalf("%d file rewrites for 200 heartbeat-only reports; coalescing (C-D3, <= 1 per 30s) is not working", rewrites)
	}
	// and the in-memory view is always current
	f, _ := s.Fleet("bank-a")
	if f[0].Report.Seq != 201 || f[0].Report.Counters.CallsAllowed != 200 {
		t.Fatalf("memory lags: %+v", f[0].Report)
	}
}

func TestRecordStatusConcurrent(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	var wg sync.WaitGroup
	const proxies, rounds = 16, 25
	for p := 0; p < proxies; p++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			id := wire.ID(fmt.Sprintf("p%02d", p))
			for r := 1; r <= rounds; r++ {
				l := last("main", rep("bank-a", id, withVersion(uint64(r)), withSeq(uint64(r), uint64(r)), withAnchor(uint64(r))), t0.Add(time.Duration(r)*time.Second))
				if err := s.RecordStatus(l); err != nil {
					t.Errorf("%s r%d: %v", id, r, err)
					return
				}
				_, _ = s.Fleet("bank-a")
				_, _ = s.Timeline("bank-a")
			}
		}(p)
	}
	// plus writers on the same proxy ID
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for r := 1; r <= rounds; r++ {
				_ = s.RecordStatus(last("main", rep("bank-a", "shared", withSeq(uint64(r), uint64(r))), t0.Add(time.Duration(r)*time.Second)))
			}
		}(w)
	}
	wg.Wait()
	for _, st := range []store.Store{s, open(t, dir)} {
		f, _ := st.Fleet("bank-a")
		if len(f) != proxies+1 {
			t.Fatalf("%d proxies, want %d", len(f), proxies+1)
		}
		for _, l := range f {
			if l.Report.ProxyID != "shared" && l.Report.AppliedVersion != rounds {
				t.Fatalf("%s lost its final version: %d", l.Report.ProxyID, l.Report.AppliedVersion)
			}
		}
		tl, _ := st.Timeline("bank-a")
		perProxy := map[wire.ID]int{}
		for _, e := range tl {
			perProxy[e.ProxyID]++
		}
		for id, n := range perProxy {
			if id != "shared" && n != rounds {
				t.Fatalf("%s has %d timeline entries, want %d", id, n, rounds)
			}
		}
	}
}

// Whatever RecordStatus accepts, the next start must load (a CP that cannot restart is an outage).
func TestStatusAcceptedImpliesReloadable(t *testing.T) {
	base := func() wire.StatusReport { return rep("bank-a", "p1") }
	weird := map[string]fleet.Last{}
	add := func(name string, f func(l *fleet.Last)) {
		l := last("main", base(), t0)
		f(&l)
		weird[name] = l
	}
	add("invalid-state", func(l *fleet.Last) { l.Report.State = "pwned" })
	add("hash-without-version", func(l *fleet.Last) { l.Report.AppliedVersion = 0 })
	add("bad-hash", func(l *fleet.Last) { l.Report.PolicyHash = "zz" })
	add("bad-log-head", func(l *fleet.Last) { l.Report.LogSeq = 3; l.Report.LogHead = "nothex" })
	add("bad-error-code", func(l *fleet.Last) { l.Report.LastError = &wire.ApplyError{Code: "<script>alert(1)</script>"} })
	add("max-uints", func(l *fleet.Last) {
		l.Report.AppliedVersion, l.Report.Seq, l.Report.UptimeSeconds = math.MaxUint64, math.MaxUint64, math.MaxUint64
		l.Report.Counters = wire.Counters{CallsAllowed: math.MaxUint64, CallsDenied: math.MaxUint64, EnvelopesRejected: math.MaxUint64}
	})
	add("zero-seen", func(l *fleet.Last) { l.SeenAt = time.Time{} })
	add("far-future-seen", func(l *fleet.Last) { l.SeenAt = time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC) })
	add("year-10000-seen", func(l *fleet.Last) { l.SeenAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC) })
	add("negative-year-seen", func(l *fleet.Last) { l.SeenAt = time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC) })
	add("non-utc-seen", func(l *fleet.Last) { l.SeenAt = t0.In(time.FixedZone("x", 5*3600+1800)) })
	add("empty-group", func(l *fleet.Last) { l.Group = "" })
	add("uppercase-group", func(l *fleet.Last) { l.Group = "Main" })
	add("zero-report", func(l *fleet.Last) { l.Report = wire.StatusReport{Tenant: "bank-a", ProxyID: "p1"} })
	for name, l := range weird {
		t.Run(name, func(t *testing.T) {
			_, dir := sandbox(t)
			s := open(t, dir)
			if err := s.RecordStatus(l); err != nil {
				return
			}
			if _, err := store.OpenFiles(dir); err != nil {
				t.Fatalf("store accepted this report but then refuses to start: %v", err)
			}
		})
	}
}

func TestRecordStatusRejectsHostileIdentity(t *testing.T) {
	_, dir := sandbox(t)
	s := open(t, dir)
	for _, bad := range []wire.ID{"", "../x", "A", "a/b", "a.json", "p1\x00", "-p", "a b"} {
		if err := s.RecordStatus(last("main", rep("bank-a", bad), t0)); err == nil {
			t.Errorf("proxy id %q accepted", bad)
		}
		if err := s.RecordStatus(last("main", rep(bad, "p1"), t0)); err == nil {
			t.Errorf("tenant %q accepted", bad)
		}
	}
	if fs := files(t, dir); len(fs) != 0 {
		t.Fatalf("files written for rejected reports: %v", fs)
	}
}
