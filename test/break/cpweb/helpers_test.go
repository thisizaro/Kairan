// Package cpwebbreak holds black-box attack tests for the fleet page (task C-06).
// Sources: PRD J7 and G2, ARCHITECTURE cp/web LLD ("Metadata only; all output
// escaped; JST and UTC times"), decisions M-D43 (auth lives in cp/api, the page
// assumes an authorized request) and C-D5 (design and mount assumptions), and
// the go doc of the web package.
package cpwebbreak

import (
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"kairan/internal/clock"
	"kairan/internal/cp/fleet"
	"kairan/internal/cp/rollout"
	"kairan/internal/cp/store"
	"kairan/internal/cp/web"
	"kairan/internal/wire"
)

var now0 = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

const canary = "CANARY-9f3b27-SECRET"

// fakeStore lets a test hand the page any data, including values wire would never validate.
type fakeStore struct {
	mu       sync.Mutex
	fleet    map[wire.ID][]fleet.Last
	roll     map[wire.ID]rollout.Rollout
	fleetErr error
	rollErr  error
	tenants  []wire.ID // every tenant the page asked about
}

func newFake() *fakeStore {
	return &fakeStore{fleet: map[wire.ID][]fleet.Last{}, roll: map[wire.ID]rollout.Rollout{}}
}

func (f *fakeStore) seen(t wire.ID) {
	f.mu.Lock()
	f.tenants = append(f.tenants, t)
	f.mu.Unlock()
}
func (f *fakeStore) PutEnvelope(wire.Envelope, store.EnvelopeMeta) error { return nil }
func (f *fakeStore) Envelope(t wire.ID, v uint64) (wire.Envelope, error) {
	f.seen(t)
	return wire.Envelope{PayloadType: wire.PayloadTypePolicy, Payload: []byte(canary)}, nil
}
func (f *fakeStore) PutRollout(rollout.Rollout) error { return nil }
func (f *fakeStore) Rollout(t wire.ID) (rollout.Rollout, bool, error) {
	f.seen(t)
	if f.rollErr != nil {
		return rollout.Rollout{}, false, f.rollErr
	}
	r, ok := f.roll[t]
	return r, ok, nil
}
func (f *fakeStore) RecordStatus(fleet.Last) error { return nil }
func (f *fakeStore) Fleet(t wire.ID) ([]fleet.Last, error) {
	f.seen(t)
	if f.fleetErr != nil {
		return nil, f.fleetErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fleet.Last(nil), f.fleet[t]...), nil
}
func (f *fakeStore) Timeline(t wire.ID) ([]wire.TimelineEntry, error) {
	f.seen(t)
	return []wire.TimelineEntry{{ProxyID: "p1", Version: 1, PolicyHash: wire.Hash(strings.Repeat("a", 64)), FirstSeenUnixMs: 1, LastSeenUnixMs: 2}}, nil
}

var _ store.Store = (*fakeStore)(nil)

func hash(c byte) wire.Hash { return wire.Hash(strings.Repeat(string(c), 64)) }

func lastOf(tenant, proxy, group wire.ID, state wire.ProxyState, applied uint64, seen time.Time) fleet.Last {
	r := wire.StatusReport{Tenant: tenant, ProxyID: proxy, Seq: 3, State: state, AppliedVersion: applied, UptimeSeconds: 99}
	if applied > 0 {
		r.PolicyHash = hash('a')
		r.LogSeq, r.LogHead = 2, hash('b')
	}
	return fleet.Last{Group: group, Report: r, SeenAt: seen}
}

type resp struct {
	code int
	hdr  http.Header
	body string
}

func newHandler(st store.Store) (http.Handler, *clock.Fake) {
	clk := clock.NewFake(now0)
	return web.Handler(st, clk, fleet.Thresholds{Stale: 30 * time.Second, Lost: 2 * time.Minute}), clk
}

func do(t testing.TB, h http.Handler, method, target string, hdr map[string]string, body string) resp {
	t.Helper()
	req := httptest.NewRequest(method, "http://cp.example"+target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	b, _ := io.ReadAll(rec.Body)
	return resp{rec.Code, rec.Header(), string(b)}
}

func get(t testing.TB, h http.Handler, target string, hdr ...string) resp {
	m := map[string]string{}
	for i := 0; i+1 < len(hdr); i += 2 {
		m[hdr[i]] = hdr[i+1]
	}
	return do(t, h, "GET", target, m, "")
}

// ---- tiny HTML helpers (stdlib only) ----

var (
	reTag      = regexp.MustCompile(`<\s*(/?)\s*([a-zA-Z][a-zA-Z0-9]*)`)
	reTagFull  = regexp.MustCompile(`<[^>]*>`)
	reAttrName = regexp.MustCompile(`\s([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=`)
	reAttrAny  = regexp.MustCompile(`\s([a-zA-Z_:][-a-zA-Z0-9_:.]*)(\s*=|\s|/|>)`)
	reRow      = regexp.MustCompile(`(?s)<tr[^>]*>.*?</tr>`)
	reURLAttr  = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction|data|poster|srcset|content)\s*=\s*"([^"]*)"`)
	reHTMLLang = regexp.MustCompile(`(?i)<html[^>]*\blang\s*=\s*"([^"]*)"`)
)

func tagSet(body string) map[string]bool {
	m := map[string]bool{}
	for _, x := range reTag.FindAllStringSubmatch(body, -1) {
		m[strings.ToLower(x[2])] = true
	}
	return m
}

func attrSet(body string) map[string]bool {
	m := map[string]bool{}
	for _, tag := range reTagFull.FindAllString(body, -1) {
		for _, a := range reAttrName.FindAllStringSubmatch(tag, -1) {
			m[strings.ToLower(a[1])] = true
		}
	}
	return m
}

// attrTokens also catches valueless attributes (autofocus, hidden) injected after a broken quote.
func attrTokens(body string) map[string]bool {
	m := map[string]bool{}
	for _, tag := range reTagFull.FindAllString(body, -1) {
		inner := tag
		// strip quoted values so words inside them do not count
		inner = regexp.MustCompile(`"[^"]*"`).ReplaceAllString(inner, `""`)
		for _, a := range reAttrAny.FindAllStringSubmatch(inner, -1) {
			m[strings.ToLower(a[1])] = true
		}
	}
	return m
}

func subset(a, b map[string]bool) []string {
	var extra []string
	for k := range a {
		if !b[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(extra)
	return extra
}

func visibleText(body string) string {
	s := regexp.MustCompile(`(?s)<(script|style)[^>]*>.*?</(script|style)>`).ReplaceAllString(body, " ")
	s = reTagFull.ReplaceAllString(s, " ")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

func rowFor(body, id string) string {
	for _, r := range reRow.FindAllString(body, -1) {
		if strings.Contains(r, ">"+id+"<") || strings.Contains(visibleText(r), id) {
			return r
		}
	}
	return ""
}

func isCJK(r rune) bool {
	return r >= 0x3040 && r <= 0x30ff || r >= 0x4e00 && r <= 0x9fff || r >= 0xff00 && r <= 0xffef || r >= 0x3000 && r <= 0x303f
}

func countCJK(s string) int {
	n := 0
	for _, r := range s {
		if isCJK(r) {
			n++
		}
	}
	return n
}

var errBoom = errors.New("boom: open /var/lib/kairan/fleet/bank-a/p1.json: permission denied " + canary)
