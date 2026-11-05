package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// Golden JSON freezes field names and shapes. If one of these fails, you are
// changing the contract: that needs a decision entry and the Overseer.
func TestGoldenJSON(t *testing.T) {
	cases := []struct {
		name string
		v    any
		want string
	}{
		{"Envelope", Envelope{
			PayloadType: PayloadTypePolicy,
			Payload:     []byte(`{"v":1}`),
			Signatures:  []Signature{{KeyID: hashA, Sig: []byte{1, 2}}},
		}, `{"payloadType":"application/vnd.kairan.policy+json","payload":"eyJ2IjoxfQ==","signatures":[{"keyid":"` + hashA + `","sig":"AQI="}]}`},
		{"PollResponse", PollResponse{Version: 8, Envelope: Envelope{PayloadType: PayloadTypePolicy, Payload: []byte("x"), Signatures: []Signature{}}},
			`{"version":8,"envelope":{"payloadType":"application/vnd.kairan.policy+json","payload":"eA==","signatures":[]}}`},
		{"StatusReport", StatusReport{
			Tenant: "bank-a", ProxyID: "bank-a-p1", Seq: 3, State: StateEnforcing,
			AppliedVersion: 8, PolicyHash: hashB, LogSeq: 12, LogHead: hashA,
			LastError:     &ApplyError{Code: ErrNotNewer, Version: 7},
			UptimeSeconds: 120,
			Counters:      Counters{CallsAllowed: 10, CallsDenied: 2, EnvelopesRejected: 1},
		}, `{"tenant":"bank-a","proxy_id":"bank-a-p1","seq":3,"state":"enforcing","applied_version":8,"policy_hash":"` + hashB + `","log_seq":12,"log_head":"` + hashA + `","last_error":{"code":"version_not_newer","version":7},"uptime_seconds":120,"counters":{"calls_allowed":10,"calls_denied":2,"envelopes_rejected":1}}`},
		{"StatusReport/empty", StatusReport{Tenant: "t", ProxyID: "p", State: StateDenyAll},
			`{"tenant":"t","proxy_id":"p","seq":0,"state":"deny_all","applied_version":0,"log_seq":0,"uptime_seconds":0,"counters":{"calls_allowed":0,"calls_denied":0,"envelopes_rejected":0}}`},
		{"PublishResponse", PublishResponse{Tenant: "bank-a", Version: 8, PolicyHash: hashA},
			`{"tenant":"bank-a","version":8,"policy_hash":"` + hashA + `"}`},
		{"RolloutRequest", RolloutRequest{Tenant: "bank-a", Version: 8, CanaryDwellSeconds: 60},
			`{"tenant":"bank-a","version":8,"canary_dwell_seconds":60}`},
		{"RolloutView", RolloutView{Tenant: "bank-a", Version: 8, Phase: PhaseHalted, Reason: ErrThreshold},
			`{"tenant":"bank-a","version":8,"phase":"halted","reason":"threshold_not_met"}`},
		{"FleetView", FleetView{Tenant: "bank-a", Proxies: []ProxyView{{
			ProxyID: "bank-a-p1", Group: "canary", Health: HealthStale, State: StateEnforcing,
			DesiredVersion: 8, AppliedVersion: 7, PolicyHash: hashA, Drift: 1, LastSeenUnixMs: 1000,
		}}}, `{"tenant":"bank-a","proxies":[{"proxy_id":"bank-a-p1","group":"canary","health":"stale","state":"enforcing","desired_version":8,"applied_version":7,"policy_hash":"` + hashA + `","drift":1,"last_seen_unix_ms":1000}]}`},
		{"TimelineView", TimelineView{Tenant: "bank-a", Entries: []TimelineEntry{{
			ProxyID: "bank-a-p1", Version: 7, PolicyHash: hashA, FirstSeenUnixMs: 1, LastSeenUnixMs: 2,
			LogSeq: 3, LogHead: hashA,
		}}}, `{"tenant":"bank-a","entries":[{"proxy_id":"bank-a-p1","version":7,"policy_hash":"` + hashA + `","first_seen_unix_ms":1,"last_seen_unix_ms":2,"log_seq":3,"log_head":"` + hashA + `"}]}`},
		{"TimelineView/dropped", TimelineView{Tenant: "bank-a", Entries: []TimelineEntry{}, Dropped: map[ID]uint64{"bank-a-p1": 4}},
			`{"tenant":"bank-a","entries":[],"dropped":{"bank-a-p1":4}}`},
		{"ErrorResponse", ErrorResponse{Code: ErrUnauthorized}, `{"code":"unauthorized"}`},
		{"ApplyError/clock_untrusted", ApplyError{Code: ErrClockUntrusted}, `{"code":"clock_untrusted"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := json.Marshal(c.v)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("contract changed\n got: %s\nwant: %s", got, c.want)
			}
		})
	}
}

func TestDecodeStrict(t *testing.T) {
	var s StatusReport
	cases := []struct {
		name  string
		body  string
		limit int64
		want  error
	}{
		{"ok", `{"tenant":"t","proxy_id":"p","state":"enforcing"}`, 1024, nil},
		{"unknown field", `{"tenant":"t","note":"tool args here"}`, 1024, ErrBodyInvalid},
		{"trailing data", `{"tenant":"t"} {"tenant":"u"}`, 1024, ErrBodyInvalid},
		{"not json", `tenant=t`, 1024, ErrBodyInvalid},
		{"empty", ``, 1024, ErrBodyInvalid},
		{"too large", `{"tenant":"` + strings.Repeat("a", 2000) + `"}`, 1024, ErrBodyTooLarge},
		{"exactly at limit", `{"tenant":"t"}`, int64(len(`{"tenant":"t"}`)), nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Decode(strings.NewReader(c.body), c.limit, &s)
			if !errors.Is(err, c.want) && !(err == nil && c.want == nil) {
				t.Fatalf("Decode err = %v, want %v", err, c.want)
			}
		})
	}
}

// Every error code, with its frozen spelling. A new code must be added here
// and to ErrorCode.Valid.
func TestErrorCodes(t *testing.T) {
	want := map[ErrorCode]string{
		ErrBadRequest:       "bad_request",
		ErrUnauthorized:     "unauthorized",
		ErrForbidden:        "forbidden",
		ErrNotFound:         "not_found",
		ErrMethodNotAllowed: "method_not_allowed", // M-D31
		ErrConflict:         "conflict",
		ErrTooLarge:         "too_large",
		ErrInternal:         "internal",
		ErrUnavailable:      "unavailable", // M-D31
		ErrMalformed:        "malformed",
		ErrPayloadType:      "payload_type",
		ErrThreshold:        "threshold_not_met",
		ErrWrongTenant:      "wrong_tenant",
		ErrNotNewer:         "version_not_newer",
		ErrExpired:          "expired",
		ErrPersist:          "persist_failed",
		ErrTampered:         "tampered",
		ErrCanaryLost:       "canary_lost",
		ErrClockUntrusted:   "clock_untrusted", // M-D30
	}
	if len(want) != 19 {
		t.Fatalf("duplicate code in table: %d entries", len(want))
	}
	for c, s := range want {
		if string(c) != s {
			t.Errorf("code %q, want %q", c, s)
		}
		if !c.Valid() {
			t.Errorf("code %q not Valid", c)
		}
	}
	for _, c := range []ErrorCode{"", "Unavailable", "service_unavailable", "clock-untrusted"} {
		if c.Valid() {
			t.Errorf("code %q should be invalid", c)
		}
	}
}

func TestIDValid(t *testing.T) {
	good := []ID{"a", "bank-a", "p1", "0x", ID(strings.Repeat("a", 63))}
	bad := []ID{"", "-a", "A", "bank_a", "bank a", "a/b", "日本", ID(strings.Repeat("a", 64))}
	for _, id := range good {
		if !id.Valid() {
			t.Errorf("ID %q should be valid", id)
		}
	}
	for _, id := range bad {
		if id.Valid() {
			t.Errorf("ID %q should be invalid", id)
		}
	}
}

func TestHashValid(t *testing.T) {
	if !Hash(hashA).Valid() || !Hash("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef").Valid() {
		t.Fatal("valid hashes rejected")
	}
	for _, h := range []Hash{"", "abc", Hash(strings.ToUpper(hashA)), Hash(hashA + "a"), Hash(strings.Replace(hashA, "a", "g", 1))} {
		if h.Valid() {
			t.Errorf("Hash %q should be invalid", h)
		}
	}
}

func validStatus() StatusReport {
	return StatusReport{Tenant: "bank-a", ProxyID: "bank-a-p1", Seq: 1, State: StateEnforcing, AppliedVersion: 3, PolicyHash: hashA, LogSeq: 4, LogHead: hashB}
}

func TestStatusValidate(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*StatusReport)
		ok   bool
	}{
		{"valid", func(*StatusReport) {}, true},
		{"no policy yet", func(s *StatusReport) { s.State, s.AppliedVersion, s.PolicyHash = StateDenyAll, 0, "" }, true},
		{"bad tenant", func(s *StatusReport) { s.Tenant = "Bank A" }, false},
		{"bad proxy id", func(s *StatusReport) { s.ProxyID = "" }, false},
		{"unknown state", func(s *StatusReport) { s.State = "happy" }, false},
		{"version without hash", func(s *StatusReport) { s.PolicyHash = "" }, false},
		{"hash without version", func(s *StatusReport) { s.AppliedVersion = 0 }, false},
		{"bad hash", func(s *StatusReport) { s.PolicyHash = "xyz" }, false},
		{"enforcing without policy", func(s *StatusReport) { s.AppliedVersion, s.PolicyHash = 0, "" }, false},
		{"unknown error code", func(s *StatusReport) { s.LastError = &ApplyError{Code: "oops"} }, false},
		{"known error code", func(s *StatusReport) { s.LastError = &ApplyError{Code: ErrExpired, Version: 4} }, true},
		{"clock untrusted", func(s *StatusReport) { s.LastError = &ApplyError{Code: ErrClockUntrusted} }, true},
		{"empty apply log", func(s *StatusReport) { s.LogSeq, s.LogHead = 0, "" }, true},
		{"log seq without head", func(s *StatusReport) { s.LogHead = "" }, false},
		{"log head without seq", func(s *StatusReport) { s.LogSeq = 0 }, false},
		{"bad log head", func(s *StatusReport) { s.LogHead = Hash(strings.ToUpper(hashB)) }, false},
		{"log ahead of nothing applied", func(s *StatusReport) {
			// rejections are logged too, so a log can exist with no policy
			s.State, s.AppliedVersion, s.PolicyHash = StateDenyAll, 0, ""
		}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := validStatus()
			c.mut(&s)
			if err := s.Validate(); (err == nil) != c.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestEnvelopeValidateShape(t *testing.T) {
	sig := Signature{KeyID: hashA, Sig: make([]byte, SignatureSize)}
	valid := func() Envelope {
		return Envelope{PayloadType: PayloadTypePolicy, Payload: []byte("{}"), Signatures: []Signature{sig}}
	}
	cases := []struct {
		name string
		mut  func(*Envelope)
		ok   bool
	}{
		{"valid", func(*Envelope) {}, true},
		{"wrong payload type", func(e *Envelope) { e.PayloadType = "text/plain" }, false},
		{"empty payload", func(e *Envelope) { e.Payload = nil }, false},
		{"no signatures", func(e *Envelope) { e.Signatures = nil }, false},
		{"too many signatures", func(e *Envelope) {
			e.Signatures = make([]Signature, MaxSignatures+1)
			for i := range e.Signatures {
				e.Signatures[i] = sig
			}
		}, false},
		{"bad key id", func(e *Envelope) { e.Signatures[0].KeyID = "k1" }, false},
		{"short signature", func(e *Envelope) { e.Signatures[0].Sig = []byte{1} }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := valid()
			c.mut(&e)
			if err := e.ValidateShape(); (err == nil) != c.ok {
				t.Fatalf("ValidateShape() = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestPollRequestQueryRoundTrip(t *testing.T) {
	p := PollRequest{Tenant: "bank-a", ProxyID: "bank-a-p1", Have: 7}
	got, err := ParsePollRequest(p.Query())
	if err != nil || got != p {
		t.Fatalf("round trip = %+v, %v; want %+v", got, err, p)
	}
	for name, q := range map[string]url.Values{
		"missing tenant": {QueryProxy: {"p"}, QueryHave: {"0"}},
		"bad proxy":      {QueryTenant: {"t"}, QueryProxy: {"P!"}, QueryHave: {"0"}},
		"have not int":   {QueryTenant: {"t"}, QueryProxy: {"p"}, QueryHave: {"seven"}},
		"have negative":  {QueryTenant: {"t"}, QueryProxy: {"p"}, QueryHave: {"-1"}},
		"repeated param": {QueryTenant: {"t", "u"}, QueryProxy: {"p"}, QueryHave: {"0"}},
		"extra param":    {QueryTenant: {"t"}, QueryProxy: {"p"}, QueryHave: {"0"}, "debug": {"1"}},
	} {
		if _, err := ParsePollRequest(q); err == nil {
			t.Errorf("%s: accepted %v", name, q)
		}
	}
}

func TestRolloutRequestValidate(t *testing.T) {
	if err := (RolloutRequest{Tenant: "bank-a", Version: 1}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []RolloutRequest{{Tenant: "bank-a"}, {Version: 1}} {
		if r.Validate() == nil {
			t.Errorf("accepted %+v", r)
		}
	}
}

// I4: a status report must not be able to carry call data. Every leaf field
// must be a number, a bool, or a named, validated string type. A plain string,
// []byte, slice, map or interface would be a place payload could leak into.
func TestStatusReportCannotCarryPayload(t *testing.T) {
	allowed := map[reflect.Type]bool{
		reflect.TypeOf(ID("")):         true,
		reflect.TypeOf(Hash("")):       true,
		reflect.TypeOf(ProxyState("")): true,
		reflect.TypeOf(ErrorCode("")):  true,
		reflect.TypeOf(uint64(0)):      true,
		reflect.TypeOf(int64(0)):       true,
		reflect.TypeOf(false):          true,
		reflect.TypeOf(Counters{}):     true,
		reflect.TypeOf(ApplyError{}):   true,
		reflect.TypeOf(&ApplyError{}):  true,
		reflect.TypeOf(StatusReport{}): true,
	}
	var walk func(t reflect.Type, path string)
	walk = func(rt reflect.Type, path string) {
		if !allowed[rt] {
			t.Errorf("%s has type %v, which could carry free text or payload (I4)", path, rt)
			return
		}
		switch rt.Kind() {
		case reflect.Pointer:
			walk(rt.Elem(), path)
		case reflect.Struct:
			for i := 0; i < rt.NumField(); i++ {
				f := rt.Field(i)
				walk(f.Type, path+"."+f.Name)
			}
		}
	}
	walk(reflect.TypeOf(StatusReport{}), "StatusReport")

	// M-D25: the walk above must actually see every field added at G0, with
	// the metadata-only type the decision fixed.
	rt := reflect.TypeOf(StatusReport{})
	for name, want := range map[string]reflect.Type{
		"LogSeq":  reflect.TypeOf(uint64(0)),
		"LogHead": reflect.TypeOf(Hash("")),
	} {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("StatusReport.%s missing (M-D35)", name)
			continue
		}
		if f.Type != want {
			t.Errorf("StatusReport.%s is %v, want %v", name, f.Type, want)
		}
	}
}

func FuzzDecodeStatus(f *testing.F) {
	seed, _ := json.Marshal(validStatus())
	f.Add(seed)
	f.Add([]byte(`{"tenant":"t","proxy_id":"p","state":"deny_all"}`))
	f.Add([]byte(`{"last_error":{"code":"expired"}}`))
	f.Add([]byte(`{"tenant":"t","proxy_id":"p","state":"deny_all","log_seq":2,"log_head":"` + hashA + `","last_error":{"code":"clock_untrusted"}}`))
	f.Add([]byte(`{"tenant":"t","proxy_id":"p","state":"deny_all","log_seq":1,"log_head":"","Log_Head":"x"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var s StatusReport
		if err := Decode(bytes.NewReader(body), MaxStatusBytes, &s); err != nil {
			return
		}
		if s.Validate() != nil {
			return
		}
		// Anything that validates must survive a re-encode unchanged.
		again, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		var s2 StatusReport
		if err := Decode(bytes.NewReader(again), MaxStatusBytes, &s2); err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !reflect.DeepEqual(s, s2) {
			t.Fatalf("round trip changed value:\n%+v\n%+v", s, s2)
		}
	})
}
