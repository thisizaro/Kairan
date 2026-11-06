package agent

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

func envJSON(t *testing.T, e wire.Envelope) []byte {
	t.Helper()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A good offline bundle goes through trust.Accept, Save, Append, then the
// swap, exactly as an envelope from the control plane (PRD J3).
func TestImportApplies(t *testing.T) {
	r := newRig(t)
	a := r.begin(newFakeCP(t))
	got, err := a.Import(envJSON(t, r.keys.goodEnv(3, time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 3 || got.Previous != 0 || !got.Hash.Valid() {
		t.Fatalf("result = %+v", got)
	}
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 3 || act.Hash != got.Hash {
		t.Fatalf("active = %+v", act)
	}
	stored, found, err := r.st.Load()
	if err != nil || !found || !strings.Contains(string(stored.Payload), `"version":3`) {
		t.Fatalf("stored = %s %v %v", stored.Payload, found, err)
	}
	es := r.logEntries()
	if len(es) != 1 || es[0].To != 3 || es[0].From != 0 || es[0].Result != "" || es[0].Hash != got.Hash {
		t.Fatalf("log = %+v", es)
	}
	// It survives a restart: a boot from disk finds the same policy.
	a = r.reopen()
	if err := a.Boot(); err != nil {
		t.Fatal(err)
	}
	if act := r.active(); act.State != wire.StateEnforcing || act.Policy.Version != 3 {
		t.Fatalf("after restart: %+v", act)
	}
	// A second import must beat the first.
	if _, err := a.Import(envJSON(t, r.keys.goodEnv(3, time.Hour))); err == nil {
		t.Fatal("same version imported twice")
	}
	if got, err := a.Import(envJSON(t, r.keys.goodEnv(4, time.Hour))); err != nil || got.Version != 4 || got.Previous != 3 {
		t.Fatalf("v4: %+v %v", got, err)
	}
}

// The S5 cases (ARCHITECTURE section 11): none is applied, the policy in force
// and the stored file do not change, and each reason is in the apply log.
func TestImportRejections(t *testing.T) {
	r0 := newRig(t)
	k := r0.keys
	good := func() wire.Envelope { return k.goodEnv(9, time.Hour) }
	flipped := func() wire.Envelope {
		e := good()
		e.Payload = append([]byte(nil), e.Payload...)
		e.Payload[len(e.Payload)/2] ^= 0x01
		return e
	}
	tests := []struct {
		name string
		data func() []byte
		code wire.ErrorCode
	}{
		{"unsigned", func() []byte {
			e := signed(payload(9, tenant, start.Add(time.Hour)))
			e.Signatures = []wire.Signature{}
			return envJSON(t, e)
		}, wire.ErrMalformed}, // an envelope with no signatures is malformed (trust_test)
		{"signatures null", func() []byte { return envJSON(t, signed(payload(9, tenant, start.Add(time.Hour)))) }, wire.ErrMalformed},
		{"one signature", func() []byte { return envJSON(t, signed(payload(9, tenant, start.Add(time.Hour)), k.a)) }, wire.ErrThreshold},
		{"same key twice", func() []byte { return envJSON(t, signed(payload(9, tenant, start.Add(time.Hour)), k.a, k.a)) }, wire.ErrThreshold},
		{"outsider keys", func() []byte {
			return envJSON(t, signed(payload(9, tenant, start.Add(time.Hour)), seedKey("x"), seedKey("y")))
		}, wire.ErrThreshold},
		{"old version", func() []byte { return envJSON(t, k.goodEnv(1, time.Hour)) }, wire.ErrNotNewer},
		{"same version", func() []byte { return envJSON(t, k.goodEnv(2, time.Hour)) }, wire.ErrNotNewer},
		{"wrong tenant", func() []byte { return envJSON(t, signed(payload(9, "other", start.Add(time.Hour)), k.a, k.b)) }, wire.ErrWrongTenant},
		{"expired", func() []byte { return envJSON(t, signed(payload(9, tenant, start.Add(-30*time.Minute)), k.a, k.b)) }, wire.ErrExpired},
		{"corrupted payload", func() []byte { return envJSON(t, flipped()) }, wire.ErrThreshold},
		{"corrupted file", func() []byte { b := envJSON(t, good()); return b[:len(b)/2] }, wire.ErrMalformed},
		{"garbage", func() []byte { return []byte("\x00\x01 not json") }, wire.ErrMalformed},
		{"empty", func() []byte { return nil }, wire.ErrMalformed},
		{"trailing data", func() []byte { return append(envJSON(t, good()), []byte(` {}`)...) }, wire.ErrMalformed},
		{"duplicate key", func() []byte {
			b := envJSON(t, good())
			return []byte(strings.Replace(string(b), `{"payloadType"`, `{"payloadType":"x","payloadType"`, 1))
		}, wire.ErrMalformed},
		{"case-variant key", func() []byte {
			return []byte(strings.Replace(string(envJSON(t, good())), `"payload":`, `"Payload":`, 1))
		}, wire.ErrMalformed},
		{"payload type", func() []byte {
			e := good()
			e.PayloadType = "text/plain"
			return envJSON(t, e)
		}, wire.ErrPayloadType},
		{"oversize", func() []byte { return []byte(strings.Repeat("a", wire.MaxEnvelopeBytes+1)) }, wire.ErrMalformed},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.seedDisk(r.keys.goodEnv(2, time.Hour), true)
			r = reopenRig(r)
			a := r.begin(newFakeCP(t))
			before := r.active()
			_, err := a.Import(tc.data())
			var ie *ImportError
			if !errors.As(err, &ie) || ie.Code != tc.code {
				t.Fatalf("err = %v, want code %s", err, tc.code)
			}
			if r.active() != before || r.active().Policy.Version != 2 || r.active().State != wire.StateEnforcing {
				t.Fatalf("policy in force changed: %+v", r.active())
			}
			stored, _, _ := r.st.Load()
			if !strings.Contains(string(stored.Payload), `"version":2`) {
				t.Fatalf("stored policy changed: %s", stored.Payload)
			}
			es := r.logEntries()
			last := es[len(es)-1]
			if len(es) != 2 || last.Result != tc.code || last.From != 2 {
				t.Fatalf("log = %+v", es)
			}
			if rep := a.report(); rep.AppliedVersion != 2 || rep.Counters.EnvelopesRejected != 1 {
				t.Fatalf("report = %+v", rep)
			}
		})
	}
}

// Nothing is applied by a proxy that cannot record it: no apply log means
// Tampered and no import.
func TestImportRefusedWhenTampered(t *testing.T) {
	r := newRig(t)
	r.al.Close()
	r.cfg.LogOpenErr = errors.New("apply log broken")
	r.al = nil
	a := r.begin(newFakeCP(t))
	_, err := a.Import(envJSON(t, r.keys.goodEnv(3, time.Hour)))
	var ie *ImportError
	if !errors.As(err, &ie) || ie.Code != wire.ErrPersist {
		t.Fatalf("err = %v", err)
	}
	if act := r.active(); act.Policy != nil || act.State != wire.StateTampered {
		t.Fatalf("active = %+v", act)
	}
	if _, found, _ := r.st.Load(); found {
		t.Fatal("something was saved")
	}
}

func TestImportBeforeBoot(t *testing.T) {
	r := newRig(t)
	a := r.build()
	if _, err := a.Import(envJSON(t, r.keys.goodEnv(3, time.Hour))); err == nil {
		t.Fatal("import before Boot")
	}
	if r.active() != nil && r.active().Policy != nil {
		t.Fatal("applied")
	}
}
