package agent

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"kairan/internal/wire"
)

// The poll response is read as strictly as an envelope (Q-D27): a duplicate or
// case-variant top-level key is a rejected answer, never applied.
func TestPollResponseStrictKeys(t *testing.T) {
	r0 := newRig(t)
	env := r0.keys.goodEnv(1, 48*time.Hour)
	eb, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	e := string(eb)
	cases := map[string]string{
		"version twice":         `{"version":1,"version":1,"envelope":` + e + `}`,
		"version twice, differ": `{"version":1,"envelope":` + e + `,"version":9}`,
		"envelope twice":        `{"version":1,"envelope":` + e + `,"envelope":` + e + `}`,
		"Envelope":              `{"version":1,"Envelope":` + e + `}`,
		"ENVELOPE":              `{"version":1,"ENVELOPE":` + e + `}`,
		"Version":               `{"Version":1,"envelope":` + e + `}`,
		"both case-variant":     `{"VERSION":1,"Envelope":` + e + `}`,
		"case-variant twin":     `{"version":1,"envelope":` + e + `,"Envelope":` + e + `}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			cp := newFakeCP(t)
			cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) { w.Write([]byte(body)) }
			a := r.begin(cp)
			if d := a.pollOnce(t.Context()); d < wire.RetryBackoffMin {
				t.Fatalf("delay = %v, want a backoff", d)
			}
			if act := r.active(); act.State != wire.StateDenyAll || act.Policy != nil {
				t.Fatalf("applied: %+v", act)
			}
			rep := a.report()
			if rep.LastError == nil || rep.LastError.Code != wire.ErrMalformed || rep.Counters.EnvelopesRejected != 1 {
				t.Fatalf("report = %+v", rep)
			}
		})
	}
	t.Run("control: the same envelope in a clean body applies", func(t *testing.T) {
		r := newRig(t)
		cp := newFakeCP(t)
		cp.pollFn = func(_ int, _ url.Values, w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(`{"version":1,"envelope":` + e + `}`))
		}
		a := r.begin(cp)
		a.pollOnce(t.Context())
		if act := r.active(); act.State != wire.StateEnforcing {
			t.Fatalf("not applied: %+v", act)
		}
	})
}
