package cpapibreak

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kairan/internal/wire"
)

// fuzzCheck asserts what every response must satisfy whatever the input: no 5xx, and an error body that
// is exactly a wire.ErrorResponse (never an echo, I4).
func fuzzCheck(t *testing.T, rec *httptest.ResponseRecorder, in []byte) {
	t.Helper()
	if rec.Code >= 500 {
		t.Fatalf("server error %d for input %q: %s", rec.Code, in, rec.Body.String())
	}
	if rec.Code >= 400 {
		var er wire.ErrorResponse
		dec := json.NewDecoder(bytes.NewReader(rec.Body.Bytes()))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&er); err != nil || !er.Code.Valid() {
			t.Fatalf("%d body is not a wire.ErrorResponse: %q", rec.Code, rec.Body.String())
		}
		if rec.Body.Len() > 256 {
			t.Fatalf("error body of %d bytes", rec.Body.Len())
		}
	}
}

func fuzzDo(h http.Handler, method, target, token string, body []byte) *httptest.ResponseRecorder {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest(method, target, bytes.NewReader(body)).WithContext(ctx)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func FuzzPublishBody(f *testing.F) {
	e := newEnv(f)
	f.Add(envBody(policyJSON("bank-a", 1), keyA, keyB))
	f.Add([]byte(`{"payloadType":"x","payload":"","signatures":[]}`))
	f.Add([]byte(`{`))
	f.Add([]byte(``))
	f.Add([]byte(`{"Payload":"e30=","payload":"e30="}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzCheck(t, fuzzDo(e.h, "POST", wire.PathPolicies, adminTok, body), body)
	})
}

func FuzzStatusBody(f *testing.F) {
	e := newEnv(f)
	f.Add(mustJSON(report("bank-a", "p1", 3, 1)))
	f.Add(mustJSON(report("bank-a", "p1", 0, 1)))
	f.Add([]byte(`{"tenant":"bank-a","proxy_id":"p1","seq":1,"state":"enforcing"}`))
	f.Add([]byte(`{"tenant":"bank-a","proxy_id":"p1","prompt":"x"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		rec := fuzzDo(e.h, "POST", wire.PathStatus, tokOf("p1"), body)
		fuzzCheck(t, rec, body)
		if rec.Code == 204 && rec.Body.Len() != 0 {
			t.Fatalf("204 with a body")
		}
	})
}

func FuzzRolloutBody(f *testing.F) {
	e := newEnv(f)
	f.Add(mustJSON(wire.RolloutRequest{Tenant: "bank-a", Version: 1}))
	f.Add([]byte(`{"tenant":"bank-a","version":1,"canary_dwell_seconds":18446744073709551615}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		fuzzCheck(t, fuzzDo(e.h, "POST", wire.PathRollouts, adminTok, body), body)
	})
}

func FuzzPollQuery(f *testing.F) {
	e := newEnv(f)
	f.Add("tenant=bank-a&proxy=p1&have=0")
	f.Add("tenant=bank-a&proxy=p1&have=-1")
	f.Add("tenant=bank-a&tenant=bank-b&proxy=p1&have=0")
	f.Add("%00=%ff")
	f.Fuzz(func(t *testing.T, qs string) {
		if strings.ContainsAny(qs, " \r\n\x00#") {
			return // not a valid request target; httptest.NewRequest would panic
		}
		rec := fuzzDo(e.h, "GET", wire.PathPoll+"?"+qs, tokOf("p1"), nil)
		fuzzCheck(t, rec, []byte(qs))
	})
}

func FuzzAuthHeader(f *testing.F) {
	e := newEnv(f)
	f.Add("Bearer " + adminTok)
	f.Add("Basic YTphZG1pbg==")
	f.Add("Bearer ")
	f.Add("")
	f.Fuzz(func(t *testing.T, h string) {
		if strings.ContainsAny(h, "\r\n\x00") {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		req := httptest.NewRequest("GET", wire.PathFleet+"?tenant=bank-a", nil).WithContext(ctx)
		req.Header.Set("Authorization", h)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		fuzzCheck(t, rec, []byte(h))
		if rec.Code == 200 && h != "Bearer "+adminTok {
			t.Fatalf("authenticated with Authorization %q", h)
		}
	})
}
