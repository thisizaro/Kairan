package agent

import (
	"bytes"
	"encoding/json"
	"io"

	"kairan/internal/trust"
	"kairan/internal/wire"
)

// decodePoll reads a 200 poll body into the advisory version and the
// envelope. It applies the same rule as trust.DecodeEnvelope (M-D32, Q-D20):
// the top-level keys must be spelled exactly "version" and "envelope", and
// each may appear once. encoding/json alone would take "Envelope" for
// "envelope" and keep the last of two equal keys. The envelope inside is then
// read with trust.DecodeEnvelope. Errors are bare wire sentinels.
func decodePoll(body io.Reader) (uint64, wire.Envelope, error) {
	data, err := io.ReadAll(io.LimitReader(body, wire.MaxEnvelopeBytes+pollSlack+1))
	if err != nil {
		return 0, wire.Envelope{}, wire.ErrBodyInvalid
	}
	if len(data) > wire.MaxEnvelopeBytes+pollSlack {
		return 0, wire.Envelope{}, wire.ErrBodyTooLarge
	}
	if !strictPollKeys(data) {
		return 0, wire.Envelope{}, wire.ErrBodyInvalid
	}
	var raw struct {
		Version  uint64          `json:"version"`
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := wire.Decode(bytes.NewReader(data), int64(len(data)), &raw); err != nil {
		return 0, wire.Envelope{}, err
	}
	env, err := trust.DecodeEnvelope(raw.Envelope)
	if err != nil {
		return 0, wire.Envelope{}, err
	}
	return raw.Version, env, nil
}

// strictPollKeys reports whether every top-level key is exactly "version" or
// "envelope" and appears once. A document that is not an object, or is not
// well formed, is left to the normal decoder to reject.
func strictPollKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return true
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true
		}
		key, ok := t.(string)
		if !ok || (key != "version" && key != "envelope") || seen[key] {
			return false
		}
		seen[key] = true
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return true
		}
	}
	return true
}
