package main

// Strict reading of the timeline answer (Q-D28, M-D63). encoding/json keeps
// the last of two equal keys, matches keys without regard to case and reads
// null as zero. For evidence a reader must not be shown a number that
// depends on which duplicate won, so the answer is scanned first with the same
// rule as trust.DecodeEnvelope (M-D32): an object key must be spelled exactly
// and appear once; in the dropped map (whose keys are proxy IDs) a key that
// differs from an earlier one only in case is also refused, and every count
// must be a JSON number, not null.

import (
	"bytes"
	"encoding/json"
	"strings"
)

// shape describes what a JSON value may hold. A nil *shape accepts any
// value as far as this scan is concerned (the normal decoder decides).
type shape struct {
	fields map[string]*shape // object with exactly these keys
	values *shape            // object with any keys (each once, ignoring case)
	elem   *shape            // array of these
	number bool              // the value must be a JSON number
}

var (
	timelineEntryShape = &shape{fields: map[string]*shape{
		"proxy_id": nil, "version": nil, "policy_hash": nil,
		"first_seen_unix_ms": nil, "last_seen_unix_ms": nil,
		"log_seq": nil, "log_head": nil,
	}}
	timelineShape = &shape{fields: map[string]*shape{
		"tenant":  nil,
		"entries": {elem: timelineEntryShape},
		"dropped": {values: &shape{number: true}},
	}}
)

// strictTimelineKeys reports whether the body obeys the key rules above.
// A document that is not well formed returns true when no rule is broken
// before the syntax error: the normal decoder rejects it.
func strictTimelineKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	ok, _ := scanValue(dec, timelineShape)
	return ok
}

// scanValue consumes one value. ok is false when a rule is broken; stop is
// true when scanning cannot go on (syntax error), in which case ok is true.
func scanValue(dec *json.Decoder, s *shape) (ok, stop bool) {
	t, err := dec.Token()
	if err != nil {
		return true, true
	}
	if s != nil && s.number {
		_, isNum := t.(float64)
		return isNum, false
	}
	d, isDelim := t.(json.Delim)
	if !isDelim {
		return true, false
	}
	switch d {
	case '{':
		return scanObject(dec, s)
	case '[':
		return scanArray(dec, s)
	}
	return true, true
}

func scanObject(dec *json.Decoder, s *shape) (ok, stop bool) {
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return true, true
		}
		key, isStr := t.(string)
		if !isStr {
			return true, true
		}
		var sub *shape
		switch {
		case s != nil && s.fields != nil:
			child, known := s.fields[key]
			if !known || seen[key] {
				return false, false
			}
			sub = child
		case s != nil && s.values != nil:
			folded := strings.ToLower(key)
			if seen[folded] {
				return false, false
			}
			seen[folded] = true
			sub = s.values
		default:
			if seen[key] {
				return false, false
			}
		}
		seen[key] = true
		if ok, stop := scanValue(dec, sub); !ok || stop {
			return ok, stop
		}
	}
	if _, err := dec.Token(); err != nil { // closing }
		return true, true
	}
	return true, false
}

func scanArray(dec *json.Decoder, s *shape) (ok, stop bool) {
	var elem *shape
	if s != nil {
		elem = s.elem
	}
	for dec.More() {
		if ok, stop := scanValue(dec, elem); !ok || stop {
			return ok, stop
		}
	}
	if _, err := dec.Token(); err != nil { // closing ]
		return true, true
	}
	return true, false
}
