package enforce

import (
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"
)

// The strict request scanner (M-D33 items 1, 2, 3 and 6; THREATS #13).
//
// The proxy must read a request exactly the way the MCP server will, or a
// request can pass the policy check as one thing and run as another. The
// differences between JSON parsers are the usual way in, so the scanner is
// deliberately narrower than JSON:
//
//   - the body is one JSON object followed only by whitespace. A top-level
//     array (a JSON-RPC batch) is its own error. Invalid UTF-8 in any string,
//     control characters, bad escapes, bad numbers and nesting deeper than
//     maxDepth are syntax errors;
//   - at the envelope, and in params for tools/call and tools/list, a key must
//     be plain: ASCII only, no upper-case letter, no backslash. That rules out
//     "Method", "method" and look-alikes that Go's case-folding key
//     matching (or another parser's) would read as "method". Duplicate keys
//     are an error, so "first wins" and "last wins" parsers cannot disagree;
//   - the method is matched exactly. A method that is only a case or padding
//     variant of tools/call or tools/list is an error, not a pass-through.
//
// Keys inside "arguments" (and inside params of any other method) are not
// inspected: they are the tool's business, and the proxy forwards them
// untouched. They are still checked for valid JSON.
//
// Errors carry a fixed reason and never any part of the body.

// maxDepth is the deepest nesting the scanner accepts, counting the envelope.
const maxDepth = 100

type kind int

const (
	kindOther kind = iota // anything but tools/list and tools/call: passes through
	kindList
	kindCall
)

var (
	errSyntax       = errors.New("not valid strict JSON")
	errBatch        = errors.New("JSON-RPC batch")
	errDuplicateKey = errors.New("duplicate key")
	errBadKey       = errors.New("key is not plain lowercase ASCII")
	errMethod       = errors.New("missing or ambiguous method")
	errShape        = errors.New("not a valid JSON-RPC request")
)

// envelope is what the scanner learned from an accepted body.
type envelope struct {
	Kind kind
	ID   json.RawMessage // raw string, number or null; nil when the request has no id
	Tool string          // params.name of a tools/call (decoded, not yet checked against the tool alphabet)
}

// scanRequest reads one request body. It returns an error for anything it
// will not vouch for.
func scanRequest(body []byte) (envelope, error) {
	var env envelope
	s := scanner{b: body}
	s.ws()
	if s.eof() {
		return env, errSyntax
	}
	if s.b[s.i] == '[' {
		return env, errBatch
	}
	if s.b[s.i] != '{' {
		return env, errSyntax
	}

	var (
		method                string
		haveMethod            bool
		haveID                bool
		idRaw                 []byte
		paramsSpan            [2]int
		haveParams            bool
		haveResult, haveError bool
	)
	err := s.object(1, true, func(key []byte, depth int) error {
		start := s.i
		switch string(key) {
		case "method":
			if s.eof() || s.b[s.i] != '"' {
				if err := s.value(depth); err != nil {
					return err
				}
				return errShape
			}
			if _, _, err := s.str(); err != nil {
				return err
			}
			if err := json.Unmarshal(s.b[start:s.i], &method); err != nil {
				return errSyntax
			}
			haveMethod = true
		case "id":
			if err := s.value(depth); err != nil {
				return err
			}
			idRaw = s.b[start:s.i]
			haveID = true
		case "params":
			if err := s.value(depth); err != nil {
				return err
			}
			paramsSpan = [2]int{start, s.i}
			haveParams = true
		case "result":
			haveResult = true
			return s.value(depth)
		case "error":
			haveError = true
			return s.value(depth)
		default:
			return s.value(depth)
		}
		return nil
	})
	if err != nil {
		return env, err
	}
	s.ws()
	if !s.eof() {
		return env, errSyntax
	}

	// An id is a string, a number or null. Anything else cannot be answered
	// (a call or list with such an id is an error below); it is not echoed.
	if haveID {
		switch idRaw[0] {
		case '"', '-', 'n', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			env.ID = json.RawMessage(idRaw)
		default:
			haveID = false
		}
	}

	if !haveMethod {
		// A client answering a server request has no method. Anything else without one is not a request.
		if haveResult || haveError {
			return env, nil
		}
		return env, errMethod
	}

	switch method {
	case "tools/call":
		env.Kind = kindCall
	case "tools/list":
		env.Kind = kindList
	default:
		if isNear(method, "tools/call") || isNear(method, "tools/list") {
			return env, errMethod
		}
		return env, nil
	}

	// A call or a list needs an id (the answer has to go somewhere); a bad id was dropped above.
	if !haveID {
		return env, errShape
	}

	// Params of the two methods we decide on are scanned with the same plain-key rule.
	if !haveParams {
		if env.Kind == kindCall {
			return env, errShape
		}
		return env, nil
	}
	p := scanner{b: body, i: paramsSpan[0]}
	if p.b[p.i] != '{' {
		return env, errShape
	}
	var name string
	haveName := false
	err = p.object(2, true, func(key []byte, depth int) error {
		if env.Kind == kindCall && string(key) == "name" {
			if p.eof() || p.b[p.i] != '"' {
				if err := p.value(depth); err != nil {
					return err
				}
				return errShape
			}
			start := p.i
			if _, _, err := p.str(); err != nil {
				return err
			}
			if err := json.Unmarshal(p.b[start:p.i], &name); err != nil {
				return errSyntax
			}
			haveName = true
			return nil
		}
		return p.value(depth)
	})
	if err != nil {
		return env, err
	}
	if env.Kind == kindCall {
		if !haveName {
			return env, errShape
		}
		env.Tool = name
	}
	return env, nil
}

// isNear reports whether method is tools/call or tools/list (target) in a
// spelling other than the exact one.
func isNear(method, target string) bool {
	return method != target && strings.EqualFold(strings.TrimSpace(method), target)
}

// scanner walks a byte slice. It only reads; nothing is copied except by
// the callers that decode a string.
type scanner struct {
	b []byte
	i int
}

func (s *scanner) eof() bool { return s.i >= len(s.b) }

// ws skips JSON whitespace (space, tab, newline, carriage return).
func (s *scanner) ws() {
	for s.i < len(s.b) {
		switch s.b[s.i] {
		case ' ', '\t', '\n', '\r':
			s.i++
		default:
			return
		}
	}
}

// object reads an object starting at s.i (which must be '{'). For every
// member it calls member with the raw key and the scanner positioned at the
// member's value; member must consume exactly that value. With plain set,
// keys must be plain and unique.
func (s *scanner) object(depth int, plain bool, member func(key []byte, depth int) error) error {
	if depth > maxDepth {
		return errSyntax
	}
	s.i++ // '{'
	var seen map[string]struct{}
	if plain {
		seen = make(map[string]struct{}, 8)
	}
	s.ws()
	if !s.eof() && s.b[s.i] == '}' {
		s.i++
		return nil
	}
	for {
		s.ws()
		if s.eof() || s.b[s.i] != '"' {
			return errSyntax
		}
		raw, escaped, err := s.str()
		if err != nil {
			return err
		}
		if plain {
			if escaped || !plainKey(raw) {
				return errBadKey
			}
			if _, dup := seen[string(raw)]; dup {
				return errDuplicateKey
			}
			seen[string(raw)] = struct{}{}
		}
		s.ws()
		if s.eof() || s.b[s.i] != ':' {
			return errSyntax
		}
		s.i++
		s.ws()
		if s.eof() {
			return errSyntax
		}
		if err := member(raw, depth); err != nil {
			return err
		}
		s.ws()
		if s.eof() {
			return errSyntax
		}
		switch s.b[s.i] {
		case ',':
			s.i++
		case '}':
			s.i++
			return nil
		default:
			return errSyntax
		}
	}
}

// plainKey: ASCII only, no upper-case letter. (Control characters and
// backslashes never get this far: str rejects the first and flags the second.)
func plainKey(k []byte) bool {
	for _, c := range k {
		if c >= 0x80 || (c >= 'A' && c <= 'Z') {
			return false
		}
	}
	return true
}

// value skips one JSON value, checking that it is valid.
func (s *scanner) value(depth int) error {
	if depth > maxDepth {
		return errSyntax
	}
	if s.eof() {
		return errSyntax
	}
	switch c := s.b[s.i]; {
	case c == '{':
		return s.object(depth+1, false, func(_ []byte, d int) error { return s.value(d) })
	case c == '[':
		s.i++
		s.ws()
		if !s.eof() && s.b[s.i] == ']' {
			s.i++
			return nil
		}
		for {
			s.ws()
			if err := s.value(depth + 1); err != nil {
				return err
			}
			s.ws()
			if s.eof() {
				return errSyntax
			}
			switch s.b[s.i] {
			case ',':
				s.i++
			case ']':
				s.i++
				return nil
			default:
				return errSyntax
			}
		}
	case c == '"':
		_, _, err := s.str()
		return err
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	}
	return errSyntax
}

func (s *scanner) literal(w string) error {
	if len(s.b)-s.i < len(w) || string(s.b[s.i:s.i+len(w)]) != w {
		return errSyntax
	}
	s.i += len(w)
	return nil
}

// number checks the JSON number grammar.
func (s *scanner) number() error {
	if s.b[s.i] == '-' {
		s.i++
	}
	if s.eof() {
		return errSyntax
	}
	switch c := s.b[s.i]; {
	case c == '0':
		s.i++
	case c >= '1' && c <= '9':
		s.digits()
	default:
		return errSyntax
	}
	if !s.eof() && s.b[s.i] == '.' {
		s.i++
		if !s.digits() {
			return errSyntax
		}
	}
	if !s.eof() && (s.b[s.i] == 'e' || s.b[s.i] == 'E') {
		s.i++
		if !s.eof() && (s.b[s.i] == '+' || s.b[s.i] == '-') {
			s.i++
		}
		if !s.digits() {
			return errSyntax
		}
	}
	return nil
}

func (s *scanner) digits() bool {
	n := 0
	for !s.eof() && s.b[s.i] >= '0' && s.b[s.i] <= '9' {
		s.i++
		n++
	}
	return n > 0
}

// str reads a string starting at the opening quote. It returns the raw bytes
// between the quotes and whether any backslash escape was present. The raw
// bytes must be valid UTF-8, free of control characters, with only the escapes
// JSON defines.
func (s *scanner) str() (raw []byte, escaped bool, err error) {
	s.i++ // opening quote
	start := s.i
	for {
		if s.eof() {
			return nil, false, errSyntax
		}
		c := s.b[s.i]
		switch {
		case c == '"':
			raw = s.b[start:s.i]
			s.i++
			if !utf8.Valid(raw) {
				return nil, false, errSyntax
			}
			return raw, escaped, nil
		case c < 0x20:
			return nil, false, errSyntax
		case c == '\\':
			escaped = true
			s.i++
			if s.eof() {
				return nil, false, errSyntax
			}
			switch s.b[s.i] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.i++
			case 'u':
				s.i++
				if len(s.b)-s.i < 4 {
					return nil, false, errSyntax
				}
				for k := 0; k < 4; k++ {
					h := s.b[s.i+k]
					if !(h >= '0' && h <= '9' || h >= 'a' && h <= 'f' || h >= 'A' && h <= 'F') {
						return nil, false, errSyntax
					}
				}
				s.i += 4
			default:
				return nil, false, errSyntax
			}
		default:
			s.i++
		}
	}
}
