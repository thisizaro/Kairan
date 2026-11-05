// Package policy parses and validates the signed policy payload
// (docs/ARCHITECTURE.md section 10.0, decisions M-D12 and M-D32).
//
// It is a pure core package: no I/O, no clock. Parse is strict. The standard
// decoder is not used to read the document because it matches field names
// case-insensitively and silently keeps the last of two equal keys, which
// would let two admins approve different policies from the same bytes.
// Instead Parse walks the JSON token stream itself and rejects any duplicate
// key at any object level, any field name that is not the exact lowercase
// spelling, any unknown field, any missing field and any trailing bytes.
// Every failure wraps wire.ErrInvalid. Error text is a fixed reason and never
// echoes payload content (I4).
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"kairan/internal/wire"
)

// Limits from section 10.0.
const (
	MaxRoles        = 256
	MaxPatterns     = 1024 // per role
	MaxToolNameLen  = 128
	maxPayloadBytes = wire.MaxEnvelopeBytes // a payload cannot be larger than the envelope that carries it
)

// Class is the kind of a tool: read, write or execute.
type Class byte

// The three classes a rule can grant.
const (
	ClassR Class = 'R'
	ClassW Class = 'W'
	ClassX Class = 'X'
)

func validClass(c Class) bool { return c == ClassR || c == ClassW || c == ClassX }

// Policy is a parsed and validated policy. The zero value is not valid; get
// one from Parse.
type Policy struct {
	Tenant              wire.ID
	Version             uint64
	IssuedAt, ExpiresAt time.Time // UTC

	roles map[string]*role // role name -> compiled rules
}

// role holds one role's rules: exact names in a map, prefix rules sorted
// longest prefix first.
type role struct {
	exact    map[string]Class
	prefixes []prefixRule
}

type prefixRule struct {
	pattern string // as written, with the trailing *
	prefix  string // pattern without the trailing *, never empty
	class   Class
}

func invalid(reason string) error {
	return fmt.Errorf("%w: policy: %s", wire.ErrInvalid, reason)
}

// Parse reads a policy payload. It returns an error wrapping wire.ErrInvalid
// for anything outside the section 10.0 format, and never panics.
func Parse(payload []byte) (*Policy, error) {
	if len(payload) > maxPayloadBytes {
		return nil, invalid("too large")
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	p, err := parseDocument(dec)
	if err != nil {
		return nil, err
	}
	// Nothing may follow the document but white space.
	if _, err := dec.Token(); err != io.EOF {
		return nil, invalid("trailing bytes")
	}
	return p, nil
}

func parseDocument(dec *json.Decoder) (*Policy, error) {
	var (
		p                  = &Policy{}
		have               = map[string]bool{}
		issuedAt, expireAt time.Time
	)
	err := object(dec, func(key string) error {
		if have[key] {
			return invalid("duplicate field")
		}
		var err error
		switch key {
		case "tenant":
			var s string
			if s, err = str(dec); err != nil {
				return err
			}
			p.Tenant = wire.ID(s)
			if !p.Tenant.Valid() {
				return invalid("bad tenant")
			}
		case "version":
			if p.Version, err = unsigned(dec); err != nil {
				return err
			}
			if p.Version < 1 {
				return invalid("bad version")
			}
		case "issued_at":
			if issuedAt, err = timestamp(dec); err != nil {
				return err
			}
		case "expires_at":
			if expireAt, err = timestamp(dec); err != nil {
				return err
			}
		case "default":
			var s string
			if s, err = str(dec); err != nil {
				return err
			}
			if s != "deny" {
				return invalid(`default must be "deny"`)
			}
		case "roles":
			if p.roles, err = parseRoles(dec); err != nil {
				return err
			}
		default:
			return invalid("unknown field")
		}
		have[key] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	for _, k := range [...]string{"tenant", "version", "issued_at", "expires_at", "default", "roles"} {
		if !have[k] {
			return nil, invalid("missing field")
		}
	}
	if !expireAt.After(issuedAt) {
		return nil, invalid("expires_at must be after issued_at")
	}
	p.IssuedAt, p.ExpiresAt = issuedAt, expireAt
	return p, nil
}

func parseRoles(dec *json.Decoder) (map[string]*role, error) {
	roles := map[string]*role{}
	err := object(dec, func(name string) error {
		if _, dup := roles[name]; dup {
			return invalid("duplicate role")
		}
		if len(roles) >= MaxRoles {
			return invalid("too many roles")
		}
		if !wire.ID(name).Valid() {
			return invalid("bad role name")
		}
		r, err := parseRole(dec)
		if err != nil {
			return err
		}
		roles[name] = r
		return nil
	})
	if err != nil {
		return nil, err
	}
	return roles, nil
}

func parseRole(dec *json.Decoder) (*role, error) {
	r := &role{exact: map[string]Class{}}
	seen := map[string]bool{}
	err := object(dec, func(pattern string) error {
		if seen[pattern] {
			return invalid("duplicate tool pattern")
		}
		if len(seen) >= MaxPatterns {
			return invalid("too many patterns")
		}
		s, err := str(dec)
		if err != nil {
			return err
		}
		if len(s) != 1 || !validClass(Class(s[0])) {
			return invalid("bad class")
		}
		class := Class(s[0])
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if !validName(prefix) { // rejects empty (bare *) and any other *
				return invalid("bad tool pattern")
			}
			r.prefixes = append(r.prefixes, prefixRule{pattern: pattern, prefix: prefix, class: class})
		} else {
			if !validName(pattern) {
				return invalid("bad tool pattern")
			}
			r.exact[pattern] = class
		}
		seen[pattern] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Longest prefix first; equal lengths in byte order so the result does
	// not depend on key order (equal-length distinct prefixes never both match).
	sort.Slice(r.prefixes, func(i, j int) bool {
		a, b := r.prefixes[i].prefix, r.prefixes[j].prefix
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
	return r, nil
}

// validName reports whether s is a tool name: 1-128 characters of [A-Za-z0-9_.-].
func validName(s string) bool {
	if len(s) == 0 || len(s) > MaxToolNameLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// object reads one JSON object from the token stream and calls member for
// every key (decoded, so "tenant" is "tenant") with the decoder
// positioned at the member's value; member must consume exactly that value.
// Duplicate detection is the caller's job because it knows the key set.
func object(dec *json.Decoder, member func(key string) error) error {
	t, err := dec.Token()
	if err != nil {
		return invalid("syntax")
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return invalid("want an object")
	}
	for {
		t, err := dec.Token()
		if err != nil {
			return invalid("syntax")
		}
		switch k := t.(type) {
		case json.Delim:
			if k == '}' {
				return nil
			}
			return invalid("want a field name")
		case string:
			if err := member(k); err != nil {
				return err
			}
		default:
			return invalid("want a field name")
		}
	}
}

func str(dec *json.Decoder) (string, error) {
	t, err := dec.Token()
	if err != nil {
		return "", invalid("syntax")
	}
	s, ok := t.(string)
	if !ok {
		return "", invalid("want a string")
	}
	return s, nil
}

// unsigned reads a JSON integer written as plain digits (no fraction or exponent).
func unsigned(dec *json.Decoder) (uint64, error) {
	t, err := dec.Token()
	if err != nil {
		return 0, invalid("syntax")
	}
	n, ok := t.(json.Number)
	if !ok {
		return 0, invalid("want a number")
	}
	v, err := strconv.ParseUint(n.String(), 10, 64)
	if err != nil {
		return 0, invalid("want an unsigned integer")
	}
	return v, nil
}

// timestamp reads an RFC 3339 time that ends in Z (UTC).
func timestamp(dec *json.Decoder) (time.Time, error) {
	s, err := str(dec)
	if err != nil {
		return time.Time{}, err
	}
	if !strings.HasSuffix(s, "Z") {
		return time.Time{}, invalid("time must be UTC (Z)")
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, invalid("bad time")
	}
	return t.UTC(), nil
}
