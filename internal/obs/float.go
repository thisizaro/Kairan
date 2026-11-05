package obs

import (
	"math"
	"strconv"

	"kairan/internal/wire"
)

func f64bits(x float64) uint64 { return math.Float64bits(x) }
func f64from(u uint64) float64 { return math.Float64frombits(u) }

// appendFloat formats a sample value: NaN, +Inf, -Inf as the text format
// spells them; whole numbers below 1e15 without an exponent; others in the
// shortest round-trip form.
func appendFloat(b []byte, v float64) []byte {
	switch {
	case math.IsNaN(v):
		return append(b, "NaN"...)
	case math.IsInf(v, 1):
		return append(b, "+Inf"...)
	case math.IsInf(v, -1):
		return append(b, "-Inf"...)
	case v == math.Trunc(v) && math.Abs(v) < 1e15:
		return strconv.AppendFloat(b, v, 'f', -1, 64)
	}
	return strconv.AppendFloat(b, v, 'g', -1, 64)
}

// StateLabel turns a proxy state into a valid label value: wire.ID allows
// hyphens but not underscores, so "deny_all" becomes "deny-all".
func StateLabel(s wire.ProxyState) wire.ID {
	b := []byte(s)
	for i, c := range b {
		if c == '_' {
			b[i] = '-'
		}
	}
	return sanitize(wire.ID(b))
}
