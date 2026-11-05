package obs

import (
	"math"
	"strconv"
)

func nan0() float64         { return math.NaN() }
func inf0(sign int) float64 { return math.Inf(sign) }
func itoa(i int) string     { return strconv.Itoa(i) }
