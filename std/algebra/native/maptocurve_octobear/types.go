package maptocurve_octobear

import (
	"github.com/consensys/gnark-crypto/ecc/octobear"
	"github.com/consensys/gnark-crypto/field/koalabear/extensions"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_octobear"
)

type E2 = fields_octobear.E2
type E4 = fields_octobear.E4
type E8 = fields_octobear.E8

type G1Affine struct {
	X, Y E8
}

func newE8(v extensions.E8) E8 {
	return fields_octobear.NewE8(v)
}

// The on-curve checks in this package (and in sw_octobear, which imports it)
// hardcode a = -3 as `MulByFp(p.X, 3)` for constraint-count reasons. Guard
// against silent drift if the underlying curve parameter ever changes.
func init() {
	a, _ := octobear.CurveCoefficients()
	var minus3 extensions.E8
	minus3.C0.B0.A0.SetUint64(3)
	minus3.Neg(&minus3)
	if !a.Equal(&minus3) {
		panic("maptocurve_octobear: octobear curve coefficient a != -3; on-curve formulas need updating")
	}
}

func fromCoeffs(v []frontend.Variable) E8 {
	return E8{
		C0: E4{
			B0: E2{A0: v[0], A1: v[1]},
			B1: E2{A0: v[2], A1: v[3]},
		},
		C1: E4{
			B0: E2{A0: v[4], A1: v[5]},
			B1: E2{A0: v[6], A1: v[7]},
		},
	}
}
