package maptocurve_octobear

import (
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
