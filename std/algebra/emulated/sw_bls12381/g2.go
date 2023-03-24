package sw_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y fields_bls12381.E2
}

func NewG2Affine(v bls12381.G2Affine) G2Affine {
	return G2Affine{
		X: fields_bls12381.E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.X.A1),
		},
		Y: fields_bls12381.E2{
			A0: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BLS12381Fp](v.Y.A1),
		},
	}
}
