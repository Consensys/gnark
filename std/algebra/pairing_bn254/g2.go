package pairing_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y E2
}

type G2Jacobian struct {
	X, Y, Z E2
}

type G2Projective struct {
	X, Y, Z E2
}

func NewG2Affine(v bn254.G2Affine) G2Affine {
	return G2Affine{
		X: E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.X.A1),
		},
		Y: E2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.Y.A1),
		},
	}
}
