package pairing_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type G2Affine struct {
	X, Y e2
}

type g2Jacobian struct {
	X, Y, Z e2
}

type g2Projective struct {
	X, Y, Z e2
}

func NewG2Affine(v bn254.G2Affine) G2Affine {
	return G2Affine{
		X: e2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.X.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.X.A1),
		},
		Y: e2{
			A0: emulated.ValueOf[emulated.BN254Fp](v.Y.A0),
			A1: emulated.ValueOf[emulated.BN254Fp](v.Y.A1),
		},
	}
}
