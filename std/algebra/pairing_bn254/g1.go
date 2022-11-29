package pairing_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/weierstrass"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = weierstrass.AffinePoint[emulated.BN254Fp]

func NewG1Affine(v bn254.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BN254Fp](v.X),
		Y: emulated.ValueOf[emulated.BN254Fp](v.Y),
	}
}
