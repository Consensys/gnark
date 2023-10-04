package sw_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = sw_emulated.AffinePoint[emulated.BN254Fp]
type Scalar = emulated.Element[emulated.BN254Fr]

func NewG1Affine(v bn254.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BN254Fp](v.X),
		Y: emulated.ValueOf[emulated.BN254Fp](v.Y),
	}
}

func NewScalar(v fr_bn254.Element) Scalar {
	return emulated.ValueOf[emulated.BN254Fr](v)
}
