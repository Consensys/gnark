package sw_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = sw_emulated.AffinePoint[emulated.BLS12381Fp]

func NewG1Affine(v bls12381.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BLS12381Fp](v.X),
		Y: emulated.ValueOf[emulated.BLS12381Fp](v.Y),
	}
}
