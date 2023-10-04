package sw_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[emulated.BN254Fp]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[emulated.BN254Fr]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bn254.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BN254Fp](v.X),
		Y: emulated.ValueOf[emulated.BN254Fp](v.Y),
	}
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bn254.Element) Scalar {
	return emulated.ValueOf[emulated.BN254Fr](v)
}
