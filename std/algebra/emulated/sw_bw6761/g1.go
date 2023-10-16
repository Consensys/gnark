package sw_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[emulated.BW6761Fp]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[emulated.BW6761Fr]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BW6761Fp](v.X),
		Y: emulated.ValueOf[emulated.BW6761Fp](v.Y),
	}
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bw6761.Element) Scalar {
	return emulated.ValueOf[emulated.BW6761Fr](v)
}
