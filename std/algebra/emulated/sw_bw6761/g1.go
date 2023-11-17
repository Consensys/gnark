package sw_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

// G1Affine is the point in G1. It is an alias to the generic emulated affine
// point.
type G1Affine = sw_emulated.AffinePoint[BaseField]

// Scalar is the scalar in the groups. It is an alias to the emulated element
// defined over the scalar field of the groups.
type Scalar = emulated.Element[ScalarField]

// NewG1Affine allocates a witness from the native G1 element and returns it.
func NewG1Affine(v bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

// NewScalar allocates a witness from the native scalar and returns it.
func NewScalar(v fr_bw6761.Element) Scalar {
	return emulated.ValueOf[ScalarField](v)
}

// ScalarField is the [emulated.FieldParams] impelementation of the curve scalar field.
type ScalarField = emulated.BW6761Fr

// BaseField is the [emulated.FieldParams] impelementation of the curve base field.
type BaseField = emulated.BW6761Fp
