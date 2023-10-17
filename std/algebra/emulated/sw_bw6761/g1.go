package sw_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = sw_emulated.AffinePoint[emulated.BW6761Fp]

func NewG1Affine(v bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BW6761Fp](v.X),
		Y: emulated.ValueOf[emulated.BW6761Fp](v.Y),
	}
}
