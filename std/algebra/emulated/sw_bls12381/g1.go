package sw_bls12381

import (
	"fmt"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
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

type G1 struct {
	curveF *emulated.Field[emulated.BLS12381Fp]
	w      *emulated.Element[emulated.BLS12381Fp]
}

func NewG1(api frontend.API) (*G1, error) {
	ba, err := emulated.NewField[emulated.BLS12381Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	w := emulated.ValueOf[emulated.BLS12381Fp]("4002409555221667392624310435006688643935503118305586438271171395842971157480381377015405980053539358417135540939436")
	return &G1{
		curveF: ba,
		w:      &w,
	}, nil
}

func (g1 *G1) phi(q *G1Affine) *G1Affine {
	x := g1.curveF.Mul(&q.X, g1.w)

	return &G1Affine{
		X: *x,
		Y: q.Y,
	}
}
