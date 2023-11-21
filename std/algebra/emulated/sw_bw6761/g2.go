package sw_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type g2AffP = sw_emulated.AffinePoint[BaseField]

type G2Affine struct {
	P     g2AffP
	Lines *lineEvaluations
}

func newG2AffP(v bw6761.G2Affine) g2AffP {
	return sw_emulated.AffinePoint[BaseField]{
		X: emulated.ValueOf[BaseField](v.X),
		Y: emulated.ValueOf[BaseField](v.Y),
	}
}

func NewG2Affine(v bw6761.G2Affine) G2Affine {
	return G2Affine{
		P: newG2AffP(v),
	}
}

func NewG2AffineFixed(v bw6761.G2Affine) G2Affine {
	lines := precomputeLines(v)
	return G2Affine{
		P:     newG2AffP(v),
		Lines: &lines,
	}
}

func NewG2AffineFixedPlaceholder() G2Affine {
	var lines lineEvaluations
	for i := 0; i < len(bw6761.LoopCounter)-1; i++ {
		lines[0][i] = &lineEvaluation{}
		lines[1][i] = &lineEvaluation{}
	}
	return G2Affine{
		Lines: &lines,
	}
}
