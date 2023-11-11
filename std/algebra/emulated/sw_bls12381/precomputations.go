package sw_bls12381

import (
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q where Q is a fixed point in G2
var precomputedLines [2]LineEvaluations
var precomputedLinesOnce sync.Once

func getPrecomputedLines(Q bls12381.G2Affine) [2]LineEvaluations {
	precomputedLinesOnce.Do(func() {
		precomputedLines = precomputeLines(Q)
	})
	return precomputedLines
}

func precomputeLines(Q bls12381.G2Affine) [2]LineEvaluations {
	var PrecomputedLines [2]LineEvaluations
	lines := bls12381.PrecomputeLines(Q)
	for j := 0; j < 63; j++ {
		PrecomputedLines[0].Eval[j].R0.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R0.A0)
		PrecomputedLines[0].Eval[j].R0.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R0.A1)
		PrecomputedLines[0].Eval[j].R1.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R1.A0)
		PrecomputedLines[0].Eval[j].R1.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R1.A1)
		PrecomputedLines[1].Eval[j].R0.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R0.A0)
		PrecomputedLines[1].Eval[j].R0.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R0.A1)
		PrecomputedLines[1].Eval[j].R1.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R1.A0)
		PrecomputedLines[1].Eval[j].R1.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R1.A1)
	}

	return PrecomputedLines
}
