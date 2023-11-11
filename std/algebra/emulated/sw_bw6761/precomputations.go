package sw_bw6761

import (
	"sync"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q where Q is a fixed point in G2
var precomputedLines [2]LineEvaluations
var precomputedLinesOnce sync.Once

func getPrecomputedLines(Q bw6761.G2Affine) [2]LineEvaluations {
	precomputedLinesOnce.Do(func() {
		precomputedLines = precomputeLines(Q)
	})
	return precomputedLines
}

func precomputeLines(Q bw6761.G2Affine) [2]LineEvaluations {
	var PrecomputedLines [2]LineEvaluations
	lines := bw6761.PrecomputeLines(Q)
	for j := 0; j < 189; j++ {
		PrecomputedLines[0].Eval[j].R0 = emulated.ValueOf[emulated.BW6761Fp](lines[0][j].R0)
		PrecomputedLines[0].Eval[j].R1 = emulated.ValueOf[emulated.BW6761Fp](lines[0][j].R1)
		PrecomputedLines[1].Eval[j].R0 = emulated.ValueOf[emulated.BW6761Fp](lines[1][j].R0)
		PrecomputedLines[1].Eval[j].R1 = emulated.ValueOf[emulated.BW6761Fp](lines[1][j].R1)
	}

	return PrecomputedLines
}
