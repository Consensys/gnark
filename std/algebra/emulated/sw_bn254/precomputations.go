package sw_bn254

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q where Q is a fixed point in G2
var precomputedLines [2]LineEvaluations
var precomputedLinesOnce sync.Once

func getPrecomputedLines(Q bn254.G2Affine) [2]LineEvaluations {
	precomputedLinesOnce.Do(func() {
		precomputedLines = precomputeLines(Q)
	})
	return precomputedLines
}

func precomputeLines(Q bn254.G2Affine) [2]LineEvaluations {
	var PrecomputedLines [2]LineEvaluations
	lines := bn254.PrecomputeLines(Q)
	for j := 0; j < 65; j++ {
		PrecomputedLines[0].Eval[j].R0.A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R0.A0)
		PrecomputedLines[0].Eval[j].R0.A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R0.A1)
		PrecomputedLines[0].Eval[j].R1.A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R1.A0)
		PrecomputedLines[0].Eval[j].R1.A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R1.A1)
		PrecomputedLines[1].Eval[j].R0.A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R0.A0)
		PrecomputedLines[1].Eval[j].R0.A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R0.A1)
		PrecomputedLines[1].Eval[j].R1.A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R1.A0)
		PrecomputedLines[1].Eval[j].R1.A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R1.A1)
	}
	PrecomputedLines[0].Eval[65].R0.A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R0.A0)
	PrecomputedLines[0].Eval[65].R0.A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R0.A1)
	PrecomputedLines[0].Eval[65].R1.A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R1.A0)
	PrecomputedLines[0].Eval[65].R1.A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R1.A1)
	PrecomputedLines[1].Eval[65].R0.A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R0.A0)
	PrecomputedLines[1].Eval[65].R0.A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R0.A1)
	PrecomputedLines[1].Eval[65].R1.A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R1.A0)
	PrecomputedLines[1].Eval[65].R1.A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R1.A1)

	return PrecomputedLines
}
