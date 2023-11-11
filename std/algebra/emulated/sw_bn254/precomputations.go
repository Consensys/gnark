package sw_bn254

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X.A0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
// Q.X.A1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
// Q.Y.A0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
// Q.Y.A1 = 0x90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
var precomputedLines [2]LineEvaluations
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [2]LineEvaluations {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputeLines()
	})
	return precomputedLines
}

func computePrecomputeLines() [2]LineEvaluations {
	var PrecomputedLines [2]LineEvaluations
	_, _, _, G2AffGen := bn254.Generators()
	lines := bn254.PrecomputeLines(G2AffGen)
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
