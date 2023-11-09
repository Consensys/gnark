package sw_bn254

import (
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X.A0 = 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed
// Q.X.A1 = 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2
// Q.Y.A0 = 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa
// Q.Y.A1 = 0x90689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b
var precomputedLines [4][67]fields_bn254.E2
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [4][67]fields_bn254.E2 {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputeLines()
	})
	return precomputedLines
}

func computePrecomputeLines() [4][67]fields_bn254.E2 {
	var PrecomputedLines [4][67]fields_bn254.E2
	_, _, _, G2AffGen := bn254.Generators()
	lines := bn254.PrecomputeLines(G2AffGen)
	for j := 0; j < 65; j++ {
		PrecomputedLines[0][j].A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R0.A0)
		PrecomputedLines[0][j].A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R0.A1)
		PrecomputedLines[1][j].A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R1.A0)
		PrecomputedLines[1][j].A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][j].R1.A1)
		PrecomputedLines[2][j].A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R0.A0)
		PrecomputedLines[2][j].A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R0.A1)
		PrecomputedLines[3][j].A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R1.A0)
		PrecomputedLines[3][j].A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][j].R1.A1)
	}
	PrecomputedLines[0][65].A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R0.A0)
	PrecomputedLines[0][65].A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R0.A1)
	PrecomputedLines[1][65].A0 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R1.A0)
	PrecomputedLines[1][65].A1 = emulated.ValueOf[emulated.BN254Fp](lines[0][65].R1.A1)
	PrecomputedLines[0][66].A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R0.A0)
	PrecomputedLines[0][66].A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R0.A1)
	PrecomputedLines[1][66].A0 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R1.A0)
	PrecomputedLines[1][66].A1 = emulated.ValueOf[emulated.BN254Fp](lines[1][65].R1.A1)

	return PrecomputedLines
}
