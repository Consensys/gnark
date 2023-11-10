package sw_bw6761

import (
	"sync"

	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X = 0x110133241d9b816c852a82e69d660f9d61053aac5a7115f4c06201013890f6d26b41c5dab3da268734ec3f1f09feb58c5bbcae9ac70e7c7963317a300e1b6bace6948cb3cd208d700e96efbc2ad54b06410cf4fe1bf995ba830c194cd025f1c
// Q.Y = 0x17c3357761369f8179eb10e4b6d2dc26b7cf9acec2181c81a78e2753ffe3160a1d86c80b95a59c94c97eb733293fef64f293dbd2c712b88906c170ffa823003ea96fcd504affc758aa2d3a3c5a02a591ec0594f9eac689eb70a16728c73b61

var precomputedLines [2][189]lineEvaluation
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [2][189]lineEvaluation {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputedLines()
	})
	return precomputedLines
}

func computePrecomputedLines() [2][189]lineEvaluation {
	var PrecomputedLines [2][189]lineEvaluation
	_, _, _, G2AffGen := bw6761.Generators()
	lines := bw6761.PrecomputeLines(G2AffGen)
	for j := 0; j < 189; j++ {
		PrecomputedLines[0][j].R0 = emulated.ValueOf[emulated.BW6761Fp](lines[0][j].R0)
		PrecomputedLines[0][j].R1 = emulated.ValueOf[emulated.BW6761Fp](lines[0][j].R1)
		PrecomputedLines[1][j].R0 = emulated.ValueOf[emulated.BW6761Fp](lines[1][j].R0)
		PrecomputedLines[1][j].R1 = emulated.ValueOf[emulated.BW6761Fp](lines[1][j].R1)
	}

	return PrecomputedLines
}
