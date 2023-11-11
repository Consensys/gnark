package sw_bls12381

import (
	"sync"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/math/emulated"
)

// precomputed lines going through Q and multiples of Q
// where Q is the fixed canonical generator of G2
//
// Q.X.A0 = 0x24aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8
// Q.X.A1 = 0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e
// Q.Y.A0 = 0xce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801
// Q.Y.A1 = 0x606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be

var precomputedLines [2][63]LineEvaluation
var precomputedLinesOnce sync.Once

func getPrecomputedLines() [2][63]LineEvaluation {
	precomputedLinesOnce.Do(func() {
		precomputedLines = computePrecomputedLines()
	})
	return precomputedLines
}

func computePrecomputedLines() [2][63]LineEvaluation {
	var PrecomputedLines [2][63]LineEvaluation
	_, _, _, G2AffGen := bls12381.Generators()
	lines := bls12381.PrecomputeLines(G2AffGen)
	for j := 0; j < 63; j++ {
		PrecomputedLines[0][j].R0.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R0.A0)
		PrecomputedLines[0][j].R0.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R0.A1)
		PrecomputedLines[0][j].R1.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R1.A0)
		PrecomputedLines[0][j].R1.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[0][j].R1.A1)
		PrecomputedLines[1][j].R0.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R0.A0)
		PrecomputedLines[1][j].R0.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R0.A1)
		PrecomputedLines[1][j].R1.A0 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R1.A0)
		PrecomputedLines[1][j].R1.A1 = emulated.ValueOf[emulated.BLS12381Fp](lines[1][j].R1.A1)
	}

	return PrecomputedLines
}
