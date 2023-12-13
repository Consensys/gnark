package sw_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
)

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type lineEvaluation struct {
	R0, R1 fields_bls12381.E2
}
type lineEvaluations [2][len(bls12381.LoopCounter) - 1]*lineEvaluation

func precomputeLines(Q bls12381.G2Affine) lineEvaluations {
	var cLines lineEvaluations
	nLines := bls12381.PrecomputeLines(Q)
	for j := range cLines[0] {
		cLines[0][j] = &lineEvaluation{
			R0: fields_bls12381.FromE2(&nLines[0][j].R0),
			R1: fields_bls12381.FromE2(&nLines[0][j].R1),
		}
		cLines[1][j] = &lineEvaluation{
			R0: fields_bls12381.FromE2(&nLines[1][j].R0),
			R1: fields_bls12381.FromE2(&nLines[1][j].R1),
		}
	}
	return cLines
}

func (p *Pairing) computeLines(Q *g2AffP) lineEvaluations {

	var cLines lineEvaluations
	Qacc := Q
	n := len(loopCounter)
	Qacc, cLines[0][n-2], cLines[1][n-2] = p.tripleStep(Qacc)
	for i := n - 3; i >= 1; i-- {
		if loopCounter[i] == 0 {
			Qacc, cLines[0][i] = p.doubleStep(Qacc)
		} else {
			Qacc, cLines[0][i], cLines[1][i] = p.doubleAndAddStep(Qacc, Q)
		}
	}
	cLines[0][0] = p.tangentCompute(Qacc)
	return cLines
}
