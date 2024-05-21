package sw_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/math/emulated"
)

// lineEvaluation represents a sparse Fp6 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type lineEvaluation struct {
	R0, R1 emulated.Element[BaseField]
}
type lineEvaluations [2][len(bw6761.LoopCounter) - 1]*lineEvaluation

func precomputeLines(Q bw6761.G2Affine) lineEvaluations {
	var cLines lineEvaluations
	nLines := bw6761.PrecomputeLines(Q)
	for j := range cLines[0] {
		cLines[0][j] = &lineEvaluation{
			R0: emulated.ValueOf[BaseField](nLines[0][j].R0),
			R1: emulated.ValueOf[BaseField](nLines[0][j].R1),
		}
		cLines[1][j] = &lineEvaluation{
			R0: emulated.ValueOf[BaseField](nLines[1][j].R0),
			R1: emulated.ValueOf[BaseField](nLines[1][j].R1),
		}
	}
	return cLines
}

func (p *Pairing) computeLines(Q *g2AffP) lineEvaluations {
	var cLines lineEvaluations
	imQ := &g2AffP{
		X: *p.curveF.Mul(&Q.X, &thirdRootOne),
		Y: *p.curveF.Neg(&Q.Y),
	}
	negQ := &g2AffP{
		X: Q.X,
		Y: imQ.Y,
	}
	accQ := &g2AffP{
		X: imQ.X,
		Y: imQ.Y,
	}
	imQneg := &g2AffP{
		X: imQ.X,
		Y: Q.Y,
	}
	for i := len(loopCounter2) - 2; i > 0; i-- {
		switch loopCounter2[i]*3 + loopCounter1[i] {
		// cases -4, -2, 2, 4 do not occur, given the static LoopCounters
		case -3:
			accQ, cLines[0][i], cLines[1][i] = p.doubleAndAddStep(accQ, imQneg)
		case -1:
			accQ, cLines[0][i], cLines[1][i] = p.doubleAndAddStep(accQ, negQ)
		case 0:
			accQ, cLines[0][i] = p.doubleStep(accQ)
		case 1:
			accQ, cLines[0][i], cLines[1][i] = p.doubleAndAddStep(accQ, Q)
		case 3:
			accQ, cLines[0][i], cLines[1][i] = p.doubleAndAddStep(accQ, imQ)
		default:
			panic("unknown case for loopCounter")
		}
	}
	cLines[0][0] = p.tangentCompute(accQ)
	return cLines
}
