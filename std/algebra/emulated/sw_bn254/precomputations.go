package sw_bn254

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
)

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy014)
type lineEvaluation struct {
	R0, R1 fields_bn254.E2
}
type lineEvaluations [2][len(bn254.LoopCounter)]*lineEvaluation

func precomputeLines(Q bn254.G2Affine) lineEvaluations {
	var cLines lineEvaluations
	nLines := bn254.PrecomputeLines(Q)
	for j := range cLines[0] {
		cLines[0][j] = &lineEvaluation{
			R0: fields_bn254.FromE2(&nLines[0][j].R0),
			R1: fields_bn254.FromE2(&nLines[0][j].R1),
		}
		cLines[1][j] = &lineEvaluation{
			R0: fields_bn254.FromE2(&nLines[1][j].R0),
			R1: fields_bn254.FromE2(&nLines[1][j].R1),
		}
	}
	return cLines
}

func (pr *Pairing) computeLines(Q *g2AffP) lineEvaluations {

	// check Q is on curve
	Qaff := G2Affine{P: *Q, Lines: nil}
	pr.IsOnTwist(&Qaff)

	var cLines lineEvaluations
	Qacc := Q
	n := len(bn254.LoopCounter)
	Qacc, cLines[0][n-2] = pr.doubleStep(Qacc)
	cLines[1][n-3] = pr.lineCompute(Qacc, Q)
	Qacc, cLines[0][n-3] = pr.addStep(Qacc, Q)
	for i := n - 4; i >= 0; i-- {
		switch loopCounter[i] {
		case 0:
			Qacc, cLines[0][i] = pr.doubleStep(Qacc)
		case 1:
			Qacc, cLines[0][i], cLines[1][i] = pr.doubleAndAddStep(Qacc, Q, false)
		case -1:
			Qacc, cLines[0][i], cLines[1][i] = pr.doubleAndAddStep(Qacc, Q, true)
		default:
			return lineEvaluations{}
		}
	}

	// Check that Q is on G2 subgroup:
	// 		[r]Q == 0 <==> [6x₀+2]Q + ψ(Q) + ψ³(Q) = ψ²(Q).
	// This is a valid short vector since x₀ ≠ 4 mod 13 and x₀ ≠ 92 mod 97.
	// See Sec. 3.1.2 (Remark 2) in https://eprint.iacr.org/2022/348.
	// This test is equivalent to [computeG2ShortVector] in [AssertIsOnG2].
	//
	// At this point Qacc = [6x₀+2]Q.
	psiQ := pr.g2.psi(&Qaff)  // ψ(Q)
	psi2Q := pr.g2.phi(&Qaff) // ϕ(Q)=ψ²(Q)
	psi3Q := pr.g2.psi(psi2Q) // ψ³(Q)
	lhs := pr.g2.add(&G2Affine{P: *Qacc, Lines: nil}, psiQ)
	lhs = pr.g2.add(lhs, psi3Q)
	pr.g2.AssertIsEqual(lhs, psi2Q)

	Q1X := pr.Ext2.Conjugate(&Q.X)
	Q1X = pr.Ext2.MulByNonResidue1Power2(Q1X)
	Q1Y := pr.Ext2.Conjugate(&Q.Y)
	Q1Y = pr.Ext2.MulByNonResidue1Power3(Q1Y)
	Q1 := &g2AffP{
		X: *Q1X,
		Y: *Q1Y,
	}

	Q2Y := pr.Ext2.MulByNonResidue2Power3(&Q.Y)
	Q2 := &g2AffP{
		X: *pr.Ext2.MulByNonResidue2Power2(&Q.X),
		Y: *Q2Y,
	}

	Qacc, cLines[0][n-1] = pr.addStep(Qacc, Q1)
	cLines[1][n-1] = pr.lineCompute(Qacc, Q2)

	return cLines
}
