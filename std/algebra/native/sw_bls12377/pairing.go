/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sw_bls12377

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
)

// GT target group of the pairing
type GT = fields_bls12377.E12

// binary decomposition of x₀=9586122913090633729 little endian
var loopCounter = [64]int8{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1}

// MillerLoop computes the product of n miller loops (n can be 1)
// ∏ᵢ { fᵢ_{x₀,Q}(P) }
func MillerLoop(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return GT{}, errors.New("invalid inputs sizes")
	}
	lines := make([]lineEvaluations, len(Q))
	for i := range Q {
		if Q[i].Lines == nil {
			Qlines := computeLines(api, Q[i].P)
			Q[i].Lines = Qlines
		}
		lines[i] = *Q[i].Lines
	}
	return millerLoopLines(api, P, lines)

}

// millerLoopLines computes the multi-Miller loop from points in G1 and precomputed lines in G2
func millerLoopLines(api frontend.API, P []G1Affine, lines []lineEvaluations) (GT, error) {

	// check input size match
	n := len(P)
	if n == 0 || n != len(lines) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	var res GT
	res.SetOne()
	var prodLines [5]fields_bls12377.E2
	var l0, l1 lineEvaluation

	// precomputations
	yInv := make([]frontend.Variable, n)
	xNegOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	// line evaluation at P[0]
	res.C1.B0.MulByFp(api, lines[0][0][62].R0, xNegOverY[0])
	res.C1.B1.MulByFp(api, lines[0][0][62].R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		// line evaluation at P[1]

		// ℓ × res
		prodLines = *fields_bls12377.Mul034By034(api,
			*l0.R0.MulByFp(api, lines[1][0][62].R0, xNegOverY[1]),
			*l0.R1.MulByFp(api, lines[1][0][62].R1, yInv[1]),
			res.C1.B0,
			res.C1.B1,
		)
		res.C0.B0 = prodLines[0]
		res.C0.B1 = prodLines[1]
		res.C0.B2 = prodLines[2]
		res.C1.B0 = prodLines[3]
		res.C1.B1 = prodLines[4]

	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy034 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		// line evaluation at P[1]

		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api,
			prodLines,
			*l0.R0.MulByFp(api, lines[2][0][62].R0, xNegOverY[2]),
			*l0.R1.MulByFp(api, lines[2][0][62].R1, yInv[2]),
		)

		// k >= 3
		for k := 3; k < n; k++ {
			// line evaluation at P[k]

			// ℓ × res
			res.MulBy034(api,
				*l0.R0.MulByFp(api, lines[k][0][62].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0][62].R1, yInv[k]),
			)
		}
	}

	// i = 61, separately to use a special E12 Square
	// k = 0
	// line evaluation at P[0]

	if n == 1 {
		res.Square034(api, res)
		prodLines[0] = res.C0.B0
		prodLines[1] = res.C0.B1
		prodLines[2] = res.C0.B2
		prodLines[3] = res.C1.B0
		prodLines[4] = res.C1.B1
		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api,
			prodLines,
			*l0.R0.MulByFp(api, lines[0][0][61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0][61].R1, yInv[0]),
		)

	} else {
		res.Square(api, res)
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[0][0][61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0][61].R1, yInv[0]),
		)

	}

	for k := 1; k < n; k++ {
		// line evaluation at P[k]
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[k][0][61].R0, xNegOverY[k]),
			*l0.R1.MulByFp(api, lines[k][0][61].R1, yInv[k]),
		)
	}

	for i := 60; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		for k := 0; k < n; k++ {
			if loopCounter[i] == 0 {
				// line evaluation at P

				// ℓ × res
				res.MulBy034(api,
					*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
					*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
				)
				continue

			}

			// lines evaluation at P

			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api,
				*l0.R0.MulByFp(api, lines[k][0][i].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0][i].R1, yInv[k]),
				*l1.R0.MulByFp(api, lines[k][1][i].R0, xNegOverY[k]),
				*l1.R1.MulByFp(api, lines[k][1][i].R1, yInv[k]),
			)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
		}
	}
	return res, nil
}

// FinalExponentiation computes the exponentiation e1ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func FinalExponentiation(api frontend.API, e1 GT) GT {
	result := e1

	// https://eprint.iacr.org/2016/130.pdf
	var t0, t1, t2 GT

	// easy part
	// (p⁶-1)(p²+1)
	t0.Conjugate(api, result)
	t0.DivUnchecked(api, t0, result)
	result.FrobeniusSquare(api, t0).
		Mul(api, result, t0)
	t3 := result

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	t0.ExpX0Minus1Square(api, result)
	t1.ExpX0(api, t0)
	t2.Frobenius(api, t0)
	result.Mul(api, t1, t2)
	t0.Conjugate(api, result)
	t1.ExpX0(api, result)
	t1.ExpX0(api, t1)
	t2.FrobeniusSquare(api, result)
	result.Mul(api, t1, t2)
	result.Mul(api, result, t0)
	t0.CyclotomicSquare(api, t3)
	t0.Mul(api, t0, t3)
	result.Mul(api, result, t0)
	return result
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup
func Pair(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	f, err := MillerLoop(api, P, Q)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiation(api, f), nil
}

// PairingCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups
func PairingCheck(api frontend.API, P []G1Affine, Q []G2Affine) error {
	f, err := MillerLoop(api, P, Q)
	if err != nil {
		return err
	}
	// We perform the easy part of the final exp to push f to the cyclotomic
	// subgroup so that AssertFinalExponentiationIsOne is carried with optimized
	// cyclotomic squaring (e.g. Karabina12345).
	//
	// f = f^(p⁶-1)(p²+1)
	var buf GT
	buf.Conjugate(api, f)
	buf.DivUnchecked(api, buf, f)
	f.FrobeniusSquare(api, buf).
		Mul(api, f, buf)

	f.AssertFinalExponentiationIsOne(api)

	return nil
}

// DoublePairingCheck calculates the reduced pairing for 2 pairs of points and asserts if the result is One
// e(P0, Q0) * e(P1, Q1) =? 1
//
// This function doesn't check that the inputs are in the correct subgroups
func DoublePairingCheck(api frontend.API, P [2]G1Affine, Q [2]G2Affine) error {
	// hint the non-residue witness
	hint, err := api.NewHint(doublePairingCheckHint, 18, P[0].X, P[0].Y, P[1].X, P[1].Y, Q[0].P.X.A0, Q[0].P.X.A1, Q[0].P.Y.A0, Q[0].P.Y.A1, Q[1].P.X.A0, Q[1].P.X.A1, Q[1].P.Y.A0, Q[1].P.Y.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var residueWitness, residueWitnessInv, scalingFactor, t0 fields_bls12377.E12
	residueWitness.C0.B0.A0 = hint[0]
	residueWitness.C0.B0.A1 = hint[1]
	residueWitness.C0.B1.A0 = hint[2]
	residueWitness.C0.B1.A1 = hint[3]
	residueWitness.C0.B2.A0 = hint[4]
	residueWitness.C0.B2.A1 = hint[5]
	residueWitness.C1.B0.A0 = hint[6]
	residueWitness.C1.B0.A1 = hint[7]
	residueWitness.C1.B1.A0 = hint[8]
	residueWitness.C1.B1.A1 = hint[9]
	residueWitness.C1.B2.A0 = hint[10]
	residueWitness.C1.B2.A1 = hint[11]
	// constrain cubicNonResiduePower to be in Fp6
	scalingFactor.C0.B0.A0 = hint[12]
	scalingFactor.C0.B0.A1 = hint[13]
	scalingFactor.C0.B1.A0 = hint[14]
	scalingFactor.C0.B1.A1 = hint[15]
	scalingFactor.C0.B2.A0 = hint[16]
	scalingFactor.C0.B2.A1 = hint[17]
	scalingFactor.C1.SetZero()

	// residueWitnessInv = 1 / residueWitness
	residueWitnessInv.Inverse(api, residueWitness)

	if Q[0].Lines == nil {
		Q0lines := computeLines(api, Q[0].P)
		Q[0].Lines = Q0lines
	}
	lines0 := *Q[0].Lines
	if Q[1].Lines == nil {
		Q1lines := computeLines(api, Q[1].P)
		Q[1].Lines = Q1lines
	}
	lines1 := *Q[1].Lines

	// precomputations
	y0Inv := api.Inverse(P[0].Y)
	x0NegOverY0 := api.Mul(P[0].X, y0Inv)
	x0NegOverY0 = api.Neg(x0NegOverY0)
	y1Inv := api.Inverse(P[1].Y)
	x1NegOverY1 := api.Mul(P[1].X, y1Inv)
	x1NegOverY1 = api.Neg(x1NegOverY1)

	// init Miller loop accumulator to residueWitness to share the squarings
	// of residueWitnessInv^{-x₀}
	res := residueWitness

	// Compute f_{x₀,Q}(P)
	var prodLines [5]fields_bls12377.E2
	var l0, l1 lineEvaluation
	for i := 62; i >= 0; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		if loopCounter[i] == 0 {
			// line evaluation at P
			// ℓ × res
			res.MulBy034(api,
				*l0.R0.MulByFp(api, lines0[0][i].R0, x0NegOverY0),
				*l0.R1.MulByFp(api, lines0[0][i].R1, y0Inv),
			)
			// ℓ × res
			res.MulBy034(api,
				*l0.R0.MulByFp(api, lines1[0][i].R0, x1NegOverY1),
				*l0.R1.MulByFp(api, lines1[0][i].R1, y1Inv),
			)
		} else {
			// multiply by residueWitness when bit=1
			res.Mul(api, res, residueWitness)

			// lines evaluation at P
			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api,
				*l0.R0.MulByFp(api, lines0[0][i].R0, x0NegOverY0),
				*l0.R1.MulByFp(api, lines0[0][i].R1, y0Inv),
				*l1.R0.MulByFp(api, lines0[1][i].R0, x0NegOverY0),
				*l1.R1.MulByFp(api, lines0[1][i].R1, y0Inv),
			)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
			// lines evaluation at P
			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api,
				*l0.R0.MulByFp(api, lines1[0][i].R0, x1NegOverY1),
				*l0.R1.MulByFp(api, lines1[0][i].R1, y1Inv),
				*l1.R0.MulByFp(api, lines1[1][i].R0, x1NegOverY1),
				*l1.R1.MulByFp(api, lines1[1][i].R1, y1Inv),
			)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
		}
	}

	// Check that  res * scalingFactor * residueWitnessInv^λ' == 1
	// where λ' = q, with u the BLS12-377 seed
	// and residueWitnessInv, scalingFactor from the hint.
	// Note that res is already MillerLoop(P,Q) * residueWitnessInv^{x₀} since
	// we initialized the Miller loop accumulator with residueWitnessInv.
	t0.Frobenius(api, residueWitnessInv)
	t0.Mul(api, t0, res)
	t0.Mul(api, t0, scalingFactor)

	var one GT
	one.SetOne()
	t0.AssertIsEqual(api, one)

	return nil

}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleAndAddStep(api frontend.API, p1, p2 *g2AffP) (g2AffP, *lineEvaluation, *lineEvaluation) {

	var n, d, l1, l2, x3, x4, y4 fields_bls12377.E2
	var line1, line2 lineEvaluation
	var p g2AffP

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-(p1.x+p2.x)
	x3.Square(api, l1)
	n.Add(api, p1.X, p2.X)
	x3.Sub(api, x3, n)

	// omit y3 computation

	// compute line1
	line1.R0 = l1
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute x4 = lambda2**2-(x1+x3)
	x4.Square(api, l2)
	n.Add(api, p1.X, x3)
	x4.Sub(api, x4, n)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4.Sub(api, p1.X, x4).
		Mul(api, l2, y4).
		Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4

	// compute line2
	line2.R0 = l2
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return p, &line1, &line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleStep(api frontend.API, p1 *g2AffP) (g2AffP, *lineEvaluation) {

	var n, d, l, xr, yr fields_bls12377.E2
	var p g2AffP
	var line lineEvaluation

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.DivUnchecked(api, n, d)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l)
	n.MulByFp(api, p1.X, 2)
	xr.Sub(api, xr, n)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	line.R0 = l
	line.R1.Mul(api, l, p1.X).Sub(api, line.R1, p1.Y)

	return p, &line

}

// linesCompute computes the lines that goes through p1 and p2, and (p1+p2) and p1 but does not compute 2p1+p2
func linesCompute(api frontend.API, p1, p2 *g2AffP) (*lineEvaluation, *lineEvaluation) {

	var n, d, l1, l2, x3 fields_bls12377.E2
	var line1, line2 lineEvaluation

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-p1.x-p2.x
	x3.Square(api, l1)
	n.Add(api, p1.X, p2.X)
	x3.Sub(api, x3, n)

	// omit y3 computation
	// compute line1
	line1.R0 = l1
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute line2
	line2.R0 = l2
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return &line1, &line2
}
