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

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy034) and between lines (Mul034By034)
// circuit-efficient.
type lineEvaluation struct {
	R0, R1 fields_bls12377.E2
}

type LineEvaluations struct {
	Eval [63]lineEvaluation
}

// MillerLoop computes the product of n miller loops (n can be 1)
// ∏ᵢ { fᵢ_{x₀,Q}(P) }
func MillerLoop(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	var res GT
	res.SetOne()
	var prodLines [5]fields_bls12377.E2

	var l1, l2 lineEvaluation
	Qacc := make([]G2Affine, n)
	yInv := make([]frontend.Variable, n)
	xNegOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		Qacc[k] = Q[k]
		// x=0x1ae3a4617c510eac63b05c06ca1493b1a22d9f300f5138f1ef3622fba094800170b5d44300000008508c00000000000
		// TODO: point P=(x,0) should be ruled out
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xNegOverY[k] = api.Mul(P[k].X, yInv[k])
		xNegOverY[k] = api.Neg(xNegOverY[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	// i = 62, separately to avoid an E12 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	Qacc[0], l1 = doubleStep(api, &Qacc[0])
	// line evaluation at P[0]
	res.C1.B0.MulByFp(api, l1.R0, xNegOverY[0])
	res.C1.B1.MulByFp(api, l1.R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		Qacc[1], l1 = doubleStep(api, &Qacc[1])

		// line evaluation at P[1]
		l1.R0.MulByFp(api, l1.R0, xNegOverY[1])
		l1.R1.MulByFp(api, l1.R1, yInv[1])

		// ℓ × res
		prodLines = *fields_bls12377.Mul034By034(api, l1.R0, l1.R1, res.C1.B0, res.C1.B1)
		res.C0.B0 = prodLines[0]
		res.C0.B1 = prodLines[1]
		res.C0.B2 = prodLines[2]
		res.C1.B0 = prodLines[3]
		res.C1.B1 = prodLines[4]

	}

	if n >= 3 {
		// k = 2, separately to avoid MulBy034 (res × ℓ)
		// (res has a zero E2 element, so we use Mul01234By034)
		Qacc[2], l1 = doubleStep(api, &Qacc[2])

		// line evaluation at P[1]
		l1.R0.MulByFp(api, l1.R0, xNegOverY[2])
		l1.R1.MulByFp(api, l1.R1, yInv[2])

		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api, prodLines, l1.R0, l1.R1)

		// k >= 3
		for k := 3; k < n; k++ {
			// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
			Qacc[k], l1 = doubleStep(api, &Qacc[k])

			// line evaluation at P[k]
			l1.R0.MulByFp(api, l1.R0, xNegOverY[k])
			l1.R1.MulByFp(api, l1.R1, yInv[k])

			// ℓ × res
			res.MulBy034(api, l1.R0, l1.R1)
		}
	}

	// i = 61, separately to use a special E12 Square
	// k = 0
	// Qacc[0] ← 2Qacc[0] and l1 the tangent ℓ passing 2Qacc[0]
	Qacc[0], l1 = doubleStep(api, &Qacc[0])
	// line evaluation at P[0]
	l1.R0.MulByFp(api, l1.R0, xNegOverY[0])
	l1.R1.MulByFp(api, l1.R1, yInv[0])

	if n == 1 {
		res.Square034(api, res)
		prodLines[0] = res.C0.B0
		prodLines[1] = res.C0.B1
		prodLines[2] = res.C0.B2
		prodLines[3] = res.C1.B0
		prodLines[4] = res.C1.B1
		// ℓ × res
		res = *fields_bls12377.Mul01234By034(api, prodLines, l1.R0, l1.R1)

	} else {
		res.Square(api, res)
		// ℓ × res
		res.MulBy034(api, l1.R0, l1.R1)

	}

	for k := 1; k < n; k++ {
		// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
		Qacc[k], l1 = doubleStep(api, &Qacc[k])

		// line evaluation at P[k]
		l1.R0.MulByFp(api, l1.R0, xNegOverY[k])
		l1.R1.MulByFp(api, l1.R1, yInv[k])

		// ℓ × res
		res.MulBy034(api, l1.R0, l1.R1)
	}

	for i := 60; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		if loopCounter[i] == 0 {
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
				Qacc[k], l1 = doubleStep(api, &Qacc[k])

				// line evaluation at P[k]
				l1.R0.MulByFp(api, l1.R0, xNegOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l1.R0, l1.R1)
			}
			continue
		}

		for k := 0; k < n; k++ {
			// Qacc[k] ← 2Qacc[k]+Q[k],
			// l1 the line ℓ passing Qacc[k] and Q[k]
			// l2 the line ℓ passing (Qacc[k]+Q[k]) and Qacc[k]
			Qacc[k], l1, l2 = doubleAndAddStep(api, &Qacc[k], &Q[k])

			// lines evaluation at P[k]
			l1.R0.MulByFp(api, l1.R0, xNegOverY[k])
			l1.R1.MulByFp(api, l1.R1, yInv[k])
			l2.R0.MulByFp(api, l2.R0, xNegOverY[k])
			l2.R1.MulByFp(api, l2.R1, yInv[k])

			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api, l1.R0, l1.R1, l2.R0, l2.R1)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
		}
	}

	// i = 0
	res.Square(api, res)
	for k := 0; k < n; k++ {
		// l1 line through Qacc[k] and Q[k]
		// l2 line through Qacc[k]+Q[k] and Qacc[k]
		l1, l2 = linesCompute(api, &Qacc[k], &Q[k])

		l1.R0.MulByFp(api, l1.R0, xNegOverY[k])
		l1.R1.MulByFp(api, l1.R1, yInv[k])
		l2.R0.MulByFp(api, l2.R0, xNegOverY[k])
		l2.R1.MulByFp(api, l2.R1, yInv[k])

		// ℓ × ℓ
		prodLines = *fields_bls12377.Mul034By034(api, l1.R0, l1.R1, l2.R0, l2.R1)
		// (ℓ × ℓ) × res
		res.MulBy01234(api, prodLines)
	}

	return res, nil
}

// FinalExponentiation computes the exponentiation e1ᵈ
// where d = (p¹²-1)/r = (p¹²-1)/Φ₁₂(p) ⋅ Φ₁₂(p)/r = (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// we use instead d=s ⋅ (p⁶-1)(p²+1)(p⁴ - p² +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func FinalExponentiation(api frontend.API, e1 GT) GT {
	const genT = 9586122913090633729

	result := e1

	// https://eprint.iacr.org/2016/130.pdf
	var t [3]GT

	// easy part
	// (p⁶-1)(p²+1)
	t[0].Conjugate(api, result)
	t[0].DivUnchecked(api, t[0], result)
	result.FrobeniusSquare(api, t[0]).
		Mul(api, result, t[0])

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	t[0].CyclotomicSquare(api, result)
	t[1].Expt(api, result, genT)
	t[2].Conjugate(api, result)
	t[1].Mul(api, t[1], t[2])
	t[2].Expt(api, t[1], genT)
	t[1].Conjugate(api, t[1])
	t[1].Mul(api, t[1], t[2])
	t[2].Expt(api, t[1], genT)
	t[1].Frobenius(api, t[1])
	t[1].Mul(api, t[1], t[2])
	result.Mul(api, result, t[0])
	t[0].Expt(api, t[1], genT)
	t[2].Expt(api, t[0], genT)
	t[0].FrobeniusSquare(api, t[1])
	t[1].Conjugate(api, t[1])
	t[1].Mul(api, t[1], t[2])
	t[1].Mul(api, t[1], t[0])
	result.Mul(api, result, t[1])

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
	f, err := Pair(api, P, Q)
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	f.AssertIsEqual(api, one)

	return nil
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleAndAddStep(api frontend.API, p1, p2 *G2Affine) (G2Affine, lineEvaluation, lineEvaluation) {

	var n, d, l1, l2, x3, x4, y4 fields_bls12377.E2
	var line1, line2 lineEvaluation
	var p G2Affine

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-p1.x-p2.x
	x3.Square(api, l1).
		Sub(api, x3, p1.X).
		Sub(api, x3, p2.X)

		// omit y3 computation

		// compute line1
	line1.R0 = l1
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute x4 = lambda2**2-x1-x3
	x4.Square(api, l2).
		Sub(api, x4, p1.X).
		Sub(api, x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4.Sub(api, p1.X, x4).
		Mul(api, l2, y4).
		Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4

	// compute line2
	line2.R0 = l2
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return p, line1, line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleStep(api frontend.API, p1 *G2Affine) (G2Affine, lineEvaluation) {

	var n, d, l, xr, yr fields_bls12377.E2
	var p G2Affine
	var line lineEvaluation

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.DivUnchecked(api, n, d)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l).
		Sub(api, xr, p1.X).
		Sub(api, xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	line.R0 = l
	line.R1.Mul(api, l, p1.X).Sub(api, line.R1, p1.Y)

	return p, line

}

// linesCompute computes the lines that goes through p1 and p2, and (p1+p2) and p1 but does not compute 2p1+p2
func linesCompute(api frontend.API, p1, p2 *G2Affine) (lineEvaluation, lineEvaluation) {

	var n, d, l1, l2, x3 fields_bls12377.E2
	var line1, line2 lineEvaluation

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.DivUnchecked(api, n, d)

	// x3 =lambda1**2-p1.x-p2.x
	x3.Square(api, l1).
		Sub(api, x3, p1.X).
		Sub(api, x3, p2.X)

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

	return line1, line2
}

// ----------------------------
//	  Fixed-argument pairing
// ----------------------------

// MillerLoopFixedQ computes the multi-Miller loop as in MillerLoop
// but Qᵢ are fixed points in G2 known in advance.
func MillerLoopFixedQ(api frontend.API, P []G1Affine, lines []*[2]LineEvaluations) (GT, error) {

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
	res.C1.B0.MulByFp(api, lines[0][0].Eval[62].R0, xNegOverY[0])
	res.C1.B1.MulByFp(api, lines[0][0].Eval[62].R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		// line evaluation at P[1]

		// ℓ × res
		prodLines = *fields_bls12377.Mul034By034(api,
			*l0.R0.MulByFp(api, lines[1][0].Eval[62].R0, xNegOverY[1]),
			*l0.R1.MulByFp(api, lines[1][0].Eval[62].R1, yInv[1]),
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
			*l0.R0.MulByFp(api, lines[2][0].Eval[62].R0, xNegOverY[2]),
			*l0.R1.MulByFp(api, lines[2][0].Eval[62].R1, yInv[2]),
		)

		// k >= 3
		for k := 3; k < n; k++ {
			// line evaluation at P[k]

			// ℓ × res
			res.MulBy034(api,
				*l0.R0.MulByFp(api, lines[k][0].Eval[62].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0].Eval[62].R1, yInv[k]),
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
			*l0.R0.MulByFp(api, lines[0][0].Eval[61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0].Eval[61].R1, yInv[0]),
		)

	} else {
		res.Square(api, res)
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[0][0].Eval[61].R0, xNegOverY[0]),
			*l0.R1.MulByFp(api, lines[0][0].Eval[61].R1, yInv[0]),
		)

	}

	for k := 1; k < n; k++ {
		// line evaluation at P[k]
		// ℓ × res
		res.MulBy034(api,
			*l0.R0.MulByFp(api, lines[k][0].Eval[61].R0, xNegOverY[k]),
			*l0.R1.MulByFp(api, lines[k][0].Eval[61].R1, yInv[k]),
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
					*l0.R0.MulByFp(api, lines[k][0].Eval[i].R0, xNegOverY[k]),
					*l0.R1.MulByFp(api, lines[k][0].Eval[i].R1, yInv[k]),
				)
				continue

			}

			// lines evaluation at P

			// ℓ × ℓ
			prodLines = *fields_bls12377.Mul034By034(api,
				*l0.R0.MulByFp(api, lines[k][0].Eval[i].R0, xNegOverY[k]),
				*l0.R1.MulByFp(api, lines[k][0].Eval[i].R1, yInv[k]),
				*l1.R0.MulByFp(api, lines[k][1].Eval[i].R0, xNegOverY[k]),
				*l1.R1.MulByFp(api, lines[k][1].Eval[i].R1, yInv[k]),
			)
			// (ℓ × ℓ) × res
			res.MulBy01234(api, prodLines)
		}
	}

	return res, nil
}

// PairFixedQ calculates the reduced pairing for a set of points
// e(P, g2), where g2 is fixed.
//
// This function doesn't check that the inputs are in the correct subgroups.
func PairFixedQ(api frontend.API, P []G1Affine, lines []*[2]LineEvaluations) (GT, error) {
	f, err := MillerLoopFixedQ(api, P, lines)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiation(api, f), nil
}

// PairingFixedQCheck calculates the reduced pairing for a set of points and asserts if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1 where Qᵢ are fixed.
//
// This function doesn't check that the inputs are in the correct subgroups
func PairingFixedQCheck(api frontend.API, P []G1Affine, lines []*[2]LineEvaluations) error {
	f, err := PairFixedQ(api, P, lines)
	if err != nil {
		return err
	}
	var one GT
	one.SetOne()
	f.AssertIsEqual(api, one)

	return nil
}
