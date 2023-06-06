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

package sw_bls24315

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls24315"
)

// GT target group of the pairing
type GT = fields_bls24315.E24

const ateLoop = 3218079743

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
// line: 1 + R0(x/y) + R1(1/y) = 0 instead of R0'*y + R1'*x + R2' = 0 This
// makes the multiplication by lines (MulBy034) and between lines (Mul034By034)
type lineEvaluation struct {
	R0, R1 fields_bls24315.E4
}

// MillerLoop computes the product of n miller loops (n can be 1)
// ∏ᵢ { fᵢ_{x₀,Q}(P) }
func MillerLoop(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	var ateLoop2NAF [33]int8
	ecc.NafDecomposition(big.NewInt(ateLoop), ateLoop2NAF[:])

	var res GT
	res.SetOne()
	var prodLines [5]fields_bls24315.E4

	var l1, l2 lineEvaluation
	Qacc := make([]G2Affine, n)
	Qneg := make([]G2Affine, n)
	yInv := make([]frontend.Variable, n)
	xOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		Qacc[k] = Q[k]
		Qneg[k].Neg(api, Q[k])
		// TODO: point P=(x,O) should be ruled out
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xOverY[k] = api.Mul(P[k].X, yInv[k])
	}

	// Compute ∏ᵢ { fᵢ_{x₀,Q}(P) }
	// i = 32, separately to avoid an E24 Square
	// (Square(res) = 1² = 1)

	// k = 0, separately to avoid MulBy034 (res × ℓ)
	// (assign line to res)
	Qacc[0], l1 = doubleStep(api, &Qacc[0])
	res.D1.C0.MulByFp(api, l1.R0, xOverY[0])
	res.D1.C1.MulByFp(api, l1.R1, yInv[0])

	if n >= 2 {
		// k = 1, separately to avoid MulBy034 (res × ℓ)
		// (res is also a line at this point, so we use Mul034By034 ℓ × ℓ)
		Qacc[1], l1 = doubleStep(api, &Qacc[1])

		// line evaluation at P[1]
		l1.R0.MulByFp(api, l1.R0, xOverY[1])
		l1.R1.MulByFp(api, l1.R1, yInv[1])

		// ℓ × res
		prodLines = *fields_bls24315.Mul034By034(api, l1.R0, l1.R1, res.D1.C0, res.D1.C1)
		res.D0.C0 = prodLines[0]
		res.D0.C1 = prodLines[1]
		res.D0.C2 = prodLines[2]
		res.D1.C0 = prodLines[3]
		res.D1.C1 = prodLines[4]

	}

	if n >= 3 {
		// k >= 2
		for k := 2; k < n; k++ {
			// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
			Qacc[k], l1 = doubleStep(api, &Qacc[k])

			// line evaluation at P[k]
			l1.R0.MulByFp(api, l1.R0, xOverY[k])
			l1.R1.MulByFp(api, l1.R1, yInv[k])

			// ℓ × res
			res.MulBy034(api, l1.R0, l1.R1)
		}
	}

	// i = 30, separately to avoid a doubleStep
	// (at this point Qacc = 2Q, so 2Qacc-Q=3Q is equivalent to Qacc+Q=3Q
	// this means doubleAndAddStep is equivalent to addStep here)
	res.Square(api, res)
	for k := 0; k < n; k++ {
		// l2 the line passing Qacc[k] and -Q
		l2 = lineCompute(api, &Qacc[k], &Qneg[k])

		// line evaluation at P[k]
		l2.R0.MulByFp(api, l2.R0, xOverY[k])
		l2.R1.MulByFp(api, l2.R1, yInv[k])

		// Qacc[k] ← Qacc[k]+Q[k] and
		// l1 the line ℓ passing Qacc[k] and Q[k]
		Qacc[k], l1 = addStep(api, &Qacc[k], &Q[k])

		// line evaluation at P[k]
		l1.R0.MulByFp(api, l1.R0, xOverY[k])
		l1.R1.MulByFp(api, l1.R1, yInv[k])

		// ℓ × res
		res.MulBy034(api, l1.R0, l1.R1)
		// ℓ × res
		res.MulBy034(api, l2.R0, l2.R1)
	}

	for i := 29; i >= 1; i-- {
		// mutualize the square among n Miller loops
		// (∏ᵢfᵢ)²
		res.Square(api, res)

		switch ateLoop2NAF[i] {
		case 0:
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k] and l1 the tangent ℓ passing 2Qacc[k]
				Qacc[k], l1 = doubleStep(api, &Qacc[k])

				// line evaluation at P[k]
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l1.R0, l1.R1)
			}
		case 1:
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k]+Q[k],
				// l1 the line ℓ passing Qacc[k] and Q[k]
				// l2 the line ℓ passing (Qacc[k]+Q[k]) and Qacc[k]
				Qacc[k], l1, l2 = doubleAndAddStep(api, &Qacc[k], &Q[k])

				// line evaluation at P[k]
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l1.R0, l1.R1)

				// line evaluation at P[k]
				l2.R0.MulByFp(api, l2.R0, xOverY[k])
				l2.R1.MulByFp(api, l2.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l2.R0, l2.R1)
			}
		case -1:
			for k := 0; k < n; k++ {
				// Qacc[k] ← 2Qacc[k]-Q[k],
				// l1 the line ℓ passing Qacc[k] and Q[k]
				// l2 the line ℓ passing (Qacc[k]-Q[k]) and Qacc[k]
				Qacc[k], l1, l2 = doubleAndAddStep(api, &Qacc[k], &Qneg[k])

				// line evaluation at P[k]
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l1.R0, l1.R1)

				// line evaluation at P[k]
				l2.R0.MulByFp(api, l2.R0, xOverY[k])
				l2.R1.MulByFp(api, l2.R1, yInv[k])

				// ℓ × res
				res.MulBy034(api, l2.R0, l2.R1)
			}
		default:
			return GT{}, errors.New("invalid loopCounter")
		}
	}

	// i = 0
	res.Square(api, res)
	for k := 0; k < n; k++ {
		// l1 the line ℓ passing Qacc[k] and -Q[k]
		// l2 the line ℓ passing (Qacc[k]-Q[k]) and Qacc[k]
		l1, l2 = linesCompute(api, &Qacc[k], &Qneg[k])

		// line evaluation at P[k]
		l1.R0.MulByFp(api, l1.R0, xOverY[k])
		l1.R1.MulByFp(api, l1.R1, yInv[k])

		// ℓ × res
		res.MulBy034(api, l1.R0, l1.R1)

		// line evaluation at P[k]
		l2.R0.MulByFp(api, l2.R0, xOverY[k])
		l2.R1.MulByFp(api, l2.R1, yInv[k])

		// ℓ × res
		res.MulBy034(api, l2.R0, l2.R1)
	}

	res.Conjugate(api, res)

	return res, nil
}

// FinalExponentiation computes the exponentiation e1ᵈ
// where d = (p²⁴-1)/r = (p²⁴-1)/Φ₂₄(p) ⋅ Φ₂₄(p)/r = (p¹²-1)(p⁴+1)(p⁸ - p⁴ +1)/r
// we use instead d=s ⋅ (p¹²-1)(p⁴+1)(p⁸ - p⁴ +1)/r
// where s is the cofactor 3 (Hayashida et al.)
func FinalExponentiation(api frontend.API, e1 GT) GT {
	const genT = ateLoop
	result := e1

	// https://eprint.iacr.org/2012/232.pdf, section 7
	var t [9]GT

	// easy part
	// (p¹²-1)(p⁴+1)
	t[0].Conjugate(api, result)
	t[0].DivUnchecked(api, t[0], result)
	result.FrobeniusQuad(api, t[0]).
		Mul(api, result, t[0])

	// hard part (api, up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	// 3(p⁸ - p⁴ +1)/r = (x₀-1)² * (x₀+p) * (x₀²+p²) * (x₀⁴+p⁴-1) + 3
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
	t[2].Mul(api, t[0], t[2])
	t[1].Expt(api, t[2], genT)
	t[1].Expt(api, t[1], genT)
	t[1].Expt(api, t[1], genT)
	t[1].Expt(api, t[1], genT)
	t[0].FrobeniusQuad(api, t[2])
	t[0].Mul(api, t[0], t[1])
	t[2].Conjugate(api, t[2])
	t[0].Mul(api, t[0], t[2])
	result.Mul(api, result, t[0])

	return result
}

// PairingCheck calculates the reduced pairing for a set of points and returns True if the result is One
// ∏ᵢ e(Pᵢ, Qᵢ) =? 1
//
// This function doesn't check that the inputs are in the correct subgroup. See IsInSubGroup.
func Pair(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	f, err := MillerLoop(api, P, Q)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiation(api, f), nil
}

// doubleAndAddStep doubles p1 and adds p2 to the result in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleAndAddStep(api frontend.API, p1, p2 *G2Affine) (G2Affine, lineEvaluation, lineEvaluation) {

	var n, d, l1, l2, x3, x4, y4 fields_bls24315.E4
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
	line1.R0.Neg(api, l1)
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
	line2.R0.Neg(api, l2)
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return p, line1, line2
}

// doubleStep doubles a point in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func doubleStep(api frontend.API, p1 *G2Affine) (G2Affine, lineEvaluation) {

	var n, d, l, xr, yr fields_bls24315.E4
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

	line.R0.Neg(api, l)
	line.R1.Mul(api, l, p1.X).Sub(api, line.R1, p1.Y)

	return p, line

}

// addStep adds two points in affine coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2022/1162 (Section 6.1)
func addStep(api frontend.API, p1, p2 *G2Affine) (G2Affine, lineEvaluation) {

	var p2ypy, p2xpx, λ, λλ, pxrx, λpxrx, xr, yr fields_bls24315.E4
	// compute λ = (y2-y1)/(x2-x1)
	p2ypy.Sub(api, p2.Y, p1.Y)
	p2xpx.Sub(api, p2.X, p1.X)
	λ.DivUnchecked(api, p2ypy, p2xpx)

	// xr = λ²-x1-x2
	λλ.Square(api, λ)
	p2xpx.Add(api, p1.X, p2.X)
	xr.Sub(api, λλ, p2xpx)

	// yr = λ(x1-xr) - y1
	pxrx.Sub(api, p1.X, xr)
	λpxrx.Mul(api, λ, pxrx)
	yr.Sub(api, λpxrx, p1.Y)

	var res G2Affine
	res.X = xr
	res.Y = yr

	var line lineEvaluation
	line.R0.Neg(api, λ)
	line.R1.Mul(api, λ, p1.X)
	line.R1.Sub(api, line.R1, p1.Y)

	return res, line

}

// linesCompute computes the lines that goes through p1 and p2, and (p1+p2) and p1 but does not compute 2p1+p2
func linesCompute(api frontend.API, p1, p2 *G2Affine) (lineEvaluation, lineEvaluation) {

	var n, d, l1, l2, x3 fields_bls24315.E4
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
	line1.R0.Neg(api, l1)
	line1.R1.Mul(api, l1, p1.X).Sub(api, line1.R1, p1.Y)

	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.DivUnchecked(api, n, d)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute line2
	line2.R0.Neg(api, l2)
	line2.R1.Mul(api, l2, p1.X).Sub(api, line2.R1, p1.Y)

	return line1, line2
}

// lineCompute computes the line that goes through p1 and p2 but does not compute p1+p2
func lineCompute(api frontend.API, p1, p2 *G2Affine) lineEvaluation {

	var qypy, qxpx, λ fields_bls24315.E4

	// compute λ = (y2-y1)/(x2-x1)
	qypy.Sub(api, p2.Y, p1.Y)
	qxpx.Sub(api, p2.X, p1.X)
	λ.DivUnchecked(api, qypy, qxpx)

	var line lineEvaluation
	line.R0.Neg(api, λ)
	line.R1.Mul(api, λ, p1.X)
	line.R1.Sub(api, line.R1, p1.Y)

	return line

}
