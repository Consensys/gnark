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
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls24315"
)

// LineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
type LineEvaluation struct {
	R0, R1 fields_bls24315.E4
}

// MillerLoop computes the miller loop
func MillerLoop(api frontend.API, P G1Affine, Q G2Affine) fields_bls24315.E24 {

	var ateLoop2NAF [33]int8
	optimaAteLoop, _ := new(big.Int).SetString("3218079743", 10)
	ecc.NafDecomposition(optimaAteLoop, ateLoop2NAF[:])

	var res fields_bls24315.E24
	res.SetOne()

	var l1, l2 LineEvaluation
	var Qacc, Qneg G2Affine
	Qacc = Q
	Qneg.Neg(api, &Q)
	yInv := api.DivUnchecked(1, P.Y)
	xOverY := api.DivUnchecked(P.X, P.Y)

	for i := len(ateLoop2NAF) - 2; i >= 0; i-- {
		res.Square(api, res)

		if ateLoop2NAF[i] == 0 {
			Qacc, l1 = DoubleStep(api, &Qacc)
			l1.R0.MulByFp(api, l1.R0, xOverY)
			l1.R1.MulByFp(api, l1.R1, yInv)
			res.MulBy034(api, l1.R0, l1.R1)
		} else if ateLoop2NAF[i] == 1 {
			Qacc, l1, l2 = DoubleAndAddStep(api, &Qacc, &Q)
			l1.R0.MulByFp(api, l1.R0, xOverY)
			l1.R1.MulByFp(api, l1.R1, yInv)
			res.MulBy034(api, l1.R0, l1.R1)
			l2.R0.MulByFp(api, l2.R0, xOverY)
			l2.R1.MulByFp(api, l2.R1, yInv)
			res.MulBy034(api, l2.R0, l2.R1)
		} else {
			Qacc, l1, l2 = DoubleAndAddStep(api, &Qacc, &Qneg)
			l1.R0.MulByFp(api, l1.R0, xOverY)
			l1.R1.MulByFp(api, l1.R1, yInv)
			res.MulBy034(api, l1.R0, l1.R1)
			l2.R0.MulByFp(api, l2.R0, xOverY)
			l2.R1.MulByFp(api, l2.R1, yInv)
			res.MulBy034(api, l2.R0, l2.R1)
		}
	}

	res.Conjugate(api, res)

	return res
}

// FinalExponentiation computes the final expo x**(p**12-1)(p**4+1)(p**8 - p**4 +1)/r
func FinalExponentiation(api frontend.API, e1 fields_bls24315.E24) fields_bls24315.E24 {
	const ateLoop = 3218079743
	const genT = ateLoop
	result := e1

	// https://eprint.iacr.org/2012/232.pdf, section 7
	var t [9]fields_bls24315.E24

	// easy part
	t[0].Conjugate(api, result)
	t[0].DivUnchecked(api, t[0], result)
	result.FrobeniusQuad(api, t[0]).
		Mul(api, result, t[0])

	// hard part (api, up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	// 3*Phi_24(api, p)/r = (api, u-1)² * (api, u+p) * (api, u²+p²) * (api, u⁴+p⁴-1) + 3
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

// DoubleAndAddStep
func DoubleAndAddStep(api frontend.API, p1, p2 *G2Affine) (G2Affine, LineEvaluation, LineEvaluation) {

	var n, d, l1, l2, x3, x4, y4 fields_bls24315.E4
	var line1, line2 LineEvaluation
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

func DoubleStep(api frontend.API, p1 *G2Affine) (G2Affine, LineEvaluation) {

	var n, d, l, xr, yr fields_bls24315.E4
	var p G2Affine
	var line LineEvaluation

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

// TripleMillerLoop computes the product of three miller loops
func TripleMillerLoop(api frontend.API, P [3]G1Affine, Q [3]G2Affine) fields_bls24315.E24 {

	var ateLoop2NAF [33]int8
	optimaAteLoop, _ := new(big.Int).SetString("3218079743", 10)
	ecc.NafDecomposition(optimaAteLoop, ateLoop2NAF[:])

	var res fields_bls24315.E24
	res.SetOne()

	var l1, l2 LineEvaluation
	Qacc := make([]G2Affine, 3)
	Qneg := make([]G2Affine, 3)
	yInv := make([]frontend.Variable, 3)
	xOverY := make([]frontend.Variable, 3)
	for k := 0; k < 3; k++ {
		Qacc[k] = Q[k]
		Qneg[k].Neg(api, &Q[k])
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xOverY[k] = api.DivUnchecked(P[k].X, P[k].Y)
	}

	for i := len(ateLoop2NAF) - 2; i >= 0; i-- {
		res.Square(api, res)

		if ateLoop2NAF[i] == 0 {
			for k := 0; k < 3; k++ {
				Qacc[k], l1 = DoubleStep(api, &Qacc[k])
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])
				res.MulBy034(api, l1.R0, l1.R1)
			}
		} else if ateLoop2NAF[i] == 1 {
			for k := 0; k < 3; k++ {
				Qacc[k], l1, l2 = DoubleAndAddStep(api, &Qacc[k], &Q[k])
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])
				res.MulBy034(api, l1.R0, l1.R1)
				l2.R0.MulByFp(api, l2.R0, xOverY[k])
				l2.R1.MulByFp(api, l2.R1, yInv[k])
				res.MulBy034(api, l2.R0, l2.R1)
			}
		} else {
			for k := 0; k < 3; k++ {
				Qacc[k], l1, l2 = DoubleAndAddStep(api, &Qacc[k], &Qneg[k])
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])
				res.MulBy034(api, l1.R0, l1.R1)
				l2.R0.MulByFp(api, l2.R0, xOverY[k])
				l2.R1.MulByFp(api, l2.R1, yInv[k])
				res.MulBy034(api, l2.R0, l2.R1)
			}
		}
	}

	res.Conjugate(api, res)

	return res
}
