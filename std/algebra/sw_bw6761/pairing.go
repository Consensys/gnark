/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package sw_bw6761

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bw6761"
	"math/big"
)

var (
	thirdRootOneG1, _ = new(big.Int).SetString("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650", 10)
	thirdRootOneG2    = new(big.Int).Mul(thirdRootOneG1, thirdRootOneG1)
	loopCounter0      = [190]int8{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	loopCounter1      [190]int8
	// x₀³-x₀²-x₀
	T, _ = new(big.Int).SetString("880904806456922042166256752416502360955572640081583800319", 10)
)

func init() {
	ecc.NafDecomposition(T, loopCounter1[:])
}

// GT target group of the pairing
type GT = fields_bw6761.E6

type lineEvaluation struct {
	r0 frontend.Variable
	r1 frontend.Variable
	r2 frontend.Variable
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup. See IsInSubGroup.
func Pair(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	f, err := MillerLoop(api, P, Q)
	if err != nil {
		return GT{}, err
	}
	return FinalExponentiation(api, f), nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p^6-1)/r = (p^6-1)/Φ_6(p) ⋅ Φ_6(p)/r = (p^3-1)(p+1)(p^2 - p +1)/r
// we use instead d=s ⋅ (p^3-1)(p+1)(p^2 - p +1)/r
// where s is the cofactor 12(x_0+1) (El Housni and Guillevic)
func FinalExponentiation(api frontend.API, z GT, _z ...GT) GT {

	var result GT
	result.Set(z)

	for _, e := range _z {
		result.Mul(api, result, e)
	}

	var buf GT

	// Easy part
	// (p^3-1)(p+1)
	buf.Conjugate(api, result)
	result.Inverse(api, result)
	buf.Mul(api, buf, result)
	result.Frobenius(api, buf).
		Mul(api, result, buf)

	// Hard part (up to permutation)
	// El Housni and Guillevic
	// https://eprint.iacr.org/2020/351.pdf
	var m1, _m1, m2, _m2, m3, f0, f0_36, g0, g1, _g1, g2, g3, _g3, g4, _g4, g5, _g5, g6, gA, gB, g034, _g1g2, gC, h1, h2, h2g2C, h4 GT
	m1.Expt(api, result)
	_m1.Conjugate(api, m1)
	m2.Expt(api, m1)
	_m2.Conjugate(api, m2)
	m3.Expt(api, m2)
	f0.Frobenius(api, result).
		Mul(api, f0, result).
		Mul(api, f0, m2)
	m2.CyclotomicSquare(api, _m1)
	f0.Mul(api, f0, m2)
	f0_36.CyclotomicSquare(api, f0).
		CyclotomicSquare(api, f0_36).
		CyclotomicSquare(api, f0_36).
		Mul(api, f0_36, f0).
		CyclotomicSquare(api, f0_36).
		CyclotomicSquare(api, f0_36)
	g0.Mul(api, result, m1).
		Frobenius(api, g0).
		Mul(api, g0, m3).
		Mul(api, g0, _m2).
		Mul(api, g0, _m1)
	g1.Expt(api, g0)
	_g1.Conjugate(api, g1)
	g2.Expt(api, g1)
	g3.Expt(api, g2)
	_g3.Conjugate(api, g3)
	g4.Expt(api, g3)
	_g4.Conjugate(api, g4)
	g5.Expt(api, g4)
	_g5.Conjugate(api, g5)
	g6.Expt(api, g5)
	gA.Mul(api, g3, _g5).
		CyclotomicSquare(api, gA).
		Mul(api, gA, g6).
		Mul(api, gA, g1).
		Mul(api, gA, g0)
	g034.Mul(api, g0, g3).
		Mul(api, g034, _g4)
	gB.CyclotomicSquare(api, g034).
		Mul(api, gB, g034).
		Mul(api, gB, g5).
		Mul(api, gB, _g1)
	_g1g2.Mul(api, _g1, g2)
	gC.Mul(api, _g3, _g1g2).
		CyclotomicSquare(api, gC).
		Mul(api, gC, _g1g2).
		Mul(api, gC, g0).
		CyclotomicSquare(api, gC).
		Mul(api, gC, g2).
		Mul(api, gC, g0).
		Mul(api, gC, g4)

	// ht, hy = 13, 9
	// c1 = ht**2+3*hy**2 = 412
	h1.Expc1(api, gA)
	// c2 = ht+hy = 22
	h2.Expc2(api, gB)
	h2g2C.CyclotomicSquare(api, gC).
		Mul(api, h2g2C, h2)
	h4.CyclotomicSquare(api, h2g2C).
		Mul(api, h4, h2g2C).
		CyclotomicSquare(api, h4)
	result.Mul(api, h1, h4).
		Mul(api, result, f0_36)

	return result
}

// MillerLoop Optimal Tate alternative (or twisted ate or Eta revisited)
// computes the multi-Miller loop ∏ᵢ MillerLoop(Pᵢ, Qᵢ)
// Alg.2 in https://eprint.iacr.org/2021/1359.pdf
// Eq. (6) in https://hackmd.io/@gnark/BW6-761-changes
func MillerLoop(api frontend.API, P []G1Affine, Q []G2Affine) (GT, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return GT{}, errors.New("invalid inputs sizes")
	}

	// filter infinity points
	p0 := make([]G1Affine, 0, n)
	q := make([]G2Affine, 0, n)

	for k := 0; k < n; k++ {
		p0 = append(p0, P[k])
		q = append(q, Q[k])
	}

	n = len(q)

	// precomputations
	pProj1 := make([]g1Proj, n)
	p1 := make([]G1Affine, n)
	pProj01 := make([]g1Proj, n) // P0+P1
	pProj10 := make([]g1Proj, n) // P0-P1
	l01 := make([]lineEvaluation, n)
	l10 := make([]lineEvaluation, n)
	for k := 0; k < n; k++ {
		p1[k].Y = api.Neg(p0[k].Y)
		p1[k].X = api.Mul(p0[k].X, thirdRootOneG2)
		pProj1[k].FromAffine(api, p1[k])

		// l_{p0,p1}(q)
		pProj01[k].Set(pProj1[k])
		pProj01[k].AddMixedStep(api, &l01[k], &p0[k])
		l01[k].r1 = api.Mul(l01[k].r1, q[k].X)
		l01[k].r0 = api.Mul(l01[k].r0, q[k].Y)

		// l_{p0,-p1}(q)
		pProj10[k].Neg(api, pProj1[k])
		pProj10[k].AddMixedStep(api, &l10[k], &p0[k])
		l10[k].r1 = api.Mul(l10[k].r1, q[k].X)
		l10[k].r0 = api.Mul(l10[k].r0, q[k].Y)
	}
	p01 := BatchProjectiveToAffineG1(api, pProj01)
	p10 := BatchProjectiveToAffineG1(api, pProj10)

	// f_{a0+\lambda*a1,P}(Q)
	var result, ss GT
	result.SetOne()
	var l, l0 lineEvaluation

	var j int8

	// i = len(loopCounter) - 2
	for k := 0; k < n; k++ {
		pProj1[k].DoubleStep(api, &l0)
		l0.r1 = api.Mul(l0.r1, q[k].X)
		l0.r0 = api.Mul(l0.r0, q[k].Y)
		result.MulBy034(api, l0.r0, l0.r1, l0.r2)
	}

	var tmp G1Affine
	for i := len(loopCounter0) - 3; i >= 0; i-- {
		// (∏ᵢfᵢ)²
		result.Square(api, result)

		j = loopCounter1[i]*3 + loopCounter0[i]

		for k := 0; k < n; k++ {
			pProj1[k].DoubleStep(api, &l0)
			l0.r1 = api.Mul(l0.r1, q[k].X)
			l0.r0 = api.Mul(l0.r0, q[k].Y)

			switch j {
			case -4:
				tmp.Neg(api, p01[k])
				pProj1[k].AddMixedStep(api, &l, &tmp)
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l01[k].r0, l01[k].r1, l01[k].r2)
				result.MulBy034(api, l0.r0, l0.r1, l0.r2).
					Mul(api, result, ss)
			case -3:
				tmp.Neg(api, p1[k])
				pProj1[k].AddMixedStep(api, &l, &tmp)
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l0.r0, l0.r1, l0.r2)
				result.Mul(api, result, ss)
			case -2:
				pProj1[k].AddMixedStep(api, &l, &p10[k])
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l01[k].r0, l01[k].r1, l01[k].r2)
				result.MulBy034(api, l0.r0, l0.r1, l0.r2).
					Mul(api, result, ss)
			case -1:
				tmp.Neg(api, p0[k])
				pProj1[k].AddMixedStep(api, &l, &tmp)
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l0.r0, l0.r1, l0.r2)
				result.Mul(api, result, ss)
			case 0:
				result.MulBy034(api, l0.r0, l0.r1, l0.r2)
			case 1:
				pProj1[k].AddMixedStep(api, &l, &p0[k])
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l0.r0, l0.r1, l0.r2)
				result.Mul(api, result, ss)
			case 2:
				tmp.Neg(api, p10[k])
				pProj1[k].AddMixedStep(api, &l, &tmp)
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l01[k].r0, l01[k].r1, l01[k].r2)
				result.MulBy034(api, l0.r0, l0.r1, l0.r2).
					Mul(api, result, ss)
			case 3:
				pProj1[k].AddMixedStep(api, &l, &p1[k])
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l0.r0, l0.r1, l0.r2)
				result.Mul(api, result, ss)
			case 4:
				pProj1[k].AddMixedStep(api, &l, &p01[k])
				l.r1 = api.Mul(l.r1, q[k].X)
				l.r0 = api.Mul(l.r0, q[k].Y)
				ss.Mul034By034(api, l.r0, l.r1, l.r2, l01[k].r0, l01[k].r1, l01[k].r2)
				result.MulBy034(api, l0.r0, l0.r1, l0.r2).
					Mul(api, result, ss)
			default:
				return GT{}, errors.New("invalid loopCounter")
			}
		}
	}

	return result, nil
}

// DoubleStep doubles a point in Homogenous projective coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *g1Proj) DoubleStep(api frontend.API, evaluations *lineEvaluation) {

	// get some Element from our pool
	var t1, A, B, C, D, E, EE, F, G, H, I, J, K frontend.Variable
	A = api.Mul(p.x, p.y)
	//A.Halve()
	A = api.Div(A, 2)
	B = api.Mul(p.y, p.y)
	C = api.Mul(p.z, p.z)
	D = api.Add(C, C)
	D = api.Add(D, C)

	// E.Mul(D, bCurveCoeff)
	E = api.Neg(D)

	F = api.Add(E, E)
	F = api.Add(F, E)
	G = api.Add(B, F)
	//G.Halve()
	G = api.Div(G, 2)
	H = api.Add(p.y, p.z)
	H = api.Mul(H, H)
	t1 = api.Add(B, C)
	H = api.Sub(H, t1)
	I = api.Sub(E, B)
	J = api.Mul(p.x, p.x)
	EE = api.Mul(E, E)
	K = api.Add(EE, EE)
	K = api.Add(K, EE)

	// X, Y, Z
	p.x = api.Sub(B, F)
	p.x = api.Mul(p.x, A)
	p.y = api.Mul(G, G)
	p.y = api.Sub(p.y, K)
	p.z = api.Mul(B, H)

	// Line evaluation
	evaluations.r0 = api.Neg(H)
	evaluations.r1 = api.Add(J, J)
	evaluations.r1 = api.Add(evaluations.r1, J)
	evaluations.r2 = I
}

// AddMixedStep point addition in Mixed Homogenous projective and Affine coordinates
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *g1Proj) AddMixedStep(api frontend.API, evaluations *lineEvaluation, a *G1Affine) {

	// get some Element from our pool
	var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J frontend.Variable
	Y2Z1 = api.Mul(a.Y, p.z)
	O = api.Sub(p.y, Y2Z1)
	X2Z1 = api.Mul(a.X, p.z)
	L = api.Sub(p.x, X2Z1)
	C = api.Mul(O, O)
	D = api.Mul(L, L)
	E = api.Mul(L, D)
	F = api.Mul(p.z, C)
	G = api.Mul(p.x, D)
	t0 = api.Add(G, G)
	H = api.Add(E, F)
	H = api.Sub(H, t0)
	t1 = api.Mul(p.y, E)

	// X, Y, Z
	p.x = api.Mul(L, H)
	p.y = api.Sub(G, H)
	p.y = api.Mul(p.y, O)
	p.y = api.Sub(p.y, t1)
	p.z = api.Mul(E, p.z)

	t2 = api.Mul(L, a.Y)
	J = api.Mul(a.X, O)
	J = api.Sub(J, t2)

	// Line evaluation
	evaluations.r0 = L
	evaluations.r1 = api.Neg(O)
	evaluations.r2 = J
}
