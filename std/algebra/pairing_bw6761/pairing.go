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

package pairing_bw6761

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

var (
	thirdRootOneG1 = emulated.NewElement[emulated.BW6761Fp]("1968985824090209297278610739700577151397666382303825728450741611566800370218827257750865013421937292370006175842381275743914023380727582819905021229583192207421122272650305267822868639090213645505120388400344940985710520836292650")
	thirdRootOneG2 = emulated.NewElement[emulated.BW6761Fp]("3876905175468200631077310367084681598448315841795389501393935922030716896759491089791062239139884430736136043081596370525752532152533918168748948422532524762769433379258873205270018176434449950195784127083892851850798970002242935133594411783692478449434154543435837344414891700653141782682622592665272535258486114040810216200011591719198498884598067930925845038459634787676665023756334020972459098834655430741989740290995313870292460737326506741396444022500")
	loopCounter0   = [190]int8{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	loopCounter1   [190]int8
	// x₀³-x₀²-x₀
	T, _ = new(big.Int).SetString("880904806456922042166256752416502360955572640081583800319", 10)
)

func init() {
	ecc.NafDecomposition(T, loopCounter1[:])
}

type Pairing struct {
	*ext6
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		ext6: NewExt6(ba),
	}, nil
}

// GT target group of the pairing
type GT = E6

type lineEvaluation struct {
	r0 baseField
	r1 baseField
	r2 baseField
}

// Pair calculates the reduced pairing for a set of points
// ∏ᵢ e(Pᵢ, Qᵢ).
//
// This function doesn't check that the inputs are in the correct subgroup. See IsInSubGroup.
func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	f, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, err
	}
	return pr.FinalExponentiation(f), nil
}

// FinalExponentiation computes the exponentiation (∏ᵢ zᵢ)ᵈ
// where d = (p^6-1)/r = (p^6-1)/Φ_6(p) ⋅ Φ_6(p)/r = (p^3-1)(p+1)(p^2 - p +1)/r
// we use instead d=s ⋅ (p^3-1)(p+1)(p^2 - p +1)/r
// where s is the cofactor 12(x_0+1) (El Housni and Guillevic)
func (pr Pairing) FinalExponentiation(z *GT, _z ...*GT) *GT {

	result := pr.Set(z)

	for _, a := range _z {
		result = pr.Mul(result, a)
	}

	// Easy part
	// (p^3-1)(p+1)
	buf := pr.Conjugate(result)
	result = pr.Inverse(result)
	buf = pr.Mul(buf, result)
	result = pr.Frobenius(buf)
	result = pr.Mul(result, buf)

	// Hard part (up to permutation)
	// El Housni and Guillevic
	// https://eprint.iacr.org/2020/351.pdf
	m1 := pr.Expt(result)
	_m1 := pr.Conjugate(m1)
	m2 := pr.Expt(m1)
	_m2 := pr.Conjugate(m2)
	m3 := pr.Expt(m2)
	f0 := pr.Frobenius(result)
	f0 = pr.Mul(f0, result)
	f0 = pr.Mul(f0, m2)
	m2 = pr.CyclotomicSquare(_m1)
	f0 = pr.Mul(f0, m2)
	f0_36 := pr.CyclotomicSquare(f0)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.Mul(f0_36, f0)
	f0_36 = pr.CyclotomicSquare(f0_36)
	f0_36 = pr.CyclotomicSquare(f0_36)
	g0 := pr.Mul(result, m1)
	g0 = pr.Frobenius(g0)
	g0 = pr.Mul(g0, m3)
	g0 = pr.Mul(g0, _m2)
	g0 = pr.Mul(g0, _m1)
	g1 := pr.Expt(g0)
	_g1 := pr.Conjugate(g1)
	g2 := pr.Expt(g1)
	g3 := pr.Expt(g2)
	_g3 := pr.Conjugate(g3)
	g4 := pr.Expt(g3)
	_g4 := pr.Conjugate(g4)
	g5 := pr.Expt(g4)
	_g5 := pr.Conjugate(g5)
	g6 := pr.Expt(g5)
	gA := pr.Mul(g3, _g5)
	gA = pr.CyclotomicSquare(gA)
	gA = pr.Mul(gA, g6)
	gA = pr.Mul(gA, g1)
	gA = pr.Mul(gA, g0)
	g034 := pr.Mul(g0, g3)
	g034 = pr.Mul(g034, _g4)
	gB := pr.CyclotomicSquare(g034)
	gB = pr.Mul(gB, g034)
	gB = pr.Mul(gB, g5)
	gB = pr.Mul(gB, _g1)
	_g1g2 := pr.Mul(_g1, g2)
	gC := pr.Mul(_g3, _g1g2)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, _g1g2)
	gC = pr.Mul(gC, g0)
	gC = pr.CyclotomicSquare(gC)
	gC = pr.Mul(gC, g2)
	gC = pr.Mul(gC, g0)
	gC = pr.Mul(gC, g4)

	// ht, hy = 13, 9
	// c1 = ht**2+3*hy**2 = 412
	h1 := pr.Expc1(gA)
	// c2 = ht+hy = 22
	h2 := pr.Expc2(gB)
	h2g2C := pr.CyclotomicSquare(gC)
	h2g2C = pr.Mul(h2g2C, h2)
	h4 := pr.CyclotomicSquare(h2g2C)
	h4 = pr.Mul(h4, h2g2C)
	h4 = pr.CyclotomicSquare(h4)
	result = pr.Mul(h1, h4)
	result = pr.Mul(result, f0_36)

	return result
}

// MillerLoop Optimal Tate alternative (or twisted ate or Eta revisited)
// computes the multi-Miller loop ∏ᵢ MillerLoop(Pᵢ, Qᵢ)
// Alg.2 in https://eprint.iacr.org/2021/1359.pdf
// Eq. (6) in https://hackmd.io/@gnark/BW6-761-changes
func (pr Pairing) MillerLoop(P []*G1Affine, Q []*G2Affine) (*GT, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return nil, errors.New("invalid inputs sizes")
	}

	// filter infinity points
	p0 := make([]G1Affine, 0, n)
	q := make([]G2Affine, 0, n)

	for k := 0; k < n; k++ {
		p0 = append(p0, *P[k])
		q = append(q, *Q[k])
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
		p1[k].Y = *pr.fp.Neg(&p0[k].Y)
		p1[k].X = *pr.fp.MulMod(&p0[k].X, &thirdRootOneG2)
		pProj1[k].FromAffine(&pr, &p1[k])

		// l_{p0,p1}(q)
		pProj01[k].Set(&pProj1[k])
		pProj01[k].AddMixedStep(&pr, &l01[k], &p0[k])
		l01[k].r1 = *pr.fp.MulMod(&l01[k].r1, &q[k].X)
		l01[k].r0 = *pr.fp.MulMod(&l01[k].r0, &q[k].Y)

		// l_{p0,-p1}(q)
		pProj10[k].Neg(&pr, &pProj1[k])
		pProj10[k].AddMixedStep(&pr, &l10[k], &p0[k])
		l10[k].r1 = *pr.fp.MulMod(&l10[k].r1, &q[k].X)
		l10[k].r0 = *pr.fp.MulMod(&l10[k].r0, &q[k].Y)
	}
	p01 := BatchProjectiveToAffineG1(&pr, pProj01)
	p10 := BatchProjectiveToAffineG1(&pr, pProj10)

	// f_{a0+\lambda*a1,P}(Q)
	result := pr.ext6.One()
	var l, l0 lineEvaluation

	var j int8

	// i = len(loopCounter) - 2
	for k := 0; k < n; k++ {
		pProj1[k].DoubleStep(&pr, &l0)
		l0.r1 = *pr.fp.MulMod(&l0.r1, &q[k].X)
		l0.r0 = *pr.fp.MulMod(&l0.r0, &q[k].Y)
		result = pr.MulBy034(result, &l0)
	}

	var tmp G1Affine
	for i := len(loopCounter0) - 3; i >= 0; i-- {
		// TODO reduce first
		result = pr.Reduce(result)
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j = loopCounter1[i]*3 + loopCounter0[i]

		for k := 0; k < n; k++ {
			pProj1[k].DoubleStep(&pr, &l0)
			l0.r1 = *pr.fp.MulMod(&l0.r1, &q[k].X)
			l0.r0 = *pr.fp.MulMod(&l0.r0, &q[k].Y)

			switch j {
			case -4:
				tmp.Neg(&pr, &p01[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l01[k].r0, &l01[k].r1, &l01[k].r2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case -3:
				tmp.Neg(&pr, &p1[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Mul(result, ss)
			case -2:
				pProj1[k].AddMixedStep(&pr, &l, &p10[k])
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l01[k].r0, &l01[k].r1, &l01[k].r2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case -1:
				tmp.Neg(&pr, &p0[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Mul(result, ss)
			case 0:
				result = pr.MulBy034(result, &l0)
			case 1:
				pProj1[k].AddMixedStep(&pr, &l, &p0[k])
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Mul(result, ss)
			case 2:
				tmp.Neg(&pr, &p10[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l01[k].r0, &l01[k].r1, &l01[k].r2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case 3:
				pProj1[k].AddMixedStep(&pr, &l, &p1[k])
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Mul(result, ss)
			case 4:
				pProj1[k].AddMixedStep(&pr, &l, &p01[k])
				l.r1 = *pr.fp.MulMod(&l.r1, &q[k].X)
				l.r0 = *pr.fp.MulMod(&l.r0, &q[k].Y)
				ss := pr.Mul034By034(&l.r0, &l.r1, &l.r2, &l01[k].r0, &l01[k].r1, &l01[k].r2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			default:
				return nil, errors.New("invalid loopCounter")
			}

		}
	}

	return result, nil
}

// DoubleStep doubles a point in Homogenous projective coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *g1Proj) DoubleStep(pr *Pairing, evaluations *lineEvaluation) {
	// TODO reduce first
	//p.x = *pr.fp.Reduce(&p.x)
	//p.y = *pr.fp.Reduce(&p.y)
	//p.z = *pr.fp.Reduce(&p.z)

	// get some Element from our pool
	A := pr.fp.Mul(&p.x, &p.y)
	//A.Halve()
	two := emulated.NewElement[emulated.BW6761Fp](2)
	A = pr.fp.Div(A, &two)
	B := pr.fp.MulMod(&p.y, &p.y)
	C := pr.fp.MulMod(&p.z, &p.z)
	D := pr.fp.Add(C, C)
	D = pr.fp.Add(D, C)

	// E.Mul(D, bCurveCoeff)
	E := pr.fp.Neg(D)

	F := pr.fp.Add(E, E)
	F = pr.fp.Add(F, E)
	G := pr.fp.Add(B, F)
	//G.Halve()
	G = pr.fp.Div(G, &two)
	H := pr.fp.Add(&p.y, &p.z)
	H = pr.fp.MulMod(H, H)
	t1 := pr.fp.Add(B, C)
	H = pr.fp.Sub(H, t1)
	I := pr.fp.Sub(E, B)
	J := pr.fp.MulMod(&p.x, &p.x)
	EE := pr.fp.MulMod(E, E)
	K := pr.fp.Add(EE, EE)
	K = pr.fp.Add(K, EE)

	// X, Y, Z
	p.x = *pr.fp.Sub(B, F)
	p.x = *pr.fp.MulMod(&p.x, A)
	p.y = *pr.fp.MulMod(G, G)
	p.y = *pr.fp.Sub(&p.y, K)
	p.z = *pr.fp.MulMod(B, H)

	// Line evaluation
	evaluations.r0 = *pr.fp.Neg(H)
	evaluations.r1 = *pr.fp.Add(J, J)
	evaluations.r1 = *pr.fp.Add(&evaluations.r1, J)
	evaluations.r2 = *I
}

// AddMixedStep point addition in Mixed Homogenous projective and Affine coordinates
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *g1Proj) AddMixedStep(pr *Pairing, evaluations *lineEvaluation, a *G1Affine) {

	// get some Element from our pool
	Y2Z1 := pr.fp.MulMod(&a.Y, &p.z)
	O := pr.fp.Sub(&p.y, Y2Z1)
	X2Z1 := pr.fp.MulMod(&a.X, &p.z)
	L := pr.fp.Sub(&p.x, X2Z1)
	C := pr.fp.MulMod(O, O)
	D := pr.fp.MulMod(L, L)
	E := pr.fp.MulMod(L, D)
	F := pr.fp.MulMod(&p.z, C)
	G := pr.fp.MulMod(&p.x, D)
	t0 := pr.fp.Add(G, G)
	H := pr.fp.Add(E, F)
	H = pr.fp.Sub(H, t0)
	t1 := pr.fp.MulMod(&p.y, E)

	// X, Y, Z
	p.x = *pr.fp.MulMod(L, H)
	p.y = *pr.fp.Sub(G, H)
	p.y = *pr.fp.MulMod(&p.y, O)
	p.y = *pr.fp.Sub(&p.y, t1)
	p.z = *pr.fp.MulMod(E, &p.z)

	// TODO reduce first
	//p.x = *pr.fp.Reduce(&p.x)
	//p.y = *pr.fp.Reduce(&p.y)
	//p.z = *pr.fp.Reduce(&p.z)

	t2 := pr.fp.MulMod(L, &a.Y)
	J := pr.fp.MulMod(&a.X, O)
	J = pr.fp.Sub(J, t2)

	// Line evaluation
	evaluations.r0 = *L
	evaluations.r1 = *pr.fp.Neg(O)
	evaluations.r2 = *J

	// TODO reduce
	//evaluations.r0 = *pr.fp.Reduce(&evaluations.r0)
	//evaluations.r1 = *pr.fp.Reduce(&evaluations.r1)
	//evaluations.r2 = *pr.fp.Reduce(&evaluations.r2)
}
