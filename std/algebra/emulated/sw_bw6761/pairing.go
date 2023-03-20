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
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"math/big"
)

var (
	thirdRootOneG2 = emulated.ValueOf[emulated.BW6761Fp]("3876905175468200631077310367084681598448315841795389501393935922030716896759491089791062239139884430736136043081596370525752532152533918168748948422532524762769433379258873205270018176434449950195784127083892851850798970002242935133594411783692478449434154543435837344414891700653141782682622592665272535258486114040810216200011591719198498884598067930925845038459634787676665023756334020972459098834655430741989740290995313870292460737326506741396444022500")
	loopCounter0   = [190]int8{0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	loopCounter1   [190]int8
	// x₀³-x₀²-x₀
	T, _ = new(big.Int).SetString("880904806456922042166256752416502360955572640081583800319", 10)
)

func init() {
	ecc.NafDecomposition(T, loopCounter1[:])
}

type Pairing struct {
	*fields_bw6761.Ext6
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		Ext6: fields_bw6761.NewExt6(ba),
	}, nil
}

// GT target group of the pairing
type GT = fields_bw6761.E6
type LineEvaluation = fields_bw6761.LineEvaluation

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
	l01 := make([]LineEvaluation, n)
	l10 := make([]LineEvaluation, n)
	for k := 0; k < n; k++ {
		p1[k].Y = *pr.Fp.Neg(&p0[k].Y)
		p1[k].X = *pr.Fp.MulMod(&p0[k].X, &thirdRootOneG2)
		pProj1[k].FromAffine(&pr, &p1[k])

		// l_{p0,p1}(q)
		pProj01[k].Set(&pProj1[k])
		pProj01[k].AddMixedStep(&pr, &l01[k], &p0[k])
		l01[k].R1 = *pr.Fp.MulMod(&l01[k].R1, &q[k].X)
		l01[k].R0 = *pr.Fp.MulMod(&l01[k].R0, &q[k].Y)

		// l_{p0,-p1}(q)
		pProj10[k].Neg(&pr, &pProj1[k])
		pProj10[k].AddMixedStep(&pr, &l10[k], &p0[k])
		l10[k].R1 = *pr.Fp.MulMod(&l10[k].R1, &q[k].X)
		l10[k].R0 = *pr.Fp.MulMod(&l10[k].R0, &q[k].Y)
	}
	p01 := BatchProjectiveToAffineG1(&pr, pProj01)
	p10 := BatchProjectiveToAffineG1(&pr, pProj10)

	// f_{a0+\lambda*a1,P}(Q)
	result := pr.Ext6.One()
	var l, l0 LineEvaluation

	var j int8

	// i = len(loopCounter) - 2
	for k := 0; k < n; k++ {
		pProj1[k].DoubleStep(&pr, &l0)
		l0.R1 = *pr.Fp.MulMod(&l0.R1, &q[k].X)
		l0.R0 = *pr.Fp.MulMod(&l0.R0, &q[k].Y)
		result = pr.MulBy034(result, &l0)
	}

	var tmp G1Affine
	for i := len(loopCounter0) - 3; i >= 0; i-- {
		result = pr.Reduce(result)
		// (∏ᵢfᵢ)²
		result = pr.Square(result)

		j = loopCounter1[i]*3 + loopCounter0[i]

		for k := 0; k < n; k++ {
			pProj1[k].DoubleStep(&pr, &l0)
			l0.R1 = *pr.Fp.MulMod(&l0.R1, &q[k].X)
			l0.R0 = *pr.Fp.MulMod(&l0.R0, &q[k].Y)

			switch j {
			case -4:
				tmp.Neg(&pr, &p01[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l01[k].R0, &l01[k].R1, &l01[k].R2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case -3:
				tmp.Neg(&pr, &p1[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l0.R0, &l0.R1, &l0.R2)
				result = pr.Mul(result, ss)
			case -2:
				pProj1[k].AddMixedStep(&pr, &l, &p10[k])
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l01[k].R0, &l01[k].R1, &l01[k].R2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case -1:
				tmp.Neg(&pr, &p0[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l0.R0, &l0.R1, &l0.R2)
				result = pr.Mul(result, ss)
			case 0:
				result = pr.MulBy034(result, &l0)
			case 1:
				pProj1[k].AddMixedStep(&pr, &l, &p0[k])
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l0.R0, &l0.R1, &l0.R2)
				result = pr.Mul(result, ss)
			case 2:
				tmp.Neg(&pr, &p10[k])
				pProj1[k].AddMixedStep(&pr, &l, &tmp)
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l01[k].R0, &l01[k].R1, &l01[k].R2)
				result = pr.MulBy034(result, &l0)
				result = pr.Mul(result, ss)
			case 3:
				pProj1[k].AddMixedStep(&pr, &l, &p1[k])
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l0.R0, &l0.R1, &l0.R2)
				result = pr.Mul(result, ss)
			case 4:
				pProj1[k].AddMixedStep(&pr, &l, &p01[k])
				l.R1 = *pr.Fp.MulMod(&l.R1, &q[k].X)
				l.R0 = *pr.Fp.MulMod(&l.R0, &q[k].Y)
				ss := pr.Mul034By034(&l.R0, &l.R1, &l.R2, &l01[k].R0, &l01[k].R1, &l01[k].R2)
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
func (p *g1Proj) DoubleStep(pr *Pairing, evaluations *LineEvaluation) {

	// get some Element from our pool
	A := pr.Fp.Mul(&p.x, &p.y)
	//A.Halve()
	two := emulated.ValueOf[emulated.BW6761Fp](2)
	A = pr.Fp.Div(A, &two)
	B := pr.Fp.MulMod(&p.y, &p.y)
	C := pr.Fp.MulMod(&p.z, &p.z)
	D := pr.Fp.Add(C, C)
	D = pr.Fp.Add(D, C)

	// E.Mul(D, bCurveCoeff)
	E := pr.Fp.Neg(D)

	F := pr.Fp.Add(E, E)
	F = pr.Fp.Add(F, E)
	G := pr.Fp.Add(B, F)
	//G.Halve()
	G = pr.Fp.Div(G, &two)
	H := pr.Fp.Add(&p.y, &p.z)
	H = pr.Fp.MulMod(H, H)
	t1 := pr.Fp.Add(B, C)
	H = pr.Fp.Sub(H, t1)
	I := pr.Fp.Sub(E, B)
	J := pr.Fp.MulMod(&p.x, &p.x)
	EE := pr.Fp.MulMod(E, E)
	K := pr.Fp.Add(EE, EE)
	K = pr.Fp.Add(K, EE)

	// X, Y, Z
	p.x = *pr.Fp.Sub(B, F)
	p.x = *pr.Fp.MulMod(&p.x, A)
	p.y = *pr.Fp.MulMod(G, G)
	p.y = *pr.Fp.Sub(&p.y, K)
	p.z = *pr.Fp.MulMod(B, H)

	// Line evaluation
	evaluations.R0 = *pr.Fp.Neg(H)
	evaluations.R1 = *pr.Fp.Add(J, J)
	evaluations.R1 = *pr.Fp.Add(&evaluations.R1, J)
	evaluations.R2 = *I
}

// AddMixedStep point addition in Mixed Homogenous projective and Affine coordinates
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *g1Proj) AddMixedStep(pr *Pairing, evaluations *LineEvaluation, a *G1Affine) {

	// get some Element from our pool
	Y2Z1 := pr.Fp.MulMod(&a.Y, &p.z)
	O := pr.Fp.Sub(&p.y, Y2Z1)
	X2Z1 := pr.Fp.MulMod(&a.X, &p.z)
	L := pr.Fp.Sub(&p.x, X2Z1)
	C := pr.Fp.MulMod(O, O)
	D := pr.Fp.MulMod(L, L)
	E := pr.Fp.MulMod(L, D)
	F := pr.Fp.MulMod(&p.z, C)
	G := pr.Fp.MulMod(&p.x, D)
	t0 := pr.Fp.Add(G, G)
	H := pr.Fp.Add(E, F)
	H = pr.Fp.Sub(H, t0)
	t1 := pr.Fp.MulMod(&p.y, E)

	// X, Y, Z
	p.x = *pr.Fp.MulMod(L, H)
	p.y = *pr.Fp.Sub(G, H)
	p.y = *pr.Fp.MulMod(&p.y, O)
	p.y = *pr.Fp.Sub(&p.y, t1)
	p.z = *pr.Fp.MulMod(E, &p.z)

	t2 := pr.Fp.MulMod(L, &a.Y)
	J := pr.Fp.MulMod(&a.X, O)
	J = pr.Fp.Sub(J, t2)

	// Line evaluation
	evaluations.R0 = *L
	evaluations.R1 = *pr.Fp.Neg(O)
	evaluations.R2 = *J

}
