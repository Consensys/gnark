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

package sw

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
)

// PairingContext contains useful info about the pairing
type PairingContext struct {
	AteLoop     uint64 // stores the ate loop
	Extension   fields.Extension
	BTwistCoeff fields.E2
}

// LineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
type LineEvaluation struct {
	R0, R1, R2 fields.E2
}

// mlStep the i-th ml step contains (f,q) where q=[i]Q, f=f_{i,Q}(P) where (f_{i,Q})=i(Q)-([i]Q)-(i-1)O
type mlStep struct {
	f fields.E12
	q G2Affine
}

// MillerLoop computes the miller loop
func MillerLoop(cs *frontend.ConstraintSystem, P G1Affine, Q G2Affine, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopBin [64]uint
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	for i := 0; i < 64; i++ {
		ateLoopBin[i] = ateLoopBigInt.Bit(i)
	}

	res.SetOne(cs)
	var l LineEvaluation

	var qProj G2Proj
	qProj.X = Q.X
	qProj.Y = Q.Y
	qProj.Z.A0 = cs.Constant(1)
	qProj.Z.A1 = cs.Constant(0)

	// Miller loop
	for i := len(ateLoopBin) - 2; i >= 0; i-- {

		// res <- res**2
		res.Mul(cs, res, res, pairingInfo.Extension)

		// l(P) where div(l) = 2(qProj)+([-2]qProj)-2(O)
		// qProj <- 2*qProj
		qProj.DoubleStep(cs, &l, pairingInfo)
		l.R0.MulByFp(cs, &l.R0, P.Y)
		l.R1.MulByFp(cs, &l.R1, P.X)

		// res <- res*l(P)
		res.MulBy034(cs, &l.R0, &l.R1, &l.R2, pairingInfo.Extension)

		if ateLoopBin[i] == 0 {
			continue
		}

		// l(P) where div(l) = (qProj)+(Q)+(-Q-qProj)-3(O)
		// qProj <- qProj + Q
		qProj.AddMixedStep(cs, &l, &Q, pairingInfo)
		l.R0.MulByFp(cs, &l.R0, P.Y)
		l.R1.MulByFp(cs, &l.R1, P.X)

		// res <- res*l(P)
		res.MulBy034(cs, &l.R0, &l.R1, &l.R2, pairingInfo.Extension)

	}

	return res
}

// computeLineCoef computes the coefficients of the line passing through Q, R of equation
// x*LineCoeff.R0 +  y*LineCoeff.R1 + LineCoeff.R2
func computeLineCoef(cs *frontend.ConstraintSystem, Q, R G2Affine, ext fields.Extension) LineEvaluation {

	var res LineEvaluation
	res.R0.Sub(cs, &Q.Y, &R.Y)
	res.R1.Sub(cs, &R.X, &Q.X)
	var tmp fields.E2
	res.R2.Mul(cs, &Q.X, &R.Y, ext)
	tmp.Mul(cs, &R.X, &Q.Y, ext)
	res.R2.Sub(cs, &res.R2, &tmp)
	return res
}

// MillerLoop computes the miller loop
func MillerLoopAffine(cs *frontend.ConstraintSystem, P G1Affine, Q G2Affine, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopBin [64]uint
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	for i := 0; i < 64; i++ {
		ateLoopBin[i] = ateLoopBigInt.Bit(i)
	}

	res.SetOne(cs)
	var l LineEvaluation

	var QCur, QNext G2Affine
	QCur = Q

	// Miller loop
	for i := len(ateLoopBin) - 2; i >= 0; i-- {

		// res <- res**2
		res.Mul(cs, res, res, pairingInfo.Extension)

		// l(P) where div(l) = 2(qProj)+([-2]qProj)-2(O)
		QNext.Double(cs, &QCur, pairingInfo.Extension).Neg(cs, &QNext)
		l = computeLineCoef(cs, QCur, QNext, pairingInfo.Extension)
		l.R0.MulByFp(cs, &l.R0, P.X)
		l.R1.MulByFp(cs, &l.R1, P.Y)

		// res <- res*l(P)
		res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)

		QCur.Neg(cs, &QNext)

		if ateLoopBin[i] == 0 {
			continue
		}

		// l(P) where div(l) = (qProj)+(Q)+(-Q-qProj)-3(O)
		QNext.Neg(cs, &QNext).AddAssign(cs, &Q, pairingInfo.Extension)
		l = computeLineCoef(cs, QCur, Q, pairingInfo.Extension)
		l.R0.MulByFp(cs, &l.R0, P.X)
		l.R1.MulByFp(cs, &l.R1, P.Y)
		res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)
		QCur = QNext
	}

	return res
}

// MillerLoopAffineSA computes the miller loop
func MillerLoopAffineSA(cs *frontend.ConstraintSystem, P G1Affine, Q G2Affine, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopBin [64]uint
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	for i := 0; i < 64; i++ {
		ateLoopBin[i] = ateLoopBigInt.Bit(i)
	}

	res.SetOne(cs)
	var l LineEvaluation

	var QCur, QNext G2Affine
	QCur = Q

	fsquareStep := func() {
		QNext.Double(cs, &QCur, pairingInfo.Extension).Neg(cs, &QNext)
		l = computeLineCoef(cs, QCur, QNext, pairingInfo.Extension)
		l.R0.MulByFp(cs, &l.R0, P.X)
		l.R1.MulByFp(cs, &l.R1, P.Y)
		res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)
		QCur.Neg(cs, &QNext)
	}

	squareStep := func() {
		res.Mul(cs, res, res, pairingInfo.Extension)
		QNext.Double(cs, &QCur, pairingInfo.Extension).Neg(cs, &QNext)
		l = computeLineCoef(cs, QCur, QNext, pairingInfo.Extension)
		l.R0.MulByFp(cs, &l.R0, P.X)
		l.R1.MulByFp(cs, &l.R1, P.Y)
		res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)
		QCur.Neg(cs, &QNext)
	}

	mulStep := func() {
		QNext.Neg(cs, &QNext).AddAssign(cs, &Q, pairingInfo.Extension)
		l = computeLineCoef(cs, QCur, Q, pairingInfo.Extension)
		l.R0.MulByFp(cs, &l.R0, P.X)
		l.R1.MulByFp(cs, &l.R1, P.Y)
		res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)
		QCur = QNext
	}

	nSquare := func(n int) {
		for i := 0; i < n; i++ {
			squareStep()
		}
	}

	var ml33 mlStep
	fsquareStep()
	nSquare(4)
	mulStep()
	ml33.f = *res
	ml33.q = QCur
	nSquare(7)

	res.Mul(cs, res, &ml33.f, pairingInfo.Extension)
	l = computeLineCoef(cs, QCur, ml33.q, pairingInfo.Extension)
	l.R0.MulByFp(cs, &l.R0, P.X)
	l.R1.MulByFp(cs, &l.R1, P.Y)
	res.MulBy034(cs, &l.R1, &l.R0, &l.R2, pairingInfo.Extension)
	QCur.AddAssign(cs, &ml33.q, pairingInfo.Extension)

	nSquare(4)
	mulStep()
	squareStep()
	mulStep()

	// remaining 46 bits
	nSquare(46)
	mulStep()

	return res
}

// DoubleStep doubles a point in Homogenous projective coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *G2Proj) DoubleStep(cs *frontend.ConstraintSystem, evaluation *LineEvaluation, pairingInfo PairingContext) {

	// get some Element from our pool
	var t0, t1, A, B, C, D, E, EE, F, G, H, I, J, K fields.E2
	twoInv := cs.Constant(2)
	twoInv = cs.Inverse(twoInv)
	t0.Mul(cs, &p.X, &p.Y, pairingInfo.Extension)
	A.MulByFp(cs, &t0, twoInv)
	B.Mul(cs, &p.Y, &p.Y, pairingInfo.Extension)
	C.Mul(cs, &p.Z, &p.Z, pairingInfo.Extension)
	D.Add(cs, &C, &C).
		Add(cs, &D, &C)
	E.Mul(cs, &D, &pairingInfo.BTwistCoeff, pairingInfo.Extension)
	F.Add(cs, &E, &E).
		Add(cs, &F, &E)
	G.Add(cs, &B, &F)
	G.MulByFp(cs, &G, twoInv)
	H.Add(cs, &p.Y, &p.Z).
		Mul(cs, &H, &H, pairingInfo.Extension)
	t1.Add(cs, &B, &C)
	H.Sub(cs, &H, &t1)
	I.Sub(cs, &E, &B)
	J.Mul(cs, &p.X, &p.X, pairingInfo.Extension)
	EE.Mul(cs, &E, &E, pairingInfo.Extension)
	K.Add(cs, &EE, &EE).
		Add(cs, &K, &EE)

	// X, Y, Z
	p.X.Sub(cs, &B, &F).
		Mul(cs, &p.X, &A, pairingInfo.Extension)
	p.Y.Mul(cs, &G, &G, pairingInfo.Extension).
		Sub(cs, &p.Y, &K)
	p.Z.Mul(cs, &B, &H, pairingInfo.Extension)

	// Line evaluation
	evaluation.R0.Neg(cs, &H)
	evaluation.R1.Add(cs, &J, &J).
		Add(cs, &evaluation.R1, &J)
	evaluation.R2 = I
}

// AddMixedStep point addition in Mixed Homogenous projective and Affine coordinates
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *G2Proj) AddMixedStep(cs *frontend.ConstraintSystem, evaluation *LineEvaluation, a *G2Affine, pairingInfo PairingContext) {

	// get some Element from our pool
	var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J fields.E2
	Y2Z1.Mul(cs, &a.Y, &p.Z, pairingInfo.Extension)
	O.Sub(cs, &p.Y, &Y2Z1)
	X2Z1.Mul(cs, &a.X, &p.Z, pairingInfo.Extension)
	L.Sub(cs, &p.X, &X2Z1)
	C.Mul(cs, &O, &O, pairingInfo.Extension)
	D.Mul(cs, &L, &L, pairingInfo.Extension)
	E.Mul(cs, &L, &D, pairingInfo.Extension)
	F.Mul(cs, &p.Z, &C, pairingInfo.Extension)
	G.Mul(cs, &p.X, &D, pairingInfo.Extension)
	t0.Add(cs, &G, &G)
	H.Add(cs, &E, &F).
		Sub(cs, &H, &t0)
	t1.Mul(cs, &p.Y, &E, pairingInfo.Extension)

	// X, Y, Z
	p.X.Mul(cs, &L, &H, pairingInfo.Extension)
	p.Y.Sub(cs, &G, &H).
		Mul(cs, &p.Y, &O, pairingInfo.Extension).
		Sub(cs, &p.Y, &t1)
	p.Z.Mul(cs, &E, &p.Z, pairingInfo.Extension)

	t2.Mul(cs, &L, &a.Y, pairingInfo.Extension)
	J.Mul(cs, &a.X, &O, pairingInfo.Extension).
		Sub(cs, &J, &t2)

	// Line evaluation
	evaluation.R0 = L
	evaluation.R1.Neg(cs, &O)
	evaluation.R2 = J
}
