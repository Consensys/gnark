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

// lineEvaluation represents a sparse Fp12 Elmt (result of the line evaluation)
type lineEvaluation struct {
	r0, r1, r2 fields.E2
}

// MillerLoop computes the miller loop
func MillerLoop(api frontend.API, P G1Affine, Q G2Affine, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopBin [64]uint
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	for i := 0; i < 64; i++ {
		ateLoopBin[i] = ateLoopBigInt.Bit(i)
	}

	res.SetOne(api)
	var l lineEvaluation

	var qProj G2Proj
	qProj.X = Q.X
	qProj.Y = Q.Y
	qProj.Z.A0 = api.Constant(1)
	qProj.Z.A1 = api.Constant(0)

	// Miller loop
	for i := len(ateLoopBin) - 2; i >= 0; i-- {

		// res <- res**2
		res.Mul(api, res, res, pairingInfo.Extension)

		// l(P) where div(l) = 2(qProj)+([-2]qProj)-2(O)
		// qProj <- 2*qProj
		qProj.DoubleStep(api, &l, pairingInfo)
		l.r0.MulByFp(api, &l.r0, P.Y)
		l.r1.MulByFp(api, &l.r1, P.X)

		// res <- res*l(P)
		res.MulBy034(api, &l.r0, &l.r1, &l.r2, pairingInfo.Extension)

		if ateLoopBin[i] == 0 {
			continue
		}

		// l(P) where div(l) = (qProj)+(Q)+(-Q-qProj)-3(O)
		// qProj <- qProj + Q
		qProj.AddMixedStep(api, &l, &Q, pairingInfo)
		l.r0.MulByFp(api, &l.r0, P.Y)
		l.r1.MulByFp(api, &l.r1, P.X)

		// res <- res*l(P)
		res.MulBy034(api, &l.r0, &l.r1, &l.r2, pairingInfo.Extension)

	}

	return res
}

// DoubleStep doubles a point in Homogenous projective coordinates, and evaluates the line in Miller loop
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *G2Proj) DoubleStep(api frontend.API, evaluation *lineEvaluation, pairingInfo PairingContext) {

	// get some Element from our pool
	var t0, t1, A, B, C, D, E, EE, F, G, H, I, J, K fields.E2
	twoInv := api.Constant(2)
	twoInv = api.Inverse(twoInv)
	t0.Mul(api, &p.X, &p.Y, pairingInfo.Extension)
	A.MulByFp(api, &t0, twoInv)
	B.Mul(api, &p.Y, &p.Y, pairingInfo.Extension)
	C.Mul(api, &p.Z, &p.Z, pairingInfo.Extension)
	D.Add(api, &C, &C).
		Add(api, &D, &C)
	E.Mul(api, &D, &pairingInfo.BTwistCoeff, pairingInfo.Extension)
	F.Add(api, &E, &E).
		Add(api, &F, &E)
	G.Add(api, &B, &F)
	G.MulByFp(api, &G, twoInv)
	H.Add(api, &p.Y, &p.Z).
		Mul(api, &H, &H, pairingInfo.Extension)
	t1.Add(api, &B, &C)
	H.Sub(api, &H, &t1)
	I.Sub(api, &E, &B)
	J.Mul(api, &p.X, &p.X, pairingInfo.Extension)
	EE.Mul(api, &E, &E, pairingInfo.Extension)
	K.Add(api, &EE, &EE).
		Add(api, &K, &EE)

	// X, Y, Z
	p.X.Sub(api, &B, &F).
		Mul(api, &p.X, &A, pairingInfo.Extension)
	p.Y.Mul(api, &G, &G, pairingInfo.Extension).
		Sub(api, &p.Y, &K)
	p.Z.Mul(api, &B, &H, pairingInfo.Extension)

	// Line evaluation
	evaluation.r0.Neg(api, &H)
	evaluation.r1.Add(api, &J, &J).
		Add(api, &evaluation.r1, &J)
	evaluation.r2 = I
}

// AddMixedStep point addition in Mixed Homogenous projective and Affine coordinates
// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
func (p *G2Proj) AddMixedStep(api frontend.API, evaluation *lineEvaluation, a *G2Affine, pairingInfo PairingContext) {

	// get some Element from our pool
	var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J fields.E2
	Y2Z1.Mul(api, &a.Y, &p.Z, pairingInfo.Extension)
	O.Sub(api, &p.Y, &Y2Z1)
	X2Z1.Mul(api, &a.X, &p.Z, pairingInfo.Extension)
	L.Sub(api, &p.X, &X2Z1)
	C.Mul(api, &O, &O, pairingInfo.Extension)
	D.Mul(api, &L, &L, pairingInfo.Extension)
	E.Mul(api, &L, &D, pairingInfo.Extension)
	F.Mul(api, &p.Z, &C, pairingInfo.Extension)
	G.Mul(api, &p.X, &D, pairingInfo.Extension)
	t0.Add(api, &G, &G)
	H.Add(api, &E, &F).
		Sub(api, &H, &t0)
	t1.Mul(api, &p.Y, &E, pairingInfo.Extension)

	// X, Y, Z
	p.X.Mul(api, &L, &H, pairingInfo.Extension)
	p.Y.Sub(api, &G, &H).
		Mul(api, &p.Y, &O, pairingInfo.Extension).
		Sub(api, &p.Y, &t1)
	p.Z.Mul(api, &E, &p.Z, pairingInfo.Extension)

	t2.Mul(api, &L, &a.Y, pairingInfo.Extension)
	J.Mul(api, &a.X, &O, pairingInfo.Extension).
		Sub(api, &J, &t2)

	// Line evaluation
	evaluation.r0 = L
	evaluation.r1.Neg(api, &O)
	evaluation.r2 = J
}
