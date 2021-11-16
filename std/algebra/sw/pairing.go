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

// computeLineCoef computes the coefficients of the line passing through Q, R of equation
// x*LineCoeff.R0 +  y*LineCoeff.R1 + LineCoeff.R2
func computeLineCoef(api frontend.API, Q, R G2Affine, ext fields.Extension) LineEvaluation {

	var res LineEvaluation
	res.R0.Sub(api, Q.Y, R.Y)
	res.R1.Sub(api, R.X, Q.X)
	var tmp fields.E2
	res.R2.Mul(api, Q.X, R.Y, ext)
	tmp.Mul(api, R.X, Q.Y, ext)
	res.R2.Sub(api, res.R2, tmp)
	return res
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

	var l LineEvaluation
	var Qacc G2Affine
	Qacc = Q

	for i := len(ateLoopBin) - 2; i >= 0; i-- {
		res.Square(api, *res, pairingInfo.Extension)
		Qacc, l = DoubleStep(api, &Qacc, pairingInfo.Extension)
		l.R0.MulByFp(api, l.R0, P.X)
		l.R1.MulByFp(api, l.R1, P.Y)
		res.MulBy034(api, l.R1, l.R0, l.R2, pairingInfo.Extension)

		if ateLoopBin[i] == 0 {
			continue
		}

		Qacc, l = AddStep(api, &Qacc, &Q, pairingInfo.Extension)
		l.R0.MulByFp(api, l.R0, P.X)
		l.R1.MulByFp(api, l.R1, P.Y)
		res.MulBy034(api, l.R1, l.R0, l.R2, pairingInfo.Extension)
	}

	return res
}

// AddStep
func AddStep(api frontend.API, p1, p2 *G2Affine, ext fields.Extension) (G2Affine, LineEvaluation) {

	var n, d, l, xr, yr fields.E2
	var line LineEvaluation
	var p G2Affine

	// compute lambda = (p1.y-p2.y)/(p1.x-p2.x)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l.Inverse(api, d, ext).Mul(api, l, n, ext)

	// xr =lambda**2-p1.x-p2.x
	xr.Square(api, l, ext).
		Sub(api, xr, p1.X).
		Sub(api, xr, p2.X)

	// yr = lambda(p2.x - xr)-p2.y
	yr.Sub(api, p2.X, xr).
		Mul(api, l, yr, ext).
		Sub(api, yr, p2.Y)

	p.X = xr
	p.Y = yr

	line.R0.Neg(api, l)
	line.R1.SetOne(api)
	line.R2.Mul(api, l, p1.X, ext).Sub(api, line.R2, p1.Y)

	return p, line
}

func DoubleStep(api frontend.API, p1 *G2Affine, ext fields.Extension) (G2Affine, LineEvaluation) {

	var n, d, l, xr, yr fields.E2
	var p G2Affine
	var line LineEvaluation

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X, ext).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.Inverse(api, d, ext).Mul(api, l, n, ext)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l, ext).
		Sub(api, xr, p1.X).
		Sub(api, xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr, ext).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	line.R0.Neg(api, l)
	line.R1.SetOne(api)
	line.R2.Mul(api, l, p1.X, ext).Sub(api, line.R2, p1.Y)

	return p, line

}
