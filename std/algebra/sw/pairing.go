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
	"github.com/consensys/gurvy/utils"
)

// PairingContext contains useful info about the pairing
type PairingContext struct {
	AteLoop   uint64 // stores the ate loop
	Extension fields.Extension
}

// LineEvalRes represents a sparse Fp12 Elmt (result of the line evaluation)
type LineEvalRes struct {
	r0, r1, r2 fields.E2
}

// LineEvalBLS377 computes f(P) where div(f) = (P)+(R)+(-(P+R))-3O, Q, R are on the twist and in the r-torsion (trace 0 subgroup)
// the result is pulled back like if it was computed on the original curve, so it's a Fp12Elmt, that is sparse,
// only 3 entries are non zero. The result is therefore stored in a custom type LineEvalRes representing a sparse element
func LineEvalBLS377(cs *frontend.CS, Q, R G2Jac, P G1Jac, result *LineEvalRes, ext fields.Extension) {

	// converts Q and R to projective coords
	Q.ToProj(cs, &Q, ext)
	R.ToProj(cs, &R, ext)

	// line eq: w^3*(QyRz-QzRy)x +  w^2*(QzRx - QxRz)y + w^5*(QxRy-QyRxz)
	// result.r1 = Px*(QyRz-QzRy)
	// result.r0 = Py*(QzRx - QxRz)
	// result.r2 = Pz*(QxRy-QyRxz)

	result.r1.Mul(cs, &Q.Y, &R.Z, ext)
	result.r0.Mul(cs, &Q.Z, &R.X, ext)
	result.r2.Mul(cs, &Q.X, &R.Y, ext)

	Q.Z.Mul(cs, &Q.Z, &R.Y, ext)
	Q.X.Mul(cs, &Q.X, &R.Z, ext)
	Q.Y.Mul(cs, &Q.Y, &R.X, ext)

	result.r1.Sub(cs, &result.r1, &Q.Z)
	result.r0.Sub(cs, &result.r0, &Q.X)
	result.r2.Sub(cs, &result.r2, &Q.Y)

	// multiply P.Z by coeffs[2] in case P is infinity
	result.r0.MulByFp(cs, &result.r0, P.Y)
	result.r1.MulByFp(cs, &result.r1, P.X)
	result.r2.MulByFp(cs, &result.r2, P.Z)
}

// LineEvalAffineBLS377 computes f(P) where div(f) = (P)+(R)+(-(P+R))-3O, Q, R are on the twist and in the r-torsion (trace 0 subgroup)
// the result is pulled back like if it was computed on the original curve, so it's a Fp12Elmt, that is sparse,
// only 3 entries are non zero. The result is therefore stored in a custom type LineEvalRes representing a sparse element
func LineEvalAffineBLS377(cs *frontend.CS, Q, R G2Affine, P G1Affine, result *LineEvalRes, ext fields.Extension) {

	// line eq: w^3*(QyRz-QzRy)x +  w^2*(QzRx - QxRz)y + w^5*(QxRy-QyRxz)
	// result.r1 = Px*(QyRz-QzRy)
	// result.r0 = Py*(QzRx - QxRz)
	// result.r2 = Pz*(QxRy-QyRx)
	// here all the z coordinates are 1

	//result.r1.Mul(cs, &Q.Y, &R.Z, ext)
	result.r1.Sub(cs, &Q.Y, &R.Y)
	result.r0.Sub(cs, &R.X, &Q.X)
	result.r2.Mul(cs, &Q.X, &R.Y, ext)

	var tmp fields.E2
	tmp.Mul(cs, &Q.Y, &R.X, ext)
	result.r2.Sub(cs, &result.r2, &tmp)

	// multiply P.Z by coeffs[2] in case P is infinity
	result.r0.MulByFp(cs, &result.r0, P.Y)
	result.r1.MulByFp(cs, &result.r1, P.X)
}

// MulAssign multiplies the result of a line evaluation to the current Fp12 accumulator
func (l *LineEvalRes) MulAssign(cs *frontend.CS, z *fields.E12, ext fields.Extension) {
	var a, b, c fields.E12
	a.MulByVW(cs, z, &l.r1, ext)
	b.MulByV(cs, z, &l.r0, ext)
	c.MulByV2W(cs, z, &l.r2, ext)
	z.Add(cs, &a, &b).Add(cs, z, &c)
}

// MillerLoop computes the miller loop
func MillerLoop(cs *frontend.CS, P G1Jac, Q G2Jac, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopNaf [64]int8
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	utils.NafDecomposition(&ateLoopBigInt, ateLoopNaf[:])

	res.SetOne(cs)

	// the line goes through QCur and QNext
	var QCur, QNext, QNextNeg G2Jac
	var QNeg G2Jac

	QCur = Q

	// Stores -Q
	QNeg.Neg(cs, &Q)

	var lEval LineEvalRes

	// Miller loop
	for i := len(ateLoopNaf) - 2; i >= 0; i-- {
		QNext = QCur
		QNext.Double(cs, &QNext, pairingInfo.Extension)
		QNextNeg.Neg(cs, &QNext)

		res.Mul(cs, res, res, pairingInfo.Extension)

		// evaluates line though Qcur,2Qcur at P
		LineEvalBLS377(cs, QCur, QNextNeg, P, &lEval, pairingInfo.Extension)
		lEval.MulAssign(cs, res, pairingInfo.Extension)

		if ateLoopNaf[i] == 1 {
			// evaluates line through 2Qcur, Q at P
			LineEvalBLS377(cs, QNext, Q, P, &lEval, pairingInfo.Extension)
			lEval.MulAssign(cs, res, pairingInfo.Extension)

			QNext.AddAssign(cs, &Q, pairingInfo.Extension)

		} else if ateLoopNaf[i] == -1 {
			// evaluates line through 2Qcur, -Q at P
			LineEvalBLS377(cs, QNext, QNeg, P, &lEval, pairingInfo.Extension)
			lEval.MulAssign(cs, res, pairingInfo.Extension)

			QNext.AddAssign(cs, &QNeg, pairingInfo.Extension)
		}

		QCur = QNext
	}

	return res
}

// MillerLoopAffine computes the miller loop, with points in affine
// When neither Q nor P are the point at infinity
func MillerLoopAffine(cs *frontend.CS, P G1Affine, Q G2Affine, res *fields.E12, pairingInfo PairingContext) *fields.E12 {

	var ateLoopNaf [64]int8
	var ateLoopBigInt big.Int
	ateLoopBigInt.SetUint64(pairingInfo.AteLoop)
	utils.NafDecomposition(&ateLoopBigInt, ateLoopNaf[:])

	res.SetOne(cs)

	// the line goes through QCur and QNext
	var QCur, QNext, QNextNeg G2Affine
	var QNeg G2Affine

	QCur = Q

	// Stores -Q
	QNeg.Neg(cs, &Q)

	var lEval LineEvalRes

	// Miller loop
	for i := len(ateLoopNaf) - 2; i >= 0; i-- {
		QNext = QCur
		QNext.Double(cs, &QNext, pairingInfo.Extension)
		QNextNeg.Neg(cs, &QNext)

		res.Mul(cs, res, res, pairingInfo.Extension)

		// evaluates line though Qcur,2Qcur at P
		LineEvalAffineBLS377(cs, QCur, QNextNeg, P, &lEval, pairingInfo.Extension)
		lEval.MulAssign(cs, res, pairingInfo.Extension)

		if ateLoopNaf[i] == 1 {
			// evaluates line through 2Qcur, Q at P
			LineEvalAffineBLS377(cs, QNext, Q, P, &lEval, pairingInfo.Extension)
			lEval.MulAssign(cs, res, pairingInfo.Extension)

			QNext.AddAssign(cs, &Q, pairingInfo.Extension)

		} else if ateLoopNaf[i] == -1 {
			// evaluates line through 2Qcur, -Q at P
			LineEvalAffineBLS377(cs, QNext, QNeg, P, &lEval, pairingInfo.Extension)
			lEval.MulAssign(cs, res, pairingInfo.Extension)

			QNext.AddAssign(cs, &QNeg, pairingInfo.Extension)
		}

		QCur = QNext
	}

	return res
}
