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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
)

// LineEvalRes represents a sparse Fp12 Elmt (result of the line evaluation)
type LineEvalRes struct {
	r0, r1, r2 fields.Fp2Elmt
}

// LineEvalBLS377 computes f(P) where div(f) = P+R-2O, Q, R are on the twist and in the r-torsion (trace 0 subgroup)
// the result is pulled back like if it was computed on the original curve, so it's a Fp12Elmt, that is sparse,
// only 3 entries are non zero. The result is therefore stored in a custom type LineEvalRes representing a sparse element
func LineEvalBLS377(circuit *frontend.CS, Q, R G2Jac, P G1Jac, result *LineEvalRes, ext fields.Extension) {

	// converts Q and R to projective coords
	Q.ToProj(circuit, &Q, ext)
	R.ToProj(circuit, &R, ext)

	// line eq: w^3*(QyRz-QzRy)x +  w^2*(QzRx - QxRz)y + w^5*(QxRy-QyRxz)
	// result.r1 = Px*(QyRz-QzRy)
	// result.r0 = Py*(QzRx - QxRz)
	// result.r2 = Pz*(QxRy-QyRxz)

	result.r1.Mul(circuit, &Q.Y, &R.Z, ext)
	result.r0.Mul(circuit, &Q.Z, &R.X, ext)
	result.r2.Mul(circuit, &Q.X, &R.Y, ext)

	Q.Z.Mul(circuit, &Q.Z, &R.Y, ext)
	Q.X.Mul(circuit, &Q.X, &R.Z, ext)
	Q.Y.Mul(circuit, &Q.Y, &R.X, ext)

	result.r1.Sub(circuit, &result.r1, &Q.Z)
	result.r0.Sub(circuit, &result.r0, &Q.X)
	result.r2.Sub(circuit, &result.r2, &Q.Y)

	// multiply P.Z by coeffs[2] in case P is infinity
	result.r0.MulByFp(circuit, &result.r0, P.Y)
	result.r1.MulByFp(circuit, &result.r1, P.X)
	result.r2.MulByFp(circuit, &result.r2, P.Z)
}

// MulAssign multiplies the result of a line evaluation to the current Fp12 accumulator
func (l *LineEvalRes) MulAssign(circuit *frontend.CS, z *fields.Fp12Elmt, ext fields.Extension) {
	var a, b, c fields.Fp12Elmt
	a.MulByVW(circuit, z, &l.r1, ext)
	b.MulByV(circuit, z, &l.r0, ext)
	c.MulByV2W(circuit, z, &l.r2, ext)
	z.Add(circuit, &a, &b).Add(circuit, z, &c)
}
