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
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/std/algebra/tower/fp24"
)

// G2Jac point in Jacobian coords
type G2Jac struct {
	X, Y, Z fp24.E4
}

type G2Proj struct {
	X, Y, Z fp24.E4
}

// G2Affine point in affine coords
type G2Affine struct {
	X, Y fp24.E4
}

// ToProj sets p to p1 in projective coords and return it
func (p *G2Jac) ToProj(api frontend.API, p1 *G2Jac, ext *fp2.Extension) *G2Jac {
	p.X.Mul(api, p1.X, p1.Z, ext)
	p.Y = p1.Y
	var t fp24.E4
	t.Square(api, p1.Z, ext)
	p.Z.Mul(api, p.Z, t, ext)
	return p
}

// Neg outputs -p
func (p *G2Jac) Neg(api frontend.API, p1 *G2Jac) *G2Jac {
	p.Y.Neg(api, p1.Y)
	p.X = p1.X
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G2Affine) Neg(api frontend.API, p1 *G2Affine) *G2Affine {
	p.Y.Neg(api, p1.Y)
	p.X = p1.X
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac) AddAssign(api frontend.API, p1 *G2Jac, ext *fp2.Extension) *G2Jac {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fp24.E4

	Z1Z1.Square(api, p1.Z, ext)

	Z2Z2.Square(api, p.Z, ext)

	U1.Mul(api, p1.X, Z2Z2, ext)

	U2.Mul(api, p.X, Z1Z1, ext)

	S1.Mul(api, p1.Y, p.Z, ext)
	S1.Mul(api, S1, Z2Z2, ext)

	S2.Mul(api, p.Y, p1.Z, ext)
	S2.Mul(api, S2, Z1Z1, ext)

	H.Sub(api, U2, U1)

	I.Add(api, H, H)
	I.Square(api, I, ext)

	J.Mul(api, H, I, ext)

	r.Sub(api, S2, S1)
	r.Add(api, r, r)

	V.Mul(api, U1, I, ext)

	p.X.Square(api, r, ext)
	p.X.Sub(api, p.X, J)
	p.X.Sub(api, p.X, V)
	p.X.Sub(api, p.X, V)

	p.Y.Sub(api, V, p.X)
	p.Y.Mul(api, p.Y, r, ext)

	S1.Mul(api, J, S1, ext)
	S1.Add(api, S1, S1)

	p.Y.Sub(api, p.Y, S1)

	p.Z.Add(api, p.Z, p1.Z)
	p.Z.Square(api, p.Z, ext)
	p.Z.Sub(api, p.Z, Z1Z1)
	p.Z.Sub(api, p.Z, Z2Z2)
	p.Z.Mul(api, p.Z, H, ext)

	return p
}

// AddAssign add p1 to p and return p
func (p *G2Affine) AddAssign(api frontend.API, p1 *G2Affine, ext *fp2.Extension) *G2Affine {

	var n, d, l, xr, yr fp24.E4

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	n.Sub(api, p1.Y, p.Y)
	d.Sub(api, p1.X, p.X)
	l.Inverse(api, d, ext).Mul(api, l, n, ext)

	// xr =lambda**2-p1.x-p.x
	xr.Square(api, l, ext).
		Sub(api, xr, p1.X).
		Sub(api, xr, p.X)

	// yr = lambda(p.x - xr)-p.y
	yr.Sub(api, p.X, xr).
		Mul(api, l, yr, ext).
		Sub(api, yr, p.Y)

	p.X = xr
	p.Y = yr

	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *G2Affine) Double(api frontend.API, p1 *G2Affine, ext *fp2.Extension) *G2Affine {

	var n, d, l, xr, yr fp24.E4

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

	return p

}

// Double doubles a point in jacobian coords
func (p *G2Jac) Double(api frontend.API, p1 *G2Jac, ext *fp2.Extension) *G2Jac {

	var XX, YY, YYYY, ZZ, S, M, T fp24.E4

	XX.Square(api, p.X, ext)
	YY.Square(api, p.Y, ext)
	YYYY.Square(api, YY, ext)
	ZZ.Square(api, p.Z, ext)
	S.Add(api, p.X, YY)
	S.Square(api, S, ext)
	S.Sub(api, S, XX)
	S.Sub(api, S, YYYY)
	S.Add(api, S, S)
	M.MulByFp(api, XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z.Add(api, p.Z, p.Y)
	p.Z.Square(api, p.Z, ext)
	p.Z.Sub(api, p.Z, YY)
	p.Z.Sub(api, p.Z, ZZ)
	p.X.Square(api, M, ext)
	T.Add(api, S, S)
	p.X.Sub(api, p.X, T)
	p.Y.Sub(api, S, p.X)
	p.Y.Mul(api, p.Y, M, ext)
	YYYY.MulByFp(api, YYYY, 8)
	p.Y.Sub(api, p.Y, YYYY)

	return p
}

// Assign a value to self (witness assignment)
func (p *G2Jac) Assign(p1 *bls24315.G2Jac) {
	p.X.Assign([2][2]interface{}{{p1.X.B0.A0, p1.X.B0.A1}, {p1.X.B1.A0, p1.X.B1.A1}})
	p.Y.Assign([2][2]interface{}{{p1.Y.B0.A0, p1.Y.B0.A1}, {p1.Y.B1.A0, p1.Y.B1.A1}})
	p.Z.Assign([2][2]interface{}{{p1.Z.B0.A0, p1.Z.B0.A1}, {p1.Z.B1.A0, p1.Z.B1.A1}})
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Jac) MustBeEqual(api frontend.API, other G2Jac) {
	p.X.MustBeEqual(api, other.X)
	p.Y.MustBeEqual(api, other.Y)
	p.Z.MustBeEqual(api, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G2Affine) Assign(p1 *bls24315.G2Affine) {
	p.X.Assign([2][2]interface{}{{p1.X.B0.A0, p1.X.B0.A1}, {p1.X.B1.A0, p1.X.B1.A1}})
	p.Y.Assign([2][2]interface{}{{p1.Y.B0.A0, p1.Y.B0.A1}, {p1.Y.B1.A0, p1.Y.B1.A1}})
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Affine) MustBeEqual(api frontend.API, other G2Affine) {
	p.X.MustBeEqual(api, other.X)
	p.Y.MustBeEqual(api, other.Y)
}

// DoubleAndAdd computes 2*p1+p2 in affine coords
func (p *G2Affine) DoubleAndAdd(api frontend.API, p1, p2 *G2Affine, ext *fp2.Extension) *G2Affine {

	var n, d, l1, l2, x3, x4, y4 fp24.E4

	// compute lambda1 = (y2-y1)/(x2-x1)
	n.Sub(api, p1.Y, p2.Y)
	d.Sub(api, p1.X, p2.X)
	l1.Inverse(api, d, ext).Mul(api, l1, n, ext)

	// compute x3 = lambda1**2-x1-x2
	x3.Square(api, l1, ext).
		Sub(api, x3, p1.X).
		Sub(api, x3, p2.X)

	// omit y3 computation
	// compute lambda2 = -lambda1-2*y1/(x3-x1)
	n.Double(api, p1.Y)
	d.Sub(api, x3, p1.X)
	l2.Inverse(api, d, ext).Mul(api, l2, n, ext)
	l2.Add(api, l2, l1).Neg(api, l2)

	// compute x4 =lambda2**2-x1-x3
	x4.Square(api, l2, ext).
		Sub(api, x4, p1.X).
		Sub(api, x4, x3)

	// compute y4 = lambda2*(x1 - x4)-y1
	y4.Sub(api, p1.X, x4).
		Mul(api, l2, y4, ext).
		Sub(api, y4, p1.Y)

	p.X = x4
	p.Y = y4

	return p
}
