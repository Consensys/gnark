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
	"github.com/consensys/gnark/std/algebra/fields"
	bls377 "github.com/consensys/gurvy/ecc/bls12-377"
)

// G2Jac point in Jacobian coords
type G2Jac struct {
	X, Y, Z fields.E2
}

// G2Affine point in affine coords
type G2Affine struct {
	X, Y fields.E2
}

// ToProj sets p to p1 in projective coords and return it
func (p *G2Jac) ToProj(cs *frontend.ConstraintSystem, p1 *G2Jac, ext fields.Extension) *G2Jac {
	p.X.Mul(cs, &p1.X, &p1.Z, ext)
	p.Y = p1.Y
	var t fields.E2
	t.Mul(cs, &p1.Z, &p1.Z, ext)
	p.Z.Mul(cs, &p.Z, &t, ext)
	return p
}

// Neg outputs -p
func (p *G2Jac) Neg(cs *frontend.ConstraintSystem, p1 *G2Jac) *G2Jac {
	p.Y.Neg(cs, &p1.Y)
	p.X = p1.X
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G2Affine) Neg(cs *frontend.ConstraintSystem, p1 *G2Affine) *G2Affine {
	p.Y.Neg(cs, &p1.Y)
	p.X = p1.X
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac) AddAssign(cs *frontend.ConstraintSystem, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fields.E2

	Z1Z1.Mul(cs, &p1.Z, &p1.Z, ext)

	Z2Z2.Mul(cs, &p.Z, &p.Z, ext)

	U1.Mul(cs, &p1.X, &Z2Z2, ext)

	U2.Mul(cs, &p.X, &Z1Z1, ext)

	S1.Mul(cs, &p1.Y, &p.Z, ext)
	S1.Mul(cs, &S1, &Z2Z2, ext)

	S2.Mul(cs, &p.Y, &p1.Z, ext)
	S2.Mul(cs, &S2, &Z1Z1, ext)

	H.Sub(cs, &U2, &U1)

	I.Add(cs, &H, &H)
	I.Mul(cs, &I, &I, ext)

	J.Mul(cs, &H, &I, ext)

	r.Sub(cs, &S2, &S1)
	r.Add(cs, &r, &r)

	V.Mul(cs, &U1, &I, ext)

	p.X.Mul(cs, &r, &r, ext)
	p.X.Sub(cs, &p.X, &J)
	p.X.Sub(cs, &p.X, &V)
	p.X.Sub(cs, &p.X, &V)

	p.Y.Sub(cs, &V, &p.X)
	p.Y.Mul(cs, &p.Y, &r, ext)

	S1.Mul(cs, &J, &S1, ext)
	S1.Add(cs, &S1, &S1)

	p.Y.Sub(cs, &p.Y, &S1)

	p.Z.Add(cs, &p.Z, &p1.Z)
	p.Z.Mul(cs, &p.Z, &p.Z, ext)
	p.Z.Sub(cs, &p.Z, &Z1Z1)
	p.Z.Sub(cs, &p.Z, &Z2Z2)
	p.Z.Mul(cs, &p.Z, &H, ext)

	return p
}

// AddAssign add p1 to p and return p
func (p *G2Affine) AddAssign(cs *frontend.ConstraintSystem, p1 *G2Affine, ext fields.Extension) *G2Affine {

	var n, d, l, xr, yr fields.E2

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	n.Sub(cs, &p1.Y, &p.Y)
	d.Sub(cs, &p1.X, &p.X)
	l.Inverse(cs, &d, ext).Mul(cs, &l, &n, ext)

	// xr =lambda**2-p1.x-p.x
	xr.Mul(cs, &l, &l, ext).
		Sub(cs, &xr, &p1.X).
		Sub(cs, &xr, &p.X)

	// yr = lambda(p.x - xr)-p.y
	yr.Sub(cs, &p.X, &xr).
		Mul(cs, &l, &yr, ext).
		Sub(cs, &yr, &p.Y)

	p.X = xr
	p.Y = yr
	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *G2Affine) Double(cs *frontend.ConstraintSystem, p1 *G2Affine, ext fields.Extension) *G2Affine {

	var n, d, l, xr, yr fields.E2

	// lambda = 3*p1.x**2/2*p.y
	n.Mul(cs, &p1.X, &p1.X, ext).MulByFp(cs, &n, 3)
	d.MulByFp(cs, &p1.Y, 2)
	l.Inverse(cs, &d, ext).Mul(cs, &l, &n, ext)

	// xr = lambda**2-2*p1.x
	xr.Mul(cs, &l, &l, ext).
		Sub(cs, &xr, &p1.X).
		Sub(cs, &xr, &p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(cs, &p.X, &xr).
		Mul(cs, &l, &yr, ext).
		Sub(cs, &yr, &p.Y)

	p.X = xr
	p.Y = yr

	return p

}

// Double doubles a point in jacobian coords
func (p *G2Jac) Double(cs *frontend.ConstraintSystem, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var XX, YY, YYYY, ZZ, S, M, T fields.E2

	XX.Mul(cs, &p.X, &p.X, ext)
	YY.Mul(cs, &p.Y, &p.Y, ext)
	YYYY.Mul(cs, &YY, &YY, ext)
	ZZ.Mul(cs, &p.Z, &p.Z, ext)
	S.Add(cs, &p.X, &YY)
	S.Mul(cs, &S, &S, ext)
	S.Sub(cs, &S, &XX)
	S.Sub(cs, &S, &YYYY)
	S.Add(cs, &S, &S)
	M.MulByFp(cs, &XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z.Add(cs, &p.Z, &p.Y)
	p.Z.Mul(cs, &p.Z, &p.Z, ext)
	p.Z.Sub(cs, &p.Z, &YY)
	p.Z.Sub(cs, &p.Z, &ZZ)
	p.X.Mul(cs, &M, &M, ext)
	T.Add(cs, &S, &S)
	p.X.Sub(cs, &p.X, &T)
	p.Y.Sub(cs, &S, &p.X)
	p.Y.Mul(cs, &p.Y, &M, ext)
	YYYY.MulByFp(cs, &YYYY, 8)
	p.Y.Sub(cs, &p.Y, &YYYY)

	return p
}

// Assign a value to self (witness assignment)
func (p *G2Jac) Assign(p1 *bls377.G2Jac) {
	p.X.Assign(&p1.X)
	p.Y.Assign(&p1.Y)
	p.Z.Assign(&p1.Z)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Jac) MustBeEqual(cs *frontend.ConstraintSystem, other G2Jac) {
	p.X.MustBeEqual(cs, other.X)
	p.Y.MustBeEqual(cs, other.Y)
	p.Z.MustBeEqual(cs, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G2Affine) Assign(p1 *bls377.G2Affine) {
	p.X.Assign(&p1.X)
	p.Y.Assign(&p1.Y)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Affine) MustBeEqual(cs *frontend.ConstraintSystem, other G2Affine) {
	p.X.MustBeEqual(cs, other.X)
	p.Y.MustBeEqual(cs, other.Y)
}
