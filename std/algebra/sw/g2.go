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
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
)

// G2Jac point in Jacobian coords
type G2Jac struct {
	X, Y, Z fields.E2
}

type G2Proj struct {
	X, Y, Z fields.E2
}

// G2Affine point in affine coords
type G2Affine struct {
	X, Y fields.E2
}

// ToProj sets p to p1 in projective coords and return it
func (p *G2Jac) ToProj(gnark frontend.API, p1 *G2Jac, ext fields.Extension) *G2Jac {
	p.X.Mul(gnark, &p1.X, &p1.Z, ext)
	p.Y = p1.Y
	var t fields.E2
	t.Mul(gnark, &p1.Z, &p1.Z, ext)
	p.Z.Mul(gnark, &p.Z, &t, ext)
	return p
}

// Neg outputs -p
func (p *G2Jac) Neg(gnark frontend.API, p1 *G2Jac) *G2Jac {
	p.Y.Neg(gnark, &p1.Y)
	p.X = p1.X
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G2Affine) Neg(gnark frontend.API, p1 *G2Affine) *G2Affine {
	p.Y.Neg(gnark, &p1.Y)
	p.X = p1.X
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac) AddAssign(gnark frontend.API, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fields.E2

	Z1Z1.Mul(gnark, &p1.Z, &p1.Z, ext)

	Z2Z2.Mul(gnark, &p.Z, &p.Z, ext)

	U1.Mul(gnark, &p1.X, &Z2Z2, ext)

	U2.Mul(gnark, &p.X, &Z1Z1, ext)

	S1.Mul(gnark, &p1.Y, &p.Z, ext)
	S1.Mul(gnark, &S1, &Z2Z2, ext)

	S2.Mul(gnark, &p.Y, &p1.Z, ext)
	S2.Mul(gnark, &S2, &Z1Z1, ext)

	H.Sub(gnark, &U2, &U1)

	I.Add(gnark, &H, &H)
	I.Mul(gnark, &I, &I, ext)

	J.Mul(gnark, &H, &I, ext)

	r.Sub(gnark, &S2, &S1)
	r.Add(gnark, &r, &r)

	V.Mul(gnark, &U1, &I, ext)

	p.X.Mul(gnark, &r, &r, ext)
	p.X.Sub(gnark, &p.X, &J)
	p.X.Sub(gnark, &p.X, &V)
	p.X.Sub(gnark, &p.X, &V)

	p.Y.Sub(gnark, &V, &p.X)
	p.Y.Mul(gnark, &p.Y, &r, ext)

	S1.Mul(gnark, &J, &S1, ext)
	S1.Add(gnark, &S1, &S1)

	p.Y.Sub(gnark, &p.Y, &S1)

	p.Z.Add(gnark, &p.Z, &p1.Z)
	p.Z.Mul(gnark, &p.Z, &p.Z, ext)
	p.Z.Sub(gnark, &p.Z, &Z1Z1)
	p.Z.Sub(gnark, &p.Z, &Z2Z2)
	p.Z.Mul(gnark, &p.Z, &H, ext)

	return p
}

// AddAssign add p1 to p and return p
func (p *G2Affine) AddAssign(gnark frontend.API, p1 *G2Affine, ext fields.Extension) *G2Affine {

	var n, d, l, xr, yr fields.E2

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	n.Sub(gnark, &p1.Y, &p.Y)
	d.Sub(gnark, &p1.X, &p.X)
	l.Inverse(gnark, &d, ext).Mul(gnark, &l, &n, ext)

	// xr =lambda**2-p1.x-p.x
	xr.Mul(gnark, &l, &l, ext).
		Sub(gnark, &xr, &p1.X).
		Sub(gnark, &xr, &p.X)

	// yr = lambda(p.x - xr)-p.y
	yr.Sub(gnark, &p.X, &xr).
		Mul(gnark, &l, &yr, ext).
		Sub(gnark, &yr, &p.Y)

	p.X = xr
	p.Y = yr
	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *G2Affine) Double(gnark frontend.API, p1 *G2Affine, ext fields.Extension) *G2Affine {

	var n, d, l, xr, yr fields.E2

	// lambda = 3*p1.x**2/2*p.y
	n.Mul(gnark, &p1.X, &p1.X, ext).MulByFp(gnark, &n, 3)
	d.MulByFp(gnark, &p1.Y, 2)
	l.Inverse(gnark, &d, ext).Mul(gnark, &l, &n, ext)

	// xr = lambda**2-2*p1.x
	xr.Mul(gnark, &l, &l, ext).
		Sub(gnark, &xr, &p1.X).
		Sub(gnark, &xr, &p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(gnark, &p.X, &xr).
		Mul(gnark, &l, &yr, ext).
		Sub(gnark, &yr, &p.Y)

	p.X = xr
	p.Y = yr

	return p

}

// Double doubles a point in jacobian coords
func (p *G2Jac) Double(gnark frontend.API, p1 *G2Jac, ext fields.Extension) *G2Jac {

	var XX, YY, YYYY, ZZ, S, M, T fields.E2

	XX.Mul(gnark, &p.X, &p.X, ext)
	YY.Mul(gnark, &p.Y, &p.Y, ext)
	YYYY.Mul(gnark, &YY, &YY, ext)
	ZZ.Mul(gnark, &p.Z, &p.Z, ext)
	S.Add(gnark, &p.X, &YY)
	S.Mul(gnark, &S, &S, ext)
	S.Sub(gnark, &S, &XX)
	S.Sub(gnark, &S, &YYYY)
	S.Add(gnark, &S, &S)
	M.MulByFp(gnark, &XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z.Add(gnark, &p.Z, &p.Y)
	p.Z.Mul(gnark, &p.Z, &p.Z, ext)
	p.Z.Sub(gnark, &p.Z, &YY)
	p.Z.Sub(gnark, &p.Z, &ZZ)
	p.X.Mul(gnark, &M, &M, ext)
	T.Add(gnark, &S, &S)
	p.X.Sub(gnark, &p.X, &T)
	p.Y.Sub(gnark, &S, &p.X)
	p.Y.Mul(gnark, &p.Y, &M, ext)
	YYYY.MulByFp(gnark, &YYYY, 8)
	p.Y.Sub(gnark, &p.Y, &YYYY)

	return p
}

// Assign a value to self (witness assignment)
func (p *G2Jac) Assign(p1 *bls12377.G2Jac) {
	p.X.Assign(&p1.X)
	p.Y.Assign(&p1.Y)
	p.Z.Assign(&p1.Z)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Jac) MustBeEqual(gnark frontend.API, other G2Jac) {
	p.X.MustBeEqual(gnark, other.X)
	p.Y.MustBeEqual(gnark, other.Y)
	p.Z.MustBeEqual(gnark, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G2Affine) Assign(p1 *bls12377.G2Affine) {
	p.X.Assign(&p1.X)
	p.Y.Assign(&p1.Y)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G2Affine) MustBeEqual(gnark frontend.API, other G2Affine) {
	p.X.MustBeEqual(gnark, other.X)
	p.Y.MustBeEqual(gnark, other.Y)
}
