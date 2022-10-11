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

package sw_bn254

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bn254"
)

// G2Jac point in Jacobian coords
type G2Jac struct {
	X, Y, Z fields_bn254.E2
}

// G2Affine point in affine coords
type G2Affine struct {
	X, Y fields_bn254.E2
}

// Neg outputs -p
func (p *G2Jac) Neg(api frontend.API, p1 G2Jac) *G2Jac {
	p.Y.Neg(api, p1.Y)
	p.X = p1.X
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G2Affine) Neg(api frontend.API, p1 G2Affine) *G2Affine {
	p.Y.Neg(api, p1.Y)
	p.X = p1.X
	return p
}

// AddAssign add p1 to p and return p
func (p *G2Affine) AddAssign(api frontend.API, p1 G2Affine) *G2Affine {

	var n, d, l, xr, yr fields_bn254.E2

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	n.Sub(api, p1.Y, p.Y)
	d.Sub(api, p1.X, p.X)
	l.DivUnchecked(api, n, d)

	// xr =lambda**2-p1.x-p.x
	xr.Square(api, l).
		Sub(api, xr, p1.X).
		Sub(api, xr, p.X)

	// yr = lambda(p.x - xr)-p.y
	yr.Sub(api, p.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p.Y)

	p.X = xr
	p.Y = yr

	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G2Jac) AddAssign(api frontend.API, p1 *G2Jac) *G2Jac {

	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V fields_bn254.E2

	Z1Z1.Square(api, p1.Z)

	Z2Z2.Square(api, p.Z)

	U1.Mul(api, p1.X, Z2Z2)

	U2.Mul(api, p.X, Z1Z1)

	S1.Mul(api, p1.Y, p.Z)
	S1.Mul(api, S1, Z2Z2)

	S2.Mul(api, p.Y, p1.Z)
	S2.Mul(api, S2, Z1Z1)

	H.Sub(api, U2, U1)

	I.Add(api, H, H)
	I.Square(api, I)

	J.Mul(api, H, I)

	r.Sub(api, S2, S1)
	r.Add(api, r, r)

	V.Mul(api, U1, I)

	p.X.Square(api, r)
	p.X.Sub(api, p.X, J)
	p.X.Sub(api, p.X, V)
	p.X.Sub(api, p.X, V)

	p.Y.Sub(api, V, p.X)
	p.Y.Mul(api, p.Y, r)

	S1.Mul(api, J, S1)
	S1.Add(api, S1, S1)

	p.Y.Sub(api, p.Y, S1)

	p.Z.Add(api, p.Z, p1.Z)
	p.Z.Square(api, p.Z)
	p.Z.Sub(api, p.Z, Z1Z1)
	p.Z.Sub(api, p.Z, Z2Z2)
	p.Z.Mul(api, p.Z, H)

	return p
}

// Double doubles a point in jacobian coords
func (p *G2Jac) Double(api frontend.API, p1 G2Jac) *G2Jac {

	var XX, YY, YYYY, ZZ, S, M, T fields_bn254.E2

	XX.Square(api, p.X)
	YY.Square(api, p.Y)
	YYYY.Square(api, YY)
	ZZ.Square(api, p.Z)
	S.Add(api, p.X, YY)
	S.Square(api, S)
	S.Sub(api, S, XX)
	S.Sub(api, S, YYYY)
	S.Add(api, S, S)
	M.MulByFp(api, XX, 3) // M = 3*XX+a*ZZ², here a=0 (we suppose sw has j invariant 0)
	p.Z.Add(api, p.Z, p.Y)
	p.Z.Square(api, p.Z)
	p.Z.Sub(api, p.Z, YY)
	p.Z.Sub(api, p.Z, ZZ)
	p.X.Square(api, M)
	T.Add(api, S, S)
	p.X.Sub(api, p.X, T)
	p.Y.Sub(api, S, p.X)
	p.Y.Mul(api, p.Y, M)
	YYYY.MulByFp(api, YYYY, 8)
	p.Y.Sub(api, p.Y, YYYY)

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G2Affine) Select(api frontend.API, b frontend.Variable, p1, p2 G2Affine) *G2Affine {

	p.X.Select(api, b, p1.X, p2.X)
	p.Y.Select(api, b, p1.Y, p2.Y)

	return p
}

// FromJac sets p to p1 in affine and returns it
func (p *G2Affine) FromJac(api frontend.API, p1 G2Jac) *G2Affine {
	var s fields_bn254.E2
	s.Mul(api, p1.Z, p1.Z)
	p.X.DivUnchecked(api, p1.X, s)
	s.Mul(api, s, p1.Z)
	p.Y.DivUnchecked(api, p1.Y, s)
	return p
}

// Double compute 2*p1, assign the result to p and return it
// Only for curve with j invariant 0 (a=0).
func (p *G2Affine) Double(api frontend.API, p1 G2Affine) *G2Affine {

	var n, d, l, xr, yr fields_bn254.E2

	// lambda = 3*p1.x**2/2*p.y
	n.Square(api, p1.X).MulByFp(api, n, 3)
	d.MulByFp(api, p1.Y, 2)
	l.DivUnchecked(api, n, d)

	// xr = lambda**2-2*p1.x
	xr.Square(api, l).
		Sub(api, xr, p1.X).
		Sub(api, xr, p1.X)

	// yr = lambda*(p.x-xr)-p.y
	yr.Sub(api, p1.X, xr).
		Mul(api, l, yr).
		Sub(api, yr, p1.Y)

	p.X = xr
	p.Y = yr

	return p

}
