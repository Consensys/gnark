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

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// G1Jac point in Jacobian coords
type G1Jac struct {
	X, Y, Z frontend.Variable
}

// G1Affine point in affine coords
type G1Affine struct {
	X, Y frontend.Variable
}

// Neg outputs -p
func (p *G1Jac) Neg(gnark frontend.API, p1 *G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = gnark.Sub(0, p1.Y)
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G1Affine) Neg(gnark frontend.API, p1 *G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = gnark.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(gnark frontend.API, p1 *G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)

	l1 := gnark.Sub(p1.Y, p.Y)
	l2 := gnark.Sub(p1.X, p.X)
	l := gnark.Div(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x1 := gnark.Mul(l, l)
	_x2 := gnark.Add(p.X, p1.X)
	_x := gnark.Sub(_x1, _x2)

	// p.y = lambda(p.x-xr) - p.y
	t1 := gnark.Mul(p.X, l)
	t2 := gnark.Mul(l, _x)
	l31 := gnark.Add(t2, p.Y)
	l3 := gnark.Sub(t1, l31)

	p.Y = gnark.Mul(l3, 1)

	//p.x = xr
	p.X = gnark.Mul(_x, 1)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Jac) AssignToRefactor(gnark frontend.API, p1 *G1Jac) *G1Jac {
	p.X = gnark.Constant(p1.X)
	p.Y = gnark.Constant(p1.Y)
	p.Z = gnark.Constant(p1.Z)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Affine) AssignToRefactor(gnark frontend.API, p1 *G1Affine) *G1Affine {
	p.X = gnark.Constant(p1.X)
	p.Y = gnark.Constant(p1.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(gnark frontend.API, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V frontend.Variable

	Z1Z1 = gnark.Mul(p1.Z, p1.Z)

	Z2Z2 = gnark.Mul(p.Z, p.Z)

	U1 = gnark.Mul(p1.X, Z2Z2)

	U2 = gnark.Mul(p.X, Z1Z1)

	S1 = gnark.Mul(p1.Y, p.Z)
	S1 = gnark.Mul(S1, Z2Z2)

	S2 = gnark.Mul(p.Y, p1.Z)
	S2 = gnark.Mul(S2, Z1Z1)

	H = gnark.Sub(U2, U1)

	I = gnark.Add(H, H)
	I = gnark.Mul(I, I)

	J = gnark.Mul(H, I)

	r = gnark.Sub(S2, S1)
	r = gnark.Add(r, r)

	V = gnark.Mul(U1, I)

	p.X = gnark.Mul(r, r)
	p.X = gnark.Sub(p.X, J)
	p.X = gnark.Sub(p.X, V)
	p.X = gnark.Sub(p.X, V)

	p.Y = gnark.Sub(V, p.X)
	p.Y = gnark.Mul(p.Y, r)

	S1 = gnark.Mul(J, S1)
	S1 = gnark.Add(S1, S1)

	p.Y = gnark.Sub(p.Y, S1)

	p.Z = gnark.Add(p.Z, p1.Z)
	p.Z = gnark.Mul(p.Z, p.Z)
	p.Z = gnark.Sub(p.Z, Z1Z1)
	p.Z = gnark.Sub(p.Z, Z2Z2)
	p.Z = gnark.Mul(p.Z, H)

	return p
}

// DoubleAssign doubles the receiver point in jacobian coords and returns it
func (p *G1Jac) DoubleAssign(gnark frontend.API) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T frontend.Variable

	XX = gnark.Mul(p.X, p.X)
	YY = gnark.Mul(p.Y, p.Y)
	YYYY = gnark.Mul(YY, YY)
	ZZ = gnark.Mul(p.Z, p.Z)
	S = gnark.Add(p.X, YY)
	S = gnark.Mul(S, S)
	S = gnark.Sub(S, XX)
	S = gnark.Sub(S, YYYY)
	S = gnark.Add(S, S)
	M = gnark.Mul(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z = gnark.Add(p.Z, p.Y)
	p.Z = gnark.Mul(p.Z, p.Z)
	p.Z = gnark.Sub(p.Z, YY)
	p.Z = gnark.Sub(p.Z, ZZ)
	p.X = gnark.Mul(M, M)
	T = gnark.Add(S, S)
	p.X = gnark.Sub(p.X, T)
	p.Y = gnark.Sub(S, p.X)
	p.Y = gnark.Mul(p.Y, M)
	YYYY = gnark.Mul(YYYY, 8)
	p.Y = gnark.Sub(p.Y, YYYY)

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(gnark frontend.API, b frontend.Variable, p1, p2 *G1Affine) *G1Affine {

	p.X = gnark.Select(b, p1.X, p2.X)
	p.Y = gnark.Select(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(gnark frontend.API, p1 *G1Jac) *G1Affine {
	s := gnark.Mul(p1.Z, p1.Z)
	p.X = gnark.Div(p1.X, s)
	p.Y = gnark.Div(p1.Y, gnark.Mul(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Affine) Double(gnark frontend.API, p1 *G1Affine) *G1Affine {

	var t, d, c1, c2, c3 big.Int
	t.SetInt64(3)
	d.SetInt64(2)
	c1.SetInt64(1)
	c2.SetInt64(-2)
	c3.SetInt64(-1)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	x2 := gnark.Mul(p1.X, p1.X)
	gnark.Mul(p1.X, p1.X)
	l1 := gnark.Mul(x2, t)
	l2 := gnark.Mul(p1.Y, d)
	l := gnark.Div(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x1 := gnark.Mul(l, l, c1)
	_x2 := gnark.Mul(p1.X, c2)
	_x := gnark.Add(_x1, _x2)

	// p.y = lambda(p.x-xr) - p.y
	t1 := gnark.Mul(p1.X, l)
	t2 := gnark.Mul(l, _x)
	l31 := gnark.Mul(t1, c1)
	l32 := gnark.Mul(t2, c3)
	l33 := gnark.Mul(p1.Y, c3)
	l3 := gnark.Add(l31, l32, l33)
	p.Y = gnark.Mul(l3, 1)

	//p.x = xr
	p.X = gnark.Mul(_x, 1)
	return p
}

// ScalarMul computes scalar*p1, affect the result to p, and returns it.
// n is the number of bits used for the scalar mul.
// TODO it doesn't work if the scalar if 1, because it ends up doing P-P at the end, involving division by 0
// TODO add a panic if scalar == 1
func (p *G1Affine) ScalarMul(gnark frontend.API, p1 *G1Affine, s interface{}, n int) *G1Affine {

	scalar := gnark.Constant(s)

	var base, res G1Affine
	base.Double(gnark, p1)
	res.AssignToRefactor(gnark, p1)

	b := gnark.ToBinary(scalar, n)

	var tmp G1Affine

	// start from 1 and use right-to-left scalar multiplication to avoid bugs due to incomplete addition law
	// (I don't see how to avoid that)
	for i := 1; i <= n-1; i++ {
		tmp.AssignToRefactor(gnark, &res).AddAssign(gnark, &base)
		res.Select(gnark, b[i], &tmp, &res)
		base.Double(gnark, &base)
	}

	// now check the lsb, if it's one, leave the result as is, otherwise substract P
	tmp.Neg(gnark, p1).AddAssign(gnark, &res)

	p.Select(gnark, b[0], &res, &tmp)

	return p

}

func bls12377FpTobw6761fr(a *fp.Element) (r fr.Element) {
	for i, v := range a {
		r[i] = v
	}
	return
}

// Assign a value to self (witness assignment)
func (p *G1Jac) Assign(p1 *bls12377.G1Jac) {
	p.X.Assign(bls12377FpTobw6761fr(&p1.X))
	p.Y.Assign(bls12377FpTobw6761fr(&p1.Y))
	p.Z.Assign(bls12377FpTobw6761fr(&p1.Z))
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Jac) MustBeEqual(gnark frontend.API, other G1Jac) {
	gnark.AssertIsEqual(p.X, other.X)
	gnark.AssertIsEqual(p.Y, other.Y)
	gnark.AssertIsEqual(p.Z, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls12377.G1Affine) {
	p.X.Assign(bls12377FpTobw6761fr(&p1.X))
	p.Y.Assign(bls12377FpTobw6761fr(&p1.Y))
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) MustBeEqual(gnark frontend.API, other G1Affine) {
	gnark.AssertIsEqual(p.X, other.X)
	gnark.AssertIsEqual(p.Y, other.Y)
}
