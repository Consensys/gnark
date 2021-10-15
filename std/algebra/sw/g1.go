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
func (p *G1Jac) Neg(api frontend.API, p1 *G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G1Affine) Neg(api frontend.API, p1 *G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(api frontend.API, p1 *G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)

	l1 := api.Sub(p1.Y, p.Y)
	l2 := api.Sub(p1.X, p.X)
	l := api.Div(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x1 := api.Mul(l, l)
	_x2 := api.Add(p.X, p1.X)
	_x := api.Sub(_x1, _x2)

	// p.y = lambda(p.x-xr) - p.y
	t1 := api.Mul(p.X, l)
	t2 := api.Mul(l, _x)
	l31 := api.Add(t2, p.Y)
	l3 := api.Sub(t1, l31)

	p.Y = api.Mul(l3, 1)

	//p.x = xr
	p.X = api.Mul(_x, 1)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Jac) AssignToRefactor(api frontend.API, p1 *G1Jac) *G1Jac {
	p.X = api.Constant(p1.X)
	p.Y = api.Constant(p1.Y)
	p.Z = api.Constant(p1.Z)
	return p
}

// AssignToRefactor sets p to p1 and return it
func (p *G1Affine) AssignToRefactor(api frontend.API, p1 *G1Affine) *G1Affine {
	p.X = api.Constant(p1.X)
	p.Y = api.Constant(p1.Y)
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(api frontend.API, p1 *G1Jac) *G1Jac {

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V frontend.Variable

	Z1Z1 = api.Mul(p1.Z, p1.Z)

	Z2Z2 = api.Mul(p.Z, p.Z)

	U1 = api.Mul(p1.X, Z2Z2)

	U2 = api.Mul(p.X, Z1Z1)

	S1 = api.Mul(p1.Y, p.Z)
	S1 = api.Mul(S1, Z2Z2)

	S2 = api.Mul(p.Y, p1.Z)
	S2 = api.Mul(S2, Z1Z1)

	H = api.Sub(U2, U1)

	I = api.Add(H, H)
	I = api.Mul(I, I)

	J = api.Mul(H, I)

	r = api.Sub(S2, S1)
	r = api.Add(r, r)

	V = api.Mul(U1, I)

	p.X = api.Mul(r, r)
	p.X = api.Sub(p.X, J)
	p.X = api.Sub(p.X, V)
	p.X = api.Sub(p.X, V)

	p.Y = api.Sub(V, p.X)
	p.Y = api.Mul(p.Y, r)

	S1 = api.Mul(J, S1)
	S1 = api.Add(S1, S1)

	p.Y = api.Sub(p.Y, S1)

	p.Z = api.Add(p.Z, p1.Z)
	p.Z = api.Mul(p.Z, p.Z)
	p.Z = api.Sub(p.Z, Z1Z1)
	p.Z = api.Sub(p.Z, Z2Z2)
	p.Z = api.Mul(p.Z, H)

	return p
}

// DoubleAssign doubles the receiver point in jacobian coords and returns it
func (p *G1Jac) DoubleAssign(api frontend.API) *G1Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T frontend.Variable

	XX = api.Mul(p.X, p.X)
	YY = api.Mul(p.Y, p.Y)
	YYYY = api.Mul(YY, YY)
	ZZ = api.Mul(p.Z, p.Z)
	S = api.Add(p.X, YY)
	S = api.Mul(S, S)
	S = api.Sub(S, XX)
	S = api.Sub(S, YYYY)
	S = api.Add(S, S)
	M = api.Mul(XX, 3) // M = 3*XX+a*ZZ^2, here a=0 (we suppose sw has j invariant 0)
	p.Z = api.Add(p.Z, p.Y)
	p.Z = api.Mul(p.Z, p.Z)
	p.Z = api.Sub(p.Z, YY)
	p.Z = api.Sub(p.Z, ZZ)
	p.X = api.Mul(M, M)
	T = api.Add(S, S)
	p.X = api.Sub(p.X, T)
	p.Y = api.Sub(S, p.X)
	p.Y = api.Mul(p.Y, M)
	YYYY = api.Mul(YYYY, 8)
	p.Y = api.Sub(p.Y, YYYY)

	return p
}

// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
func (p *G1Affine) Select(api frontend.API, b frontend.Variable, p1, p2 *G1Affine) *G1Affine {

	p.X = api.Select(b, p1.X, p2.X)
	p.Y = api.Select(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(api frontend.API, p1 *G1Jac) *G1Affine {
	s := api.Mul(p1.Z, p1.Z)
	p.X = api.Div(p1.X, s)
	p.Y = api.Div(p1.Y, api.Mul(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Affine) Double(api frontend.API, p1 *G1Affine) *G1Affine {

	var t, d, c1, c2, c3 big.Int
	t.SetInt64(3)
	d.SetInt64(2)
	c1.SetInt64(1)
	c2.SetInt64(-2)
	c3.SetInt64(-1)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	x2 := api.Mul(p1.X, p1.X)
	api.Mul(p1.X, p1.X)
	l1 := api.Mul(x2, t)
	l2 := api.Mul(p1.Y, d)
	l := api.Div(l1, l2)

	// xr = lambda**2-p.x-p1.x
	_x1 := api.Mul(l, l, c1)
	_x2 := api.Mul(p1.X, c2)
	_x := api.Add(_x1, _x2)

	// p.y = lambda(p.x-xr) - p.y
	t1 := api.Mul(p1.X, l)
	t2 := api.Mul(l, _x)
	l31 := api.Mul(t1, c1)
	l32 := api.Mul(t2, c3)
	l33 := api.Mul(p1.Y, c3)
	l3 := api.Add(l31, l32, l33)
	p.Y = api.Mul(l3, 1)

	//p.x = xr
	p.X = api.Mul(_x, 1)
	return p
}

// ScalarMul computes scalar*p1, affect the result to p, and returns it.
// n is the number of bits used for the scalar mul.
// TODO it doesn't work if the scalar if 1, because it ends up doing P-P at the end, involving division by 0
// TODO add a panic if scalar == 1
func (p *G1Affine) ScalarMul(api frontend.API, p1 *G1Affine, s interface{}, n int) *G1Affine {

	scalar := api.Constant(s)

	var base, res G1Affine
	base.Double(api, p1)
	res.AssignToRefactor(api, p1)

	b := api.ToBinary(scalar, n)

	var tmp G1Affine

	// start from 1 and use right-to-left scalar multiplication to avoid bugs due to incomplete addition law
	// (I don't see how to avoid that)
	for i := 1; i <= n-1; i++ {
		tmp.AssignToRefactor(api, &res).AddAssign(api, &base)
		res.Select(api, b[i], &tmp, &res)
		base.Double(api, &base)
	}

	// now check the lsb, if it's one, leave the result as is, otherwise substract P
	tmp.Neg(api, p1).AddAssign(api, &res)

	p.Select(api, b[0], &res, &tmp)

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
func (p *G1Jac) MustBeEqual(api frontend.API, other G1Jac) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
	api.AssertIsEqual(p.Z, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls12377.G1Affine) {
	p.X.Assign(bls12377FpTobw6761fr(&p1.X))
	p.Y.Assign(bls12377FpTobw6761fr(&p1.Y))
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) MustBeEqual(api frontend.API, other G1Affine) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}
