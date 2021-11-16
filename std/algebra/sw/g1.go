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
func (p *G1Jac) Neg(api frontend.API, p1 G1Jac) *G1Jac {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	p.Z = p1.Z
	return p
}

// Neg outputs -p
func (p *G1Affine) Neg(api frontend.API, p1 G1Affine) *G1Affine {
	p.X = p1.X
	p.Y = api.Sub(0, p1.Y)
	return p
}

// AddAssign adds p1 to p using the affine formulas with division, and return p
func (p *G1Affine) AddAssign(api frontend.API, p1 G1Affine) *G1Affine {

	// compute lambda = (p1.y-p.y)/(p1.x-p.x)
	lambda := api.DivUnchecked(api.Sub(p1.Y, p.Y), api.Sub(p1.X, p.X))

	// xr = lambda**2-p.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Add(p.X, p1.X))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p.X, xr)), p.Y)

	//p.x = xr
	p.X = xr
	return p
}

// AddAssign adds 2 point in Jacobian coordinates
// p=p, a=p1
func (p *G1Jac) AddAssign(api frontend.API, p1 G1Jac) *G1Jac {

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
func (p *G1Affine) Select(api frontend.API, b frontend.Variable, p1, p2 G1Affine) *G1Affine {

	p.X = api.Select(b, p1.X, p2.X)
	p.Y = api.Select(b, p1.Y, p2.Y)

	return p

}

// FromJac sets p to p1 in affine and returns it
func (p *G1Affine) FromJac(api frontend.API, p1 G1Jac) *G1Affine {
	s := api.Mul(p1.Z, p1.Z)
	p.X = api.DivUnchecked(p1.X, s)
	p.Y = api.DivUnchecked(p1.Y, api.Mul(s, p1.Z))
	return p
}

// Double double a point in affine coords
func (p *G1Affine) Double(api frontend.API, p1 G1Affine) *G1Affine {

	var three, two big.Int
	three.SetInt64(3)
	two.SetInt64(2)

	// compute lambda = (3*p1.x**2+a)/2*p1.y, here we assume a=0 (j invariant 0 curve)
	lambda := api.DivUnchecked(api.Mul(p1.X, p1.X, three), api.Mul(p1.Y, two))

	// xr = lambda**2-p1.x-p1.x
	xr := api.Sub(api.Mul(lambda, lambda), api.Mul(p1.X, two))

	// p.y = lambda(p.x-xr) - p.y
	p.Y = api.Sub(api.Mul(lambda, api.Sub(p1.X, xr)), p1.Y)

	//p.x = xr
	p.X = xr

	return p
}

// ScalarMul computes scalar*p1, affect the result to p, and returns it.
// n is the number of bits used for the scalar mul.
// TODO it doesn't work if the scalar if 1, because it ends up doing P-P at the end, involving division by 0
// TODO add a panic if scalar == 1
// TODO s is an interface, but treated as a variable (ToBinary), there is no specific path for constants
func (p *G1Affine) ScalarMul(api frontend.API, p1 G1Affine, s interface{}) *G1Affine {
	// scalar bits
	scalar := api.Constant(s)
	bits := api.ToBinary(scalar)

	var base G1Affine
	base.Double(api, p1)
	r1 := p1

	// start from 1 and use right-to-left scalar multiplication to avoid bugs due to incomplete addition law
	// (I don't see how to avoid that)
	for i := 1; i < len(bits); i++ {
		tmp := r1
		tmp.AddAssign(api, base)

		// if bits[i] == 0, do nothing, if bits[i] == 1, res += 2**p1
		r1.Select(api, bits[i], tmp, r1)

		base.Double(api, base)
	}

	// now check the lsb, if it's one, leave the result as is, otherwise substract P
	var r2 G1Affine
	r2.Neg(api, p1).AddAssign(api, r1)

	p.Select(api, bits[0], r1, r2)

	return p

}

// Assign a value to self (witness assignment)
func (p *G1Jac) Assign(p1 *bls12377.G1Jac) {
	p.X = (fr.Element)(p1.X)
	p.Y = (fr.Element)(p1.Y)
	p.Z = (fr.Element)(p1.Z)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Jac) MustBeEqual(api frontend.API, other G1Jac) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
	api.AssertIsEqual(p.Z, other.Z)
}

// Assign a value to self (witness assignment)
func (p *G1Affine) Assign(p1 *bls12377.G1Affine) {
	p.X = (fr.Element)(p1.X)
	p.Y = (fr.Element)(p1.Y)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (p *G1Affine) MustBeEqual(api frontend.API, other G1Affine) {
	api.AssertIsEqual(p.X, other.X)
	api.AssertIsEqual(p.Y, other.Y)
}
