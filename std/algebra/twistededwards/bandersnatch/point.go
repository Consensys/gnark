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

package bandersnatch

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
)

// Point point on a twisted Edwards curve in a Snark cs
type Point struct {
	X, Y frontend.Variable
}

// Set a point to a point
func (p *Point) Set(api frontend.API, p1 *Point) *Point {
	p.X = p1.X
	p.Y = p1.Y
	return p
}

// Neg computes the negative of a point in SNARK coordinates
func (p *Point) Neg(api frontend.API, p1 *Point) *Point {
	p.X = api.Sub(0, p1.X)
	p.Y = p1.Y
	return p
}

// MustBeOnCurve checks if a point is on the reduced twisted Edwards curve
// a*x² + y² = 1 + d*x²*y².
func (p *Point) MustBeOnCurve(api frontend.API, curve EdCurve) {

	one := big.NewInt(1)

	xx := api.Mul(p.X, p.X)
	yy := api.Mul(p.Y, p.Y)
	axx := api.Mul(xx, &curve.A)
	lhs := api.Add(axx, yy)

	dxx := api.Mul(xx, &curve.D)
	dxxyy := api.Mul(dxx, yy)
	rhs := api.Add(dxxyy, one)

	api.AssertIsEqual(lhs, rhs)

}

// Add Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) Add(api frontend.API, p1, p2 *Point, curve EdCurve) *Point {

	// https://eprint.iacr.org/2008/013.pdf

	n11 := api.Mul(p1.X, p2.Y)
	n12 := api.Mul(p1.Y, p2.X)
	n1 := api.Add(n11, n12)

	n21 := api.Mul(p1.Y, p2.Y)
	n22 := api.Mul(p1.X, p2.X)
	an22 := api.Mul(n22, &curve.A)
	n2 := api.Sub(n21, an22)

	d11 := api.Mul(curve.D, n11, n12)
	d1 := api.Add(1, d11)

	d2 := api.Sub(1, d11)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// Double doubles a points in SNARK coordinates
func (p *Point) Double(api frontend.API, p1 *Point, curve EdCurve) *Point {

	u := api.Mul(p1.X, p1.Y)
	v := api.Mul(p1.X, p1.X)
	w := api.Mul(p1.Y, p1.Y)

	n1 := api.Mul(2, u)
	av := api.Mul(v, &curve.A)
	n2 := api.Sub(w, av)
	d1 := api.Add(w, av)
	d2 := api.Sub(2, d1)

	p.X = api.DivUnchecked(n1, d1)
	p.Y = api.DivUnchecked(n2, d2)

	return p
}

// phi endomorphism √-2 ∈ 𝒪₋₈
// (x,y) → λ × (x,y) s.t. λ² = -2 mod Order
func (p *Point) phi(api frontend.API, p1 *Point, curve EdCurve) *Point {

	xy := api.Mul(p1.X, p1.Y)
	yy := api.Mul(p1.Y, p1.Y)
	f := api.Sub(1, yy)
	f = api.Mul(f, curve.endo1)
	g := api.Add(yy, curve.endo0)
	g = api.Mul(g, curve.endo0)
	h := api.Sub(yy, curve.endo0)

	p.X = api.DivUnchecked(f, xy)
	p.Y = api.DivUnchecked(g, h)

	return p
}

var scalarDecompositionHint = hint.NewStaticHint(func(curve ecc.ID, inputs []*big.Int, res []*big.Int) error {
	// TODO: handle properly negative scalars
	var lambda, order big.Int
	var glvBasis ecc.Lattice
	lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
	order.SetString("13108968793781547619861935127046491459309155893440570251786403306729687672801", 10)
	ecc.PrecomputeLattice(&order, &lambda, &glvBasis)
	sp := ecc.SplitScalar(inputs[0], &glvBasis)
	res[0].Neg(&(sp[0])) // Set
	res[1].Set(&(sp[1]))

	// figure out how many times we have overflowed
	// res[2].Mul(res[1], &lambda).Add(res[2], res[0])
	res[2].Mul(res[1], &lambda).Sub(res[2], res[0])
	res[2].Sub(res[2], inputs[0])
	res[2].Div(res[2], &order)

	return nil
}, 1, 3)

func init() {
	hint.Register(scalarDecompositionHint)
}

// ScalarMul computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMul(api frontend.API, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {
	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + λ * s2 == s mod r,
	// with λ s.t. λ² = -2 mod Order.
	sd, err := api.NewHint(scalarDecompositionHint, scalar)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	s1, s2 := sd[0], sd[1]

	// s1 + λ * s2 == s + k*r
	// api.AssertIsEqual(api.Add(s1, api.Mul(s2, &curve.lambda)), api.Add(scalar, api.Mul(&curve.Order, sd[2])))
	api.AssertIsEqual(api.Sub(api.Mul(s2, &curve.lambda), s1), api.Add(scalar, api.Mul(&curve.Order, sd[2])))

	n := curve.lambda.BitLen()/2 + 2

	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, _p1, p2, p3, tmp Point
	_p1.Neg(api, p1)
	p2.phi(api, p1, curve)
	p3.Add(api, &_p1, &p2, curve)

	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, _p1.X, p2.X, p3.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, _p1.Y, p2.Y, p3.Y)

	for i := n - 2; i >= 0; i-- {
		res.Double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, _p1.X, p2.X, p3.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, _p1.Y, p2.Y, p3.Y)
		res.Add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}

// DoubleBaseScalarMul computes s1*P1+s2*P2
// where P1 and P2 are points on a twisted Edwards curve
// and s1, s2 scalars.
func (p *Point) DoubleBaseScalarMul(api frontend.API, p1, p2 *Point, s1, s2 frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalars
	b1 := api.ToBinary(s1)
	b2 := api.ToBinary(s2)

	res := Point{}
	tmp := Point{}
	sum := Point{}
	sum.Add(api, p1, p2, curve)

	n := len(b1)
	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p1.X, p2.X, sum.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p1.Y, p2.Y, sum.Y)

	for i := n - 2; i >= 0; i-- {
		res.Double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, sum.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, sum.Y)
		res.Add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}
