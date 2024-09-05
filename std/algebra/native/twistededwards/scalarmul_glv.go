/*
Copyright © 2022 ConsenSys Software Inc.

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

package twistededwards

import "github.com/consensys/gnark/frontend"

// phi endomorphism √-2 ∈ 𝒪₋₈
// (x,y) → λ × (x,y) s.t. λ² = -2 mod Order
func (p *Point) phi(api frontend.API, p1 *Point, curve *CurveParams, endo *EndoParams) *Point {

	xy := api.Mul(p1.X, p1.Y)
	yy := api.Mul(p1.Y, p1.Y)
	f := api.Sub(1, yy)
	f = api.Mul(f, endo.Endo[1])
	g := api.Add(yy, endo.Endo[0])
	g = api.Mul(g, endo.Endo[0])
	h := api.Sub(yy, endo.Endo[0])

	p.X = api.DivUnchecked(f, xy)
	p.Y = api.DivUnchecked(g, h)

	return p
}

// ScalarMul computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) scalarMulGLV(api frontend.API, p1 *Point, scalar frontend.Variable, curve *CurveParams, endo *EndoParams) *Point {
	// the hints allow to decompose the scalar s into s1 and s2 such that
	// s1 + λ * s2 == s mod Order,
	// with λ s.t. λ² = -2 mod Order.
	s1, s2 := callDecomposeScalar(api, scalar)

	n := 127

	b1 := api.ToBinary(s1, n)
	b2 := api.ToBinary(s2, n)

	var res, p2, p3, tmp Point
	p2.phi(api, p1, curve, endo).neg(api, &p2)
	p3.add(api, p1, &p2, curve)

	res.X = api.Lookup2(b1[n-1], b2[n-1], 0, p1.X, p2.X, p3.X)
	res.Y = api.Lookup2(b1[n-1], b2[n-1], 1, p1.Y, p2.Y, p3.Y)

	for i := n - 2; i >= 0; i-- {
		res.double(api, &res, curve)
		tmp.X = api.Lookup2(b1[i], b2[i], 0, p1.X, p2.X, p3.X)
		tmp.Y = api.Lookup2(b1[i], b2[i], 1, p1.Y, p2.Y, p3.Y)
		res.add(api, &res, &tmp, curve)
	}

	p.X = res.X
	p.Y = res.Y

	return p
}
