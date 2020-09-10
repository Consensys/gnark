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

package twistededwards

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Point point on a twisted Edwards curve in a Snark cs
type Point struct {
	X, Y frontend.Variable
}

// MustBeOnCurve checks if a point is on the twisted Edwards curve
// ax^2 + y^2 = 1 + d*x^2*y^2
func (p *Point) MustBeOnCurve(cs *frontend.CS, curve EdCurve) {

	one := big.NewInt(1)
	idxOne := cs.GetCoeffID(one)
	idxA := cs.GetCoeffID(&curve.A)
	idxD := cs.GetCoeffID(&curve.D)

	l1 := frontend.LinearCombination{frontend.LinearTerm{Variable: p.X, Coeff: idxA}}
	l2 := frontend.LinearCombination{frontend.LinearTerm{Variable: p.X, Coeff: idxOne}}
	axx := cs.Mul(l1, l2)
	yy := cs.Mul(p.Y, p.Y)
	lhs := cs.Add(axx, yy)

	l1 = frontend.LinearCombination{frontend.LinearTerm{Variable: p.X, Coeff: idxD}}
	l2 = frontend.LinearCombination{frontend.LinearTerm{Variable: p.X, Coeff: idxOne}}
	dxx := cs.Mul(l1, l2)
	dxxyy := cs.Mul(dxx, yy)
	rhs := cs.Add(dxxyy, one)

	cs.MustBeEqual(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddFixedPoint(cs *frontend.CS, p1 *Point, x, y interface{}, curve EdCurve) *Point {
	X := cs.Constant(x)
	Y := cs.Constant(y)
	return p.AddGeneric(cs, p1, &Point{X, Y}, curve)

	// TODO fixme
	// // cf https://z.cash/technology/jubjub/
	// // or https://eprint.iacr.org/2008/013.pdf
	// res := Point{}

	// // constraint 1
	// b := cs.Mul(p1.X, p1.Y)

	// X := backend.FromInterface(x)
	// Y := backend.FromInterface(y)

	// var duv big.Int
	// duv.Mul(&X, &Y).Mul(&duv, &curve.D)

	// one := big.NewInt(1)
	// oneWire := cs.ALLOCATE(one)

	// // constraint 2
	// den := frontend.LinearCombination{
	// 	frontend.LinearTerm{Variable: oneWire, Coeff: *one},
	// 	frontend.LinearTerm{Variable: b, Coeff: duv},
	// }
	// num := frontend.LinearCombination{
	// 	frontend.LinearTerm{Variable: p1.X, Coeff: Y},
	// 	frontend.LinearTerm{Variable: p1.Y, Coeff: X},
	// }
	// res.X = cs.DIV(num, den)

	// // constraint 3
	// duv.Neg(&duv)
	// den = frontend.LinearCombination{
	// 	frontend.LinearTerm{Variable: oneWire, Coeff: *one},
	// 	frontend.LinearTerm{Variable: b, Coeff: duv},
	// }
	// var tmp big.Int
	// tmp.Neg(&curve.A).Mul(&tmp, &X).Mod(&tmp, &curve.Modulus)
	// num = frontend.LinearCombination{
	// 	frontend.LinearTerm{Variable: p1.Y, Coeff: Y},
	// 	frontend.LinearTerm{Variable: p1.X, Coeff: X},
	// }
	// res.Y = cs.DIV(num, den)

	// p.X = res.X
	// p.Y = res.Y

	// return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddGeneric(cs *frontend.CS, p1, p2 *Point, curve EdCurve) *Point {

	// cf https://z.cash/technology/jubjub/
	// or https://eprint.iacr.org/2008/013.pdf
	res := Point{}

	one := big.NewInt(1)
	idxOne := cs.GetCoeffID(one)
	idxD := cs.GetCoeffID(&curve.D)

	oneWire := cs.Constant(one)

	beta := cs.Mul(p1.X, p2.Y)
	gamma := cs.Mul(p1.Y, p2.X)
	delta := cs.Mul(p1.Y, p2.Y)
	epsilon := cs.Mul(p1.X, p2.X)
	tau := cs.Mul(delta, epsilon)
	num := frontend.LinearCombination{
		frontend.LinearTerm{Variable: beta, Coeff: idxOne},
		frontend.LinearTerm{Variable: gamma, Coeff: idxOne},
	}
	den := frontend.LinearCombination{
		frontend.LinearTerm{Variable: oneWire, Coeff: idxOne},
		frontend.LinearTerm{Variable: tau, Coeff: idxD},
	}
	res.X = cs.Div(num, den)
	var minusa big.Int
	minusa.Neg(&curve.A).Mod(&minusa, &curve.Modulus)
	idxMinusA := cs.GetCoeffID(&minusa)
	num = frontend.LinearCombination{
		frontend.LinearTerm{Variable: delta, Coeff: idxOne},
		frontend.LinearTerm{Variable: epsilon, Coeff: idxMinusA},
	}
	var minusd big.Int
	minusd.Neg(&curve.D).Mod(&minusd, &curve.Modulus)
	idxMinusD := cs.GetCoeffID(&minusd)
	den = frontend.LinearCombination{
		frontend.LinearTerm{Variable: oneWire, Coeff: idxOne},
		frontend.LinearTerm{Variable: tau, Coeff: idxMinusD},
	}
	res.Y = cs.Div(num, den)

	p.X = res.X
	p.Y = res.Y
	return p
}

// Double doubles a points in SNARK coordinates
func (p *Point) Double(cs *frontend.CS, p1 *Point, curve EdCurve) *Point {
	p.AddGeneric(cs, p1, p1, curve)
	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulNonFixedBase(cs *frontend.CS, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := cs.ToBinary(scalar, 256)

	res := Point{
		cs.Constant(0),
		cs.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(cs, &res, curve)
		tmp := Point{}
		tmp.AddGeneric(cs, &res, p1, curve)
		res.X = cs.Select(b[i], tmp.X, res.X)
		res.Y = cs.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y
	return p
}

// ScalarMulFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// x, y: coordinates of the base point
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulFixedBase(cs *frontend.CS, x, y interface{}, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := cs.ToBinary(scalar, 256)

	res := Point{
		cs.Constant(0),
		cs.Constant(1),
	}

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(cs, &res, curve)
		tmp := Point{}
		tmp.AddFixedPoint(cs, &res, x, y, curve)
		res.X = cs.Select(b[i], tmp.X, res.X)
		res.Y = cs.Select(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y
	return p
}
