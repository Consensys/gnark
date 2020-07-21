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

// version of bn256
// https://github.com/matter-labs/pairing/blob/master/src/bn256/fq.rs

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Point point on a twisted Edwards curve in a Snark circuit
type Point struct {
	X, Y frontend.Variable
}

// NewPoint creates a new instance of Point
// if x and y are not of type frontend.Constraint
// they must be fr.Element and will be allocated (ALLOCATE) in the circuit
func NewPoint(circuit *frontend.CS, _x, _y interface{}) Point {
	// TODO one should be able to create an empty point, should we use this switch in ALLOCATE?
	if _x == nil && _y == nil {
		return Point{}
	}
	return Point{
		circuit.ALLOCATE(_x),
		circuit.ALLOCATE(_y),
	}
}

// MustBeOnCurve checks if a point is on the twisted Edwards curve
// ax^2 + y^2 = 1 + d*x^2*y^2
func (p *Point) MustBeOnCurve(circuit *frontend.CS, curve EdCurve) {
	one := big.NewInt(1)

	l1 := frontend.LinearCombination{frontend.Term{Variable: p.X, Coeff: curve.A}}
	l2 := frontend.LinearCombination{frontend.Term{Variable: p.X, Coeff: *one}}
	axx := circuit.MUL(l1, l2)
	yy := circuit.MUL(p.Y, p.Y)
	lhs := circuit.ADD(axx, yy)

	l1 = frontend.LinearCombination{frontend.Term{Variable: p.X, Coeff: curve.D}}
	l2 = frontend.LinearCombination{frontend.Term{Variable: p.X, Coeff: *one}}
	dxx := circuit.MUL(l1, l2)
	dxxyy := circuit.MUL(dxx, yy)
	rhs := circuit.ADD(dxxyy, one)

	circuit.MUSTBE_EQ(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddFixedPoint(circuit *frontend.CS, p1 *Point, x, y interface{}, curve EdCurve) *Point {
	X := circuit.ALLOCATE(x)
	Y := circuit.ALLOCATE(y)
	return p.AddGeneric(circuit, p1, &Point{X, Y}, curve)
	// // cf https://z.cash/technology/jubjub/
	// // or https://eprint.iacr.org/2008/013.pdf
	// res := Point{}

	// // constraint 1
	// b := circuit.MUL(p1.X, p1.Y)

	// X := backend.FromInterface(x)
	// Y := backend.FromInterface(y)

	// var duv big.Int
	// duv.Mul(&X, &Y).Mul(&duv, &curve.D)

	// one := big.NewInt(1)
	// oneWire := circuit.ALLOCATE(one)

	// // constraint 2
	// den := frontend.LinearCombination{
	// 	frontend.Term{Variable: oneWire, Coeff: *one},
	// 	frontend.Term{Variable: b, Coeff: duv},
	// }
	// num := frontend.LinearCombination{
	// 	frontend.Term{Variable: p1.X, Coeff: Y},
	// 	frontend.Term{Variable: p1.Y, Coeff: X},
	// }
	// res.X = circuit.DIV(num, den)

	// // constraint 3
	// duv.Neg(&duv)
	// den = frontend.LinearCombination{
	// 	frontend.Term{Variable: oneWire, Coeff: *one},
	// 	frontend.Term{Variable: b, Coeff: duv},
	// }
	// var tmp big.Int
	// tmp.Neg(&curve.A).Mul(&tmp, &X).Mod(&tmp, &curve.Modulus)
	// num = frontend.LinearCombination{
	// 	frontend.Term{Variable: p1.Y, Coeff: Y},
	// 	frontend.Term{Variable: p1.X, Coeff: X},
	// }
	// res.Y = circuit.DIV(num, den)

	// p.X = res.X
	// p.Y = res.Y

	// return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *Point) AddGeneric(circuit *frontend.CS, p1, p2 *Point, curve EdCurve) *Point {

	// cf https://z.cash/technology/jubjub/
	// or https://eprint.iacr.org/2008/013.pdf
	res := Point{}

	one := big.NewInt(1)
	oneWire := circuit.ALLOCATE(one)

	beta := circuit.MUL(p1.X, p2.Y)
	gamma := circuit.MUL(p1.Y, p2.X)
	delta := circuit.MUL(p1.Y, p2.Y)
	epsilon := circuit.MUL(p1.X, p2.X)
	tau := circuit.MUL(delta, epsilon)
	num := frontend.LinearCombination{
		frontend.Term{Variable: beta, Coeff: *one},
		frontend.Term{Variable: gamma, Coeff: *one},
	}
	den := frontend.LinearCombination{
		frontend.Term{Variable: oneWire, Coeff: *one},
		frontend.Term{Variable: tau, Coeff: curve.D},
	}
	res.X = circuit.DIV(num, den)
	var minusa big.Int
	minusa.Neg(&curve.A).Mod(&minusa, &curve.Modulus)
	num = frontend.LinearCombination{
		frontend.Term{Variable: delta, Coeff: *one},
		frontend.Term{Variable: epsilon, Coeff: minusa},
	}
	var minusd big.Int
	minusd.Neg(&curve.D).Mod(&minusd, &curve.Modulus)
	den = frontend.LinearCombination{
		frontend.Term{Variable: oneWire, Coeff: *one},
		frontend.Term{Variable: tau, Coeff: minusd},
	}
	res.Y = circuit.DIV(num, den)

	p.X = res.X
	p.Y = res.Y
	return p
}

// Double doubles a points in SNARK coordinates
func (p *Point) Double(circuit *frontend.CS, p1 *Point, curve EdCurve) *Point {
	p.AddGeneric(circuit, p1, p1, curve)
	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *Point) ScalarMulNonFixedBase(circuit *frontend.CS, p1 *Point, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := circuit.TO_BINARY(scalar, 256)

	res := NewPoint(circuit, 0, 1)

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(circuit, &res, curve)
		tmp := NewPoint(circuit, nil, nil)
		tmp.AddGeneric(circuit, &res, p1, curve)
		res.X = circuit.SELECT(b[i], tmp.X, res.X)
		res.Y = circuit.SELECT(b[i], tmp.Y, res.Y)
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
// TODO passing a point a x, y interface{} is a bit ugly, but on the other hand creating a special struct{x, y interface{}} only for general point seems too much
func (p *Point) ScalarMulFixedBase(circuit *frontend.CS, x, y interface{}, scalar frontend.Variable, curve EdCurve) *Point {

	// first unpack the scalar
	b := circuit.TO_BINARY(scalar, 256)

	res := NewPoint(circuit, 0, 1)

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(circuit, &res, curve)
		tmp := NewPoint(circuit, nil, nil)
		tmp.AddFixedPoint(circuit, &res, x, y, curve)
		res.X = circuit.SELECT(b[i], tmp.X, res.X)
		res.Y = circuit.SELECT(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y
	return p
}
