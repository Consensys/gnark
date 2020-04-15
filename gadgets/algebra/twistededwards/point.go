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

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils/debug"
)

// PointGadget point on a twisted Edwards curve in a Snark circuit
type PointGadget struct {
	X, Y *frontend.Constraint
}

// NewPointGadget creates a new instance of Point
// if x and y are not of type frontend.Constraint
// they must be fr.Element and will be allocated (ALLOCATE) in the circuit
func NewPointGadget(circuit *frontend.CS, _x, _y interface{}) PointGadget {
	// TODO one should be able to create an empty point, should we use this switch in ALLOCATE?
	if _x == nil && _y == nil {
		return PointGadget{
			nil,
			nil,
		}
	}
	return PointGadget{
		circuit.ALLOCATE(_x),
		circuit.ALLOCATE(_y),
	}
}

// IsOnCurveGadget checks if a point is on the twisted Edwards curve
// ax^2 + y^2 = 1 + d*x^2*y^2
func (p *PointGadget) IsOnCurveGadget(circuit *frontend.CS, curve EdCurveGadget) {

	debug.Assert(p.X != nil && p.Y != nil, "point not initialized")

	one := big.NewInt(1)

	l1 := frontend.LinearCombination{frontend.Term{Constraint: p.X, Coeff: curve.A}}
	l2 := frontend.LinearCombination{frontend.Term{Constraint: p.X, Coeff: *one}}
	axx := circuit.MUL(l1, l2)
	yy := circuit.MUL(p.Y, p.Y)
	lhs := circuit.ADD(axx, yy)

	l1 = frontend.LinearCombination{frontend.Term{Constraint: p.X, Coeff: curve.D}}
	l2 = frontend.LinearCombination{frontend.Term{Constraint: p.X, Coeff: *one}}
	dxx := circuit.MUL(l1, l2)
	dxxyy := circuit.MUL(dxx, yy)
	rhs := circuit.ADD(dxxyy, one)

	circuit.MUSTBE_EQ(lhs, rhs)

}

// AddFixedPoint Adds two points, among which is one fixed point (the base), on a twisted edwards curve (eg jubjub)
// p1, base, ecurve are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *PointGadget) AddFixedPoint(circuit *frontend.CS, p1 *PointGadget, x, y interface{}, curve EdCurveGadget) *PointGadget {

	debug.Assert(p1.X != nil && p1.Y != nil, "point not initialized")

	// cf https://z.cash/technology/jubjub/
	// or https://eprint.iacr.org/2008/013.pdf
	res := PointGadget{nil, nil}

	// constraint 1
	b := circuit.MUL(p1.X, p1.Y)

	X := backend.FromInterface(x)
	Y := backend.FromInterface(y)

	var duv big.Int
	duv.Mul(&X, &Y).Mul(&duv, &curve.D)

	one := big.NewInt(1)
	oneWire := circuit.ALLOCATE(one)

	// constraint 2
	den := frontend.LinearCombination{
		frontend.Term{Constraint: oneWire, Coeff: *one},
		frontend.Term{Constraint: b, Coeff: duv},
	}
	num := frontend.LinearCombination{
		frontend.Term{Constraint: p1.X, Coeff: Y},
		frontend.Term{Constraint: p1.Y, Coeff: X},
	}
	res.X = circuit.DIV(num, den)

	// constraint 3
	duv.Neg(&duv)
	den = frontend.LinearCombination{
		frontend.Term{Constraint: oneWire, Coeff: *one},
		frontend.Term{Constraint: b, Coeff: duv},
	}
	var tmp big.Int
	tmp.Neg(&curve.A).Mul(&tmp, &X).Mod(&tmp, &curve.Modulus)
	num = frontend.LinearCombination{
		frontend.Term{Constraint: p1.Y, Coeff: Y},
		frontend.Term{Constraint: p1.X, Coeff: tmp},
	}
	res.Y = circuit.DIV(num, den)

	p.X = res.X
	p.Y = res.Y

	return p
}

// AddGeneric Adds two points on a twisted edwards curve (eg jubjub)
// p1, p2, c are respectively: the point to add, a known base point, and the parameters of the twisted edwards curve
func (p *PointGadget) AddGeneric(circuit *frontend.CS, p1, p2 *PointGadget, curve EdCurveGadget) *PointGadget {

	debug.Assert(p1.X != nil && p1.Y != nil, "point not initialized")
	debug.Assert(p2.X != nil && p2.Y != nil, "point not initialized")

	// cf https://z.cash/technology/jubjub/
	// or https://eprint.iacr.org/2008/013.pdf
	res := PointGadget{nil, nil}

	one := big.NewInt(1)
	oneWire := circuit.ALLOCATE(one)

	beta := circuit.MUL(p1.X, p2.Y)
	gamma := circuit.MUL(p1.Y, p2.X)
	delta := circuit.MUL(p1.Y, p2.Y)
	epsilon := circuit.MUL(p1.X, p2.X)
	tau := circuit.MUL(delta, epsilon)
	num := frontend.LinearCombination{
		frontend.Term{Constraint: beta, Coeff: *one},
		frontend.Term{Constraint: gamma, Coeff: *one},
	}
	den := frontend.LinearCombination{
		frontend.Term{Constraint: oneWire, Coeff: *one},
		frontend.Term{Constraint: tau, Coeff: curve.D},
	}
	res.X = circuit.DIV(num, den)
	var minusa big.Int
	minusa.Neg(&curve.A).Mod(&minusa, &curve.Modulus)
	num = frontend.LinearCombination{
		frontend.Term{Constraint: delta, Coeff: *one},
		frontend.Term{Constraint: epsilon, Coeff: minusa},
	}
	var minusd big.Int
	minusd.Neg(&curve.D).Mod(&minusd, &curve.Modulus)
	den = frontend.LinearCombination{
		frontend.Term{Constraint: oneWire, Coeff: *one},
		frontend.Term{Constraint: tau, Coeff: minusd},
	}
	res.Y = circuit.DIV(num, den)

	p.X = res.X
	p.Y = res.Y
	return p
}

// Double doubles a points in SNARK coordinates
func (p *PointGadget) Double(circuit *frontend.CS, p1 *PointGadget, curve EdCurveGadget) *PointGadget {
	p.AddGeneric(circuit, p1, p1, curve)
	return p
}

// ScalarMulNonFixedBase computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (as snark point)
// curve: parameters of the Edwards curve
// scal: scalar as a SNARK constraint
// Standard left to right double and add
func (p *PointGadget) ScalarMulNonFixedBase(circuit *frontend.CS, p1 *PointGadget, scalar *frontend.Constraint, curve EdCurveGadget) *PointGadget {

	// first unpack the scalar
	b := circuit.TO_BINARY(scalar, 256)

	res := NewPointGadget(circuit, 0, 1)

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(circuit, &res, curve)
		tmp := NewPointGadget(circuit, nil, nil)
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
func (p *PointGadget) ScalarMulFixedBase(circuit *frontend.CS, x, y interface{}, scalar *frontend.Constraint, curve EdCurveGadget) *PointGadget {

	// first unpack the scalar
	b := circuit.TO_BINARY(scalar, 256)

	res := NewPointGadget(circuit, 0, 1)

	for i := len(b) - 1; i >= 0; i-- {
		res.Double(circuit, &res, curve)
		tmp := NewPointGadget(circuit, nil, nil)
		tmp.AddFixedPoint(circuit, &res, x, y, curve)
		res.X = circuit.SELECT(b[i], tmp.X, res.X)
		res.Y = circuit.SELECT(b[i], tmp.Y, res.Y)
	}

	p.X = res.X
	p.Y = res.Y
	return p
}

// // ScalarMul computes the scalar multiplication of a point on a twisted Edwards curve
// func (p *Point) ScalarMul(p1 interface{}, ecurve twistededwards.CurveParams, scalar *frontend.Constraint, n int) *Point {

// 	switch point := p1.(type) {
// 	// case *twistededwards.Point:
// 	// 	p.scalarMulFixedBase(point, ecurve, scalar, n)
// 	// case twistededwards.Point:
// 	// 	p.scalarMulFixedBase(&point, ecurve, scalar, n)
// 	case *Point:
// 		p.scalarMulNonFixedBase(point, scalar, ecurve, n)
// 	case Point:
// 		p.scalarMulNonFixedBase(&point, scalar, ecurve, n)
// 	}
// 	return p
// }

// ScalarMulGadget computes the scalar multiplication of a point on a twisted Edwards curve
// p1: base point (in plain go)
// c: parameters of the curve
// scal: scalar as a SNARK constraint
// n: nbBits of the scalar
// Without lookup table -> 6 constraints/bit (1 (bool constraint) + 3 (addition with fixed point) + 1 (select constraint) per bit)
// With loopkup table -> 5.5 constraints/bit (7 (generic addition) + 2(bool constraints) + 2 (select lookup table) per 2 bits)
// func (p *Point) scalarMulFixedBase(p1 *twistededwards.Point, ecurve twistededwards.CurveParams, scalar *frontend.Constraint, n int) *Point {

// 	debug.Assert(p.circuit != nil, "point not initialized")

// 	circuit := p.circuit

// 	// fir	st unpack the scalar
// 	b := circuit.TO_BINARY(scalar, n)

// 	// look up tables for x, y coordinates of the current point
// 	// lut[i] = coords of i*base_point for i=0..3
// 	var lutx, luty [4]fr.Element
// 	var tmp [4]twistededwards.Point

// 	// infinity
// 	tmp[0].X.SetZero()
// 	tmp[0].Y.SetOne()
// 	lutx[0] = tmp[0].X
// 	luty[0] = tmp[0].Y

// 	// p1
// 	tmp[1] = *p1
// 	lutx[1] = tmp[1].X
// 	luty[1] = tmp[1].Y

// 	// 2*p1
// 	tmp[2].Double(p1, ecurve)
// 	lutx[2] = tmp[2].X
// 	luty[2] = tmp[2].Y

// 	// 3*p1
// 	tmp[3].Add(&tmp[2], &tmp[1], ecurve)
// 	lutx[3] = tmp[3].X
// 	luty[3] = tmp[3].Y

// 	curPoint := &Point{circuit: p.circuit}
// 	curPoint.X = circuit.SELECT_LUT(b[1], b[0], lutx)
// 	curPoint.Y = circuit.SELECT_LUT(b[1], b[0], luty)

// 	for i := 1; i < n/2; i++ {

// 		// update lookup table
// 		tmp[1].Double(&tmp[1], ecurve).Double(&tmp[1], ecurve)
// 		tmp[2].Double(&tmp[2], ecurve).Double(&tmp[2], ecurve)
// 		tmp[3].Double(&tmp[3], ecurve).Double(&tmp[3], ecurve)

// 		lutx[1] = tmp[1].X
// 		luty[1] = tmp[1].Y

// 		lutx[2] = tmp[2].X
// 		luty[2] = tmp[2].Y

// 		lutx[3] = tmp[3].X
// 		luty[3] = tmp[3].Y

// 		// select the point to add in the lookup table
// 		toAddx := circuit.SELECT_LUT(b[2*i+1], b[2*i], lutx)
// 		toAddy := circuit.SELECT_LUT(b[2*i+1], b[2*i], luty)
// 		toAdd := &Point{circuit: p.circuit, X: toAddx, Y: toAddy}

// 		curPoint.AddGeneric(curPoint, toAdd, ecurve)
// 	}

// 	if n%2 != 0 {
// 		tmp[2].Double(&tmp[2], ecurve)
// 		lutx[2] = tmp[2].X
// 		luty[2] = tmp[2].Y

// 		var one, zero fr.Element
// 		zero.SetZero()
// 		one.SetOne()
// 		last := &Point{circuit: p.circuit}
// 		last.Add(curPoint, &tmp[2], ecurve)

// 		curPoint.X = circuit.SELECT(b[n-1], last.X, curPoint.X)
// 		curPoint.Y = circuit.SELECT(b[n-1], last.Y, curPoint.Y)
// 	}

// 	p.X = curPoint.X
// 	p.Y = curPoint.Y
// 	return p
// }
