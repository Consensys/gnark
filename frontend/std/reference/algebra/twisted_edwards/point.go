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
	"math/bits"

	"github.com/consensys/gnark/curve/fr"
)

// Point point on a twisted Edwards curve
type Point struct {
	X, Y fr.Element
}

// NewPoint creates a new instance of Point
func NewPoint(x, y fr.Element) Point {
	return Point{x, y}
}

// IsOnCurve checks if a point is on the twisted Edwards curve
func (p *Point) IsOnCurve(ecurve CurveParams) bool {

	var lhs, rhs, tmp fr.Element

	tmp.Mul(&p.Y, &p.Y)
	lhs.Mul(&p.X, &p.X).
		Mul(&lhs, &ecurve.A).
		Add(&lhs, &tmp)

	tmp.Mul(&p.X, &p.X).
		Mul(&tmp, &p.Y).
		Mul(&tmp, &p.Y).
		Mul(&tmp, &ecurve.D)
	rhs.SetOne().Add(&rhs, &tmp)

	// TODO why do we not compare lhs and rhs directly?
	lhsreg := lhs.ToRegular()
	rhsreg := rhs.ToRegular()

	return rhsreg.Equal(&lhsreg)
}

// Add adds two points (x,y), (u,v) on a twisted Edwards curve with parameters a, d
// modifies p
func (p *Point) Add(p1, p2 *Point, ecurve CurveParams) *Point {

	var xu, yv, xv, yu, dxyuv, one, denx, deny fr.Element
	pRes := new(Point)
	xv.Mul(&p1.X, &p2.Y)
	yu.Mul(&p1.Y, &p2.X)
	pRes.X.Add(&xv, &yu)

	xu.Mul(&p1.X, &p2.X).Mul(&xu, &ecurve.A)
	yv.Mul(&p1.Y, &p2.Y)
	pRes.Y.Sub(&yv, &xu)

	dxyuv.Mul(&xv, &yu).Mul(&dxyuv, &ecurve.D)
	one.SetOne()
	denx.Add(&one, &dxyuv)
	deny.Sub(&one, &dxyuv)

	p.X.Div(&pRes.X, &denx)
	p.Y.Div(&pRes.Y, &deny)

	return p
}

// Double doubles point (x,y) on a twisted Edwards curve with parameters a, d
// modifies p
func (p *Point) Double(p1 *Point, ecurve CurveParams) *Point {
	p.Add(p1, p1, ecurve)
	return p
}

// ScalarMul scalar multiplication of a point
// p1 points on the twisted Edwards curve
// c parameters of the twisted Edwards curve
// scal scalar NOT in Montgomery form
// modifies p
func (p *Point) ScalarMul(p1 *Point, ecurve CurveParams, scalar fr.Element) *Point {

	pRes := new(Point)

	pRes.X.SetZero()
	pRes.Y.SetOne()

	const wordSize = bits.UintSize

	for i := fr.NbLimbs - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			pRes.Double(pRes, ecurve)
			b := (scalar[i] & (uint64(1) << uint64(wordSize-1-j))) >> uint64(wordSize-1-j)
			if b == 1 {
				pRes.Add(pRes, p1, ecurve)
			}
		}
	}
	p.X.Set(&pRes.X)
	p.Y.Set(&pRes.Y)

	return p
}
