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

package fields

import (
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp6->Fp12 (Fp2 = Fp(u), Fp6 = Fp2(v), Fp12 = Fp6(w))
type Extension struct {

	// generators of each sub field
	uSquare interface{}
	vCube   E2
	wSquare E6

	// frobenius applied to generators
	frobv   interface{} // v**p  = (v**6)**(p-1/6)*v, frobv=(v**6)**(p-1/6), belongs to Fp)
	frobv2  interface{} // frobv2 = (v**6)**(p-1/3)
	frobw   interface{} // frobw = (w**12)**(p-1/12)
	frobvw  interface{} // frobvw = (v**6)**(p-1/6)*(w*12)**(p-1/12)
	frobv2w interface{} // frobv2w = (v**6)**(2*(p-1)/6)*(w*12)**(p-1/12)

	// frobenius square applied to generators
	frob2v   interface{} // v**(p**2)  = (v**6)**(p**2-1/6)*v, frobv=(v**6)**(p**2-1/6), belongs to Fp)
	frob2v2  interface{} // frobv2 = (v**6)**(2*(p**2-1)/6)
	frob2w   interface{} // frobw = (w**12)**(p**2-1/12)
	frob2vw  interface{} // frobvw = (v**6)**(p**2-1/6)*(w*12)**(p**2-1/12)
	frob2v2w interface{} // frobv2w = (v**6)**(2*(p**2-1)/6)*(w*12)**(p**2-1/12)

	// frobenius cube applied to generators
	frob3v   interface{} // v**(p**3)  = (v**6)**(p**3-1/6)*v, frobv=(v**6)**(p**3-1/6), belongs to Fp)
	frob3v2  interface{} // frobv2 = (v**6)**(2*(p**3-1)/6)
	frob3w   interface{} // frobw = (w**12)**(p**3-1/12)
	frob3vw  interface{} // frobvw = (v**6)**(p**3-1/6)*(w*12)**(p**3-1/12)
	frob3v2w interface{} // frobv2w = (v**6)**(2*(p**3-1)/6)*(w*12)**(p**3-1/12)

}

// E12 element in a quadratic extension
type E12 struct {
	C0, C1 E6
}

// GetBLS377ExtensionFp12 get extension field parameters for bls12377
func GetBLS377ExtensionFp12(api frontend.API) Extension {

	res := Extension{}

	res.uSquare = -5

	res.vCube = E2{A0: 0, A1: 1}

	res.wSquare = E6{
		B0: E2{0, 0},
		B1: E2{1, 0},
		B2: E2{0, 0},
	}

	res.frobv = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946"
	res.frobv2 = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"
	res.frobw = "92949345220277864758624960506473182677953048909283248980960104381795901929519566951595905490535835115111760994353"
	res.frobvw = "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"
	res.frobv2w = "123516416119946754630746545296132064952198520638002533875843642777304321125866014634106496325844844051843001220146"

	res.frob2v = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945"
	res.frob2v2 = "258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047231"
	res.frob2w = "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946"
	res.frob2vw = "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176"
	res.frob2v2w = "258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047232"

	res.frob3v = "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176"
	res.frob3v2 = "1"
	res.frob3w = "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"
	res.frob3vw = "42198664672744474621281227892288285906241943207628877683080515507620245292955241189266486323192680957485559243678"
	res.frob3v2w = "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499"

	return res
}

// SetOne returns a newly allocated element equal to 1
func (e *E12) SetOne(api frontend.API) *E12 {
	e.C0.B0.A0 = 1
	e.C0.B0.A1 = 0
	e.C0.B1.A0 = 0
	e.C0.B1.A1 = 0
	e.C0.B2.A0 = 0
	e.C0.B2.A1 = 0
	e.C1.B0.A0 = 0
	e.C1.B0.A1 = 0
	e.C1.B1.A0 = 0
	e.C1.B1.A1 = 0
	e.C1.B2.A0 = 0
	e.C1.B2.A1 = 0
	return e
}

// Add adds 2 elmts in Fp12
func (e *E12) Add(api frontend.API, e1, e2 E12) *E12 {
	e.C0.Add(api, e1.C0, e2.C0)
	e.C1.Add(api, e1.C1, e2.C1)
	return e
}

// Sub substracts 2 elmts in Fp12
func (e *E12) Sub(api frontend.API, e1, e2 E12) *E12 {
	e.C0.Sub(api, e1.C0, e2.C0)
	e.C1.Sub(api, e1.C1, e2.C1)
	return e
}

// Neg negates an Fp6elmt
func (e *E12) Neg(api frontend.API, e1 E12) *E12 {
	e.C0.Neg(api, e1.C0)
	e.C1.Neg(api, e1.C1)
	return e
}

// Mul multiplies 2 elmts in Fp12
func (e *E12) Mul(api frontend.API, e1, e2 E12, ext Extension) *E12 {

	var u, v, ac, bd E6
	u.Add(api, e1.C0, e1.C1)
	v.Add(api, e2.C0, e2.C1)
	v.Mul(api, u, v, ext)

	ac.Mul(api, e1.C0, e2.C0, ext)
	bd.Mul(api, e1.C1, e2.C1, ext)
	e.C1.Sub(api, v, ac).Sub(api, e.C1, bd)

	bd.Mul(api, bd, ext.wSquare, ext)
	e.C0.Add(api, ac, bd)

	return e
}

// Square squares an element in Fp12
func (e *E12) Square(api frontend.API, x E12, ext Extension) *E12 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var c0, c2, c3 E6
	c0.Sub(api, x.C0, x.C1)
	c3.Mul(api, x.C1, ext.wSquare, ext)
	c3.Neg(api, c3).Add(api, x.C0, c3)
	c2.Mul(api, x.C0, x.C1, ext)
	c0.Mul(api, c0, c3, ext).Add(api, c0, c2)
	e.C1.Add(api, c2, c2)
	c2.Mul(api, c2, ext.wSquare, ext)
	e.C0.Add(api, c0, c2)

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e *E12) CyclotomicSquareCompressed(api frontend.API, x E12, ext Extension) *E12 {

	var t [7]E2

	// t0 = g1^2
	t[0].Square(api, x.C0.B1, ext)
	// t1 = g5^2
	t[1].Square(api, x.C1.B2, ext)
	// t5 = g1 + g5
	t[5].Add(api, x.C0.B1, x.C1.B2)
	// t2 = (g1 + g5)^2
	t[2].Square(api, t[5], ext)

	// t3 = g1^2 + g5^2
	t[3].Add(api, t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5].Sub(api, t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(api, x.C1.B0, x.C0.B2)
	// t3 = (g3 + g2)^2
	t[3].Square(api, t[6], ext)
	// t2 = g3^2
	t[2].Square(api, x.C1.B0, ext)

	// t6 = 2 * nr * g1 * g5
	t[6].MulByIm(api, t[5], ext)
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5].Add(api, t[6], x.C1.B0).
		Double(api, t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	e.C1.B0.Add(api, t[5], t[6])

	// t4 = nr * g5^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = nr * g5^2 + g1^2
	t[5].Add(api, t[0], t[4])
	// t6 = nr * g5^2 + g1^2 - g2
	t[6].Sub(api, t[5], x.C0.B2)

	// t1 = g2^2
	t[1].Square(api, x.C0.B2, ext)

	// t6 = 2 * nr * g5^2 + 2 * g1^2 - 2*g2
	t[6].Double(api, t[6])
	// z2 = 3 * nr * g5^2 + 3 * g1^2 - 2*g2
	e.C0.B2.Add(api, t[6], t[5])

	// t4 = nr * g2^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = g3^2 + nr * g2^2
	t[5].Add(api, t[2], t[4])
	// t6 = g3^2 + nr * g2^2 - g1
	t[6].Sub(api, t[5], x.C0.B1)
	// t6 = 2 * g3^2 + 2 * nr * g2^2 - 2 * g1
	t[6].Double(api, t[6])
	// z1 = 3 * g3^2 + 3 * nr * g2^2 - 2 * g1
	e.C0.B1.Add(api, t[6], t[5])

	// t0 = g2^2 + g3^2
	t[0].Add(api, t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5].Sub(api, t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6].Add(api, t[5], x.C1.B2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6].Double(api, t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	e.C1.B2.Add(api, t[5], t[6])

	return e
}

// Decompress Karabina's cyclotomic square result
func (e *E12) Decompress(api frontend.API, x E12, ext Extension) *E12 {

	var t [3]E2
	var one E2
	one.SetOne(api)

	// t0 = g1^2
	t[0].Square(api, x.C0.B1, ext)
	// t1 = 3 * g1^2 - 2 * g2
	t[1].Sub(api, t[0], x.C0.B2).
		Double(api, t[1]).
		Add(api, t[1], t[0])
		// t0 = E * g5^2 + t1
	t[2].Square(api, x.C1.B2, ext)
	t[0].MulByIm(api, t[2], ext).
		Add(api, t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1].Double(api, x.C1.B0).
		Double(api, t[1]).
		Inverse(api, t[1], ext)
	// z4 = g4
	e.C1.B1.Mul(api, t[0], t[1], ext)

	// t1 = g2 * g1
	t[1].Mul(api, x.C0.B2, x.C0.B1, ext)
	// t2 = 2 * g4^2 - 3 * g2 * g1
	t[2].Square(api, e.C1.B1, ext).
		Sub(api, t[2], t[1]).
		Double(api, t[2]).
		Sub(api, t[2], t[1])
	// t1 = g3 * g5
	t[1].Mul(api, x.C1.B0, x.C1.B2, ext)
	// c_0 = E * (2 * g4^2 + g3 * g5 - 3 * g2 * g1) + 1
	t[2].Add(api, t[2], t[1])
	e.C0.B0.MulByIm(api, t[2], ext).
		Add(api, e.C0.B0, one)

	e.C0.B1 = x.C0.B1
	e.C0.B2 = x.C0.B2
	e.C1.B0 = x.C1.B0
	e.C1.B2 = x.C1.B2

	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp12 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E12) CyclotomicSquare(api frontend.API, x E12, ext Extension) *E12 {

	// https://eprint.iacr.org/2009/565.pdf, 3.2
	var t [9]E2

	t[0].Square(api, x.C1.B1, ext)
	t[1].Square(api, x.C0.B0, ext)
	t[6].Add(api, x.C1.B1, x.C0.B0).Square(api, t[6], ext).Sub(api, t[6], t[0]).Sub(api, t[6], t[1]) // 2*x4*x0
	t[2].Square(api, x.C0.B2, ext)
	t[3].Square(api, x.C1.B0, ext)
	t[7].Add(api, x.C0.B2, x.C1.B0).Square(api, t[7], ext).Sub(api, t[7], t[2]).Sub(api, t[7], t[3]) // 2*x2*x3
	t[4].Square(api, x.C1.B2, ext)
	t[5].Square(api, x.C0.B1, ext)
	t[8].Add(api, x.C1.B2, x.C0.B1).Square(api, t[8], ext).Sub(api, t[8], t[4]).Sub(api, t[8], t[5]).Mul(api, t[8], ext.vCube, ext) // 2*x5*x1*u

	t[0].Mul(api, t[0], ext.vCube, ext).Add(api, t[0], t[1]) // x4^2*u + x0^2
	t[2].Mul(api, t[2], ext.vCube, ext).Add(api, t[2], t[3]) // x2^2*u + x3^2
	t[4].Mul(api, t[4], ext.vCube, ext).Add(api, t[4], t[5]) // x5^2*u + x1^2

	e.C0.B0.Sub(api, t[0], x.C0.B0).Add(api, e.C0.B0, e.C0.B0).Add(api, e.C0.B0, t[0])
	e.C0.B1.Sub(api, t[2], x.C0.B1).Add(api, e.C0.B1, e.C0.B1).Add(api, e.C0.B1, t[2])
	e.C0.B2.Sub(api, t[4], x.C0.B2).Add(api, e.C0.B2, e.C0.B2).Add(api, e.C0.B2, t[4])

	e.C1.B0.Add(api, t[8], x.C1.B0).Add(api, e.C1.B0, e.C1.B0).Add(api, e.C1.B0, t[8])
	e.C1.B1.Add(api, t[6], x.C1.B1).Add(api, e.C1.B1, e.C1.B1).Add(api, e.C1.B1, t[6])
	e.C1.B2.Add(api, t[7], x.C1.B2).Add(api, e.C1.B2, e.C1.B2).Add(api, e.C1.B2, t[7])

	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E12) Conjugate(api frontend.API, e1 E12) *E12 {
	zero := NewFp6Zero(api)
	e.C1.Sub(api, *zero, e1.C1)
	e.C0 = e1.C0
	return e
}

// MulBy034 multiplication by sparse element
func (e *E12) MulBy034(api frontend.API, c3, c4 E2, ext Extension) *E12 {

	var d E6

	a := e.C0
	b := e.C1

	b.MulBy01(api, c3, c4, ext)

	c3.Add(api, E2{A0: api.Constant(1), A1: api.Constant(0)}, c3)
	d.Add(api, e.C0, e.C1)
	d.MulBy01(api, c3, c4, ext)

	e.C1.Add(api, a, b).Neg(api, e.C1).Add(api, e.C1, d)
	e.C0.MulByNonResidue(api, b, ext).Add(api, e.C0, a)

	return e
}

// Mul034By034 multiplication of sparse element (y,0,0,c3,c4,0) by sparse element (y,0,0,d3,d4,0)
func (e *E12) Mul034By034(api frontend.API, yy, d3, d4, y, c3, c4 E2, ext Extension) *E12 {

	var tmp, x3, x4, x04, x03, x34 E2
	zero := E2{A0: api.Constant(0), A1: api.Constant(0)}

	x3.Mul(api, c3, d3, ext)
	x4.Mul(api, c4, d4, ext)
	tmp.Add(api, y, c4)
	x04.Add(api, y, d4).
		Mul(api, x04, tmp, ext).
		Sub(api, x04, yy).
		Sub(api, x04, x4)
	tmp.Add(api, y, c3)
	x03.Add(api, y, d3).
		Mul(api, x03, tmp, ext).
		Sub(api, x03, yy).
		Sub(api, x03, x3)
	tmp.Add(api, c3, c4)
	x34.Add(api, d3, d4).
		Mul(api, x34, tmp, ext).
		Sub(api, x34, x3).
		Sub(api, x34, x4)

	e.C0.B0.MulByIm(api, x4, ext).
		Add(api, e.C0.B0, yy)
	e.C0.B1 = x3
	e.C0.B2 = x34
	e.C1.B0 = x03
	e.C1.B1 = x04
	e.C1.B2 = zero

	return e
}

// Frobenius applies frob to an fp12 elmt
func (e *E12) Frobenius(api frontend.API, e1 E12, ext Extension) *E12 {

	e.C0.B0.Conjugate(api, e1.C0.B0)
	e.C0.B1.Conjugate(api, e1.C0.B1).MulByFp(api, e.C0.B1, ext.frobv)
	e.C0.B2.Conjugate(api, e1.C0.B2).MulByFp(api, e.C0.B2, ext.frobv2)
	e.C1.B0.Conjugate(api, e1.C1.B0).MulByFp(api, e.C1.B0, ext.frobw)
	e.C1.B1.Conjugate(api, e1.C1.B1).MulByFp(api, e.C1.B1, ext.frobvw)
	e.C1.B2.Conjugate(api, e1.C1.B2).MulByFp(api, e.C1.B2, ext.frobv2w)

	return e

}

// FrobeniusSquare applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusSquare(api frontend.API, e1 E12, ext Extension) *E12 {

	e.C0.B0 = e1.C0.B0
	e.C0.B1.MulByFp(api, e1.C0.B1, ext.frob2v)
	e.C0.B2.MulByFp(api, e1.C0.B2, ext.frob2v2)
	e.C1.B0.MulByFp(api, e1.C1.B0, ext.frob2w)
	e.C1.B1.MulByFp(api, e1.C1.B1, ext.frob2vw)
	e.C1.B2.MulByFp(api, e1.C1.B2, ext.frob2v2w)

	return e
}

// FrobeniusCube applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusCube(api frontend.API, e1 E12, ext Extension) *E12 {

	e.C0.B0.Conjugate(api, e1.C0.B0)
	e.C0.B1.Conjugate(api, e1.C0.B1).MulByFp(api, e.C0.B1, ext.frob3v)
	e.C0.B2.Conjugate(api, e1.C0.B2).MulByFp(api, e.C0.B2, ext.frob3v2)
	e.C1.B0.Conjugate(api, e1.C1.B0).MulByFp(api, e.C1.B0, ext.frob3w)
	e.C1.B1.Conjugate(api, e1.C1.B1).MulByFp(api, e.C1.B1, ext.frob3vw)
	e.C1.B2.Conjugate(api, e1.C1.B2).MulByFp(api, e.C1.B2, ext.frob3v2w)

	return e
}

// Inverse inverse an elmt in Fp12
func (e *E12) Inverse(api frontend.API, e1 E12, ext Extension) *E12 {

	var t [2]E6
	var buf E6

	t[0].Square(api, e1.C0, ext)
	t[1].Square(api, e1.C1, ext)

	buf.MulByNonResidue(api, t[1], ext)
	t[0].Sub(api, t[0], buf)

	t[1].Inverse(api, t[0], ext)
	e.C0.Mul(api, e1.C0, t[1], ext)
	e.C1.Mul(api, e1.C1, t[1], ext).Neg(api, e.C1)

	return e
}

// ConjugateFp12 conjugates an Fp12 elmt (applies Frob**6)
func (e *E12) ConjugateFp12(api frontend.API, e1 E12) *E12 {
	e.C0 = e1.C0
	e.C1.Neg(api, e1.C1)
	return e
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E12) Select(api frontend.API, b frontend.Variable, r1, r2 E12) *E12 {

	e.C0.B0.A0 = api.Select(b, r1.C0.B0.A0, r2.C0.B0.A0)
	e.C0.B0.A1 = api.Select(b, r1.C0.B0.A1, r2.C0.B0.A1)
	e.C0.B1.A0 = api.Select(b, r1.C0.B1.A0, r2.C0.B1.A0)
	e.C0.B1.A1 = api.Select(b, r1.C0.B1.A1, r2.C0.B1.A1)
	e.C0.B2.A0 = api.Select(b, r1.C0.B2.A0, r2.C0.B2.A0)
	e.C0.B2.A1 = api.Select(b, r1.C0.B2.A1, r2.C0.B2.A1)
	e.C1.B0.A0 = api.Select(b, r1.C1.B0.A0, r2.C1.B0.A0)
	e.C1.B0.A1 = api.Select(b, r1.C1.B0.A1, r2.C1.B0.A1)
	e.C1.B1.A0 = api.Select(b, r1.C1.B1.A0, r2.C1.B1.A0)
	e.C1.B1.A1 = api.Select(b, r1.C1.B1.A1, r2.C1.B1.A1)
	e.C1.B2.A0 = api.Select(b, r1.C1.B2.A0, r2.C1.B2.A0)
	e.C1.B2.A1 = api.Select(b, r1.C1.B2.A1, r2.C1.B2.A1)

	return e
}

// nSquareCompressed repeated compressed cyclotmic square
func (e *E12) nSquareCompressed(api frontend.API, n int, ext Extension) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareCompressed(api, *e, ext)
	}
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls12377, so the exponent is supposed to be hardcoded
// and on 64 bits.
func (e *E12) Expt(api frontend.API, e1 E12, exponent uint64, ext Extension) *E12 {

	res := E12{}
	x33 := E12{}
	res = e1

	res.nSquareCompressed(api, 5, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, e1, ext)
	x33 = res
	res.nSquareCompressed(api, 7, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, x33, ext)
	res.nSquareCompressed(api, 4, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, e1, ext)
	res.CyclotomicSquare(api, res, ext)
	res.Mul(api, res, e1, ext)
	res.nSquareCompressed(api, 46, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, e1, ext)

	*e = res

	return e

}

// FinalExponentiation computes the final expo x**(p**6-1)(p**2+1)(p**4 - p**2 +1)/r
func (e *E12) FinalExponentiation(api frontend.API, e1 E12, genT uint64, ext Extension) *E12 {

	result := e1

	// https://eprint.iacr.org/2016/130.pdf
	var t [3]E12

	// easy part
	t[0].Conjugate(api, result)
	result.Inverse(api, result, ext)
	t[0].Mul(api, t[0], result, ext)
	result.FrobeniusSquare(api, t[0], ext).
		Mul(api, result, t[0], ext)

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	t[0].CyclotomicSquare(api, result, ext)
	t[1].Expt(api, result, genT, ext)
	t[2].Conjugate(api, result)
	t[1].Mul(api, t[1], t[2], ext)
	t[2].Expt(api, t[1], genT, ext)
	t[1].Conjugate(api, t[1])
	t[1].Mul(api, t[1], t[2], ext)
	t[2].Expt(api, t[1], genT, ext)
	t[1].Frobenius(api, t[1], ext)
	t[1].Mul(api, t[1], t[2], ext)
	result.Mul(api, result, t[0], ext)
	t[0].Expt(api, t[1], genT, ext)
	t[2].Expt(api, t[0], genT, ext)
	t[0].FrobeniusSquare(api, t[1], ext)
	t[1].Conjugate(api, t[1])
	t[1].Mul(api, t[1], t[2], ext)
	t[1].Mul(api, t[1], t[0], ext)
	result.Mul(api, result, t[1], ext)

	*e = result
	return e
}

// Assign a value to self (witness assignment)
func (e *E12) Assign(a *bls12377.E12) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E12) MustBeEqual(api frontend.API, other E12) {
	e.C0.MustBeEqual(api, other.C0)
	e.C1.MustBeEqual(api, other.C1)
}
