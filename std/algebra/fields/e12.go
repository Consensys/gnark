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
	bls377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp6->Fp12 (Fp2 = Fp(u), Fp6 = Fp2(v), Fp12 = Fp6(w))
type Extension struct {

	// generators of each sub field
	uSquare interface{}
	vCube   *E2
	wSquare *E6

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

// GetBLS377ExtensionFp12 get extension field parameters for bls377
func GetBLS377ExtensionFp12(cs *frontend.ConstraintSystem) Extension {
	res := Extension{}
	res.uSquare = 5
	res.vCube = &E2{A0: cs.Constant(0), A1: cs.Constant(1)}
	res.wSquare = &E6{
		B0: E2{cs.Constant(0), cs.Constant(0)},
		B1: E2{cs.Constant(1), cs.Constant(0)},
		B2: E2{cs.Constant(0), cs.Constant(0)},
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
func (e *E12) SetOne(cs *frontend.ConstraintSystem) *E12 {
	e.C0.B0.A0 = cs.Constant(1)
	e.C0.B0.A1 = cs.Constant(0)
	e.C0.B1.A0 = cs.Constant(0)
	e.C0.B1.A1 = cs.Constant(0)
	e.C0.B2.A0 = cs.Constant(0)
	e.C0.B2.A1 = cs.Constant(0)
	e.C1.B0.A0 = cs.Constant(0)
	e.C1.B0.A1 = cs.Constant(0)
	e.C1.B1.A0 = cs.Constant(0)
	e.C1.B1.A1 = cs.Constant(0)
	e.C1.B2.A0 = cs.Constant(0)
	e.C1.B2.A1 = cs.Constant(0)
	return e
}

// Add adds 2 elmts in Fp12
func (e *E12) Add(cs *frontend.ConstraintSystem, e1, e2 *E12) *E12 {
	e.C0.Add(cs, &e1.C0, &e2.C0)
	e.C1.Add(cs, &e1.C1, &e2.C1)
	return e
}

// Sub substracts 2 elmts in Fp12
func (e *E12) Sub(cs *frontend.ConstraintSystem, e1, e2 *E12) *E12 {
	e.C0.Sub(cs, &e1.C0, &e2.C0)
	e.C1.Sub(cs, &e1.C1, &e2.C1)
	return e
}

// Neg negates an Fp6elmt
func (e *E12) Neg(cs *frontend.ConstraintSystem, e1 *E12) *E12 {
	e.C0.Neg(cs, &e1.C0)
	e.C1.Neg(cs, &e1.C1)
	return e
}

// Mul multiplies 2 elmts in Fp12
func (e *E12) Mul(cs *frontend.ConstraintSystem, e1, e2 *E12, ext Extension) *E12 {

	var u, v, ac, bd E6
	u.Add(cs, &e1.C0, &e1.C1) // 6C
	v.Add(cs, &e2.C0, &e2.C1) // 6C
	v.Mul(cs, &u, &v, ext)    // 61C

	ac.Mul(cs, &e1.C0, &e2.C0, ext)           // 61C
	bd.Mul(cs, &e1.C1, &e2.C1, ext)           // 61C
	e.C1.Sub(cs, &v, &ac).Sub(cs, &e.C1, &bd) // 12C

	bd.Mul(cs, &bd, ext.wSquare, ext) // 6C
	e.C0.Add(cs, &ac, &bd)            // 6C

	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E12) Conjugate(cs *frontend.ConstraintSystem, e1 *E12) *E12 {
	zero := NewFp6Zero(cs)
	e.C1.Sub(cs, &zero, &e1.C1)
	e.C0 = e1.C0
	return e
}

// MulByVW multiplies an e12 elmt by an elmt of the form a*VW (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *E12) MulByVW(cs *frontend.ConstraintSystem, e1 *E12, e2 *E2, ext Extension) *E12 {

	tmp := E2{}
	tmp.MulByIm(cs, e2, ext)

	res := E12{}

	res.C0.B0.Mul(cs, &e1.C1.B1, &tmp, ext)
	res.C0.B1.Mul(cs, &e1.C1.B2, &tmp, ext)
	res.C0.B2.Mul(cs, &e1.C1.B0, e2, ext)
	res.C1.B0.Mul(cs, &e1.C0.B2, &tmp, ext)
	res.C1.B1.Mul(cs, &e1.C0.B0, e2, ext)
	res.C1.B2.Mul(cs, &e1.C0.B1, e2, ext)

	e.C0 = res.C0
	e.C1 = res.C1

	return e
}

// MulByV multiplies an e12 elmt by an elmt of the form a*V (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *E12) MulByV(cs *frontend.ConstraintSystem, e1 *E12, e2 *E2, ext Extension) *E12 {

	tmp := E2{}
	tmp.MulByIm(cs, e2, ext)

	res := E12{}

	res.C0.B0.Mul(cs, &e1.C0.B2, &tmp, ext)
	res.C0.B1.Mul(cs, &e1.C0.B0, e2, ext)
	res.C0.B2.Mul(cs, &e1.C0.B1, e2, ext)
	res.C1.B0.Mul(cs, &e1.C1.B2, &tmp, ext)
	res.C1.B1.Mul(cs, &e1.C1.B0, e2, ext)
	res.C1.B2.Mul(cs, &e1.C1.B1, e2, ext)

	e.C0 = res.C0
	e.C1 = res.C1

	return e
}

// MulByV2W multiplies an e12 elmt by an elmt of the form a*V**2W (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *E12) MulByV2W(cs *frontend.ConstraintSystem, e1 *E12, e2 *E2, ext Extension) *E12 {

	tmp := E2{}
	tmp.MulByIm(cs, e2, ext)

	res := E12{}

	res.C0.B0.Mul(cs, &e1.C1.B0, &tmp, ext)
	res.C0.B1.Mul(cs, &e1.C1.B1, &tmp, ext)
	res.C0.B2.Mul(cs, &e1.C1.B2, &tmp, ext)
	res.C1.B0.Mul(cs, &e1.C0.B1, &tmp, ext)
	res.C1.B1.Mul(cs, &e1.C0.B2, &tmp, ext)
	res.C1.B2.Mul(cs, &e1.C0.B0, e2, ext)

	e.C0 = res.C0
	e.C1 = res.C1

	return e
}

// Frobenius applies frob to an fp12 elmt
func (e *E12) Frobenius(cs *frontend.ConstraintSystem, e1 *E12, ext Extension) *E12 {

	e.C0.B0.Conjugate(cs, &e1.C0.B0)
	e.C0.B1.Conjugate(cs, &e1.C0.B1).MulByFp(cs, &e.C0.B1, ext.frobv)
	e.C0.B2.Conjugate(cs, &e1.C0.B2).MulByFp(cs, &e.C0.B2, ext.frobv2)
	e.C1.B0.Conjugate(cs, &e1.C1.B0).MulByFp(cs, &e.C1.B0, ext.frobw)
	e.C1.B1.Conjugate(cs, &e1.C1.B1).MulByFp(cs, &e.C1.B1, ext.frobvw)
	e.C1.B2.Conjugate(cs, &e1.C1.B2).MulByFp(cs, &e.C1.B2, ext.frobv2w)

	return e

}

// FrobeniusSquare applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusSquare(cs *frontend.ConstraintSystem, e1 *E12, ext Extension) *E12 {

	e.C0.B0 = e1.C0.B0
	e.C0.B1.MulByFp(cs, &e1.C0.B1, ext.frob2v)
	e.C0.B2.MulByFp(cs, &e1.C0.B2, ext.frob2v2)
	e.C1.B0.MulByFp(cs, &e1.C1.B0, ext.frob2w)
	e.C1.B1.MulByFp(cs, &e1.C1.B1, ext.frob2vw)
	e.C1.B2.MulByFp(cs, &e1.C1.B2, ext.frob2v2w)

	return e
}

// FrobeniusCube applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusCube(cs *frontend.ConstraintSystem, e1 *E12, ext Extension) *E12 {

	e.C0.B0.Conjugate(cs, &e1.C0.B0)
	e.C0.B1.Conjugate(cs, &e1.C0.B1).MulByFp(cs, &e.C0.B1, ext.frob3v)
	e.C0.B2.Conjugate(cs, &e1.C0.B2).MulByFp(cs, &e.C0.B2, ext.frob3v2)
	e.C1.B0.Conjugate(cs, &e1.C1.B0).MulByFp(cs, &e.C1.B0, ext.frob3w)
	e.C1.B1.Conjugate(cs, &e1.C1.B1).MulByFp(cs, &e.C1.B1, ext.frob3vw)
	e.C1.B2.Conjugate(cs, &e1.C1.B2).MulByFp(cs, &e.C1.B2, ext.frob3v2w)

	return e
}

// Inverse inverse an elmt in Fp12
func (e *E12) Inverse(cs *frontend.ConstraintSystem, e1 *E12, ext Extension) *E12 {

	var t [2]E6
	var buf E6

	t[0].Mul(cs, &e1.C0, &e1.C0, ext)
	t[1].Mul(cs, &e1.C1, &e1.C1, ext)

	buf.MulByNonResidue(cs, &t[1], ext)
	t[0].Sub(cs, &t[0], &buf)

	t[1].Inverse(cs, &t[0], ext)
	e.C0.Mul(cs, &e1.C0, &t[1], ext)
	e.C1.Mul(cs, &e1.C1, &t[1], ext).Neg(cs, &e.C1)

	return e
}

// ConjugateFp12 conjugates an Fp12 elmt (applies Frob**6)
func (e *E12) ConjugateFp12(cs *frontend.ConstraintSystem, e1 *E12) *E12 {
	e.C0 = e1.C0
	e.C1.Neg(cs, &e1.C1)
	return e
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E12) Select(cs *frontend.ConstraintSystem, b frontend.Variable, r1, r2 *E12) *E12 {

	e.C0.B0.A0 = cs.Select(b, r1.C0.B0.A0, r2.C0.B0.A0)
	e.C0.B0.A1 = cs.Select(b, r1.C0.B0.A1, r2.C0.B0.A1)
	e.C0.B1.A0 = cs.Select(b, r1.C0.B1.A0, r2.C0.B1.A0)
	e.C0.B1.A1 = cs.Select(b, r1.C0.B1.A1, r2.C0.B1.A1)
	e.C0.B2.A0 = cs.Select(b, r1.C0.B2.A0, r2.C0.B2.A0)
	e.C0.B2.A1 = cs.Select(b, r1.C0.B2.A1, r2.C0.B2.A1)
	e.C1.B0.A0 = cs.Select(b, r1.C1.B0.A0, r2.C1.B0.A0)
	e.C1.B0.A1 = cs.Select(b, r1.C1.B0.A1, r2.C1.B0.A1)
	e.C1.B1.A0 = cs.Select(b, r1.C1.B1.A0, r2.C1.B1.A0)
	e.C1.B1.A1 = cs.Select(b, r1.C1.B1.A1, r2.C1.B1.A1)
	e.C1.B2.A0 = cs.Select(b, r1.C1.B2.A0, r2.C1.B2.A0)
	e.C1.B2.A1 = cs.Select(b, r1.C1.B2.A1, r2.C1.B2.A1)

	return e
}

// FixedExponentiation compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls377, so the exponent is supposed to be hardcoded
// and on 64 bits.
func (e *E12) FixedExponentiation(cs *frontend.ConstraintSystem, e1 *E12, exponent uint64, ext Extension) *E12 {

	var expoBin [64]uint8
	for i := 0; i < 64; i++ {
		expoBin[i] = uint8((exponent >> (63 - i))) & 1
	}

	res := E12{}
	res.SetOne(cs)

	for i := 0; i < 64; i++ {
		res.Mul(cs, &res, &res, ext)
		if expoBin[i] == 1 {
			res.Mul(cs, &res, e1, ext)
		}
	}
	*e = res

	return e
}

// FinalExpoBLS final  exponentation for curves of the bls family (t is the parameter used to generate the curve)
func (e *E12) FinalExpoBLS(cs *frontend.ConstraintSystem, e1 *E12, genT uint64, ext Extension) *E12 {

	res := *e1

	var t [6]E12

	t[0].FrobeniusCube(cs, e1, ext).FrobeniusCube(cs, &t[0], ext)

	res.Inverse(cs, &res, ext)
	t[0].Mul(cs, &t[0], &res, ext)

	res.FrobeniusSquare(cs, &t[0], ext).Mul(cs, &res, &t[0], ext)

	t[0].ConjugateFp12(cs, &res).Mul(cs, &t[0], &t[0], ext)
	t[5].FixedExponentiation(cs, &res, genT, ext)
	t[1].Mul(cs, &t[5], &t[5], ext)
	t[3].Mul(cs, &t[0], &t[5], ext)

	t[0].FixedExponentiation(cs, &t[3], genT, ext)
	t[2].FixedExponentiation(cs, &t[0], genT, ext)
	t[4].FixedExponentiation(cs, &t[2], genT, ext)

	t[4].Mul(cs, &t[1], &t[4], ext)
	t[1].FixedExponentiation(cs, &t[4], genT, ext)
	t[3].Conjugate(cs, &t[3])
	t[1].Mul(cs, &t[3], &t[1], ext)
	t[1].Mul(cs, &t[1], &res, ext)

	t[0].Mul(cs, &t[0], &res, ext)
	t[0].FrobeniusCube(cs, &t[0], ext)

	t[3].Conjugate(cs, &res)
	t[4].Mul(cs, &t[3], &t[4], ext)
	t[4].Frobenius(cs, &t[4], ext)

	t[5].Mul(cs, &t[2], &t[5], ext)
	t[5].FrobeniusSquare(cs, &t[5], ext)

	t[5].Mul(cs, &t[5], &t[0], ext)
	t[5].Mul(cs, &t[5], &t[4], ext)
	t[5].Mul(cs, &t[5], &t[1], ext)

	*e = t[5]
	return e
}

// Assign a value to self (witness assignment)
func (e *E12) Assign(a *bls377.E12) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E12) MustBeEqual(cs *frontend.ConstraintSystem, other E12) {
	e.C0.MustBeEqual(cs, other.C0)
	e.C1.MustBeEqual(cs, other.C1)
}
