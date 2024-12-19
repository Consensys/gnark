// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
)

// E2 element in a quadratic extension
type E2 struct {
	A0, A1 frontend.Variable
}

// SetZero returns a newly allocated element equal to 0
func (e *E2) SetZero() *E2 {
	e.A0 = 0
	e.A1 = 0
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E2) SetOne() *E2 {
	e.A0 = 1
	e.A1 = 0
	return e
}

// IsZero returns 1 if the element is equal to 0 and 0 otherwise
func (e *E2) IsZero(api frontend.API) frontend.Variable {
	return api.And(api.IsZero(e.A0), api.IsZero(e.A1))
}

func (e *E2) assign(e1 []frontend.Variable) {
	e.A0 = e1[0]
	e.A1 = e1[1]
}

// Neg negates a e2 elmt
func (e *E2) Neg(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Sub(0, e1.A0)
	e.A1 = api.Sub(0, e1.A1)
	return e
}

// Add e2 elmts
func (e *E2) Add(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Add(e1.A0, e2.A0)
	e.A1 = api.Add(e1.A1, e2.A1)
	return e
}

// Double e2 elmt
func (e *E2) Double(api frontend.API, e1 E2) *E2 {
	e.A0 = api.Mul(e1.A0, 2)
	e.A1 = api.Mul(e1.A1, 2)
	return e
}

// Sub e2 elmts
func (e *E2) Sub(api frontend.API, e1, e2 E2) *E2 {
	e.A0 = api.Sub(e1.A0, e2.A0)
	e.A1 = api.Sub(e1.A1, e2.A1)
	return e
}

// Mul e2 elmts
func (e *E2) Mul(api frontend.API, e1, e2 E2) *E2 {

	l1 := api.Add(e1.A0, e1.A1)
	l2 := api.Add(e2.A0, e2.A1)

	u := api.Mul(l1, l2)

	ac := api.Mul(e1.A0, e2.A0)
	bd := api.Mul(e1.A1, e2.A1)

	l31 := api.Add(ac, bd)
	e.A1 = api.Sub(u, l31)

	l41 := api.Mul(bd, ext.uSquare)
	e.A0 = api.Add(ac, l41)

	return e
}

// Square e2 elt
func (e *E2) Square(api frontend.API, x E2) *E2 {
	//algo 22 https://eprint.iacr.org/2010/354.pdf
	c0 := api.Add(x.A0, x.A1)
	c2 := api.Mul(x.A1, ext.uSquare)
	c2 = api.Add(c2, x.A0)

	c0 = api.Mul(c0, c2) // (x1+x2)*(x1+(u**2)x2)
	c2 = api.Mul(x.A0, x.A1)
	c2 = api.Mul(c2, 2)
	e.A1 = c2
	c2 = api.Mul(c2, 2)
	e.A0 = api.Add(c0, c2)

	return e
}

// MulByFp multiplies an fp2 elmt by an fp elmt
func (e *E2) MulByFp(api frontend.API, e1 E2, c interface{}) *E2 {
	e.A0 = api.Mul(e1.A0, c)
	e.A1 = api.Mul(e1.A1, c)
	return e
}

// MulByNonResidue multiplies an fp2 elmt by the imaginary elmt
// ext.uSquare is the square of the imaginary root
func (e *E2) MulByNonResidue(api frontend.API, e1 E2) *E2 {
	x := e1.A0
	e.A0 = api.Mul(e1.A1, ext.uSquare)
	e.A1 = x
	return e
}

// Conjugate conjugation of an e2 elmt
func (e *E2) Conjugate(api frontend.API, e1 E2) *E2 {
	e.A0 = e1.A0
	e.A1 = api.Sub(0, e1.A1)
	return e
}

// Inverse e2 elmts
func (e *E2) Inverse(api frontend.API, e1 E2) *E2 {

	res, err := api.NewHint(inverseE2Hint, 2, e1.A0, e1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E2
	e3.assign(res[:2])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:2])

	return e
}

// DivUnchecked e2 elmts
func (e *E2) DivUnchecked(api frontend.API, e1, e2 E2) *E2 {

	res, err := api.NewHint(divE2Hint, 2, e1.A0, e1.A1, e2.A0, e2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3 E2
	e3.assign(res[:2])

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:2])

	return e
}

// Assign a value to self (witness assignment)
func (e *E2) Assign(a *bls12377.E2) {
	e.A0 = (fr.Element)(a.A0)
	e.A1 = (fr.Element)(a.A1)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E2) AssertIsEqual(api frontend.API, other E2) {
	api.AssertIsEqual(e.A0, other.A0)
	api.AssertIsEqual(e.A1, other.A1)
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E2) Select(api frontend.API, b frontend.Variable, r1, r2 E2) *E2 {

	e.A0 = api.Select(b, r1.A0, r2.A0)
	e.A1 = api.Select(b, r1.A1, r2.A1)

	return e
}

// Lookup2 implements two-bit lookup. It returns:
//   - r1 if b1=0 and b2=0,
//   - r2 if b1=0 and b2=1,
//   - r3 if b1=1 and b2=0,
//   - r3 if b1=1 and b2=1.
func (e *E2) Lookup2(api frontend.API, b1, b2 frontend.Variable, r1, r2, r3, r4 E2) *E2 {

	e.A0 = api.Lookup2(b1, b2, r1.A0, r2.A0, r3.A0, r4.A0)
	e.A1 = api.Lookup2(b1, b2, r1.A1, r2.A1, r3.A1, r4.A1)

	return e
}

// --
var ext = getBLS12377ExtensionFp12()

// return big.Int from base10 input
func newInt(in string) *big.Int {
	r := new(big.Int)
	_, ok := r.SetString(in, 10)
	if !ok {
		panic("invalid base10 big.Int: " + in)
	}
	return r
}

// getBLS12377ExtensionFp12 get extension field parameters for bls12377
func getBLS12377ExtensionFp12() Extension {

	res := Extension{}

	res.uSquare = newInt("-5")

	res.frobv = newInt("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946")
	res.frobv2 = newInt("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")
	res.frobw = newInt("92949345220277864758624960506473182677953048909283248980960104381795901929519566951595905490535835115111760994353")
	res.frobvw = newInt("216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499")
	res.frobv2w = newInt("123516416119946754630746545296132064952198520638002533875843642777304321125866014634106496325844844051843001220146")

	res.frob2v = newInt("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945")
	res.frob2v2 = newInt("258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047231")
	res.frob2w = newInt("80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946")
	res.frob2vw = newInt("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176")
	res.frob2v2w = newInt("258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047232")

	res.frob3v = newInt("258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176")
	res.frob3v2 = newInt("1")
	res.frob3w = newInt("216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499")
	res.frob3vw = newInt("42198664672744474621281227892288285906241943207628877683080515507620245292955241189266486323192680957485559243678")
	res.frob3v2w = newInt("216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499")

	return res
}

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp6->Fp12 (Fp2 = Fp(u), Fp6 = Fp2(v), Fp12 = Fp6(w))
type Extension struct {

	// generators of each sub field
	uSquare *big.Int

	// frobenius applied to generators
	frobv   *big.Int // v**p  = (v**6)**(p-1/6)*v, frobv=(v**6)**(p-1/6), belongs to Fp)
	frobv2  *big.Int // frobv2 = (v**6)**(p-1/3)
	frobw   *big.Int // frobw = (w**12)**(p-1/12)
	frobvw  *big.Int // frobvw = (v**6)**(p-1/6)*(w*12)**(p-1/12)
	frobv2w *big.Int // frobv2w = (v**6)**(2*(p-1)/6)*(w*12)**(p-1/12)

	// frobenius square applied to generators
	frob2v   *big.Int // v**(p**2)  = (v**6)**(p**2-1/6)*v, frobv=(v**6)**(p**2-1/6), belongs to Fp)
	frob2v2  *big.Int // frobv2 = (v**6)**(2*(p**2-1)/6)
	frob2w   *big.Int // frobw = (w**12)**(p**2-1/12)
	frob2vw  *big.Int // frobvw = (v**6)**(p**2-1/6)*(w*12)**(p**2-1/12)
	frob2v2w *big.Int // frobv2w = (v**6)**(2*(p**2-1)/6)*(w*12)**(p**2-1/12)

	// frobenius cube applied to generators
	frob3v   *big.Int // v**(p**3)  = (v**6)**(p**3-1/6)*v, frobv=(v**6)**(p**3-1/6), belongs to Fp)
	frob3v2  *big.Int // frobv2 = (v**6)**(2*(p**3-1)/6)
	frob3w   *big.Int // frobw = (w**12)**(p**3-1/12)
	frob3vw  *big.Int // frobvw = (v**6)**(p**3-1/6)*(w*12)**(p**3-1/12)
	frob3v2w *big.Int // frobv2w = (v**6)**(2*(p**3-1)/6)*(w*12)**(p**3-1/12)

}
