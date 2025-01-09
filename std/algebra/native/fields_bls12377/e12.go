// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package fields_bls12377

import (
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"

	"github.com/consensys/gnark/frontend"
)

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

// E12 element in a quadratic extension
type E12 struct {
	C0, C1 E6
}

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

// SetZero returns a newly allocated element equal to 0
func (e *E12) SetZero() *E12 {
	e.C0.SetZero()
	e.C1.SetZero()
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E12) SetOne() *E12 {
	e.C0.SetOne()
	e.C1.SetZero()
	return e
}

func (e *E12) assign(e1 []frontend.Variable) {
	e.C0.A0 = e1[0]
	e.C0.A1 = e1[2]
	e.C0.A2 = e1[4]
	e.C0.A3 = e1[1]
	e.C0.A4 = e1[3]
	e.C0.A5 = e1[5]
	e.C1.A0 = e1[6]
	e.C1.A1 = e1[7]
	e.C1.A2 = e1[8]
	e.C1.A3 = e1[9]
	e.C1.A4 = e1[10]
	e.C1.A5 = e1[11]
}

// Add adds 2 elmts in Fp12
func (e *E12) Add(api frontend.API, e1, e2 E12) *E12 {
	e.C0.Add(api, e1.C0, e2.C0)
	e.C1.Add(api, e1.C1, e2.C1)
	return e
}

// Sub subtracts 2 elmts in Fp12
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
func (e *E12) Mul(api frontend.API, e1, e2 E12) *E12 {

	var u, v, ac, bd E6
	u.Add(api, e1.C0, e1.C1)
	v.Add(api, e2.C0, e2.C1)
	v.Mul(api, u, v)

	ac.Mul(api, e1.C0, e2.C0)
	bd.Mul(api, e1.C1, e2.C1)
	e.C1.Sub(api, v, ac).Sub(api, e.C1, bd)

	bd.MulByNonResidue(api, bd)
	e.C0.Add(api, ac, bd)

	return e
}

// Square squares an element in Fp12
func (e *E12) Square(api frontend.API, x E12) *E12 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var c0, c2, c3 E6
	c0.Sub(api, x.C0, x.C1)
	c3.MulByNonResidue(api, x.C1)
	c3.Sub(api, x.C0, c3)
	c2.Mul(api, x.C0, x.C1)
	c0.Mul(api, c0, c3).Add(api, c0, c2)
	e.C1.Double(api, c2)
	c2.MulByNonResidue(api, c2)
	e.C0.Add(api, c0, c2)

	return e
}

func (e *E12) CyclotomicSquareKarabina12345(api frontend.API, e1 E12) *E12 {
	// TODO: implement Karabina sq
	return e.Square(api, e1)
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e *E12) CyclotomicSquareKarabina2345(api frontend.API, x E12) *E12 {
	// TODO: implement Karabina sq
	return e.Square(api, x)
}

// DecompressKarabina12345 Karabina's cyclotomic square result SQR12345
func (e *E12) DecompressKarabina12345(api frontend.API, x E12) *E12 {
	// TODO: implement Karabina decompression
	e = &x
	return e
}

// DecompressKarabina2345 Karabina's cyclotomic square result SQR2345
func (e *E12) DecompressKarabina2345(api frontend.API, x E12) *E12 {
	// TODO: implement Karabina decompression
	e = &x
	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp12 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E12) CyclotomicSquare(api frontend.API, x E12) *E12 {
	// TODO: implement GS sq
	return e.Square(api, x)
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E12) Conjugate(api frontend.API, e1 E12) *E12 {
	e.C0 = e1.C0
	e.C1.Neg(api, e1.C1)
	return e
}

// Inverse e12 elmts
func (e *E12) Inverse(api frontend.API, e1 E12) *E12 {

	res, err := api.NewHint(inverseE12Hint, 12, e1.C0.A0, e1.C0.A1, e1.C0.A2, e1.C0.A3, e1.C0.A4, e1.C0.A5, e1.C1.A0, e1.C1.A1, e1.C1.A2, e1.C1.A3, e1.C1.A4, e1.C1.A5)

	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E12
	e3.C0.assign(res[:6])
	e3.C1.assign(res[6:12])
	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.C0.assign(res[:6])
	e.C1.assign(res[6:12])

	return e
}

// DivUnchecked e12 elmts
func (e *E12) DivUnchecked(api frontend.API, e1, e2 E12) *E12 {

	res, err := api.NewHint(divE12Hint, 12, e1.C0.A0, e1.C0.A1, e1.C0.A2, e1.C0.A3, e1.C0.A4, e1.C0.A5, e1.C1.A0, e1.C1.A1, e1.C1.A2, e1.C1.A3, e1.C1.A4, e1.C1.A5, e2.C0.A0, e2.C0.A1, e2.C0.A2, e2.C0.A3, e2.C0.A4, e2.C0.A5, e2.C1.A0, e2.C1.A1, e2.C1.A2, e2.C1.A3, e2.C1.A4, e2.C1.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3 E12
	e3.C0.assign(res[:6])
	e3.C1.assign(res[6:12])

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.C0.assign(res[:6])
	e.C1.assign(res[6:12])

	return e
}

// Frobenius applies frob to an fp12 elmt
func (e *E12) Frobenius(api frontend.API, e1 E12) *E12 {

	e.C0.A0 = e1.C0.A0
	e.C0.A3 = api.Neg(e1.C0.A3)
	e.C0.A1 = e1.C0.A1
	e.C0.A4 = api.Neg(e1.C0.A4)
	e.C0.A1 = api.Mul(e.C0.A1, ext.frobv)
	e.C0.A4 = api.Mul(e.C0.A4, ext.frobv)
	e.C0.A2 = e1.C0.A2
	e.C0.A5 = api.Neg(e1.C0.A5)
	e.C0.A2 = api.Mul(e.C0.A2, ext.frobv2)
	e.C0.A5 = api.Mul(e.C0.A5, ext.frobv2)
	e.C1.A0 = e1.C1.A0
	e.C1.A3 = api.Neg(e1.C1.A3)
	e.C1.A0 = api.Mul(e.C1.A0, ext.frobw)
	e.C1.A3 = api.Mul(e.C1.A3, ext.frobw)
	e.C1.A1 = e1.C1.A1
	e.C1.A4 = api.Neg(e1.C1.A4)
	e.C1.A1 = api.Mul(e.C1.A1, ext.frobvw)
	e.C1.A4 = api.Mul(e.C1.A4, ext.frobvw)
	e.C1.A2 = e1.C1.A2
	e.C1.A5 = api.Neg(e1.C1.A5)
	e.C1.A2 = api.Mul(e.C1.A2, ext.frobv2w)
	e.C1.A5 = api.Mul(e.C1.A5, ext.frobv2w)

	return e

}

// FrobeniusSquare applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusSquare(api frontend.API, e1 E12) *E12 {

	e.C0.A0 = e1.C0.A0
	e.C0.A3 = e1.C0.A3
	e.C0.A1 = api.Mul(e1.C0.A1, ext.frob2v)
	e.C0.A4 = api.Mul(e1.C0.A4, ext.frob2v)
	e.C0.A2 = api.Mul(e1.C0.A2, ext.frob2v2)
	e.C0.A5 = api.Mul(e1.C0.A5, ext.frob2v2)
	e.C1.A0 = api.Mul(e1.C1.A0, ext.frob2w)
	e.C1.A3 = api.Mul(e1.C1.A3, ext.frob2w)
	e.C1.A1 = api.Mul(e1.C1.A1, ext.frob2vw)
	e.C1.A4 = api.Mul(e1.C1.A4, ext.frob2vw)
	e.C1.A2 = api.Mul(e1.C1.A2, ext.frob2v2w)
	e.C1.A5 = api.Mul(e1.C1.A5, ext.frob2v2w)
	return e
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E12) Select(api frontend.API, b frontend.Variable, r1, r2 E12) *E12 {

	e.C0.Select(api, b, r1.C0, r2.C0)
	e.C1.Select(api, b, r1.C1, r2.C1)

	return e
}

// Assign a value to self (witness assignment)
func (e *E12) Assign(a *bls12377.E12) {
	e.C0.Assign(&a.C0)
	e.C1.Assign(&a.C1)
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E12) AssertIsEqual(api frontend.API, other E12) {
	e.C0.AssertIsEqual(api, other.C0)
	e.C1.AssertIsEqual(api, other.C1)
}
