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

package fp12

import (
	"fmt"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
)

// TODO(ivokub): check that instead of = have Set (keep api)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp6->Fp12 (Fp2 = Fp(u), Fp6 = Fp2(v), Fp12 = Fp6(w))
type extension struct {

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
	api    frontend.API
	ext    *extension
}

func NewFp12Zero(api frontend.API) (E12, error) {
	var ret E12
	c0, err := NewFp6Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new c0: %w", err)
	}
	c1, err := NewFp6Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new c1: %w", err)
	}
	ext, err := newExtension(api)
	if err != nil {
		return ret, fmt.Errorf("new extension: %w", err)
	}
	return E12{
		C0:  c0,
		C1:  c1,
		api: api,
		ext: ext,
	}, nil
}

type E12Constraint interface {
	bls12377.E12
}

func FromFp12[F E12Constraint](v F) E12 {
	var c0, c1 E6
	switch vv := (any)(v).(type) {
	case bls12377.E12:
		c0, c1 = FromFp6(vv.C0), FromFp6(vv.C1)
	}
	return E12{
		C0: c0,
		C1: c1,
	}
}

// GetBLS12377ExtensionFp12 get extension field parameters for bls12377
func newExtension(api frontend.API) (*extension, error) {
	// TODO define per curve
	res := &extension{
		frobv:    "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946",
		frobv2:   "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945",
		frobw:    "92949345220277864758624960506473182677953048909283248980960104381795901929519566951595905490535835115111760994353",
		frobvw:   "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499",
		frobv2w:  "123516416119946754630746545296132064952198520638002533875843642777304321125866014634106496325844844051843001220146",
		frob2v:   "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410945",
		frob2v2:  "258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047231",
		frob2w:   "80949648264912719408558363140637477264845294720710499478137287262712535938301461879813459410946",
		frob2vw:  "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176",
		frob2v2w: "258664426012969093929703085429980814127835149614277183275038967946009968870203535512256352201271898244626862047232",

		frob3v:   "258664426012969094010652733694893533536393512754914660539884262666720468348340822774968888139573360124440321458176",
		frob3v2:  "1",
		frob3w:   "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499",
		frob3vw:  "42198664672744474621281227892288285906241943207628877683080515507620245292955241189266486323192680957485559243678",
		frob3v2w: "216465761340224619389371505802605247630151569547285782856803747159100223055385581585702401816380679166954762214499",
	}
	return res, nil
}

// SetOne returns a newly allocated element equal to 1
func (e *E12) SetOne() *E12 {
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
func (e *E12) Add(e1, e2 E12) *E12 {
	e.C0.Add(e1.C0, e2.C0)
	e.C1.Add(e1.C1, e2.C1)
	return e
}

// Sub substracts 2 elmts in Fp12
func (e *E12) Sub(e1, e2 E12) *E12 {
	e.C0.Sub(e1.C0, e2.C0)
	e.C1.Sub(e1.C1, e2.C1)
	return e
}

// Neg negates an Fp6elmt
func (e *E12) Neg(e1 E12) *E12 {
	e.C0.Neg(e1.C0)
	e.C1.Neg(e1.C1)
	return e
}

// Mul multiplies 2 elmts in Fp12
func (e *E12) Mul(e1, e2 E12) *E12 {
	u, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	v, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	ac, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	bd, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	u.Add(e1.C0, e1.C1)
	v.Add(e2.C0, e2.C1)
	v.Mul(u, v)

	ac.Mul(e1.C0, e2.C0)
	bd.Mul(e1.C1, e2.C1)
	e.C1.Sub(v, ac).Sub(e.C1, bd)

	bd.MulByNonResidue(bd)
	e.C0.Add(ac, bd)

	return e
}

// Square squares an element in Fp12
func (e *E12) Square(x E12) *E12 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var err error
	var c [3]E6
	for i := range c {
		c[i], err = NewFp6Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	c[0].Sub(x.C0, x.C1)
	c[2].MulByNonResidue(x.C1)
	c[2].Sub(x.C0, c[2])
	c[1].Mul(x.C0, x.C1)
	c[0].Mul(c[0], c[2]).Add(c[0], c[1])
	e.C1.Add(c[1], c[1])
	c[1].MulByNonResidue(c[1])
	e.C0.Add(c[0], c[1])

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e *E12) CyclotomicSquareCompressed(x E12) *E12 {
	var err error
	var t [7]fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}

	// t0 = g1^2
	t[0].Square(x.C0.B1)
	// t1 = g5^2
	t[1].Square(x.C1.B2)
	// t5 = g1 + g5
	t[5].Add(x.C0.B1, x.C1.B2)
	// t2 = (g1 + g5)^2
	t[2].Square(t[5])

	// t3 = g1^2 + g5^2
	t[3].Add(t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5].Sub(t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(x.C1.B0, x.C0.B2)
	// t3 = (g3 + g2)^2
	t[3].Square(t[6])
	// t2 = g3^2
	t[2].Square(x.C1.B0)

	// t6 = 2 * nr * g1 * g5
	t[6].MulByNonResidue(t[5])
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5].Add(t[6], x.C1.B0).
		Double(t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	e.C1.B0.Add(t[5], t[6])

	// t4 = nr * g5^2
	t[4].MulByNonResidue(t[1])
	// t5 = nr * g5^2 + g1^2
	t[5].Add(t[0], t[4])
	// t6 = nr * g5^2 + g1^2 - g2
	t[6].Sub(t[5], x.C0.B2)

	// t1 = g2^2
	t[1].Square(x.C0.B2)

	// t6 = 2 * nr * g5^2 + 2 * g1^2 - 2*g2
	t[6].Double(t[6])
	// z2 = 3 * nr * g5^2 + 3 * g1^2 - 2*g2
	e.C0.B2.Add(t[6], t[5])

	// t4 = nr * g2^2
	t[4].MulByNonResidue(t[1])
	// t5 = g3^2 + nr * g2^2
	t[5].Add(t[2], t[4])
	// t6 = g3^2 + nr * g2^2 - g1
	t[6].Sub(t[5], x.C0.B1)
	// t6 = 2 * g3^2 + 2 * nr * g2^2 - 2 * g1
	t[6].Double(t[6])
	// z1 = 3 * g3^2 + 3 * nr * g2^2 - 2 * g1
	e.C0.B1.Add(t[6], t[5])

	// t0 = g2^2 + g3^2
	t[0].Add(t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5].Sub(t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6].Add(t[5], x.C1.B2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6].Double(t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	e.C1.B2.Add(t[5], t[6])

	return e
}

// Decompress Karabina's cyclotomic square result
func (e *E12) Decompress(x E12) *E12 {
	var err error
	var t [3]fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	one, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one.SetOne()

	// t0 = g1^2
	t[0].Square(x.C0.B1)
	// t1 = 3 * g1^2 - 2 * g2
	t[1].Sub(t[0], x.C0.B2).
		Double(t[1]).
		Add(t[1], t[0])
		// t0 = E * g5^2 + t1
	t[2].Square(x.C1.B2)
	t[0].MulByNonResidue(t[2]).
		Add(t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1].Double(x.C1.B0).
		Double(t[1]).
		Inverse(t[1])
	// z4 = g4
	e.C1.B1.Mul(t[0], t[1])

	// t1 = g2 * g1
	t[1].Mul(x.C0.B2, x.C0.B1)
	// t2 = 2 * g4^2 - 3 * g2 * g1
	t[2].Square(e.C1.B1).
		Sub(t[2], t[1]).
		Double(t[2]).
		Sub(t[2], t[1])
	// t1 = g3 * g5
	t[1].Mul(x.C1.B0, x.C1.B2)
	// c_0 = E * (2 * g4^2 + g3 * g5 - 3 * g2 * g1) + 1
	t[2].Add(t[2], t[1])
	e.C0.B0.MulByNonResidue(t[2]).
		Add(e.C0.B0, one)

	e.C0.B1.Set(x.C0.B1)
	e.C0.B2.Set(x.C0.B2)
	e.C1.B0.Set(x.C1.B0)
	e.C1.B2.Set(x.C1.B2)

	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp12 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E12) CyclotomicSquare(x E12) *E12 {
	var err error
	// https://eprint.iacr.org/2009/565.pdf, 3.2
	var t [9]fp2.E2
	for i := range t {
		t[i], err = fp2.New(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}

	t[0].Square(x.C1.B1)
	t[1].Square(x.C0.B0)
	t[6].Add(x.C1.B1, x.C0.B0).Square(t[6]).Sub(t[6], t[0]).Sub(t[6], t[1]) // 2*x4*x0
	t[2].Square(x.C0.B2)
	t[3].Square(x.C1.B0)
	t[7].Add(x.C0.B2, x.C1.B0).Square(t[7]).Sub(t[7], t[2]).Sub(t[7], t[3]) // 2*x2*x3
	t[4].Square(x.C1.B2)
	t[5].Square(x.C0.B1)
	t[8].Add(x.C1.B2, x.C0.B1).Square(t[8]).Sub(t[8], t[4]).Sub(t[8], t[5]).MulByNonResidue(t[8]) // 2*x5*x1*u

	t[0].MulByNonResidue(t[0]).Add(t[0], t[1]) // x4^2*u + x0^2
	t[2].MulByNonResidue(t[2]).Add(t[2], t[3]) // x2^2*u + x3^2
	t[4].MulByNonResidue(t[4]).Add(t[4], t[5]) // x5^2*u + x1^2

	e.C0.B0.Sub(t[0], x.C0.B0).Add(e.C0.B0, e.C0.B0).Add(e.C0.B0, t[0])
	e.C0.B1.Sub(t[2], x.C0.B1).Add(e.C0.B1, e.C0.B1).Add(e.C0.B1, t[2])
	e.C0.B2.Sub(t[4], x.C0.B2).Add(e.C0.B2, e.C0.B2).Add(e.C0.B2, t[4])

	e.C1.B0.Add(t[8], x.C1.B0).Add(e.C1.B0, e.C1.B0).Add(e.C1.B0, t[8])
	e.C1.B1.Add(t[6], x.C1.B1).Add(e.C1.B1, e.C1.B1).Add(e.C1.B1, t[6])
	e.C1.B2.Add(t[7], x.C1.B2).Add(e.C1.B2, e.C1.B2).Add(e.C1.B2, t[7])

	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E12) Conjugate(e1 E12) *E12 {
	e.C0.Set(e1.C0)
	e.C1.Neg(e1.C1)
	return e
}

// MulBy034 multiplication by sparse element
func (e *E12) MulBy034(c3, c4 fp2.E2) *E12 {

	d, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistend api")
	}
	f, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one, err := fp2.New(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one.SetOne()

	a := e.C0
	b := e.C1
	f.Set(c3)

	b.MulBy01(f, c4)

	f.Add(one, f)
	d.Add(e.C0, e.C1)
	d.MulBy01(f, c4)

	e.C1.Add(a, b).Neg(e.C1).Add(e.C1, d)
	e.C0.MulByNonResidue(b).Add(e.C0, a)

	return e
}

// Frobenius applies frob to an fp12 elmt
func (e *E12) Frobenius(e1 E12) *E12 {

	e.C0.B0.Conjugate(e1.C0.B0)
	e.C0.B1.Conjugate(e1.C0.B1).MulByFp(e.C0.B1, e.ext.frobv)
	e.C0.B2.Conjugate(e1.C0.B2).MulByFp(e.C0.B2, e.ext.frobv2)
	e.C1.B0.Conjugate(e1.C1.B0).MulByFp(e.C1.B0, e.ext.frobw)
	e.C1.B1.Conjugate(e1.C1.B1).MulByFp(e.C1.B1, e.ext.frobvw)
	e.C1.B2.Conjugate(e1.C1.B2).MulByFp(e.C1.B2, e.ext.frobv2w)

	return e

}

// FrobeniusSquare applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusSquare(e1 E12) *E12 {
	e.C0.B0.Set(e1.C0.B0)
	e.C0.B1.MulByFp(e1.C0.B1, e.ext.frob2v)
	e.C0.B2.MulByFp(e1.C0.B2, e.ext.frob2v2)
	e.C1.B0.MulByFp(e1.C1.B0, e.ext.frob2w)
	e.C1.B1.MulByFp(e1.C1.B1, e.ext.frob2vw)
	e.C1.B2.MulByFp(e1.C1.B2, e.ext.frob2v2w)

	return e
}

// FrobeniusCube applies frob**2 to an fp12 elmt
func (e *E12) FrobeniusCube(e1 E12) *E12 {

	e.C0.B0.Conjugate(e1.C0.B0)
	e.C0.B1.Conjugate(e1.C0.B1).MulByFp(e.C0.B1, e.ext.frob3v)
	e.C0.B2.Conjugate(e1.C0.B2).MulByFp(e.C0.B2, e.ext.frob3v2)
	e.C1.B0.Conjugate(e1.C1.B0).MulByFp(e.C1.B0, e.ext.frob3w)
	e.C1.B1.Conjugate(e1.C1.B1).MulByFp(e.C1.B1, e.ext.frob3vw)
	e.C1.B2.Conjugate(e1.C1.B2).MulByFp(e.C1.B2, e.ext.frob3v2w)

	return e
}

// Inverse inverse an elmt in Fp12
func (e *E12) Inverse(e1 E12) *E12 {
	var err error
	var t [2]E6
	for i := range t {
		t[i], err = NewFp6Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	buf, err := NewFp6Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	t[0].Square(e1.C0)
	t[1].Square(e1.C1)

	buf.MulByNonResidue(t[1])
	t[0].Sub(t[0], buf)

	t[1].Inverse(t[0])
	e.C0.Mul(e1.C0, t[1])
	e.C1.Mul(e1.C1, t[1]).Neg(e.C1)

	return e
}

// Select sets e to r1 if b=1, r2 otherwise
func (e *E12) Select(b frontend.Variable, r1, r2 E12) *E12 {

	e.C0.B0.A0 = e.api.Select(b, r1.C0.B0.A0, r2.C0.B0.A0)
	e.C0.B0.A1 = e.api.Select(b, r1.C0.B0.A1, r2.C0.B0.A1)
	e.C0.B1.A0 = e.api.Select(b, r1.C0.B1.A0, r2.C0.B1.A0)
	e.C0.B1.A1 = e.api.Select(b, r1.C0.B1.A1, r2.C0.B1.A1)
	e.C0.B2.A0 = e.api.Select(b, r1.C0.B2.A0, r2.C0.B2.A0)
	e.C0.B2.A1 = e.api.Select(b, r1.C0.B2.A1, r2.C0.B2.A1)
	e.C1.B0.A0 = e.api.Select(b, r1.C1.B0.A0, r2.C1.B0.A0)
	e.C1.B0.A1 = e.api.Select(b, r1.C1.B0.A1, r2.C1.B0.A1)
	e.C1.B1.A0 = e.api.Select(b, r1.C1.B1.A0, r2.C1.B1.A0)
	e.C1.B1.A1 = e.api.Select(b, r1.C1.B1.A1, r2.C1.B1.A1)
	e.C1.B2.A0 = e.api.Select(b, r1.C1.B2.A0, r2.C1.B2.A0)
	e.C1.B2.A1 = e.api.Select(b, r1.C1.B2.A1, r2.C1.B2.A1)

	return e
}

// nSquareCompressed repeated compressed cyclotmic square
func (e *E12) nSquareCompressed(n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareCompressed(*e)
	}
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls12377, so the exponent is supposed to be hardcoded
// and on 64 bits.
func (e *E12) Expt(e1 E12, exponent uint64) *E12 {
	res, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	x33, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	res.Set(e1)

	res.nSquareCompressed(5)
	res.Decompress(res)
	res.Mul(res, e1)
	x33.Set(res)
	res.nSquareCompressed(7)
	res.Decompress(res)
	res.Mul(res, x33)
	res.nSquareCompressed(4)
	res.Decompress(res)
	res.Mul(res, e1)
	res.CyclotomicSquare(res)
	res.Mul(res, e1)
	res.nSquareCompressed(46)
	res.Decompress(res)
	res.Mul(res, e1)

	e.Set(res)

	return e

}

// FinalExponentiation computes the final expo x**(p**6-1)(p**2+1)(p**4 - p**2 +1)/r
func (e *E12) FinalExponentiation(e1 E12, genT uint64) *E12 {
	// https://eprint.iacr.org/2016/130.pdf
	res, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	var t [3]E12
	for i := range t {
		t[i], err = NewFp12Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	res.Set(e1)

	// easy part
	t[0].Conjugate(res)
	res.Inverse(res)
	t[0].Mul(t[0], res)
	res.FrobeniusSquare(t[0]).
		Mul(res, t[0])

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	t[0].CyclotomicSquare(res)
	t[1].Expt(res, genT)
	t[2].Conjugate(res)
	t[1].Mul(t[1], t[2])
	t[2].Expt(t[1], genT)
	t[1].Conjugate(t[1])
	t[1].Mul(t[1], t[2])
	t[2].Expt(t[1], genT)
	t[1].Frobenius(t[1])
	t[1].Mul(t[1], t[2])
	res.Mul(res, t[0])
	t[0].Expt(t[1], genT)
	t[2].Expt(t[0], genT)
	t[0].FrobeniusSquare(t[1])
	t[1].Conjugate(t[1])
	t[1].Mul(t[1], t[2])
	t[1].Mul(t[1], t[0])
	res.Mul(res, t[1])

	*e = res
	return e
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E12) MustBeEqual(other E12) {
	e.C0.MustBeEqual(other.C0)
	e.C1.MustBeEqual(other.C1)
}

func (e *E12) Set(other E12) {
	e.C0.Set(other.C0)
	e.C1.Set(other.C1)
}

func (e *E12) SetAPI(api frontend.API) {
	e.api = api
}
