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

import "github.com/consensys/gnark/frontend"

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp6->Fp12 (Fp2 = Fp(u), Fp6 = Fp2(v), Fp12 = Fp6(w))
type Extension struct {

	// generators of each sub field
	uSquare interface{}
	vCube   *Fp2Elmt
	wSquare *Fp6Elmt

	// frobenius applied to generators
	frobv   interface{} // v**p  = (v**6)**(p-1/6)*v, frobv=(v**6)**(p-1/6), belongs to Fp)
	frobv2  interface{} // frobv2 = (v**6)**(2*(p-1)/6)
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

// Fp12Elmt element in a quadratic extension
type Fp12Elmt struct {
	c0, c1 Fp6Elmt
}

// NewFp12Elmt creates a fp6elmt from fp elmts
func NewFp12Elmt(circuit *frontend.CS, a, b, c, d, e, f, g, h, i, j, k, l interface{}) Fp12Elmt {

	u := NewFp6Elmt(circuit, a, b, c, d, e, f)
	v := NewFp6Elmt(circuit, g, h, i, j, k, l)
	res := NewFp12ElmtFromFp6(circuit, &u, &v)
	return res
}

// NewFp12ElmtFromFp6 creates a fp6elmt from fp elmts
func NewFp12ElmtFromFp6(circuit *frontend.CS, a, b *Fp6Elmt) Fp12Elmt {

	res := Fp12Elmt{
		c0: *a,
		c1: *b,
	}
	return res
}

// NewFp12ElmtNil creates a fp6elmt from fp elmts
func NewFp12ElmtNil(circuit *frontend.CS) Fp12Elmt {

	a := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	b := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)

	res := Fp12Elmt{
		c0: a,
		c1: b,
	}
	return res
}

// Add adds 2 elmts in Fp12
func (e *Fp12Elmt) Add(circuit *frontend.CS, e1, e2 *Fp12Elmt) *Fp12Elmt {
	e.c0.Add(circuit, &e1.c0, &e2.c0)
	e.c1.Add(circuit, &e1.c1, &e2.c1)
	return e
}

// Sub substracts 2 elmts in Fp12
func (e *Fp12Elmt) Sub(circuit *frontend.CS, e1, e2 *Fp12Elmt) *Fp12Elmt {
	e.c0.Sub(circuit, &e1.c0, &e2.c0)
	e.c1.Sub(circuit, &e1.c1, &e2.c1)
	return e
}

// Mul multiplies 2 elmts in Fp12
func (e *Fp12Elmt) Mul(circuit *frontend.CS, e1, e2 *Fp12Elmt, ext Extension) *Fp12Elmt {
	a := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	b := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	c := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	d := NewFp6Elmt(circuit, nil, nil, nil, nil, nil, nil)
	a.Mul(circuit, &e1.c0, &e2.c0, ext)
	b.Mul(circuit, &e1.c1, &e2.c1, ext).
		Mul(circuit, &b, ext.wSquare, ext)
	c.Mul(circuit, &e1.c0, &e2.c1, ext)
	d.Mul(circuit, &e1.c1, &e2.c0, ext)
	e.c0.Add(circuit, &a, &b)
	e.c1.Add(circuit, &c, &d)
	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *Fp12Elmt) Conjugate(circuit *frontend.CS, e1 *Fp12Elmt) *Fp12Elmt {
	zero := NewFp6Zero(circuit)
	e1.c1.Sub(circuit, &zero, &e1.c1)
	return e1
}

// MulByVW multiplies an e12 elmt by an elmt of the form a*VW (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *Fp12Elmt) MulByVW(circuit *frontend.CS, e1 *Fp12Elmt, e2 *Fp2Elmt, ext Extension) *Fp12Elmt {

	tmp := NewFp2Elmt(circuit, nil, nil)
	tmp.MulByIm(circuit, e2, ext)

	res := NewFp12ElmtNil(circuit)

	res.c0.b0.Mul(circuit, &e1.c1.b1, &tmp, ext)
	res.c0.b1.Mul(circuit, &e1.c1.b2, &tmp, ext)
	res.c0.b2.Mul(circuit, &e1.c1.b0, e2, ext)
	res.c1.b0.Mul(circuit, &e1.c0.b2, &tmp, ext)
	res.c1.b1.Mul(circuit, &e1.c0.b0, e2, ext)
	res.c1.b2.Mul(circuit, &e1.c0.b1, e2, ext)

	e.c0 = res.c0
	e.c1 = res.c1

	return e
}

// MulByV multiplies an e12 elmt by an elmt of the form a*V (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *Fp12Elmt) MulByV(circuit *frontend.CS, e1 *Fp12Elmt, e2 *Fp2Elmt, ext Extension) *Fp12Elmt {

	tmp := NewFp2Elmt(circuit, nil, nil)
	tmp.MulByIm(circuit, e2, ext)

	res := NewFp12ElmtNil(circuit)

	res.c0.b0.Mul(circuit, &e1.c0.b2, &tmp, ext)
	res.c0.b1.Mul(circuit, &e1.c0.b0, e2, ext)
	res.c0.b2.Mul(circuit, &e1.c0.b1, e2, ext)
	res.c1.b0.Mul(circuit, &e1.c1.b2, &tmp, ext)
	res.c1.b1.Mul(circuit, &e1.c1.b0, e2, ext)
	res.c1.b2.Mul(circuit, &e1.c1.b1, e2, ext)

	e.c0 = res.c0
	e.c1 = res.c1

	return e
}

// MulByV2W multiplies an e12 elmt by an elmt of the form a*V**2W (Fp6=Fp2(V), Fp12 = Fp6(W))
func (e *Fp12Elmt) MulByV2W(circuit *frontend.CS, e1 *Fp12Elmt, e2 *Fp2Elmt, ext Extension) *Fp12Elmt {

	tmp := NewFp2Elmt(circuit, nil, nil)
	tmp.MulByIm(circuit, e2, ext)

	res := NewFp12ElmtNil(circuit)

	res.c0.b0.Mul(circuit, &e1.c1.b0, &tmp, ext)
	res.c0.b1.Mul(circuit, &e1.c1.b1, &tmp, ext)
	res.c0.b2.Mul(circuit, &e1.c1.b2, &tmp, ext)
	res.c1.b0.Mul(circuit, &e1.c0.b1, &tmp, ext)
	res.c1.b1.Mul(circuit, &e1.c0.b2, &tmp, ext)
	res.c1.b2.Mul(circuit, &e1.c0.b0, &tmp, ext)

	e.c0 = res.c0
	e.c1 = res.c1

	return e
}

// Frobenius applies frob to an fp12 elmt
func (e *Fp12Elmt) Frobenius(circuit *frontend.CS, e1 *Fp12Elmt, ext Extension) *Fp12Elmt {

	e.c0.b0.Conjugate(circuit, &e1.c0.b0)
	e.c0.b1.Conjugate(circuit, &e1.c0.b1).MulByFp(circuit, &e.c0.b0, ext.frobv)
	e.c0.b2.Conjugate(circuit, &e1.c0.b2).MulByFp(circuit, &e.c0.b0, ext.frobv2)
	e.c1.b0.Conjugate(circuit, &e1.c1.b0).MulByFp(circuit, &e.c1.b0, ext.frobw)
	e.c1.b1.Conjugate(circuit, &e1.c1.b1).MulByFp(circuit, &e.c1.b1, ext.frobvw)
	e.c1.b2.Conjugate(circuit, &e1.c1.b2).MulByFp(circuit, &e.c1.b2, ext.frobv2w)

	return e

}

// FrobeniusSquare applies frob**2 to an fp12 elmt
func (e *Fp12Elmt) FrobeniusSquare(circuit *frontend.CS, e1 *Fp12Elmt, ext Extension) *Fp12Elmt {

	e.c0.b1.MulByFp(circuit, &e.c0.b0, ext.frob2v)
	e.c0.b2.MulByFp(circuit, &e.c0.b0, ext.frob2v2)
	e.c1.b0.MulByFp(circuit, &e.c1.b0, ext.frob2w)
	e.c1.b1.MulByFp(circuit, &e.c1.b1, ext.frob2vw)
	e.c1.b2.MulByFp(circuit, &e.c1.b2, ext.frob2v2w)

	return e
}

// FrobeniusCube applies frob**2 to an fp12 elmt
func (e *Fp12Elmt) FrobeniusCube(circuit *frontend.CS, e1 *Fp12Elmt, ext Extension) *Fp12Elmt {

	e.c0.b0.Conjugate(circuit, &e.c0.b0)
	e.c0.b1.Conjugate(circuit, &e.c0.b1).MulByFp(circuit, &e.c0.b1, ext.frob3v)
	e.c0.b2.Conjugate(circuit, &e.c0.b2).MulByFp(circuit, &e.c0.b2, ext.frob3v2)
	e.c1.b0.Conjugate(circuit, &e.c0.b1).MulByFp(circuit, &e.c1.b0, ext.frob3w)
	e.c1.b1.Conjugate(circuit, &e.c0.b1).MulByFp(circuit, &e.c1.b1, ext.frob3vw)
	e.c1.b2.Conjugate(circuit, &e.c0.b1).MulByFp(circuit, &e.c1.b2, ext.frob3v2w)

	return e
}
