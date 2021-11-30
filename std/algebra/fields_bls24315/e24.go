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

package fields_bls24315

import (
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp4->Fp12->Fp24 (Fp2 = Fp(u), Fp4 = Fp2(v), Fp12 = Fp4(w), Fp24 = Fp6(i))
type Extension struct {

	// generators of each sub field
	uSquare interface{}
}

// E24 element in a quadratic extension
type E24 struct {
	D0, D1 E12
}

// GetBLS24315ExtensionFp24 get extension field parameters for bls24315
func GetBLS24315ExtensionFp24(api frontend.API) Extension {

	res := Extension{}

	res.uSquare = 13

	return res
}

// SetOne returns a newly allocated element equal to 1
func (e *E24) SetOne(api frontend.API) *E24 {
	e.D0.C0.B0.A0 = 1
	e.D0.C0.B0.A1 = 0
	e.D0.C0.B1.A0 = 0
	e.D0.C0.B1.A1 = 0
	e.D0.C1.B0.A0 = 0
	e.D0.C1.B0.A1 = 0
	e.D0.C1.B1.A0 = 1
	e.D0.C1.B1.A1 = 0
	e.D0.C2.B0.A0 = 0
	e.D0.C2.B0.A1 = 0
	e.D0.C2.B1.A0 = 0
	e.D0.C2.B1.A1 = 0
	e.D1.C0.B0.A0 = 0
	e.D1.C0.B0.A1 = 0
	e.D1.C0.B1.A0 = 0
	e.D1.C0.B1.A1 = 0
	e.D1.C1.B0.A0 = 0
	e.D1.C1.B0.A1 = 0
	e.D1.C1.B1.A0 = 0
	e.D1.C1.B1.A1 = 0
	e.D1.C2.B0.A0 = 0
	e.D1.C2.B0.A1 = 0
	e.D1.C2.B1.A0 = 0
	e.D1.C2.B1.A1 = 0

	return e
}

// Add adds 2 elmts in Fp24
func (e *E24) Add(api frontend.API, e1, e2 E24) *E24 {
	e.D0.Add(api, e1.D0, e2.D0)
	e.D1.Add(api, e1.D1, e2.D1)
	return e
}

// Sub substracts 2 elmts in Fp24
func (e *E24) Sub(api frontend.API, e1, e2 E24) *E24 {
	e.D0.Sub(api, e1.D0, e2.D0)
	e.D1.Sub(api, e1.D1, e2.D1)
	return e
}

// Neg negates an Fp6elmt
func (e *E24) Neg(api frontend.API, e1 E24) *E24 {
	e.D0.Neg(api, e1.D0)
	e.D1.Neg(api, e1.D1)
	return e
}

// Mul multiplies 2 elmts in Fp24
func (e *E24) Mul(api frontend.API, e1, e2 E24, ext Extension) *E24 {

	var u, v, ac, bd E12
	u.Add(api, e1.D0, e1.D1)
	v.Add(api, e2.D0, e2.D1)
	v.Mul(api, u, v, ext)

	ac.Mul(api, e1.D0, e2.D0, ext)
	bd.Mul(api, e1.D1, e2.D1, ext)
	e.D1.Sub(api, v, ac).Sub(api, e.D1, bd)

	bd.MulByIm(api, bd, ext)
	e.D0.Add(api, ac, bd)

	return e
}

// Square squares an element in Fp24
func (e *E24) Square(api frontend.API, x E24, ext Extension) *E24 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var c0, c2, c3 E12
	c0.Sub(api, x.D0, x.D1)
	c3.MulByIm(api, x.D1, ext)
	c3.Sub(api, x.D0, c3)
	c2.Mul(api, x.D0, x.D1, ext)
	c0.Mul(api, c0, c3, ext).Add(api, c0, c2)
	e.D1.Add(api, c2, c2)
	c2.MulByIm(api, c2, ext)
	e.D0.Add(api, c0, c2)

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e *E24) CyclotomicSquareCompressed(api frontend.API, x E24, ext Extension) *E24 {

	var t [7]E4

	// t0 = g1^2
	t[0].Square(api, x.D0.C1, ext)
	// t1 = g5^2
	t[1].Square(api, x.D1.C2, ext)
	// t5 = g1 + g5
	t[5].Add(api, x.D0.C1, x.D1.C2)
	// t2 = (g1 + g5)^2
	t[2].Square(api, t[5], ext)

	// t3 = g1^2 + g5^2
	t[3].Add(api, t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5].Sub(api, t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(api, x.D1.C1, x.D0.C2)
	// t3 = (g3 + g2)^2
	t[3].Square(api, t[6], ext)
	// t2 = g3^2
	t[2].Square(api, x.D1.C1, ext)

	// t6 = 2 * nr * g1 * g5
	t[6].MulByIm(api, t[5], ext)
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5].Add(api, t[6], x.D1.C1).
		Double(api, t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	e.D1.C1.Add(api, t[5], t[6])

	// t4 = nr * g5^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = nr * g5^2 + g1^2
	t[5].Add(api, t[0], t[4])
	// t6 = nr * g5^2 + g1^2 - g2
	t[6].Sub(api, t[5], x.D0.C2)

	// t1 = g2^2
	t[1].Square(api, x.D0.C2, ext)

	// t6 = 2 * nr * g5^2 + 2 * g1^2 - 2*g2
	t[6].Double(api, t[6])
	// z2 = 3 * nr * g5^2 + 3 * g1^2 - 2*g2
	e.D0.C2.Add(api, t[6], t[5])

	// t4 = nr * g2^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = g3^2 + nr * g2^2
	t[5].Add(api, t[2], t[4])
	// t6 = g3^2 + nr * g2^2 - g1
	t[6].Sub(api, t[5], x.D0.C1)
	// t6 = 2 * g3^2 + 2 * nr * g2^2 - 2 * g1
	t[6].Double(api, t[6])
	// z1 = 3 * g3^2 + 3 * nr * g2^2 - 2 * g1
	e.D0.C1.Add(api, t[6], t[5])

	// t0 = g2^2 + g3^2
	t[0].Add(api, t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5].Sub(api, t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6].Add(api, t[5], x.D1.C2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6].Double(api, t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	e.D1.C2.Add(api, t[5], t[6])

	return e
}

// Decompress Karabina's cyclotomic square result
func (e *E24) Decompress(api frontend.API, x E24, ext Extension) *E24 {

	var t [3]E4
	var one E4
	one.SetOne(api)

	// t0 = g1^2
	t[0].Square(api, x.D0.C1, ext)
	// t1 = 3 * g1^2 - 2 * g2
	t[1].Sub(api, t[0], x.D0.C2).
		Double(api, t[1]).
		Add(api, t[1], t[0])
		// t0 = E * g5^2 + t1
	t[2].Square(api, x.D1.C2, ext)
	t[0].MulByIm(api, t[2], ext).
		Add(api, t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1].Double(api, x.D1.C1).
		Double(api, t[1]).
		Inverse(api, t[1], ext)
	// z4 = g4
	e.D1.C1.Mul(api, t[0], t[1], ext)

	// t1 = g2 * g1
	t[1].Mul(api, x.D0.C2, x.D0.C1, ext)
	// t2 = 2 * g4^2 - 3 * g2 * g1
	t[2].Square(api, e.D1.C1, ext).
		Sub(api, t[2], t[1]).
		Double(api, t[2]).
		Sub(api, t[2], t[1])
	// t1 = g3 * g5
	t[1].Mul(api, x.D1.C1, x.D1.C2, ext)
	// c_0 = E * (2 * g4^2 + g3 * g5 - 3 * g2 * g1) + 1
	t[2].Add(api, t[2], t[1])
	e.D0.C1.MulByIm(api, t[2], ext).
		Add(api, e.D0.C1, one)

	e.D0.C1 = x.D0.C1
	e.D0.C2 = x.D0.C2
	e.D1.C1 = x.D1.C1
	e.D1.C2 = x.D1.C2

	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp24 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E24) CyclotomicSquare(api frontend.API, x E24, ext Extension) *E24 {

	// https://eprint.iacr.org/2009/565.pdf, 3.2
	var t [9]E4

	t[0].Square(api, x.D1.C1, ext)
	t[1].Square(api, x.D0.C1, ext)
	t[6].Add(api, x.D1.C1, x.D0.C1).Square(api, t[6], ext).Sub(api, t[6], t[0]).Sub(api, t[6], t[1]) // 2*x4*x0
	t[2].Square(api, x.D0.C2, ext)
	t[3].Square(api, x.D1.C1, ext)
	t[7].Add(api, x.D0.C2, x.D1.C1).Square(api, t[7], ext).Sub(api, t[7], t[2]).Sub(api, t[7], t[3]) // 2*x2*x3
	t[4].Square(api, x.D1.C2, ext)
	t[5].Square(api, x.D0.C1, ext)
	t[8].Add(api, x.D1.C2, x.D0.C1).Square(api, t[8], ext).Sub(api, t[8], t[4]).Sub(api, t[8], t[5]).MulByIm(api, t[8], ext) // 2*x5*x1*u

	t[0].MulByIm(api, t[0], ext).Add(api, t[0], t[1]) // x4^2*u + x0^2
	t[2].MulByIm(api, t[2], ext).Add(api, t[2], t[3]) // x2^2*u + x3^2
	t[4].MulByIm(api, t[4], ext).Add(api, t[4], t[5]) // x5^2*u + x1^2

	e.D0.C1.Sub(api, t[0], x.D0.C1).Add(api, e.D0.C1, e.D0.C1).Add(api, e.D0.C1, t[0])
	e.D0.C1.Sub(api, t[2], x.D0.C1).Add(api, e.D0.C1, e.D0.C1).Add(api, e.D0.C1, t[2])
	e.D0.C2.Sub(api, t[4], x.D0.C2).Add(api, e.D0.C2, e.D0.C2).Add(api, e.D0.C2, t[4])

	e.D1.C1.Add(api, t[8], x.D1.C1).Add(api, e.D1.C1, e.D1.C1).Add(api, e.D1.C1, t[8])
	e.D1.C1.Add(api, t[6], x.D1.C1).Add(api, e.D1.C1, e.D1.C1).Add(api, e.D1.C1, t[6])
	e.D1.C2.Add(api, t[7], x.D1.C2).Add(api, e.D1.C2, e.D1.C2).Add(api, e.D1.C2, t[7])

	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E24) Conjugate(api frontend.API, e1 E24) *E24 {
	e.D0 = e1.D0
	e.D1.Neg(api, e1.D1)
	return e
}

// MulBy034 multiplication by sparse element
func (e *E24) MulBy034(api frontend.API, c3, c4 E4, ext Extension) *E24 {

	var d E12
	var one E4
	one.SetOne(api)

	a := e.D0
	b := e.D1

	b.MulBy01(api, c3, c4, ext)

	c3.Add(api, one, c3)
	d.Add(api, e.D0, e.D1)
	d.MulBy01(api, c3, c4, ext)

	e.D1.Add(api, a, b).Neg(api, e.D1).Add(api, e.D1, d)
	e.D0.MulByIm(api, b, ext).Add(api, e.D0, a)

	return e
}

// Inverse inverse an elmt in Fp24
func (e *E24) Inverse(api frontend.API, e1 E24, ext Extension) *E24 {

	var t [2]E12
	var buf E12

	t[0].Square(api, e1.D0, ext)
	t[1].Square(api, e1.D1, ext)

	buf.MulByIm(api, t[1], ext)
	t[0].Sub(api, t[0], buf)

	t[1].Inverse(api, t[0], ext)
	e.D0.Mul(api, e1.D0, t[1], ext)
	e.D1.Mul(api, e1.D1, t[1], ext).Neg(api, e.D1)

	return e
}

// nSquareCompressed repeated compressed cyclotmic square
func (e *E24) nSquareCompressed(api frontend.API, n int, ext Extension) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareCompressed(api, *e, ext)
	}
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls24315, so the exponent is supposed to be hardcoded
// and on 64 bits.
func (e *E24) Expt(api frontend.API, e1 E24, exponent uint64, ext Extension) *E24 {

	res := E24{}
	x33 := E24{}
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

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E24) MustBeEqual(api frontend.API, other E24) {
	e.D0.MustBeEqual(api, other.D0)
	e.D1.MustBeEqual(api, other.D1)
}

// Assign a value to self (witness assignment)
func (e *E24) Assign(a *bls24315.E24) {
	e.D0.Assign(&a.D0)
	e.D1.Assign(&a.D1)
}
