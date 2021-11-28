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

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp4->Fp8->Fp24 (Fp2 = Fp(u), Fp4 = Fp2(v), Fp8 = Fp4(w), Fp24 = Fp8(i))
type Extension struct {

	// generators of each sub field
	uSquare interface{}

	// Frobenius coefficients
	frobCoeffA interface{}
	frobCoeffB interface{}
	frobCoeffC interface{}
	frobCoeffD interface{}
	frobCoeffE interface{}
	frobCoeffF interface{}
	frobCoeffG interface{}
	frobCoeffH interface{}
	frobCoeffI interface{}
	frobCoeffJ interface{}
	frobCoeffK interface{}
}

// GetBLS24315ExtensionFp24 get extension field parameters for bls24315
func GetBLS24315ExtensionFp24(api frontend.API) Extension {

	res := Extension{}

	res.uSquare = 13

	res.frobCoeffA = "14265754707630841383590096931465005402246260064523506653409458152869013672931584279153351926943"
	res.frobCoeffB = "13266452002786802757645810648664867986567631927642464177452792960815113608167203350720036682455"
	res.frobCoeffC = "37719635718874797449167165011304104204868932892052995456614707782168504515295626008356825673023"
	res.frobCoeffD = "17432737665785421589107433512831558061649422754130449334965277047994983947893909429238815314776"
	res.frobCoeffE = "39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303427"
	res.frobCoeffF = "29019463919452620058839222695754364428302059305947724697987901631588253225470374568267230540725"
	res.frobCoeffG = "39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303426"
	res.frobCoeffH = "27033956928813979172980697816649498888237489781085970819538323908118873647639658229550439080179"
	res.frobCoeffI = "36538159751358858129508353309042417085530339727307806653508466610511913818164017196988153745736"
	res.frobCoeffJ = "33342866563749162527758572927163102293238492708847648721152723115703639794013692274261201232097"
	res.frobCoeffK = "20076414560962359770112762278498234306670860781205184543699930154888526185846488923541164549642"

	return res
}

// E24 element in a quadratic extension
type E24 struct {
	D0, D1, D2 E8
}

// SetOne returns a newly allocated element equal to 1
func (e *E24) SetOne(api frontend.API) *E24 {
	e.D0.C0.B0.A0 = 1
	e.D0.C0.B0.A1 = 0
	e.D0.C0.B1.A0 = 0
	e.D0.C0.B1.A1 = 0
	e.D0.C1.B0.A0 = 0
	e.D0.C1.B0.A1 = 0
	e.D0.C1.B1.A0 = 0
	e.D0.C1.B1.A1 = 0
	e.D1.C0.B0.A0 = 0
	e.D1.C0.B0.A1 = 0
	e.D1.C0.B1.A0 = 0
	e.D1.C0.B1.A1 = 0
	e.D1.C1.B0.A0 = 0
	e.D1.C1.B0.A1 = 0
	e.D1.C1.B1.A0 = 0
	e.D1.C1.B1.A1 = 0
	e.D2.C0.B0.A0 = 0
	e.D2.C0.B0.A1 = 0
	e.D2.C0.B1.A0 = 0
	e.D2.C0.B1.A1 = 0
	e.D2.C1.B0.A0 = 0
	e.D2.C1.B0.A1 = 0
	e.D2.C1.B1.A0 = 0
	e.D2.C1.B1.A1 = 0

	return e
}

// Add creates a fp24elmt from fp elmts
func (e *E24) Add(api frontend.API, e1, e2 E24) *E24 {

	e.D0.Add(api, e1.D0, e2.D0)
	e.D1.Add(api, e1.D1, e2.D1)
	e.D2.Add(api, e1.D2, e2.D2)

	return e
}

// Sub creates a fp24elmt from fp elmts
func (e *E24) Sub(api frontend.API, e1, e2 E24) *E24 {

	e.D0.Sub(api, e1.D0, e2.D0)
	e.D1.Sub(api, e1.D1, e2.D1)
	e.D2.Sub(api, e1.D2, e2.D2)

	return e
}

// Neg negates an Fp24 elmt
func (e *E24) Neg(api frontend.API, e1 E24) *E24 {
	e.D0.Neg(api, e1.D0)
	e.D1.Neg(api, e1.D1)
	e.D2.Neg(api, e1.D2)
	return e
}

// Mul creates a fp24elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E24) Mul(api frontend.API, e1, e2 E24, ext Extension) *E24 {

	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, c0, c1, c2, tmp E8
	t0.Mul(api, e1.D0, e2.D0, ext)
	t1.Mul(api, e1.D1, e2.D1, ext)
	t2.Mul(api, e1.D2, e2.D2, ext)

	c0.Add(api, e1.D1, e1.D2)
	tmp.Add(api, e2.D1, e2.D2)
	c0.Mul(api, c0, tmp, ext).Sub(api, c0, t1).Sub(api, c0, t2).MulByIm(api, c0, ext).Add(api, c0, t0)

	c1.Add(api, e1.D0, e1.D1)
	tmp.Add(api, e2.D0, e2.D1)
	c1.Mul(api, c1, tmp, ext).Sub(api, c1, t0).Sub(api, c1, t1)
	tmp.MulByIm(api, t2, ext)
	c1.Add(api, c1, tmp)

	tmp.Add(api, e1.D0, e1.D2)
	c2.Add(api, e2.D0, e2.D2).Mul(api, c2, tmp, ext).Sub(api, c2, t0).Sub(api, c2, t2).Add(api, c2, t1)

	e.D0 = c0
	e.D1 = c1
	e.D2 = c2

	return e
}

// MulByFp2 creates a fp24elmt from fp elmts
// icube is the imaginary elmt to the cube
func (e *E24) MulByFp2(api frontend.API, e1 E24, e2 E8, ext Extension) *E24 {
	res := E24{}

	res.D0.Mul(api, e1.D0, e2, ext)
	res.D1.Mul(api, e1.D1, e2, ext)
	res.D2.Mul(api, e1.D2, e2, ext)

	e.D0 = res.D0
	e.D1 = res.D1
	e.D2 = res.D2

	return e
}

// Conjugate set e to e1 conjugated and return e
func (e *E24) Conjugate(api frontend.API, e1 *E24, ext Extension) *E24 {
	e.D0.Conjugate(api, e1.D0)
	e.D1.Conjugate(api, e1.D1).Neg(api, e.D1)
	e.D2.Conjugate(api, e1.D2)
	return e
}

// Square sets z to the E24 product of x,x, returns e
func (e *E24) Square(api frontend.API, x E24, ext Extension) *E24 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0 E8
	c4.Mul(api, x.D0, x.D1, ext).Double(api, c4)
	c5.Square(api, x.D2, ext)
	c1.MulByIm(api, c5, ext).Add(api, c1, c4)
	c2.Sub(api, c4, c5)
	c3.Square(api, x.D0, ext)
	c4.Sub(api, x.D0, x.D1).Add(api, c4, x.D2)
	c5.Mul(api, x.D1, x.D2, ext).Double(api, c5)
	c4.Square(api, c4, ext)
	c0.MulByIm(api, c5, ext).Add(api, c0, c3)
	e.D2.Add(api, c2, c4).Add(api, e.D2, c5).Sub(api, e.D2, c3)
	e.D0 = c0
	e.D1 = c1

	return e
}

// Granger-Scott's cyclotomic square
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E24) CyclotomicSquare(api frontend.API, e1 E24, ext Extension) *E24 {

	var A, B, C, D E8

	A = e1.D0
	B = e1.D2
	C = e1.D1
	e.D0.Square(api, e1.D0, ext)
	D.Double(api, e.D0)
	e.D0.Add(api, e.D0, D)
	A.Conjugate(api, A).Neg(api, A)
	A.Double(api, A)
	e.D0.Add(api, e.D0, A)
	B.Square(api, B, ext)
	B.MulByIm(api, B, ext)
	D.Double(api, B)
	B.Add(api, B, D)
	C.Square(api, C, ext)
	D.Double(api, C)
	C.Add(api, C, D)
	e.D1.Conjugate(api, e1.D1)
	e.D1.Double(api, e.D1)
	e.D2.Conjugate(api, e1.D2).Neg(api, e.D2)
	e.D2.Double(api, e.D2)
	e.D1.Add(api, e.D1, B)
	e.D2.Add(api, e.D2, C)

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (z *E24) CyclotomicSquareCompressed(api frontend.API, x E24, ext Extension) *E24 {

	var t [7]E4

	// t0 = g4^2
	t[0].Square(api, x.D2.C0, ext)
	// t1 = g5^2
	t[1].Square(api, x.D2.C1, ext)
	// t5 = g4 + g5
	t[5].Add(api, x.D2.C0, x.D2.C1)
	// t2 = (api, g4 + g5)^2
	t[2].Square(api, t[5], ext)

	// t3 = g4^2 + g5^2
	t[3].Add(api, t[0], t[1])
	// t5 = 2 * g4 * g5
	t[5].Sub(api, t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(api, x.D1.C1, x.D1.C0)
	// t3 = (api, g3 + g2)^2
	t[3].Square(api, t[6], ext)
	// t2 = g2^2
	t[2].Square(api, x.D1.C0, ext)

	// t6 = 2 * nr * g4 * g5
	t[6].MulByIm(api, t[5], ext)
	// t5 = 4 * nr * g4 * g5 + 2 * g2
	t[5].Add(api, t[6], x.D1.C0).
		Double(api, t[5])
	// z2 = 6 * nr * g4 * g5 + 2 * g2
	z.D1.C0.Add(api, t[5], t[6])

	// t4 = nr * g5^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = nr * g5^2 + g4^2
	t[5].Add(api, t[0], t[4])
	// t6 = nr * g5^2 + g1^2 - g3
	t[6].Sub(api, t[5], x.D1.C1)

	// t1 = g3^2
	t[1].Square(api, x.D1.C1, ext)

	// t6 = 2 * nr * g5^2 + 2 * g4^2 - 2*g3
	t[6].Double(api, t[6])
	// z3 = 3 * nr * g5^2 + 3 * g4^2 - 2*g3
	z.D1.C1.Add(api, t[6], t[5])

	// t4 = nr * g3^2
	t[4].MulByIm(api, t[1], ext)
	// t5 = g2^2 + nr * g3^2
	t[5].Add(api, t[2], t[4])
	// t6 = g2^2 + nr * g3^2 - g4
	t[6].Sub(api, t[5], x.D2.C0)
	// t6 = 2 * g2^2 + 2 * nr * g3^2 - 2 * g4
	t[6].Double(api, t[6])
	// z4 = 3 * g2^2 + 3 * nr * g3^2 - 2 * g4
	z.D2.C0.Add(api, t[6], t[5])

	// t0 = g3^2 + g2^2
	t[0].Add(api, t[2], t[1])
	// t5 = 2 * g2 * g3
	t[5].Sub(api, t[3], t[0])
	// t6 = 2 * g2 * g3 + g5
	t[6].Add(api, t[5], x.D2.C1)
	// t6 = 4 * g2 * g3 + 2 * g5
	t[6].Double(api, t[6])
	// z5 = 6 * g2 * g3 + 2 * g5
	z.D2.C1.Add(api, t[5], t[6])

	return z
}

// Decompress Karabina's cyclotomic square result
func (z *E24) Decompress(api frontend.API, x E24, ext Extension) *E24 {

	var t [3]E4
	var one E4
	one.SetOne(api)

	// t0 = g4^2
	t[0].Square(api, x.D2.C0, ext)
	// t1 = 3 * g4^2 - 2 * g3
	t[1].Sub(api, t[0], x.D1.C1).
		Double(api, t[1]).
		Add(api, t[1], t[0])
		// t0 = E * g5^2 + t1
	t[2].Square(api, x.D2.C1, ext)
	t[0].MulByIm(api, t[2], ext).
		Add(api, t[0], t[1])
	// t1 = 1/(api, 4 * g2)
	t[1].Double(api, x.D1.C0).
		Double(api, t[1]).
		Inverse(api, t[1], ext)
	// z1 = g4
	z.D0.C1.Mul(api, t[0], t[1], ext)

	// t1 = g3 * g4
	t[1].Mul(api, x.D1.C1, x.D2.C0, ext)
	// t2 = 2 * g1^2 - 3 * g3 * g4
	t[2].Square(api, z.D0.C1, ext).
		Sub(api, t[2], t[1]).
		Double(api, t[2]).
		Sub(api, t[2], t[1])
	// t1 = g2 * g5
	t[1].Mul(api, x.D1.C0, x.D2.C1, ext)
	// z0 = E * (api, 2 * g1^2 + g2 * g5 - 3 * g3 * g4) + 1
	t[2].Add(api, t[2], t[1])
	z.D0.C0.MulByIm(api, t[2], ext).
		Add(api, z.D0.C0, one)

	z.D1.C0 = x.D1.C0
	z.D1.C1 = x.D1.C1
	z.D2.C0 = x.D2.C0
	z.D2.C1 = x.D2.C1

	return z
}

// Inverse inverses an Fp24 elmt
func (e *E24) Inverse(api frontend.API, e1 E24, ext Extension) *E24 {

	var t [7]E8
	var c [3]E8
	var buf E8

	t[0].Square(api, e1.D0, ext)
	t[1].Square(api, e1.D1, ext)
	t[2].Square(api, e1.D2, ext)
	t[3].Mul(api, e1.D0, e1.D1, ext)
	t[4].Mul(api, e1.D0, e1.D2, ext)
	t[5].Mul(api, e1.D1, e1.D2, ext)

	c[0].MulByIm(api, t[5], ext)

	c[0].Neg(api, c[0]).Add(api, c[0], t[0])

	c[1].MulByIm(api, t[2], ext)

	c[1].Sub(api, c[1], t[3])
	c[2].Sub(api, t[1], t[4])
	t[6].Mul(api, e1.D2, c[1], ext)
	buf.Mul(api, e1.D1, c[2], ext)
	t[6].Add(api, t[6], buf)

	t[6].MulByIm(api, t[6], ext)

	buf.Mul(api, e1.D0, c[0], ext)
	t[6].Add(api, t[6], buf)

	t[6].Inverse(api, t[6], ext)
	e.D0.Mul(api, c[0], t[6], ext)
	e.D1.Mul(api, c[1], t[6], ext)
	e.D2.Mul(api, c[2], t[6], ext)

	return e

}

// MulBy012 multiplication by sparse element
// https://eprint.iacr.org/2019/077.pdf
func (e *E24) MulBy012(api frontend.API, c1, c2 E4, ext Extension) *E24 {

	var d0, v0, v1, tmp E8

	d0.C0.SetOne(api)
	d0.C1 = c1

	v0.Mul(api, e.D0, d0, ext)
	v1.C0.Mul(api, e.D1.C0, c2, ext)
	v1.C1.Mul(api, e.D1.C1, c2, ext)

	e.D1.Add(api, e.D1, e.D0)
	tmp = d0
	tmp.C0.Add(api, tmp.C0, c2)
	e.D1.Mul(api, e.D1, tmp, ext)
	e.D1.Sub(api, e.D1, v0)
	e.D1.Sub(api, e.D1, v1)

	e.D0.C0.Mul(api, e.D2.C0, c2, ext)
	e.D0.C1.Mul(api, e.D2.C1, c2, ext)
	e.D0.MulByIm(api, e.D0, ext)
	e.D0.Add(api, e.D0, v0)

	e.D2.Mul(api, e.D2, d0, ext)
	e.D2.Add(api, e.D2, v1)

	return e
}

// nSquareCompressed repeated compressed cyclotmic square
func (e *E24) nSquareCompressed(api frontend.API, n int, ext Extension) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareCompressed(api, *e, ext)
	}
}

// Expt compute x**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls24-315, so the exponent is supposed to be hardcoded
// and on 64 bits.
// todo: check for optimal short addition chain
func (e *E24) Expt(api frontend.API, x E24, exponent uint64, ext Extension) *E24 {

	res := E24{}
	xInv := E24{}
	res = x
	xInv.Conjugate(api, &x, ext)

	res.nSquareCompressed(api, 2, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, xInv, ext)
	res.nSquareCompressed(api, 8, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, xInv, ext)
	res.nSquareCompressed(api, 2, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, x, ext)
	res.nSquareCompressed(api, 20, ext)
	res.Decompress(api, res, ext)
	res.Mul(api, res, xInv, ext)
	res.Conjugate(api, &res, ext)

	*e = res

	return e

}

// Assign a value to self (witness assignment)
func (e *E24) Assign(a *bls24315.E24) {
	e.D0.Assign(&a.D0)
	e.D1.Assign(&a.D1)
	e.D2.Assign(&a.D2)
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E24) MustBeEqual(api frontend.API, other E24) {
	e.D0.MustBeEqual(api, other.D0)
	e.D1.MustBeEqual(api, other.D1)
	e.D2.MustBeEqual(api, other.D2)
}

// Frobenius applies frob to an fp24 elmt
func (e *E24) Frobenius(api frontend.API, e1 E24, ext Extension) *E24 {

	var t [12]E2

	t[0].Conjugate(api, e1.D0.C0.B0)
	t[1].Conjugate(api, e1.D0.C0.B1).MulByFp(api, t[1], ext.frobCoeffA)
	t[2].Conjugate(api, e1.D0.C1.B0).MulByFp(api, t[2], ext.frobCoeffB)
	t[3].Conjugate(api, e1.D0.C1.B1).MulByFp(api, t[3], ext.frobCoeffF)
	t[4].Conjugate(api, e1.D1.C0.B0).MulByFp(api, t[4], ext.frobCoeffC)
	t[5].Conjugate(api, e1.D1.C0.B1).MulByFp(api, t[5], ext.frobCoeffJ)
	t[6].Conjugate(api, e1.D1.C1.B0).MulByFp(api, t[6], ext.frobCoeffE)
	t[7].Conjugate(api, e1.D1.C1.B1).MulByFp(api, t[7], ext.frobCoeffI)
	t[8].Conjugate(api, e1.D2.C0.B0).MulByFp(api, t[8], ext.frobCoeffD)
	t[9].Conjugate(api, e1.D2.C0.B1).MulByFp(api, t[9], ext.frobCoeffG)
	t[10].Conjugate(api, e1.D2.C1.B0).MulByFp(api, t[10], ext.frobCoeffH)
	t[11].Conjugate(api, e1.D2.C1.B1).MulByFp(api, t[11], ext.frobCoeffK)

	e.D0.C0.B0 = t[0]
	e.D0.C0.B1 = t[1]
	e.D0.C1.B0 = t[2]
	e.D0.C1.B1 = t[3]
	e.D1.C0.B0 = t[4]
	e.D1.C0.B1 = t[5]
	e.D1.C1.B0 = t[6]
	e.D1.C1.B1 = t[7]
	e.D2.C0.B0 = t[8]
	e.D2.C0.B1 = t[9]
	e.D2.C1.B0 = t[10]
	e.D2.C1.B1 = t[11]

	return e

}

// FrobeniusSquare applies frob**2 to an fp24 elmt
func (e *E24) FrobeniusSquare(api frontend.API, e1 E24, ext Extension) *E24 {

	var t [6]E4

	t[0].Conjugate(api, e1.D0.C0)
	t[1].Conjugate(api, e1.D0.C1).MulByFp(api, t[1], ext.frobCoeffA)
	t[2].Conjugate(api, e1.D1.C0).MulByFp(api, t[2], ext.frobCoeffD)
	t[3].Conjugate(api, e1.D1.C1).MulByFp(api, t[3], ext.frobCoeffG)
	t[4].Conjugate(api, e1.D2.C0).MulByFp(api, t[4], ext.frobCoeffE)
	t[5].Conjugate(api, e1.D2.C1).MulByFp(api, t[5], ext.frobCoeffI)

	e.D0.C0 = t[0]
	e.D0.C1 = t[1]
	e.D1.C0 = t[2]
	e.D1.C1 = t[3]
	e.D2.C0 = t[4]
	e.D2.C1 = t[5]

	return e

}

// FrobeniusQuad applies frob**4 to an fp24 elmt
func (e *E24) FrobeniusQuad(api frontend.API, e1 E24, ext Extension) *E24 {

	var t [3]E8

	t[0].Conjugate(api, e1.D0)
	t[1].Conjugate(api, e1.D1).MulByFp(api, t[1], ext.frobCoeffE)
	t[2].Conjugate(api, e1.D2).MulByFp(api, t[2], ext.frobCoeffG)

	e.D0 = t[0]
	e.D1 = t[1]
	e.D2 = t[2]

	return e

}

// FinalExponentiation computes the final expo x**(p**12-1)(p**4+1)(p**8 - p**4 +1)/r
func (e *E24) FinalExponentiation(api frontend.API, e1 E24, genT uint64, ext Extension) *E24 {

	result := e1

	// https://eprint.iacr.org/2012/232.pdf, section 7
	var t [9]E24

	// easy part
	t[0].Conjugate(api, &result, ext)
	result.Inverse(api, result, ext)
	t[0].Mul(api, t[0], result, ext)
	result.FrobeniusQuad(api, t[0], ext).
		Mul(api, result, t[0], ext)

	// hard part (api, up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	// 3*Phi_24(api, p)/r = (api, u-1)^2 * (api, u+p) * (api, u^2+p^2) * (api, u^4+p^4-1) + 3
	t[0].CyclotomicSquare(api, result, ext)
	t[1].Expt(api, result, genT, ext)
	t[2].Conjugate(api, &result, ext)
	t[1].Mul(api, t[1], t[2], ext)
	t[2].Expt(api, t[1], genT, ext)
	t[1].Conjugate(api, &t[1], ext)
	t[1].Mul(api, t[1], t[2], ext)
	t[2].Expt(api, t[1], genT, ext)
	t[1].Frobenius(api, t[1], ext)
	t[1].Mul(api, t[1], t[2], ext)
	result.Mul(api, result, t[0], ext)
	t[0].Expt(api, t[1], genT, ext)
	t[2].Expt(api, t[0], genT, ext)
	t[0].FrobeniusSquare(api, t[1], ext)
	t[2].Mul(api, t[0], t[2], ext)
	t[1].Expt(api, t[2], genT, ext)
	t[1].Expt(api, t[1], genT, ext)
	t[1].Expt(api, t[1], genT, ext)
	t[1].Expt(api, t[1], genT, ext)
	t[0].FrobeniusQuad(api, t[2], ext)
	t[0].Mul(api, t[0], t[1], ext)
	t[2].Conjugate(api, &t[2], ext)
	t[0].Mul(api, t[0], t[2], ext)
	result.Mul(api, result, t[0], ext)

	*e = result

	return e
}
