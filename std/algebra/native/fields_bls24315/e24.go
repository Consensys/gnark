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
	"math/big"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp4->Fp12->Fp24 (Fp2 = Fp(u), Fp4 = Fp2(v), Fp12 = Fp4(w), Fp24 = Fp6(i))
type Extension struct {

	// generators of each sub field
	uSquare *big.Int

	// Frobenius coefficients
	frobCoeff0  *big.Int
	frobCoeff1  *big.Int
	frobCoeff2  *big.Int
	frobCoeff3  *big.Int
	frobCoeff4  *big.Int
	frobCoeff5  *big.Int
	frobCoeff6  *big.Int
	frobCoeff7  *big.Int
	frobCoeff8  *big.Int
	frobCoeff9  *big.Int
	frobCoeff10 *big.Int
	frobCoeff11 *big.Int
	frobCoeff12 *big.Int
}

// E24 element in a quadratic extension
type E24 struct {
	D0, D1 E12
}

var ext = getBLS24315ExtensionFp24()

// return big.Int from base10 input
func newInt(in string) *big.Int {
	r := new(big.Int)
	_, ok := r.SetString(in, 10)
	if !ok {
		panic("invalid base10 big.Int: " + in)
	}
	return r
}

// getBLS24315ExtensionFp24 get extension field parameters for bls24315
func getBLS24315ExtensionFp24() Extension {

	res := Extension{}

	res.uSquare = newInt("13")
	res.frobCoeff0 = newInt("14265754707630841383590096931465005402246260064523506653409458152869013672931584279153351926943")
	res.frobCoeff1 = newInt("17432737665785421589107433512831558061649422754130449334965277047994983947893909429238815314776")
	res.frobCoeff2 = newInt("39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303426")
	res.frobCoeff3 = newInt("39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303427")
	res.frobCoeff4 = newInt("36538159751358858129508353309042417085530339727307806653508466610511913818164017196988153745736")
	res.frobCoeff5 = newInt("37719635718874797449167165011304104204868932892052995456614707782168504515295626008356825673023")
	res.frobCoeff6 = newInt("33342866563749162527758572927163102293238492708847648721152723115703639794013692274261201232097")
	res.frobCoeff7 = newInt("13266452002786802757645810648664867986567631927642464177452792960815113608167203350720036682455")
	res.frobCoeff8 = newInt("29019463919452620058839222695754364428302059305947724697987901631588253225470374568267230540725")
	res.frobCoeff9 = newInt("27033956928813979172980697816649498888237489781085970819538323908118873647639658229550439080179")
	res.frobCoeff10 = newInt("20076414560962359770112762278498234306670860781205184543699930154888526185846488923541164549642")
	res.frobCoeff11 = newInt("37014442673353839783463348892746893664389658635873267609916377398480286678854893830142")
	res.frobCoeff12 = newInt("37014442673353839783463348892746893664389658635873267609916377398480286678854893830143")

	return res
}

// SetZero returns a newly allocated element equal to 0
func (e *E24) SetZero() *E24 {
	e.D0.SetZero()
	e.D1.SetZero()
	return e
}

// SetOne returns a newly allocated element equal to 1
func (e *E24) SetOne() *E24 {
	e.D0.SetOne()
	e.D1.SetZero()
	return e
}

func (e *E24) assign(e1 []frontend.Variable) {
	e.D0.C0.B0.A0 = e1[0]
	e.D0.C0.B0.A1 = e1[1]
	e.D0.C0.B1.A0 = e1[2]
	e.D0.C0.B1.A1 = e1[3]
	e.D0.C1.B0.A0 = e1[4]
	e.D0.C1.B0.A1 = e1[5]
	e.D0.C1.B1.A0 = e1[6]
	e.D0.C1.B1.A1 = e1[7]
	e.D0.C2.B0.A0 = e1[8]
	e.D0.C2.B0.A1 = e1[9]
	e.D0.C2.B1.A0 = e1[10]
	e.D0.C2.B1.A1 = e1[11]
	e.D1.C0.B0.A0 = e1[12]
	e.D1.C0.B0.A1 = e1[13]
	e.D1.C0.B1.A0 = e1[14]
	e.D1.C0.B1.A1 = e1[15]
	e.D1.C1.B0.A0 = e1[16]
	e.D1.C1.B0.A1 = e1[17]
	e.D1.C1.B1.A0 = e1[18]
	e.D1.C1.B1.A1 = e1[19]
	e.D1.C2.B0.A0 = e1[20]
	e.D1.C2.B0.A1 = e1[21]
	e.D1.C2.B1.A0 = e1[22]
	e.D1.C2.B1.A1 = e1[23]
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
func (e *E24) Mul(api frontend.API, e1, e2 E24) *E24 {

	var u, v, ac, bd E12
	u.Add(api, e1.D0, e1.D1)
	v.Add(api, e2.D0, e2.D1)
	v.Mul(api, u, v)

	ac.Mul(api, e1.D0, e2.D0)
	bd.Mul(api, e1.D1, e2.D1)
	e.D1.Sub(api, v, ac).Sub(api, e.D1, bd)

	bd.MulByNonResidue(api, bd)
	e.D0.Add(api, ac, bd)

	return e
}

// Square squares an element in Fp24
func (e *E24) Square(api frontend.API, x E24) *E24 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var c0, c2, c3 E12
	c0.Sub(api, x.D0, x.D1)
	c3.MulByNonResidue(api, x.D1)
	c3.Sub(api, x.D0, c3)
	c2.Mul(api, x.D0, x.D1)
	c0.Mul(api, c0, c3).Add(api, c0, c2)
	e.D1.Add(api, c2, c2)
	c2.MulByNonResidue(api, c2)
	e.D0.Add(api, c0, c2)

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
func (e *E24) CyclotomicSquareKarabina2345(api frontend.API, x E24) *E24 {
	var t [7]E4

	// t0 = g1²
	t[0].Square(api, x.D0.C1)
	// t1 = g5²
	t[1].Square(api, x.D1.C2)
	// t5 = g1 + g5
	t[5].Add(api, x.D0.C1, x.D1.C2)
	// t2 = (g1 + g5)²
	t[2].Square(api, t[5])

	// t3 = g1² + g5²
	t[3].Add(api, t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5].Sub(api, t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(api, x.D1.C0, x.D0.C2)
	// t3 = (g3 + g2)²
	t[3].Square(api, t[6])
	// t2 = g3²
	t[2].Square(api, x.D1.C0)

	// t6 = 2 * nr * g1 * g5
	t[6].MulByNonResidue(api, t[5])
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5].Add(api, t[6], x.D1.C0).
		Double(api, t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	e.D1.C0.Add(api, t[5], t[6])

	// t4 = nr * g5²
	t[4].MulByNonResidue(api, t[1])
	// t5 = nr * g5² + g1²
	t[5].Add(api, t[0], t[4])
	// t6 = nr * g5² + g1² - g2
	t[6].Sub(api, t[5], x.D0.C2)

	// t1 = g2²
	t[1].Square(api, x.D0.C2)

	// t6 = 2 * nr * g5² + 2 * g1² - 2*g2
	t[6].Double(api, t[6])
	// z2 = 3 * nr * g5² + 3 * g1² - 2*g2
	e.D0.C2.Add(api, t[6], t[5])

	// t4 = nr * g2²
	t[4].MulByNonResidue(api, t[1])
	// t5 = g3² + nr * g2²
	t[5].Add(api, t[2], t[4])
	// t6 = g3² + nr * g2² - g1
	t[6].Sub(api, t[5], x.D0.C1)
	// t6 = 2 * g3² + 2 * nr * g2² - 2 * g1
	t[6].Double(api, t[6])
	// z1 = 3 * g3² + 3 * nr * g2² - 2 * g1
	e.D0.C1.Add(api, t[6], t[5])

	// t0 = g2² + g3²
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

// DecompressKarabina2345 Karabina's cyclotomic square result
func (e *E24) DecompressKarabina2345(api frontend.API, x E24) *E24 {

	var t [3]E4
	var _t [2]E4
	var one E4
	one.SetOne()

	// if g3 == 0
	// t0 = 2 * g1 * g5
	// t1 = g2
	selector1 := x.D1.C0.IsZero(api)
	_t[0].Square(api, x.D0.C1)
	_t[0].Double(api, _t[0])
	_t[1] = x.D0.C2

	// if g3 != 0
	// t0 = E * g5^2 + 3 * g1^2 - 2 * g2
	// t1 = 4 * g3
	t[0].Square(api, x.D0.C1)
	t[1].Sub(api, t[0], x.D0.C2).
		Double(api, t[1]).
		Add(api, t[1], t[0])
	t[2].Square(api, x.D1.C2)
	t[0].MulByNonResidue(api, t[2]).
		Add(api, t[0], t[1])
	t[1].Double(api, x.D1.C0).
		Double(api, t[1])

	// g4 = (E * g5^2 + 3 * g1^2 - 2 * g2)/4g3 or (2 * g1 * g5)/g2
	t[0].Select(api, selector1, _t[0], t[0])
	t[1].Select(api, selector1, _t[1], t[1])
	// if g2 == g3 == 0 we do nothing as DivUnchecked sets g4 to 0
	// and all gi to 0 returning, correctly in this case, at the end:
	// e = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1 = 1

	e.D1.C1.DivUnchecked(api, t[0], t[1])

	// t1 = g2 * g1
	t[1].Mul(api, x.D0.C2, x.D0.C1)
	// t2 = 2 * g4² - 3 * g2 * g1
	t[2].Square(api, e.D1.C1).
		Sub(api, t[2], t[1]).
		Double(api, t[2]).
		Sub(api, t[2], t[1])
	// t1 = g3 * g5
	t[1].Mul(api, x.D1.C0, x.D1.C2)
	// c₀ = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1
	t[2].Add(api, t[2], t[1])
	e.D0.C0.MulByNonResidue(api, t[2]).
		Add(api, e.D0.C0, one)

	e.D0.C1 = x.D0.C1
	e.D0.C2 = x.D0.C2
	e.D1.C0 = x.D1.C0
	e.D1.C2 = x.D1.C2

	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp24 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E24) CyclotomicSquare(api frontend.API, x E24) *E24 {

	var t [9]E4

	t[0].Square(api, x.D1.C1)
	t[1].Square(api, x.D0.C0)
	t[6].Add(api, x.D1.C1, x.D0.C0).Square(api, t[6]).Sub(api, t[6], t[0]).Sub(api, t[6], t[1]) // 2*x4*x0
	t[2].Square(api, x.D0.C2)
	t[3].Square(api, x.D1.C0)
	t[7].Add(api, x.D0.C2, x.D1.C0).Square(api, t[7]).Sub(api, t[7], t[2]).Sub(api, t[7], t[3]) // 2*x2*x3
	t[4].Square(api, x.D1.C2)
	t[5].Square(api, x.D0.C1)
	t[8].Add(api, x.D1.C2, x.D0.C1).Square(api, t[8]).Sub(api, t[8], t[4]).Sub(api, t[8], t[5]).MulByNonResidue(api, t[8])

	t[0].MulByNonResidue(api, t[0]).Add(api, t[0], t[1])
	t[2].MulByNonResidue(api, t[2]).Add(api, t[2], t[3])
	t[4].MulByNonResidue(api, t[4]).Add(api, t[4], t[5])

	e.D0.C0.Sub(api, t[0], x.D0.C0).Add(api, e.D0.C0, e.D0.C0).Add(api, e.D0.C0, t[0])
	e.D0.C1.Sub(api, t[2], x.D0.C1).Add(api, e.D0.C1, e.D0.C1).Add(api, e.D0.C1, t[2])
	e.D0.C2.Sub(api, t[4], x.D0.C2).Add(api, e.D0.C2, e.D0.C2).Add(api, e.D0.C2, t[4])

	e.D1.C0.Add(api, t[8], x.D1.C0).Add(api, e.D1.C0, e.D1.C0).Add(api, e.D1.C0, t[8])
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

// Inverse e24 elmts
func (e *E24) Inverse(api frontend.API, e1 E24) *E24 {

	res, err := api.NewHint(inverseE24Hint, 24, e1.D0.C0.B0.A0, e1.D0.C0.B0.A1, e1.D0.C0.B1.A0, e1.D0.C0.B1.A1, e1.D0.C1.B0.A0, e1.D0.C1.B0.A1, e1.D0.C1.B1.A0, e1.D0.C1.B1.A1, e1.D0.C2.B0.A0, e1.D0.C2.B0.A1, e1.D0.C2.B1.A0, e1.D0.C2.B1.A1, e1.D1.C0.B0.A0, e1.D1.C0.B0.A1, e1.D1.C0.B1.A0, e1.D1.C0.B1.A1, e1.D1.C1.B0.A0, e1.D1.C1.B0.A1, e1.D1.C1.B1.A0, e1.D1.C1.B1.A1, e1.D1.C2.B0.A0, e1.D1.C2.B0.A1, e1.D1.C2.B1.A0, e1.D1.C2.B1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E24
	e3.assign(res[:24])

	one.SetOne()

	// 1 == e3 * e1
	e3.Mul(api, e3, e1)
	e3.AssertIsEqual(api, one)

	e.assign(res[:24])

	return e
}

// DivUnchecked e24 elmts
func (e *E24) DivUnchecked(api frontend.API, e1, e2 E24) *E24 {

	res, err := api.NewHint(divE24Hint, 24, e1.D0.C0.B0.A0, e1.D0.C0.B0.A1, e1.D0.C0.B1.A0, e1.D0.C0.B1.A1, e1.D0.C1.B0.A0, e1.D0.C1.B0.A1, e1.D0.C1.B1.A0, e1.D0.C1.B1.A1, e1.D0.C2.B0.A0, e1.D0.C2.B0.A1, e1.D0.C2.B1.A0, e1.D0.C2.B1.A1, e1.D1.C0.B0.A0, e1.D1.C0.B0.A1, e1.D1.C0.B1.A0, e1.D1.C0.B1.A1, e1.D1.C1.B0.A0, e1.D1.C1.B0.A1, e1.D1.C1.B1.A0, e1.D1.C1.B1.A1, e1.D1.C2.B0.A0, e1.D1.C2.B0.A1, e1.D1.C2.B1.A0, e1.D1.C2.B1.A1, e2.D0.C0.B0.A0, e2.D0.C0.B0.A1, e2.D0.C0.B1.A0, e2.D0.C0.B1.A1, e2.D0.C1.B0.A0, e2.D0.C1.B0.A1, e2.D0.C1.B1.A0, e2.D0.C1.B1.A1, e2.D0.C2.B0.A0, e2.D0.C2.B0.A1, e2.D0.C2.B1.A0, e2.D0.C2.B1.A1, e2.D1.C0.B0.A0, e2.D1.C0.B0.A1, e2.D1.C0.B1.A0, e2.D1.C0.B1.A1, e2.D1.C1.B0.A0, e2.D1.C1.B0.A1, e2.D1.C1.B1.A0, e2.D1.C1.B1.A1, e2.D1.C2.B0.A0, e2.D1.C2.B0.A1, e2.D1.C2.B1.A0, e2.D1.C2.B1.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3 E24
	e3.assign(res[:24])

	// e1 == e3 * e2
	e3.Mul(api, e3, e2)
	e3.AssertIsEqual(api, e1)

	e.assign(res[:24])

	return e
}

// nSquareKarabina2345 repeated compressed cyclotmic square
func (e *E24) nSquareKarabina2345(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareKarabina2345(api, *e)
	}
}

// nSquare repeated compressed cyclotmic square
func (e *E24) nSquare(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquare(api, *e)
	}
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e *E24) AssertIsEqual(api frontend.API, other E24) {
	e.D0.AssertIsEqual(api, other.D0)
	e.D1.AssertIsEqual(api, other.D1)
}

// Assign a value to self (witness assignment)
func (e *E24) Assign(a *bls24315.E24) {
	e.D0.Assign(&a.D0)
	e.D1.Assign(&a.D1)
}

// Frobenius applies frob to an fp24 elmt
func (e *E24) Frobenius(api frontend.API, x E24) *E24 {

	e.D0.C0.B0.Conjugate(api, x.D0.C0.B0)
	e.D0.C0.B1.Conjugate(api, x.D0.C0.B1).MulByFp(api, e.D0.C0.B1, ext.frobCoeff0)
	e.D0.C1.B0.Conjugate(api, x.D0.C1.B0).MulByFp(api, e.D0.C1.B0, ext.frobCoeff1)
	e.D0.C1.B1.Conjugate(api, x.D0.C1.B1).MulByFp(api, e.D0.C1.B1, ext.frobCoeff2)
	e.D0.C2.B0.Conjugate(api, x.D0.C2.B0).MulByFp(api, e.D0.C2.B0, ext.frobCoeff3)
	e.D0.C2.B1.Conjugate(api, x.D0.C2.B1).MulByFp(api, e.D0.C2.B1, ext.frobCoeff4)
	e.D1.C0.B0.Conjugate(api, x.D1.C0.B0).MulByFp(api, e.D1.C0.B0, ext.frobCoeff5)
	e.D1.C0.B1.Conjugate(api, x.D1.C0.B1).MulByFp(api, e.D1.C0.B1, ext.frobCoeff6)
	e.D1.C1.B0.Conjugate(api, x.D1.C1.B0).MulByFp(api, e.D1.C1.B0, ext.frobCoeff7)
	e.D1.C1.B1.Conjugate(api, x.D1.C1.B1).MulByFp(api, e.D1.C1.B1, ext.frobCoeff8)
	e.D1.C2.B0.Conjugate(api, x.D1.C2.B0).MulByFp(api, e.D1.C2.B0, ext.frobCoeff9)
	e.D1.C2.B1.Conjugate(api, x.D1.C2.B1).MulByFp(api, e.D1.C2.B1, ext.frobCoeff10)

	return e
}

// FrobeniusSquare applies frob**2 to an fp24 elmt
func (e *E24) FrobeniusSquare(api frontend.API, x E24) *E24 {

	e.D0.C0.Conjugate(api, x.D0.C0)
	e.D0.C1.Conjugate(api, x.D0.C1).MulByFp(api, e.D0.C1, ext.frobCoeff3)
	e.D0.C2.Conjugate(api, x.D0.C2).MulByFp(api, e.D0.C2, ext.frobCoeff2)
	e.D1.C0.Conjugate(api, x.D1.C0).MulByFp(api, e.D1.C0, ext.frobCoeff1)
	e.D1.C1.Conjugate(api, x.D1.C1).MulByFp(api, e.D1.C1, ext.frobCoeff0)
	e.D1.C2.Conjugate(api, x.D1.C2).MulByFp(api, e.D1.C2, ext.frobCoeff4)

	return e
}

// FrobeniusQuad applies frob**4 to an fp24 elmt
func (e *E24) FrobeniusQuad(api frontend.API, x E24) *E24 {

	e.D0.C0 = x.D0.C0
	e.D0.C1.MulByFp(api, x.D0.C1, ext.frobCoeff2)
	e.D0.C2.MulByFp(api, x.D0.C2, ext.frobCoeff11)
	e.D1.C0.MulByFp(api, x.D1.C0, ext.frobCoeff3)
	e.D1.C1.Neg(api, x.D1.C1)
	e.D1.C2.MulByFp(api, x.D1.C2, ext.frobCoeff12)

	return e
}
