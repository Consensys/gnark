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

package fp24

import (
	"fmt"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark/frontend"
)

// Extension stores the non residue elmt for an extension of type Fp->Fp2->Fp4->Fp12->Fp24 (Fp2 = Fp(u), Fp4 = Fp2(v), Fp12 = Fp4(w), Fp24 = Fp6(i))
type extension struct {
	// Frobenius coefficients
	frobCoeff0  interface{}
	frobCoeff1  interface{}
	frobCoeff2  interface{}
	frobCoeff3  interface{}
	frobCoeff4  interface{}
	frobCoeff5  interface{}
	frobCoeff6  interface{}
	frobCoeff7  interface{}
	frobCoeff8  interface{}
	frobCoeff9  interface{}
	frobCoeff10 interface{}
	frobCoeff11 interface{}
	frobCoeff12 interface{}
}

// E24 element in a quadratic extension
type E24 struct {
	D0, D1 E12
	api    frontend.API
	ext    *extension
}

func NewFp24Zero(api frontend.API) (E24, error) {
	var ret E24
	d0, err := NewFp12Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new d0: %w", err)
	}
	d1, err := NewFp12Zero(api)
	if err != nil {
		return ret, fmt.Errorf("new d1: %w", err)
	}
	ext, err := newExtension(api)
	if err != nil {
		return E24{}, fmt.Errorf("new extension: %w", err)
	}
	return E24{
		D0:  d0,
		D1:  d1,
		ext: ext,
		api: api,
	}, nil
}

// NewExtension get extension field parameters for bls24315
func newExtension(api frontend.API) (*extension, error) {
	// TODO: map for different curves
	ext := &extension{
		frobCoeff0:  "14265754707630841383590096931465005402246260064523506653409458152869013672931584279153351926943",
		frobCoeff1:  "17432737665785421589107433512831558061649422754130449334965277047994983947893909429238815314776",
		frobCoeff2:  "39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303426",
		frobCoeff3:  "39705142672498995661671850106945620852186608752525090699191017895721506694646055668218723303427",
		frobCoeff4:  "36538159751358858129508353309042417085530339727307806653508466610511913818164017196988153745736",
		frobCoeff5:  "37719635718874797449167165011304104204868932892052995456614707782168504515295626008356825673023",
		frobCoeff6:  "33342866563749162527758572927163102293238492708847648721152723115703639794013692274261201232097",
		frobCoeff7:  "13266452002786802757645810648664867986567631927642464177452792960815113608167203350720036682455",
		frobCoeff8:  "29019463919452620058839222695754364428302059305947724697987901631588253225470374568267230540725",
		frobCoeff9:  "27033956928813979172980697816649498888237489781085970819538323908118873647639658229550439080179",
		frobCoeff10: "20076414560962359770112762278498234306670860781205184543699930154888526185846488923541164549642",
		frobCoeff11: "37014442673353839783463348892746893664389658635873267609916377398480286678854893830142",
		frobCoeff12: "37014442673353839783463348892746893664389658635873267609916377398480286678854893830143",
	}
	return ext, nil
}

type E24Constraint interface {
	bls24315.E24
}

func FromFp24[F E24Constraint](v F) E24 {
	var d0, d1 E12
	switch vv := (any)(v).(type) {
	case bls24315.E24:
		d0, d1 = FromFp12(vv.D0), FromFp12(vv.D1)
	}
	return E24{
		D0: d0,
		D1: d1,
	}
}

// SetOne returns a newly allocated element equal to 1
func (e *E24) SetOne() *E24 {
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
func (e *E24) Add(e1, e2 E24) *E24 {
	e.D0.Add(e1.D0, e2.D0)
	e.D1.Add(e1.D1, e2.D1)
	return e
}

// Sub substracts 2 elmts in Fp24
func (e *E24) Sub(e1, e2 E24) *E24 {
	e.D0.Sub(e1.D0, e2.D0)
	e.D1.Sub(e1.D1, e2.D1)
	return e
}

// Neg negates an Fp6elmt
func (e *E24) Neg(e1 E24) *E24 {
	e.D0.Neg(e1.D0)
	e.D1.Neg(e1.D1)
	return e
}

// Mul multiplies 2 elmts in Fp24
func (e *E24) Mul(e1, e2 E24) *E24 {
	u, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	v, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	ac, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	bd, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	u.Add(e1.D0, e1.D1)
	v.Add(e2.D0, e2.D1)
	v.Mul(u, v)

	ac.Mul(e1.D0, e2.D0)
	bd.Mul(e1.D1, e2.D1)
	e.D1.Sub(v, ac).Sub(e.D1, bd)

	bd.MulByNonResidue(bd)
	e.D0.Add(ac, bd)

	return e
}

// Square squares an element in Fp24
func (e *E24) Square(x E24) *E24 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var err error
	var c [3]E12
	for i := range c {
		c[i], err = NewFp12Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	c[0].Sub(x.D0, x.D1)
	c[2].MulByNonResidue(x.D1)
	c[2].Sub(x.D0, c[2])
	c[1].Mul(x.D0, x.D1)
	c[0].Mul(c[0], c[2]).Add(c[0], c[1])
	e.D1.Add(c[1], c[1])
	c[1].MulByNonResidue(c[1])
	e.D0.Add(c[0], c[1])

	return e
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
func (e *E24) CyclotomicSquareCompressed(x E24) *E24 {
	var err error
	var t [7]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}

	// t0 = g1^2
	t[0].Square(x.D0.C1)
	// t1 = g5^2
	t[1].Square(x.D1.C2)
	// t5 = g1 + g5
	t[5].Add(x.D0.C1, x.D1.C2)
	// t2 = (g1 + g5)^2
	t[2].Square(t[5])

	// t3 = g1^2 + g5^2
	t[3].Add(t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5].Sub(t[2], t[3])

	// t6 = g3 + g2
	t[6].Add(x.D1.C0, x.D0.C2)
	// t3 = (g3 + g2)^2
	t[3].Square(t[6])
	// t2 = g3^2
	t[2].Square(x.D1.C0)

	// t6 = 2 * nr * g1 * g5
	t[6].MulByNonResidue(t[5])
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5].Add(t[6], x.D1.C0).
		Double(t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	e.D1.C0.Add(t[5], t[6])

	// t4 = nr * g5^2
	t[4].MulByNonResidue(t[1])
	// t5 = nr * g5^2 + g1^2
	t[5].Add(t[0], t[4])
	// t6 = nr * g5^2 + g1^2 - g2
	t[6].Sub(t[5], x.D0.C2)

	// t1 = g2^2
	t[1].Square(x.D0.C2)

	// t6 = 2 * nr * g5^2 + 2 * g1^2 - 2*g2
	t[6].Double(t[6])
	// z2 = 3 * nr * g5^2 + 3 * g1^2 - 2*g2
	e.D0.C2.Add(t[6], t[5])

	// t4 = nr * g2^2
	t[4].MulByNonResidue(t[1])
	// t5 = g3^2 + nr * g2^2
	t[5].Add(t[2], t[4])
	// t6 = g3^2 + nr * g2^2 - g1
	t[6].Sub(t[5], x.D0.C1)
	// t6 = 2 * g3^2 + 2 * nr * g2^2 - 2 * g1
	t[6].Double(t[6])
	// z1 = 3 * g3^2 + 3 * nr * g2^2 - 2 * g1
	e.D0.C1.Add(t[6], t[5])

	// t0 = g2^2 + g3^2
	t[0].Add(t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5].Sub(t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6].Add(t[5], x.D1.C2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6].Double(t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	e.D1.C2.Add(t[5], t[6])

	return e
}

// Decompress Karabina's cyclotomic square result
func (e *E24) Decompress(x E24) *E24 {
	var err error
	var t [3]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	one, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one.SetOne()

	// t0 = g1^2
	t[0].Square(x.D0.C1)
	// t1 = 3 * g1^2 - 2 * g2
	t[1].Sub(t[0], x.D0.C2).
		Double(t[1]).
		Add(t[1], t[0])
		// t0 = E * g5^2 + t1
	t[2].Square(x.D1.C2)
	t[0].MulByNonResidue(t[2]).
		Add(t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1].Double(x.D1.C0).
		Double(t[1]).
		Inverse(t[1])
	// z4 = g4
	e.D1.C1.Mul(t[0], t[1])

	// t1 = g2 * g1
	t[1].Mul(x.D0.C2, x.D0.C1)
	// t2 = 2 * g4^2 - 3 * g2 * g1
	t[2].Square(e.D1.C1).
		Sub(t[2], t[1]).
		Double(t[2]).
		Sub(t[2], t[1])
	// t1 = g3 * g5
	t[1].Mul(x.D1.C0, x.D1.C2)
	// c_0 = E * (2 * g4^2 + g3 * g5 - 3 * g2 * g1) + 1
	t[2].Add(t[2], t[1])
	e.D0.C0.MulByNonResidue(t[2]).
		Add(e.D0.C0, one)

	e.D0.C1.Set(x.D0.C1)
	e.D0.C2.Set(x.D0.C2)
	e.D1.C0.Set(x.D1.C0)
	e.D1.C2.Set(x.D1.C2)

	return e
}

// Granger-Scott's cyclotomic square
// squares a Fp24 elt in the cyclotomic group
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e *E24) CyclotomicSquare(x E24) *E24 {
	var err error
	var t [9]E4
	for i := range t {
		t[i], err = NewFp4Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}

	t[0].Square(x.D1.C1)
	t[1].Square(x.D0.C0)
	t[6].Add(x.D1.C1, x.D0.C0).Square(t[6]).Sub(t[6], t[0]).Sub(t[6], t[1]) // 2*x4*x0
	t[2].Square(x.D0.C2)
	t[3].Square(x.D1.C0)
	t[7].Add(x.D0.C2, x.D1.C0).Square(t[7]).Sub(t[7], t[2]).Sub(t[7], t[3]) // 2*x2*x3
	t[4].Square(x.D1.C2)
	t[5].Square(x.D0.C1)
	t[8].Add(x.D1.C2, x.D0.C1).Square(t[8]).Sub(t[8], t[4]).Sub(t[8], t[5]).MulByNonResidue(t[8])

	t[0].MulByNonResidue(t[0]).Add(t[0], t[1])
	t[2].MulByNonResidue(t[2]).Add(t[2], t[3])
	t[4].MulByNonResidue(t[4]).Add(t[4], t[5])

	e.D0.C0.Sub(t[0], x.D0.C0).Add(e.D0.C0, e.D0.C0).Add(e.D0.C0, t[0])
	e.D0.C1.Sub(t[2], x.D0.C1).Add(e.D0.C1, e.D0.C1).Add(e.D0.C1, t[2])
	e.D0.C2.Sub(t[4], x.D0.C2).Add(e.D0.C2, e.D0.C2).Add(e.D0.C2, t[4])

	e.D1.C0.Add(t[8], x.D1.C0).Add(e.D1.C0, e.D1.C0).Add(e.D1.C0, t[8])
	e.D1.C1.Add(t[6], x.D1.C1).Add(e.D1.C1, e.D1.C1).Add(e.D1.C1, t[6])
	e.D1.C2.Add(t[7], x.D1.C2).Add(e.D1.C2, e.D1.C2).Add(e.D1.C2, t[7])

	return e
}

// Conjugate applies Frob**6 (conjugation over Fp6)
func (e *E24) Conjugate(e1 E24) *E24 {
	e.D0.Set(e1.D0)
	e.D1.Neg(e1.D1)
	return e
}

// MulBy034 multiplication by sparse element
func (e *E24) MulBy034(c3, c4 E4) *E24 {
	d, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistend api")
	}
	f, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one, err := NewFp4Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	one.SetOne()

	a := e.D0
	b := e.D1
	f.Set(c3)

	b.MulBy01(f, c4)

	f.Add(one, f)
	d.Add(e.D0, e.D1)
	d.MulBy01(f, c4)

	e.D1.Add(a, b).Neg(e.D1).Add(e.D1, d)
	e.D0.MulByNonResidue(b).Add(e.D0, a)

	return e
}

// Inverse inverse an elmt in Fp24
func (e *E24) Inverse(e1 E24) *E24 {
	var err error
	var t [2]E12
	for i := range t {
		t[i], err = NewFp12Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}
	buf, err := NewFp12Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}

	t[0].Square(e1.D0)
	t[1].Square(e1.D1)

	buf.MulByNonResidue(t[1])
	t[0].Sub(t[0], buf)

	t[1].Inverse(t[0])
	e.D0.Mul(e1.D0, t[1])
	e.D1.Mul(e1.D1, t[1]).Neg(e.D1)

	return e
}

// nSquareCompressed repeated compressed cyclotmic square
func (e *E24) nSquareCompressed(n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareCompressed(*e)
	}
}

// nSquare repeated compressed cyclotmic square
func (e *E24) nSquare(n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquare(*e)
	}
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls24315, so the exponent is supposed to be hardcoded and on 32 bits.
func (e *E24) Expt(e1 E24, exponent uint64) *E24 {
	res, err := NewFp24Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	xInv, err := NewFp24Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	res.Set(e1)
	xInv.Conjugate(e1)

	res.nSquare(2)
	res.Mul(res, xInv)
	res.nSquareCompressed(8)
	res.Decompress(res)
	res.Mul(res, xInv)
	res.nSquare(2)
	res.Mul(res, e1)
	res.nSquareCompressed(20)
	res.Decompress(res)
	res.Mul(res, xInv)
	res.Conjugate(res)

	*e = res

	return e
}

// MustBeEqual constraint self to be equal to other into the given constraint system
func (e *E24) MustBeEqual(other E24) {
	e.D0.MustBeEqual(other.D0)
	e.D1.MustBeEqual(other.D1)
}

// Frobenius applies frob to an fp24 elmt
func (e *E24) Frobenius(e1 E24) *E24 {

	e.D0.C0.B0.Conjugate(e1.D0.C0.B0)
	e.D0.C0.B1.Conjugate(e1.D0.C0.B1).MulByFp(e.D0.C0.B1, e.ext.frobCoeff0)
	e.D0.C1.B0.Conjugate(e1.D0.C1.B0).MulByFp(e.D0.C1.B0, e.ext.frobCoeff1)
	e.D0.C1.B1.Conjugate(e1.D0.C1.B1).MulByFp(e.D0.C1.B1, e.ext.frobCoeff2)
	e.D0.C2.B0.Conjugate(e1.D0.C2.B0).MulByFp(e.D0.C2.B0, e.ext.frobCoeff3)
	e.D0.C2.B1.Conjugate(e1.D0.C2.B1).MulByFp(e.D0.C2.B1, e.ext.frobCoeff4)
	e.D1.C0.B0.Conjugate(e1.D1.C0.B0).MulByFp(e.D1.C0.B0, e.ext.frobCoeff5)
	e.D1.C0.B1.Conjugate(e1.D1.C0.B1).MulByFp(e.D1.C0.B1, e.ext.frobCoeff6)
	e.D1.C1.B0.Conjugate(e1.D1.C1.B0).MulByFp(e.D1.C1.B0, e.ext.frobCoeff7)
	e.D1.C1.B1.Conjugate(e1.D1.C1.B1).MulByFp(e.D1.C1.B1, e.ext.frobCoeff8)
	e.D1.C2.B0.Conjugate(e1.D1.C2.B0).MulByFp(e.D1.C2.B0, e.ext.frobCoeff9)
	e.D1.C2.B1.Conjugate(e1.D1.C2.B1).MulByFp(e.D1.C2.B1, e.ext.frobCoeff10)

	return e
}

// FrobeniusSquare applies frob**2 to an fp24 elmt
func (e *E24) FrobeniusSquare(e1 E24) *E24 {

	e.D0.C0.Conjugate(e1.D0.C0)
	e.D0.C1.Conjugate(e1.D0.C1).MulByFp(e.D0.C1, e.ext.frobCoeff3)
	e.D0.C2.Conjugate(e1.D0.C2).MulByFp(e.D0.C2, e.ext.frobCoeff2)
	e.D1.C0.Conjugate(e1.D1.C0).MulByFp(e.D1.C0, e.ext.frobCoeff1)
	e.D1.C1.Conjugate(e1.D1.C1).MulByFp(e.D1.C1, e.ext.frobCoeff0)
	e.D1.C2.Conjugate(e1.D1.C2).MulByFp(e.D1.C2, e.ext.frobCoeff4)

	return e
}

// FrobeniusQuad applies frob**4 to an fp24 elmt
func (e *E24) FrobeniusQuad(e1 E24) *E24 {

	e.D0.C0.Set(e1.D0.C0)
	e.D0.C1.MulByFp(e1.D0.C1, e.ext.frobCoeff2)
	e.D0.C2.MulByFp(e1.D0.C2, e.ext.frobCoeff11)
	e.D1.C0.MulByFp(e1.D1.C0, e.ext.frobCoeff3)
	e.D1.C1.Neg(e1.D1.C1)
	e.D1.C2.MulByFp(e1.D1.C2, e.ext.frobCoeff12)

	return e
}

// FinalExponentiation computes the final expo x**(p**12-1)(p**4+1)(p**8 - p**4 +1)/r
func (e *E24) FinalExponentiation(e1 E24, genT uint64) *E24 {
	res, err := NewFp24Zero(e.api)
	if err != nil {
		panic("inconsistent api")
	}
	res.Set(e1)

	// https://eprint.iacr.org/2012/232.pdf, section 7
	var t [9]E24
	for i := range t {
		t[i], err = NewFp24Zero(e.api)
		if err != nil {
			panic("inconsistent api")
		}
	}

	// easy part
	t[0].Conjugate(res)
	res.Inverse(res)
	t[0].Mul(t[0], res)
	res.FrobeniusQuad(t[0]).
		Mul(res, t[0])

	// hard part (up to permutation)
	// Daiki Hayashida and Kenichiro Hayasaka
	// and Tadanori Teruya
	// https://eprint.iacr.org/2020/875.pdf
	// 3*Phi_24(p)/r = (u-1)^2 * (u+p) * (u^2+p^2) * (u^4+p^4-1) + 3
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
	t[2].Mul(t[0], t[2])
	t[1].Expt(t[2], genT)
	t[1].Expt(t[1], genT)
	t[1].Expt(t[1], genT)
	t[1].Expt(t[1], genT)
	t[0].FrobeniusQuad(t[2])
	t[0].Mul(t[0], t[1])
	t[2].Conjugate(t[2])
	t[0].Mul(t[0], t[2])
	res.Mul(res, t[0])

	e.Set(res)

	return e
}

func (e *E24) Set(other E24) {
	e.D0.Set(other.D0)
	e.D1.Set(other.D1)
}

func (e *E24) SetAPI(api frontend.API) {
	e.api = api
}
