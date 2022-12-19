/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package pairing_bw6761

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
)

type E6 struct {
	B0, B1 E3
}

type ext6 struct {
	*ext3
}

func NewExt6(baseField *curveF) *ext6 {
	return &ext6{ext3: NewExt3(baseField)}
}

// SetZero sets an *E3 elmt to zero
func (e ext6) Zero() *E6 {
	b0 := e.ext3.Zero()
	b1 := e.ext3.Zero()
	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// One sets z to 1 in Montgomery form and returns z
func (e ext6) One() *E6 {
	return &E6{
		B0: *e.ext3.One(),
		B1: *e.ext3.Zero(),
	}
}

// Add set z=x+y in *E6 and return z
func (e ext6) Add(x, y *E6) *E6 {
	return &E6{
		B0: *e.ext3.Add(&x.B0, &y.B0),
		B1: *e.ext3.Add(&x.B1, &y.B1),
	}
}

// Sub sets z to x sub y and return z
func (e ext6) Sub(x, y *E6) *E6 {
	return &E6{
		B0: *e.ext3.Sub(&x.B0, &y.B0),
		B1: *e.ext3.Sub(&x.B1, &y.B1),
	}
}

// Double sets z=2*x and returns z
func (e ext6) Double(x *E6) *E6 {
	return &E6{
		B0: *e.ext3.Add(&x.B0, &x.B0),
		B1: *e.ext3.Add(&x.B1, &x.B1),
	}
}

// Mul set z=x*y in *E6 and return z
func (e ext6) Mul(x, y *E6) *E6 {
	a := e.ext3.Add(&x.B0, &x.B1)
	b := e.ext3.Add(&y.B0, &y.B1)
	a = e.ext3.Mul(a, b)
	b = e.ext3.Mul(&x.B0, &y.B0)
	c := e.ext3.Mul(&x.B1, &y.B1)
	b1 := e.ext3.Sub(a, b)
	b1 = e.ext3.Sub(b1, c)
	b0 := e.ext3.MulByNonResidue(c)
	b0 = e.ext3.Add(b0, b)
	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Square set z=x*x in *E6 and return z
func (e ext6) Square(x *E6) *E6 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	c0 := e.ext3.Sub(&x.B0, &x.B1)
	c3 := e.ext3.MulByNonResidue(&x.B1)
	c3 = e.ext3.Neg(c3)
	c3 = e.ext3.Add(&x.B0, c3)
	c2 := e.ext3.Mul(&x.B0, &x.B1)
	c0 = e.ext3.Mul(c0, c3)
	c0 = e.ext3.Add(c0, c2)
	b1 := e.ext3.Double(c2)
	c2 = e.ext3.MulByNonResidue(c2)
	b0 := e.ext3.Add(c0, c2)

	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (e ext6) CyclotomicSquareCompressed(z *E6, x *E6) *E6 {

	var t [7]*baseField

	// t0 = g1²
	t[0] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	// t1 = g5²
	t[1] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	// t5 = g1 + g5
	t[5] = e.fp.Add(&x.B0.A1, &x.B1.A2)
	// t2 = (g1 + g5)²
	t[2] = e.fp.Mul(t[5], t[5])

	// t3 = g1² + g5²
	t[3] = e.fp.Add(t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5] = e.fp.Sub(t[2], t[3])

	// t6 = g3 + g2
	t[6] = e.fp.Add(&x.B1.A0, &x.B0.A2)
	// t3 = (g3 + g2)²
	t[3] = e.fp.Mul(t[6], t[6])
	// t2 = g3²
	t[2] = e.fp.Mul(&x.B1.A0, &x.B1.A0)

	// t6 = 2 * nr * g1 * g5
	t[6] = MulByNonResidue(e.fp, t[5])
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5] = e.fp.Add(t[6], &x.B1.A0)
	t[5] = e.fp.Add(t[5], t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	z.B1.A0 = *e.fp.Add(t[5], t[6])

	// t4 = nr * g5²
	t[4] = MulByNonResidue(e.fp, t[1])
	// t5 = nr * g5² + g1²
	t[5] = e.fp.Add(t[0], t[4])
	// t6 = nr * g5² + g1² - g2
	t[6] = e.fp.Sub(t[5], &x.B0.A2)

	// t1 = g2²
	t[1] = e.fp.Mul(&x.B0.A2, &x.B0.A2)

	// t6 = 2 * nr * g5² + 2 * g1² - 2*g2
	t[6] = e.fp.Add(t[6], t[6])
	// z2 = 3 * nr * g5² + 3 * g1² - 2*g2
	z.B0.A2 = *e.fp.Add(t[6], t[5])

	// t4 = nr * g2²
	t[4] = MulByNonResidue(e.fp, t[1])
	// t5 = g3² + nr * g2²
	t[5] = e.fp.Add(t[2], t[4])
	// t6 = g3² + nr * g2² - g1
	t[6] = e.fp.Sub(t[5], &x.B0.A1)
	// t6 = 2 * g3² + 2 * nr * g2² - 2 * g1
	t[6] = e.fp.Add(t[6], t[6])
	// z1 = 3 * g3² + 3 * nr * g2² - 2 * g1
	z.B0.A1 = *e.fp.Add(t[6], t[5])

	// t0 = g2² + g3²
	t[0] = e.fp.Add(t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5] = e.fp.Sub(t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6] = e.fp.Add(t[5], &x.B1.A2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6] = e.fp.Add(t[6], t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	z.B1.A2 = *e.fp.Add(t[5], t[6])

	return z
}

// DecompressKarabina Karabina's cyclotomic square result
// if g3 != 0
//   g4 = (E * g5^2 + 3 * g1^2 - 2 * g2)/4g3
// if g3 == 0
//   g4 = 2g1g5/g2
//
// if g3=g2=0 then g4=g5=g1=0 and g0=1 (x=1)
// Theorem 3.1 is well-defined for all x in Gϕₙ\{1}
func (e ext6) DecompressKarabina(x *E6) *E6 {
	var z E6

	var t [3]*baseField
	var one *baseField
	one = e.fp.One()

	// t0 = g1^2
	t[0] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	// t1 = 3 * g1^2 - 2 * g2
	t[1] = e.fp.Sub(t[0], &x.B0.A2)
	t[1] = e.fp.Add(t[1], t[1])
	t[1] = e.fp.Add(t[1], t[0])
	// t0 = E * g5^2 + t1
	t[2] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	t[0] = MulByNonResidue(e.fp, t[2])
	t[0] = e.fp.Add(t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1] = e.fp.Add(&x.B1.A0, &x.B1.A0)
	t[1] = e.fp.Add(t[1], t[1])

	// z4 = g4
	z.B1.A1 = *e.fp.Div(t[0], t[1]) // costly

	// t1 = g2 * g1
	t[1] = e.fp.Mul(&x.B0.A2, &x.B0.A1)
	// t2 = 2 * g4² - 3 * g2 * g1
	t[2] = e.fp.Mul(&x.B1.A1, &x.B1.A1)
	t[2] = e.fp.Sub(t[2], t[1])
	t[2] = e.fp.Add(t[2], t[2])
	t[2] = e.fp.Sub(t[2], t[1])
	// t1 = g3 * g5 (g3 can be 0)
	t[1] = e.fp.Mul(&x.B1.A0, &x.B1.A2)
	// c₀ = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1
	t[2] = e.fp.Add(t[2], t[1])

	z.B0.A0 = *MulByNonResidue(e.fp, t[2])
	z.B0.A0 = *e.fp.Add(&z.B0.A0, one)

	z.B0.A1 = x.B0.A1
	z.B0.A2 = x.B0.A2
	z.B1.A0 = x.B1.A0
	z.B1.A2 = x.B1.A2

	return &z
}

// Granger-Scott's cyclotomic square
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (e ext6) CyclotomicSquare(x *E6) *E6 {
	// x=(x0,x1,x2,x3,x4,x5,x6,x7) in E3⁶
	// cyclosquare(x)=(3*x4²*u + 3*x0² - 2*x0,
	//					3*x2²*u + 3*x3² - 2*x1,
	//					3*x5²*u + 3*x1² - 2*x2,
	//					6*x1*x5*u + 2*x3,
	//					6*x0*x4 + 2*x4,
	//					6*x2*x3 + 2*x5)

	var t [9]*baseField

	t[0] = e.fp.Mul(&x.B1.A1, &x.B1.A1)
	t[1] = e.fp.Mul(&x.B0.A0, &x.B0.A0)
	t[6] = e.fp.Add(&x.B1.A1, &x.B0.A0)
	t[6] = e.fp.Mul(t[6], t[6])
	t[6] = e.fp.Sub(t[6], t[0])
	t[6] = e.fp.Sub(t[6], t[1]) // 2*x4*x0
	t[2] = e.fp.Mul(&x.B0.A2, &x.B0.A2)
	t[3] = e.fp.Mul(&x.B1.A0, &x.B1.A0)
	t[7] = e.fp.Add(&x.B0.A2, &x.B1.A0)
	t[7] = e.fp.Mul(t[7], t[7])
	t[7] = e.fp.Sub(t[7], t[2])
	t[7] = e.fp.Sub(t[7], t[3]) // 2*x2*x3
	t[4] = e.fp.Mul(&x.B1.A2, &x.B1.A2)
	t[5] = e.fp.Mul(&x.B0.A1, &x.B0.A1)
	t[8] = e.fp.Add(&x.B1.A2, &x.B0.A1)
	t[8] = e.fp.Mul(t[8], t[8])
	t[8] = e.fp.Sub(t[8], t[4])
	t[8] = e.fp.Sub(t[8], t[5])
	t[8] = MulByNonResidue(e.fp, t[8]) // 2*x5*x1*u

	t[0] = MulByNonResidue(e.fp, t[0])
	t[0] = e.fp.Add(t[0], t[1]) // x4²*u + x0²
	t[2] = MulByNonResidue(e.fp, t[2])
	t[2] = e.fp.Add(t[2], t[3]) // x2²*u + x3²
	t[4] = MulByNonResidue(e.fp, t[4])
	t[4] = e.fp.Add(t[4], t[5]) // x5²*u + x1²

	var z E6
	z.B0.A0 = *e.fp.Sub(t[0], &x.B0.A0)
	z.B0.A0 = *e.fp.Add(&z.B0.A0, &z.B0.A0)
	z.B0.A0 = *e.fp.Add(&z.B0.A0, t[0])
	z.B0.A1 = *e.fp.Sub(t[2], &x.B0.A1)
	z.B0.A1 = *e.fp.Add(&z.B0.A1, &z.B0.A1)
	z.B0.A1 = *e.fp.Add(&z.B0.A1, t[2])
	z.B0.A2 = *e.fp.Sub(t[4], &x.B0.A2)
	z.B0.A2 = *e.fp.Add(&z.B0.A2, &z.B0.A2)
	z.B0.A2 = *e.fp.Add(&z.B0.A2, t[4])

	z.B1.A0 = *e.fp.Add(t[8], &x.B1.A0)
	z.B1.A0 = *e.fp.Add(&z.B1.A0, &z.B1.A0)
	z.B1.A0 = *e.fp.Add(&z.B1.A0, t[8])
	z.B1.A1 = *e.fp.Add(t[6], &x.B1.A1)
	z.B1.A1 = *e.fp.Add(&z.B1.A1, &z.B1.A1)
	z.B1.A1 = *e.fp.Add(&z.B1.A1, t[6])
	z.B1.A2 = *e.fp.Add(t[7], &x.B1.A2)
	z.B1.A2 = *e.fp.Add(&z.B1.A2, &z.B1.A2)
	z.B1.A2 = *e.fp.Add(&z.B1.A2, t[7])

	return &z
}

// Inverse set z to the inverse of x in *E6 and return z
//
// if x == 0, sets and returns z = x
func (e ext6) Inverse(x *E6) *E6 {
	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	t0 := e.ext3.Square(&x.B0)
	t1 := e.ext3.Square(&x.B1)
	tmp := e.ext3.MulByNonResidue(t1)
	t0 = e.ext3.Sub(t0, tmp)
	t1 = e.ext3.Inverse(t0)
	b0 := e.ext3.Mul(&x.B0, t1)
	b1 := e.ext3.Mul(&x.B1, t1)
	b1 = e.ext3.Neg(b1)

	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Conjugate set z to x conjugated and return z
func (e ext6) Conjugate(x *E6) *E6 {
	return &E6{
		B0: x.B0,
		B1: *e.ext3.Neg(&x.B1),
	}
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (e ext6) AssertIsEqual(a, b *E6) {
	e.ext3.AssertIsEqual(&a.B0, &b.B0)
	e.ext3.AssertIsEqual(&a.B1, &b.B1)
}

func (e ext6) Set(x *E6) *E6 {
	b0 := e.ext3.Set(&x.B0)
	b1 := e.ext3.Set(&x.B1)
	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Equal returns true if z equals x, fasle otherwise
func (e ext6) Equal(a, b *E6) {
	e.ext3.Equal(&a.B0, &b.B0)
	e.ext3.Equal(&a.B1, &b.B1)
}

func NewE6(a bw6761.E6) E6 {
	return E6{
		B0: NewE3(a.B0),
		B1: NewE3(a.B1),
	}
}
