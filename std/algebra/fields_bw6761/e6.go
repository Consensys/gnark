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

package fields_bw6761

import (
	"github.com/consensys/gnark/frontend"
)

type E6 struct {
	B0, B1 E3
}

// SetOne sets z to 1 in Montgomery form and returns z
func (z *E6) SetOne() *E6 {
	z.B0.SetOne()
	z.B1.SetZero()
	return z
}

// Add set z=x+y in E6 and return z
func (z *E6) Add(api frontend.API, x, y E6) *E6 {
	z.B0.Add(api, x.B0, y.B0)
	z.B1.Add(api, x.B1, y.B1)
	return z
}

// Sub sets z to x sub y and return z
func (z *E6) Sub(api frontend.API, x, y E6) *E6 {
	z.B0.Sub(api, x.B0, y.B0)
	z.B1.Sub(api, x.B1, y.B1)
	return z
}

// Double sets z=2*x and returns z
func (z *E6) Double(api frontend.API, x E6) *E6 {
	z.B0.Double(api, x.B0)
	z.B1.Double(api, x.B1)
	return z
}

// Mul set z=x*y in E6 and return z
func (z *E6) Mul(api frontend.API, x, y E6) *E6 {
	var a, b, c E3
	a.Add(api, x.B0, x.B1)
	b.Add(api, y.B0, y.B1)
	a.Mul(api, a, b)
	b.Mul(api, x.B0, y.B0)
	c.Mul(api, x.B1, y.B1)
	z.B1.Sub(api, a, b).Sub(api, z.B1, c)
	z.B0.MulByNonResidue(api, c).Add(api, z.B0, b)
	return z
}

// Square set z=x*x in E6 and return z
func (z *E6) Square(api frontend.API, x E6) *E6 {

	//Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	var c0, c2, c3 E3
	c0.Sub(api, x.B0, x.B1)
	c3.MulByNonResidue(api, x.B1).Neg(api, c3).Add(api, x.B0, c3)
	c2.Mul(api, x.B0, x.B1)
	c0.Mul(api, c0, c3).Add(api, c0, c2)
	z.B1.Double(api, c2)
	c2.MulByNonResidue(api, c2)
	z.B0.Add(api, c0, c2)

	return z
}

// Karabina's compressed cyclotomic square
// https://eprint.iacr.org/2010/542.pdf
// Th. 3.2 with minor modifications to fit our tower
func (z *E6) CyclotomicSquareCompressed(api frontend.API, x E6) *E6 {

	var t [7]frontend.Variable

	// t0 = g1²
	t[0] = api.Mul(x.B0.A1, x.B0.A1)
	// t1 = g5²
	t[1] = api.Mul(x.B1.A2, x.B1.A2)
	// t5 = g1 + g5
	t[5] = api.Add(x.B0.A1, x.B1.A2)
	// t2 = (g1 + g5)²
	t[2] = api.Mul(t[5], t[5])

	// t3 = g1² + g5²
	t[3] = api.Add(t[0], t[1])
	// t5 = 2 * g1 * g5
	t[5] = api.Sub(t[2], t[3])

	// t6 = g3 + g2
	t[6] = api.Add(x.B1.A0, x.B0.A2)
	// t3 = (g3 + g2)²
	t[3] = api.Mul(t[6], t[6])
	// t2 = g3²
	t[2] = api.Mul(x.B1.A0, x.B1.A0)

	// t6 = 2 * nr * g1 * g5
	t[6] = MulByNonResidue(api, t[5])
	// t5 = 4 * nr * g1 * g5 + 2 * g3
	t[5] = api.Add(t[6], x.B1.A0)
	t[5] = api.Add(t[5], t[5])
	// z3 = 6 * nr * g1 * g5 + 2 * g3
	z.B1.A0 = api.Add(t[5], t[6])

	// t4 = nr * g5²
	t[4] = MulByNonResidue(api, t[1])
	// t5 = nr * g5² + g1²
	t[5] = api.Add(t[0], t[4])
	// t6 = nr * g5² + g1² - g2
	t[6] = api.Sub(t[5], x.B0.A2)

	// t1 = g2²
	t[1] = api.Mul(x.B0.A2, x.B0.A2)

	// t6 = 2 * nr * g5² + 2 * g1² - 2*g2
	t[6] = api.Add(t[6], t[6])
	// z2 = 3 * nr * g5² + 3 * g1² - 2*g2
	z.B0.A2 = api.Add(t[6], t[5])

	// t4 = nr * g2²
	t[4] = MulByNonResidue(api, t[1])
	// t5 = g3² + nr * g2²
	t[5] = api.Add(t[2], t[4])
	// t6 = g3² + nr * g2² - g1
	t[6] = api.Sub(t[5], x.B0.A1)
	// t6 = 2 * g3² + 2 * nr * g2² - 2 * g1
	t[6] = api.Add(t[6], t[6])
	// z1 = 3 * g3² + 3 * nr * g2² - 2 * g1
	z.B0.A1 = api.Add(t[6], t[5])

	// t0 = g2² + g3²
	t[0] = api.Add(t[2], t[1])
	// t5 = 2 * g3 * g2
	t[5] = api.Sub(t[3], t[0])
	// t6 = 2 * g3 * g2 + g5
	t[6] = api.Add(t[5], x.B1.A2)
	// t6 = 4 * g3 * g2 + 2 * g5
	t[6] = api.Add(t[6], t[6])
	// z5 = 6 * g3 * g2 + 2 * g5
	z.B1.A2 = api.Add(t[5], t[6])

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
func (z *E6) DecompressKarabina(api frontend.API, x E6) *E6 {

	var t [3]frontend.Variable
	var one frontend.Variable
	one = 1

	// t0 = g1^2
	t[0] = api.Mul(x.B0.A1, x.B0.A1)
	// t1 = 3 * g1^2 - 2 * g2
	t[1] = api.Sub(t[0], x.B0.A2)
	t[1] = api.Add(t[1], t[1])
	t[1] = api.Add(t[1], t[0])
	// t0 = E * g5^2 + t1
	t[2] = api.Mul(x.B1.A2, x.B1.A2)
	t[0] = MulByNonResidue(api, t[2])
	t[0] = api.Add(t[0], t[1])
	// t1 = 1/(4 * g3)
	t[1] = api.Add(x.B1.A0, x.B1.A0)
	t[1] = api.Add(t[1], t[1])

	// z4 = g4
	// TODO
	//z.B1.A1 = api.DivUnchecked(t[0], t[1]) // costly

	// t1 = g2 * g1
	t[1] = api.Mul(x.B0.A2, x.B0.A1)
	// t2 = 2 * g4² - 3 * g2 * g1
	t[2] = api.Mul(x.B1.A1, x.B1.A1)
	t[2] = api.Sub(t[2], t[1])
	t[2] = api.Add(t[2], t[2])
	t[2] = api.Sub(t[2], t[1])
	// t1 = g3 * g5 (g3 can be 0)
	t[1] = api.Mul(x.B1.A0, x.B1.A2)
	// c₀ = E * (2 * g4² + g3 * g5 - 3 * g2 * g1) + 1
	t[2] = api.Add(t[2], t[1])
	z.B0.A0 = MulByNonResidue(api, t[2])
	z.B0.A0 = api.Add(z.B0.A0, one)

	z.B0.A1 = x.B0.A1
	z.B0.A2 = x.B0.A2
	z.B1.A0 = x.B1.A0
	z.B1.A2 = x.B1.A2

	return z
}

// Granger-Scott's cyclotomic square
// https://eprint.iacr.org/2009/565.pdf, 3.2
func (z *E6) CyclotomicSquare(api frontend.API, x E6) *E6 {
	// x=(x0,x1,x2,x3,x4,x5,x6,x7) in E3⁶
	// cyclosquare(x)=(3*x4²*u + 3*x0² - 2*x0,
	//					3*x2²*u + 3*x3² - 2*x1,
	//					3*x5²*u + 3*x1² - 2*x2,
	//					6*x1*x5*u + 2*x3,
	//					6*x0*x4 + 2*x4,
	//					6*x2*x3 + 2*x5)

	var t [9]frontend.Variable

	t[0] = api.Mul(x.B1.A1, x.B1.A1)
	t[1] = api.Mul(x.B0.A0, x.B0.A0)
	t[6] = api.Add(x.B1.A1, x.B0.A0)
	t[6] = api.Mul(t[6], t[6])
	t[6] = api.Sub(t[6], t[0])
	t[6] = api.Sub(t[6], t[1]) // 2*x4*x0
	t[2] = api.Mul(x.B0.A2, x.B0.A2)
	t[3] = api.Mul(x.B1.A0, x.B1.A0)
	t[7] = api.Add(x.B0.A2, x.B1.A0)
	t[7] = api.Mul(t[7], t[7])
	t[7] = api.Sub(t[7], t[2])
	t[7] = api.Sub(t[7], t[3]) // 2*x2*x3
	t[4] = api.Mul(x.B1.A2, x.B1.A2)
	t[5] = api.Mul(x.B0.A1, x.B0.A1)
	t[8] = api.Add(x.B1.A2, x.B0.A1)
	t[8] = api.Mul(t[8], t[8])
	t[8] = api.Sub(t[8], t[4])
	t[8] = api.Sub(t[8], t[5])
	t[8] = MulByNonResidue(api, t[8]) // 2*x5*x1*u

	t[0] = MulByNonResidue(api, t[0])
	t[0] = api.Add(t[0], t[1]) // x4²*u + x0²
	t[2] = MulByNonResidue(api, t[2])
	t[2] = api.Add(t[2], t[3]) // x2²*u + x3²
	t[4] = MulByNonResidue(api, t[4])
	t[4] = api.Add(t[4], t[5]) // x5²*u + x1²

	z.B0.A0 = api.Sub(t[0], x.B0.A0)
	z.B0.A0 = api.Add(z.B0.A0, z.B0.A0)
	z.B0.A0 = api.Add(z.B0.A0, t[0])
	z.B0.A1 = api.Sub(t[2], x.B0.A1)
	z.B0.A1 = api.Add(z.B0.A1, z.B0.A1)
	z.B0.A1 = api.Add(z.B0.A1, t[2])
	z.B0.A2 = api.Sub(t[4], x.B0.A2)
	z.B0.A2 = api.Add(z.B0.A2, z.B0.A2)
	z.B0.A2 = api.Add(z.B0.A2, t[4])

	z.B1.A0 = api.Add(t[8], x.B1.A0)
	z.B1.A0 = api.Add(z.B1.A0, z.B1.A0)
	z.B1.A0 = api.Add(z.B1.A0, t[8])
	z.B1.A1 = api.Add(t[6], x.B1.A1)
	z.B1.A1 = api.Add(z.B1.A1, z.B1.A1)
	z.B1.A1 = api.Add(z.B1.A1, t[6])
	z.B1.A2 = api.Add(t[7], x.B1.A2)
	z.B1.A2 = api.Add(z.B1.A2, z.B1.A2)
	z.B1.A2 = api.Add(z.B1.A2, t[7])

	return z
}

// Inverse set z to the inverse of x in E6 and return z
//
// if x == 0, sets and returns z = x
func (z *E6) Inverse(api frontend.API, x E6) *E6 {
	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	var t0, t1, tmp E3
	t0.Square(api, x.B0)
	t1.Square(api, x.B1)
	tmp.MulByNonResidue(api, t1)
	t0.Sub(api, t0, tmp)
	t1.Inverse(api, t0)
	z.B0.Mul(api, x.B0, t1)
	z.B1.Mul(api, x.B1, t1).Neg(api, z.B1)

	return z
}

// Conjugate set z to x conjugated and return z
func (z *E6) Conjugate(api frontend.API, x E6) *E6 {
	z.Set(x)
	z.B1.Neg(api, z.B1)
	return z
}

func (z *E6) Set(x E6) {
	z.B0.Set(x.B0)
	z.B1.Set(x.B1)
}

// Equal returns true if z equals x, fasle otherwise
func (z *E6) Equal(api frontend.API, x E6) {
	z.B0.Equal(api, x.B0)
	z.B1.Equal(api, x.B1)
}
