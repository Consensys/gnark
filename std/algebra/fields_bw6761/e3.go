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
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

type E3 struct {
	A0, A1, A2 frontend.Variable
}

// SetZero sets an E3 elmt to zero
func (z *E3) SetZero() *E3 {
	z.A0 = 0
	z.A1 = 0
	z.A2 = 0
	return z
}

// SetOne sets z to 1 in Montgomery form and returns z
func (z *E3) SetOne() *E3 {
	z.A0 = 1
	z.A1 = 0
	z.A2 = 0
	return z
}

func (z *E3) assign(z1 []frontend.Variable) {
	z.A0 = z1[0]
	z.A1 = z1[1]
	z.A2 = z1[2]
}

// Neg negates the E3 number
func (z *E3) Neg(api frontend.API, x E3) *E3 {
	z.A0 = api.Sub(0, x.A0)
	z.A1 = api.Sub(0, x.A1)
	z.A2 = api.Sub(0, x.A2)
	return z
}

// Add adds two elements of E3
func (z *E3) Add(api frontend.API, x, y E3) *E3 {
	z.A0 = api.Add(x.A0, y.A0)
	z.A1 = api.Add(x.A1, y.A1)
	z.A2 = api.Add(x.A2, y.A2)
	return z
}

// Sub two elements of E3
func (z *E3) Sub(api frontend.API, x, y E3) *E3 {
	z.A0 = api.Sub(x.A0, y.A0)
	z.A1 = api.Sub(x.A1, y.A1)
	z.A2 = api.Sub(x.A2, y.A2)
	return z
}

// Double doubles an element in E3
func (z *E3) Double(api frontend.API, x E3) *E3 {
	z.A0 = api.Add(x.A0, x.A0)
	z.A1 = api.Add(x.A1, x.A1)
	z.A2 = api.Add(x.A2, x.A2)
	return z
}

func MulByNonResidue(api frontend.API, x frontend.Variable) (z frontend.Variable) {
	z = api.Add(x, x)
	z = api.Add(z, z)
	z = api.Neg(z)
	return z
}

// Conjugate conjugates an element in E3
func (z *E3) Conjugate(api frontend.API, x E3) *E3 {
	z.Set(x)
	z.A1 = api.Sub(0, z.A1)
	return z
}

// MulByElement multiplies an element in E3 by an element in fp
func (z *E3) MulByElement(api frontend.API, x E3, y frontend.Variable) *E3 {
	z.A0 = api.Mul(x.A0, y)
	z.A1 = api.Mul(x.A1, y)
	z.A2 = api.Mul(x.A2, y)
	return z
}

// MulBy01 multiplication by sparse element (c0,c1,0)
func (z *E3) MulBy01(api frontend.API, c0, c1 frontend.Variable) *E3 {

	var a, b, tmp, t0, t1, t2 frontend.Variable

	a = api.Mul(z.A0, c0)
	b = api.Mul(z.A1, c1)

	tmp = api.Add(z.A1, z.A2)
	t0 = api.Mul(c1, tmp)
	t0 = api.Sub(t0, b)
	t0 = MulByNonResidue(api, t0)
	t0 = api.Add(t0, a)

	tmp = api.Add(z.A0, z.A2)
	t2 = api.Mul(c0, tmp)
	t2 = api.Sub(t2, a)
	t2 = api.Add(t2, b)

	t1 = api.Add(c0, c1)
	tmp = api.Add(z.A0, z.A1)
	t1 = api.Mul(t1, tmp)
	t1 = api.Sub(t1, a)
	t1 = api.Sub(t1, b)

	z.A0 = t0
	z.A1 = t1
	z.A2 = t2

	return z
}

// MulBy1 multiplication of E6 by sparse element (0, c1, 0)
func (z *E3) MulBy1(api frontend.API, c1 frontend.Variable) *E3 {

	var b, tmp, t0, t1 frontend.Variable
	b = api.Mul(z.A1, c1)

	tmp = api.Add(z.A1, z.A2)
	t0 = api.Mul(c1, tmp)
	t0 = api.Sub(t0, b)
	t0 = MulByNonResidue(api, t0)

	tmp = api.Add(z.A0, z.A1)
	t1 = api.Mul(c1, tmp)
	t1 = api.Sub(t1, b)

	z.A0 = t0
	z.A1 = t1
	z.A2 = b

	return z
}

// Mul sets z to the E3-product of x,y, returns z
func (z *E3) Mul(api frontend.API, x, y E3) *E3 {
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var t0, t1, t2, c0, c1, c2, tmp frontend.Variable
	t0 = api.Mul(x.A0, y.A0)
	t1 = api.Mul(x.A1, y.A1)
	t2 = api.Mul(x.A2, y.A2)

	c0 = api.Add(x.A1, x.A2)
	tmp = api.Add(y.A1, y.A2)
	c0 = api.Mul(c0, tmp)
	c0 = api.Sub(c0, t1)
	c0 = api.Sub(c0, t2)
	c0 = MulByNonResidue(api, c0)

	tmp = api.Add(x.A0, x.A2)
	c2 = api.Add(y.A0, y.A2)
	c2 = api.Mul(c2, tmp)
	c2 = api.Sub(c2, t0)
	c2 = api.Sub(c2, t2)

	c1 = api.Add(x.A0, x.A1)
	tmp = api.Add(y.A0, y.A1)
	c1 = api.Mul(c1, tmp)
	c1 = api.Sub(c1, t0)
	c1 = api.Sub(c1, t1)
	t2 = MulByNonResidue(api, t2)

	z.A0 = api.Add(c0, t0)
	z.A1 = api.Add(c1, t2)
	z.A2 = api.Add(c2, t1)

	return z
}

// Square sets z to the E3-product of x,x, returns z
func (z *E3) Square(api frontend.API, x E3) *E3 {

	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var c4, c5, c1, c2, c3, c0, c6 frontend.Variable

	c6 = api.Add(x.A1, x.A1)
	c4 = api.Mul(x.A0, c6) // x.A0 * xA1 * 2
	c5 = api.Mul(x.A2, x.A2)
	c1 = MulByNonResidue(api, c5)
	c1 = api.Add(c1, c4)
	c2 = api.Sub(c4, c5)

	c3 = api.Mul(x.A0, x.A0)
	c4 = api.Sub(x.A0, x.A1)
	c4 = api.Add(c4, x.A2)
	c5 = api.Mul(c6, x.A2) // x.A1 * xA2 * 2
	c4 = api.Mul(c4, c4)
	c0 = MulByNonResidue(api, c5)
	c4 = api.Add(c4, c5)
	c4 = api.Sub(c4, c3)

	z.A0 = api.Add(c0, c3)
	z.A1 = c1
	z.A2 = api.Add(c2, c4)

	return z
}

var InverseE3Hint = func(_ *big.Int, inputs []*big.Int, res []*big.Int) error {
	var a, c bw6761.E3

	a.A0.SetBigInt(inputs[0])
	a.A1.SetBigInt(inputs[1])
	a.A2.SetBigInt(inputs[2])

	c.Inverse(&a)

	c.A0.ToBigIntRegular(res[0])
	c.A1.ToBigIntRegular(res[1])
	c.A2.ToBigIntRegular(res[2])

	return nil
}

func init() {
	hint.Register(InverseE3Hint)
}

// Inverse e2 elmts
func (z *E3) Inverse(api frontend.API, z1 E3) *E3 {

	res, err := api.NewHint(InverseE3Hint, 3, z1.A0, z1.A1, z1.A2)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var e3, one E3
	e3.assign(res[:3])
	one.SetOne()

	// 1 == e3 * z1
	e3.Mul(api, e3, z1)
	e3.AssertIsEqual(api, one)

	z.assign(res[:3])

	return z
}

// MulByNonResidue mul x by (0,1,0)
func (z *E3) MulByNonResidue(api frontend.API, x E3) *E3 {
	z.A2, z.A1, z.A0 = x.A1, x.A0, x.A2
	z.A0 = MulByNonResidue(api, z.A0)
	return z
}

// AssertIsEqual constraint self to be equal to other into the given constraint system
func (z *E3) AssertIsEqual(api frontend.API, other E3) {
	api.AssertIsEqual(z.A0, other.A0)
	api.AssertIsEqual(z.A1, other.A1)
	api.AssertIsEqual(z.A2, other.A2)
}

// Select sets e to r1 if b=1, r2 otherwise
func (z *E3) Select(api frontend.API, b frontend.Variable, r1, r2 E3) *E3 {

	z.A0 = api.Select(b, r1.A0, r2.A0)
	z.A1 = api.Select(b, r1.A1, r2.A1)
	z.A2 = api.Select(b, r1.A2, r2.A2)

	return z
}

func (z *E3) Set(x E3) {
	z.A2, z.A1, z.A0 = x.A1, x.A0, x.A2
}

// Equal returns true if z equals x, fasle otherwise
func (z *E3) Equal(api frontend.API, x E3) {
	api.AssertIsEqual(z.A0, x.A0)
	api.AssertIsEqual(z.A1, x.A1)
	api.AssertIsEqual(z.A2, x.A2)
}
