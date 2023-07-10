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

package fields_bw6761

type LineEvaluation struct {
	R0 baseEl
	R1 baseEl
	R2 baseEl
}

func (e Ext6) nSquare(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquare(z)
	}
	return z
}

func (e Ext6) nSquareCompressed(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z)
	}
	return z
}

// Expt set z to x^t in *E6 and return z
func (e Ext6) Expt(x *E6) *E6 {
	x = e.Reduce(x)

	// const tAbsVal uint64 = 9586122913090633729
	// tAbsVal in binary: 1000010100001000110000000000000000000000000000000000000000000001
	// drop the low 46 bits (all 0 except the least significant bit): 100001010000100011 = 136227
	// Shortest addition chains can be found at https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html

	// a shortest addition chain for 136227
	result := e.Set(x)
	result = e.nSquare(result, 5)
	result = e.Mul(result, x)
	x33 := e.Set(result)
	result = e.nSquare(result, 7)
	result = e.Mul(result, x33)
	result = e.nSquare(result, 4)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)

	// the remaining 46 bits
	result = e.nSquareCompressed(result, 46)
	result = e.DecompressKarabina(result)
	result = e.Mul(result, x)

	return e.Set(result)
}

// Expc2 set z to x^c2 in *E6 and return z
// ht, hy = 13, 9
// c1 = ht+hy = 22 (10110)
func (e Ext6) Expc2(x *E6) *E6 {

	result := e.CyclotomicSquare(x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)

	return e.Set(result)
}

// Expc1 set z to x^c1 in *E6 and return z
// ht, hy = 13, 9
// c1 = ht**2+3*hy**2 = 412 (110011100)
func (e Ext6) Expc1(x *E6) *E6 {
	x = e.Reduce(x)

	result := e.CyclotomicSquare(x)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.Mul(result, x)
	result = e.CyclotomicSquare(result)
	result = e.CyclotomicSquare(result)

	return e.Set(result)
}

// MulBy034 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: E3{A0: 1, A1: 0, A2: 0},
//		B1: E3{A0: c3, A1: c4, A2: 0},
//	}
func (e *Ext6) MulBy034(z *E6, c3, c4 *baseEl) *E6 {

	a := z.B0
	b := z.B1
	b = *e.Ext3.MulBy01(&b, c3, c4)
	c3 = e.fp.Add(e.fp.One(), c3)
	d := e.Ext3.Add(&z.B0, &z.B1)
	d = e.Ext3.MulBy01(d, c3, c4)

	zC1 := e.Ext3.Add(&a, &b)
	zC1 = e.Ext3.Neg(zC1)
	zC1 = e.Ext3.Add(zC1, d)
	zC0 := e.Ext3.MulByNonResidue(&b)
	zC0 = e.Ext3.Add(zC0, &a)

	return &E6{
		B0: *zC0,
		B1: *zC1,
	}
}

//	multiplies two E6 sparse element of the form:
//
//	E6{
//		B0: E3{A0: 1, A1: 0, A2: 0},
//		B1: E3{A0: c3, A1: c4, A2: 0},
//	}
//
// and
//
//	E6{
//		B0: E3{A0: 1, A1: 0, A2: 0},
//		B1: E3{A0: d3, A1: d4, A2: 0},
//	}
func (e *Ext6) Mul034By034(d3, d4, c3, c4 *baseEl) *[5]baseEl {
	x3 := e.fp.MulMod(c3, d3)
	x4 := e.fp.MulMod(c4, d4)
	x04 := e.fp.Add(c4, d4)
	x03 := e.fp.Add(c3, d3)
	tmp := e.fp.Add(c3, c4)
	x34 := e.fp.Add(d3, d4)
	x34 = e.fp.MulMod(x34, tmp)
	x34 = e.fp.Sub(x34, x3)
	x34 = e.fp.Sub(x34, x4)

	zC0B0 := MulByNonResidue(e.fp, x4)
	zC0B0 = e.fp.Add(zC0B0, e.fp.One())
	zC0B1 := x3
	zC0B2 := x34
	zC1B0 := x03
	zC1B1 := x04

	return &[5]baseEl{*zC0B0, *zC0B1, *zC0B2, *zC1B0, *zC1B1}
}

// MulBy01234 multiplies z by an E6 sparse element of the form
//
//	E6{
//		B0: E3{A0: c0, A1: c1, A2: c2},
//		B1: E3{A0: c3, A1: c4, A2: 0},
//	}
func (e *Ext6) MulBy01234(z *E6, x *[5]baseEl) *E6 {
	c0 := &E3{A0: x[0], A1: x[1], A2: x[2]}
	c1 := &E3{A0: x[3], A1: x[4], A2: *e.fp.Zero()}
	a := e.Ext3.Add(&z.B0, &z.B1)
	b := e.Ext3.Add(c0, c1)
	a = e.Ext3.Mul(a, b)
	b = e.Ext3.Mul(&z.B0, c0)
	c := e.Ext3.MulBy01(&z.B1, &x[3], &x[4])
	z1 := e.Ext3.Sub(a, b)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, b)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}

//	multiplies two E6 sparse element of the form:
//
//	E6{
//		B0: E3{A0: x0, A1: x1, A2: x2},
//		B1: E3{A0: x3, A1: x4, A2: 0},
//	}
//
// and
//
//	E6{
//		B0: E6{A0: 1, A1: 0, A2: 0},
//		B1: E6{A0: z3, A1: z4, A2: 0},
//	}
func (e *Ext6) Mul01234By034(x *[5]baseEl, z3, z4 *baseEl) *E6 {
	c0 := &E3{A0: x[0], A1: x[1], A2: x[2]}
	c1 := &E3{A0: x[3], A1: x[4], A2: *e.fp.Zero()}
	a := e.Ext3.Add(e.Ext3.One(), &E3{A0: *z3, A1: *z4, A2: *e.fp.Zero()})
	b := e.Ext3.Add(c0, c1)
	a = e.Ext3.Mul(a, b)
	c := e.Ext3.Mul01By01(z3, z4, &x[3], &x[4])
	z1 := e.Ext3.Sub(a, c0)
	z1 = e.Ext3.Sub(z1, c)
	z0 := e.Ext3.MulByNonResidue(c)
	z0 = e.Ext3.Add(z0, c0)
	return &E6{
		B0: *z0,
		B1: *z1,
	}
}
