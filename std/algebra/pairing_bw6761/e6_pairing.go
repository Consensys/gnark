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

func (e ext6) nSquare(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquare(z)
	}
	return z
}

func (e ext6) nSquareCompressed(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareCompressed(z)
	}
	return z
}

// Expt set z to x^t in *E6 and return z
func (e ext6) Expt(x *E6) *E6 {
	// TODO reduce first
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
func (e ext6) Expc2(x *E6) *E6 {
	// TODO reduce first
	x = e.Reduce(x)

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
func (e ext6) Expc1(x *E6) *E6 {
	// TODO reduce first
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

// MulBy034 multiplication by sparse element (c0,0,0,c3,c4,0)
func (e ext6) MulBy034(z *E6, l *lineEvaluation) *E6 {
	// TODO reduce first
	z = e.Reduce(z)

	a := e.ext3.MulByElement(&z.B0, &l.r0)

	b := e.ext3.MulBy01(&z.B1, &l.r1, &l.r2)

	l.r0 = *e.fp.Add(&l.r0, &l.r1)
	d := e.ext3.Add(&z.B0, &z.B1)
	d = e.ext3.MulBy01(d, &l.r0, &l.r2)

	b1 := e.ext3.Add(a, b)
	b1 = e.ext3.Neg(b1)
	b1 = e.ext3.Add(b1, d)
	b0 := e.ext3.MulByNonResidue(b)
	b0 = e.ext3.Add(b0, a)

	return &E6{
		B0: *b0,
		B1: *b1,
	}
}

// Mul034By034 multiplication of sparse element (c0,0,0,c3,c4,0) by sparse element (d0,0,0,d3,d4,0)
func (e ext6) Mul034By034(d0, d3, d4, c0, c3, c4 *baseField) *E6 {
	// TODO reduce first
	//d0 = e.fp.Reduce(d0)
	//d3 = e.fp.Reduce(d3)
	//d4 = e.fp.Reduce(d4)
	//c0 = e.fp.Reduce(c0)
	//c3 = e.fp.Reduce(c3)
	//c4 = e.fp.Reduce(c4)

	x0 := e.fp.Mul(c0, d0)
	x3 := e.fp.Mul(c3, d3)
	x4 := e.fp.Mul(c4, d4)
	tmp := e.fp.Add(c0, c4)
	x04 := e.fp.Add(d0, d4)
	x04 = e.fp.Mul(x04, tmp)
	x04 = e.fp.Sub(x04, x0)
	x04 = e.fp.Sub(x04, x4)
	tmp = e.fp.Add(c0, c3)
	x03 := e.fp.Add(d0, d3)
	x03 = e.fp.Mul(x03, tmp)
	x03 = e.fp.Sub(x03, x0)
	x03 = e.fp.Sub(x03, x3)
	tmp = e.fp.Add(c3, c4)
	x34 := e.fp.Add(d3, d4)
	x34 = e.fp.Mul(x34, tmp)
	x34 = e.fp.Sub(x34, x3)
	x34 = e.fp.Sub(x34, x4)

	var z E6
	z.B0.A0 = *MulByNonResidue(e.fp, x4)
	z.B0.A0 = *e.fp.Add(&z.B0.A0, x0)
	z.B0.A1 = *x3
	z.B0.A2 = *x34
	z.B1.A0 = *x03
	z.B1.A1 = *x04
	z.B1.A2 = *e.fp.Zero()

	return &z
}
