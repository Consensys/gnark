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

import "github.com/consensys/gnark/frontend"

func (z *E6) nSquare(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		z.CyclotomicSquare(api, *z)
	}
}

func (z *E6) nSquareCompressed(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		z.CyclotomicSquareCompressed(api, *z)
	}
}

// Expt set z to x^t in E6 and return z
func (z *E6) Expt(api frontend.API, x E6) *E6 {
	// const tAbsVal uint64 = 9586122913090633729
	// tAbsVal in binary: 1000010100001000110000000000000000000000000000000000000000000001
	// drop the low 46 bits (all 0 except the least significant bit): 100001010000100011 = 136227
	// Shortest addition chains can be found at https://wwwhomes.uni-bielefeld.de/achim/addition_chain.html

	var result, x33 E6

	// a shortest addition chain for 136227
	result.Set(x)
	result.nSquare(api, 5)
	result.Mul(api, result, x)
	x33.Set(result)
	result.nSquare(api, 7)
	result.Mul(api, result, x33)
	result.nSquare(api, 4)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)

	// the remaining 46 bits
	result.nSquareCompressed(api, 46)
	result.DecompressKarabina(api, result)
	result.Mul(api, result, x)

	z.Set(result)
	return z
}

// Expc2 set z to x^c2 in E6 and return z
// ht, hy = 13, 9
// c1 = ht+hy = 22 (10110)
func (z *E6) Expc2(api frontend.API, x E6) *E6 {

	var result E6

	result.CyclotomicSquare(api, x)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)

	z.Set(result)

	return z
}

// Expc1 set z to x^c1 in E6 and return z
// ht, hy = 13, 9
// c1 = ht**2+3*hy**2 = 412 (110011100)
func (z *E6) Expc1(api frontend.API, x E6) *E6 {

	var result E6

	result.CyclotomicSquare(api, x)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.CyclotomicSquare(api, result)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.Mul(api, result, x)
	result.CyclotomicSquare(api, result)
	result.CyclotomicSquare(api, result)

	z.Set(result)

	return z
}

// MulBy034 multiplication by sparse element (c0,0,0,c3,c4,0)
func (z *E6) MulBy034(api frontend.API, c0, c3, c4 frontend.Variable) *E6 {

	var a, b, d E3

	a.MulByElement(api, z.B0, c0)

	b.Set(z.B1)
	b.MulBy01(api, c3, c4)

	c0 = api.Add(c0, c3)
	d.Add(api, z.B0, z.B1)
	d.MulBy01(api, c0, c4)

	z.B1.Add(api, a, b).Neg(api, z.B1).Add(api, z.B1, d)
	z.B0.MulByNonResidue(api, b).Add(api, z.B0, a)

	return z
}

// Mul034By034 multiplication of sparse element (c0,0,0,c3,c4,0) by sparse element (d0,0,0,d3,d4,0)
func (z *E6) Mul034By034(api frontend.API, d0, d3, d4, c0, c3, c4 frontend.Variable) *E6 {
	var tmp, x0, x3, x4, x04, x03, x34 frontend.Variable
	x0 = api.Mul(c0, d0)
	x3 = api.Mul(c3, d3)
	x4 = api.Mul(c4, d4)
	tmp = api.Add(c0, c4)
	x04 = api.Add(d0, d4)
	x04 = api.Mul(x04, tmp)
	x04 = api.Sub(x04, x0)
	x04 = api.Sub(x04, x4)
	tmp = api.Add(c0, c3)
	x03 = api.Add(d0, d3)
	x03 = api.Mul(x03, tmp)
	x03 = api.Sub(x03, x0)
	x03 = api.Sub(x03, x3)
	tmp = api.Add(c3, c4)
	x34 = api.Add(d3, d4)
	x34 = api.Mul(x34, tmp)
	x34 = api.Sub(x34, x3)
	x34 = api.Sub(x34, x4)

	z.B0.A0 = MulByNonResidue(api, x4)
	z.B0.A0 = api.Add(z.B0.A0, x0)
	z.B0.A1 = x3
	z.B0.A2 = x34
	z.B1.A0 = x03
	z.B1.A1 = x04
	z.B1.A2 = 0

	return z
}
