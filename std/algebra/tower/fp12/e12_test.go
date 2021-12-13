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

package fp12

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/tower/fp2"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// test

type fp12Add struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Add) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Add(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	var circuit, witness fp12Add

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Sub struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Sub) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Sub(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	var circuit, witness fp12Sub

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Mul struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Mul) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Mul(circuit.A, circuit.B)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	var circuit, witness fp12Mul

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Square struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12Square) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Square(circuit.A)
	expected.MustBeEqual(circuit.B)
	return nil
}

func TestSquareFp12(t *testing.T) {

	var circuit, witness fp12Square

	// witness values
	var a, b bls12377.E12
	a.SetRandom()
	b.Square(&a)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquare struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquare) Define(api frontend.API) error {
	u, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new u: %w", err)
	}
	v, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new v: %w", err)
	}
	u.Square(circuit.A)
	v.CyclotomicSquare(circuit.A)
	u.MustBeEqual(v)
	u.MustBeEqual(circuit.B)
	return nil
}

func TestFp12CyclotomicSquare(t *testing.T) {

	var circuit, witness fp12CycloSquare

	// witness values
	var a, b bls12377.E12
	a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	var tmp bls12377.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquare(&a)
	witness.A = FromFp12(a)
	witness.B = FromFp12(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquareCompressed struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquareCompressed) Define(api frontend.API) error {
	u, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new u: %w", err)
	}
	v, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new v: %w", err)
	}
	u.Square(circuit.A)
	v.CyclotomicSquareCompressed(circuit.A)
	v.Decompress(v)
	u.MustBeEqual(v)
	u.MustBeEqual(circuit.B)
	return nil
}

func TestFp12CyclotomicSquareCompressed(t *testing.T) {

	var circuit, witness fp12CycloSquareCompressed

	// witness values
	var a, b bls12377.E12
	a.SetRandom()

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	var tmp bls12377.E12
	tmp.Conjugate(&a)
	a.Inverse(&a)
	tmp.Mul(&tmp, &a)
	a.FrobeniusSquare(&tmp).Mul(&a, &tmp)

	b.CyclotomicSquareCompressed(&a)
	b.Decompress(&b)
	witness.A = FromFp12(a)
	witness.B = FromFp12(b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Conjugate) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Conjugate(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestConjugateFp12(t *testing.T) {

	var circuit, witness fp12Conjugate

	// witness values
	var a, c bls12377.E12
	a.SetRandom()
	c.Conjugate(&a)

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Frobenius struct {
	A       E12
	C, D, E E12 `gnark:",public"`
}

func (circuit *fp12Frobenius) Define(api frontend.API) error {
	fb, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new fb: %w", err)
	}
	fb.Frobenius(circuit.A)
	fb.MustBeEqual(circuit.C)

	fbSquare, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new fb: %w", err)
	}
	fbSquare.FrobeniusSquare(circuit.A)
	fbSquare.MustBeEqual(circuit.D)

	fbCube, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new fb: %w", err)
	}
	fbCube.FrobeniusCube(circuit.A)
	fbCube.MustBeEqual(circuit.E)
	return nil
}

func TestFrobeniusFp12(t *testing.T) {

	var circuit, witness fp12Frobenius

	// witness values
	var a, c, d, e bls12377.E12
	a.SetRandom()
	c.Frobenius(&a)
	d.FrobeniusSquare(&a)
	e.FrobeniusCube(&a)

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)
	witness.D = FromFp12(d)
	witness.E = FromFp12(e)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Inverse) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Inverse(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestInverseFp12(t *testing.T) {

	var circuit, witness fp12Inverse

	// witness values
	var a, c bls12377.E12
	a.SetRandom()
	c.Inverse(&a)

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12FixedExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FixedExpo) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expo := uint64(9586122913090633729)
	expected.Expt(circuit.A, expo)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestExpFixedExpoFp12(t *testing.T) {
	var circuit, witness fp12FixedExpo

	// witness values
	var a, b, c bls12377.E12
	expo := uint64(9586122913090633729)

	// put a in the cyclotomic subgroup (we assume the group is Fp12, field of definition of bls277)
	a.SetRandom()
	b.Conjugate(&a)
	a.Inverse(&a)
	b.Mul(&b, &a)
	a.FrobeniusSquare(&b).Mul(&a, &b)

	c.Exp(&a, *new(big.Int).SetUint64(expo))

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12FinalExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FinalExpo) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expo := uint64(9586122913090633729)
	expected.FinalExponentiation(circuit.A, expo)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestExpFinalExpoFp12(t *testing.T) {
	var circuit, witness fp12FinalExpo

	// witness values
	var a, c bls12377.E12

	a.SetRandom()
	c = bls12377.FinalExponentiation(&a)

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12MulBy034 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C fp2.E2
}

func (circuit *fp12MulBy034) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.Set(circuit.A)
	expected.MulBy034(circuit.B, circuit.C)
	expected.MustBeEqual(circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

	var circuit, witness fp12MulBy034

	var a bls12377.E12
	var b, c, one bls12377.E2
	one.SetOne()
	a.SetRandom()
	witness.A = FromFp12(a)
	// witness.A.Assign([2][3][2]interface{}{
	// 	{{a.C0.B0.A0, a.C0.B0.A1}, {a.C0.B1.A0, a.C0.B1.A1}, {a.C0.B2.A0, a.C0.B2.A1}},
	// 	{{a.C1.B0.A0, a.C1.B0.A1}, {a.C1.B1.A0, a.C1.B1.A1}, {a.C1.B2.A0, a.C1.B2.A1}},
	// })

	b.SetRandom()
	witness.B = fp2.From(b)

	c.SetRandom()
	witness.C = fp2.From(c)

	a.MulBy034(&one, &b, &c)

	witness.W = FromFp12(a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}
