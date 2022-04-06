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

package fields_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// test

type fp12Add struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Add) Define(api frontend.API) error {
	expected := E12{}
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	var circuit, witness fp12Add

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Sub struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Sub) Define(api frontend.API) error {
	expected := E12{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	var circuit, witness fp12Sub

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Mul struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Mul) Define(api frontend.API) error {
	expected := E12{}

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	var circuit, witness fp12Mul

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Square struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12Square) Define(api frontend.API) error {

	s := circuit.A.Square(api, circuit.A)
	s.AssertIsEqual(api, circuit.B)
	return nil
}

func TestSquareFp12(t *testing.T) {

	var circuit, witness fp12Square

	// witness values
	var a, b bls12377.E12
	a.SetRandom()
	b.Square(&a)

	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquare struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquare) Define(api frontend.API) error {

	var u, v E12
	u.Square(api, circuit.A)
	v.CyclotomicSquare(api, circuit.A)
	u.AssertIsEqual(api, v)
	u.AssertIsEqual(api, circuit.B)
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
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12CycloSquareCompressed struct {
	A E12
	B E12 `gnark:",public"`
}

func (circuit *fp12CycloSquareCompressed) Define(api frontend.API) error {

	var u, v E12
	u.Square(api, circuit.A)
	v.CyclotomicSquareCompressed(api, circuit.A)
	v.Decompress(api, v)
	u.AssertIsEqual(api, v)
	u.AssertIsEqual(api, circuit.B)
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
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Conjugate) Define(api frontend.API) error {
	expected := E12{}
	expected.Conjugate(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConjugateFp12(t *testing.T) {

	var circuit, witness fp12Conjugate

	// witness values
	var a, c bls12377.E12
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Frobenius struct {
	A       E12
	C, D, E E12 `gnark:",public"`
}

func (circuit *fp12Frobenius) Define(api frontend.API) error {

	fb := E12{}
	fb.Frobenius(api, circuit.A)
	fb.AssertIsEqual(api, circuit.C)

	fbSquare := E12{}
	fbSquare.FrobeniusSquare(api, circuit.A)
	fbSquare.AssertIsEqual(api, circuit.D)

	fbCube := E12{}
	fbCube.FrobeniusCube(api, circuit.A)
	fbCube.AssertIsEqual(api, circuit.E)
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

	witness.A.Assign(&a)
	witness.C.Assign(&c)
	witness.D.Assign(&d)
	witness.E.Assign(&e)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Inverse) Define(api frontend.API) error {
	expected := E12{}

	expected.Inverse(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp12(t *testing.T) {

	var circuit, witness fp12Inverse

	// witness values
	var a, c bls12377.E12
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type e12Div struct {
	A, B, C E12
}

func (circuit *e12Div) Define(api frontend.API) error {
	var expected E12

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp12(t *testing.T) {

	// witness values
	var a, b, c bls12377.E12
	a.SetRandom()
	b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e12Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e12Div{}, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12FixedExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FixedExpo) Define(api frontend.API) error {
	expected := E12{}

	expo := uint64(9586122913090633729)
	expected.Expt(api, circuit.A, expo)
	expected.AssertIsEqual(api, circuit.C)
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

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12MulBy034 struct {
	A    E12 `gnark:",public"`
	W    E12
	B, C E2
}

func (circuit *fp12MulBy034) Define(api frontend.API) error {

	circuit.A.MulBy034(api, circuit.B, circuit.C)
	circuit.A.AssertIsEqual(api, circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

	var circuit, witness fp12MulBy034

	var a bls12377.E12
	var b, c, one bls12377.E2
	one.SetOne()
	a.SetRandom()
	witness.A.Assign(&a)

	b.SetRandom()
	witness.B.Assign(&b)

	c.SetRandom()
	witness.C.Assign(&c)

	a.MulBy034(&one, &b, &c)

	witness.W.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}
