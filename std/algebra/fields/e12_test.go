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

package fields

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

func (circuit *fp12Add) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	expected.Add(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
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

func (circuit *fp12Sub) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
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

func (circuit *fp12Mul) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(api)
	expected.Mul(api, circuit.A, circuit.B, ext)
	expected.MustBeEqual(api, circuit.C)
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

func (circuit *fp12Square) Define(curveID ecc.ID, api frontend.API) error {
	ext := GetBLS377ExtensionFp12(api)
	s := circuit.A.Square(api, circuit.A, ext)
	s.MustBeEqual(api, *s)
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

func (circuit *fp12CycloSquare) Define(curveID ecc.ID, api frontend.API) error {
	ext := GetBLS377ExtensionFp12(api)
	var u, v E12
	u.Square(api, circuit.A, ext)
	v.CyclotomicSquare(api, circuit.A, ext)
	u.MustBeEqual(api, v)
	u.MustBeEqual(api, circuit.B)
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

type fp12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Conjugate) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	expected.Conjugate(api, circuit.A)
	expected.MustBeEqual(api, circuit.C)
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

func (circuit *fp12Frobenius) Define(curveID ecc.ID, api frontend.API) error {
	ext := GetBLS377ExtensionFp12(api)
	fb := E12{}
	fb.Frobenius(api, circuit.A, ext)
	fb.MustBeEqual(api, circuit.C)

	fbSquare := E12{}
	fbSquare.FrobeniusSquare(api, circuit.A, ext)
	fbSquare.MustBeEqual(api, circuit.D)

	fbCube := E12{}
	fbCube.FrobeniusCube(api, circuit.A, ext)
	fbCube.MustBeEqual(api, circuit.E)
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

func (circuit *fp12Inverse) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(api)
	expected.Inverse(api, circuit.A, ext)
	expected.MustBeEqual(api, circuit.C)
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

type fp12FixedExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FixedExpo) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(api)
	expo := uint64(9586122913090633729)
	expected.FixedExponentiation(api, circuit.A, expo, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestExpFixedExpoFp12(t *testing.T) {
	var circuit, witness fp12FixedExpo

	// witness values
	var a, c bls12377.E12
	expo := uint64(9586122913090633729)

	a.SetRandom()
	c.Exp(&a, *new(big.Int).SetUint64(expo))

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12FinalExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FinalExpo) Define(curveID ecc.ID, api frontend.API) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(api)
	expo := uint64(9586122913090633729)
	expected.FinalExponentiation(api, circuit.A, expo, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestExpFinalExpoFp12(t *testing.T) {
	var circuit, witness fp12FinalExpo

	// witness values
	var a, c bls12377.E12

	a.SetRandom()
	c = bls12377.FinalExponentiation(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp12MulBy034 struct {
	A       E12 `gnark:",public"`
	W       E12
	B, C, D E2
}

func (circuit *fp12MulBy034) Define(curveID ecc.ID, api frontend.API) error {
	ext := GetBLS377ExtensionFp12(api)
	circuit.A.MulBy034(api, circuit.B, circuit.C, circuit.D, ext)
	circuit.A.MustBeEqual(api, circuit.W)
	return nil
}

func TestFp12MulBy034(t *testing.T) {

	var circuit, witness fp12MulBy034

	var a bls12377.E12
	var b, c, d bls12377.E2
	a.SetRandom()
	witness.A.Assign(&a)

	b.SetRandom()
	witness.B.Assign(&b)

	c.SetRandom()
	witness.C.Assign(&c)

	d.SetRandom()
	witness.D.Assign(&d)

	a.MulBy034(&b, &c, &d)

	witness.W.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}
