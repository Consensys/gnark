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

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377"
)

//--------------------------------------------------------------------
// test

type fp12Add struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Add) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	expected.Add(cs, &circuit.A, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestAddFp12(t *testing.T) {

	var circuit, witness fp12Add
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12Sub struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Sub) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	expected.Sub(cs, &circuit.A, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestSubFp12(t *testing.T) {

	var circuit, witness fp12Sub
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12Mul struct {
	A, B E12
	C    E12 `gnark:",public"`
}

func (circuit *fp12Mul) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expected.Mul(cs, &circuit.A, &circuit.B, ext)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulFp12(t *testing.T) {

	var circuit, witness fp12Mul
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E12
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12Conjugate struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Conjugate) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	expected.Conjugate(cs, &circuit.A)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestConjugateFp12(t *testing.T) {

	var circuit, witness fp12Conjugate
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12MulByV struct {
	A E12
	B E2
	C E12 `gnark:",public"`
}

func (circuit *fp12MulByV) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expected.MulByV(cs, &circuit.A, &circuit.B, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulByVFp12(t *testing.T) {

	var circuit, witness fp12MulByV
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	b.SetRandom()
	a.SetRandom()
	c.MulByV(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

type fp12MulByV2W struct {
	A E12
	B E2
	C E12 `gnark:",public"`
}

func (circuit *fp12MulByV2W) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expected.MulByV2W(cs, &circuit.A, &circuit.B, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulByV2WFp12(t *testing.T) {

	var circuit, witness fp12MulByV2W
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	b.SetRandom()
	a.SetRandom()
	c.MulByV2W(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

type fp12MulByVW struct {
	A E12
	B E2
	C E12 `gnark:",public"`
}

func (circuit *fp12MulByVW) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expected.MulByVW(cs, &circuit.A, &circuit.B, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulByVWFp12(t *testing.T) {

	var circuit, witness fp12MulByVW
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	var b bls377.E2
	b.SetRandom()
	a.SetRandom()
	c.MulByVW(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

type fp12Frobenius struct {
	A       E12
	C, D, E E12 `gnark:",public"`
}

func (circuit *fp12Frobenius) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	ext := GetBLS377ExtensionFp12(cs)
	fb := E12{}
	fb.Frobenius(cs, &circuit.A, ext)
	fb.MustBeEqual(cs, circuit.C)

	fbSquare := E12{}
	fbSquare.FrobeniusSquare(cs, &circuit.A, ext)
	fbSquare.MustBeEqual(cs, circuit.D)

	fbCube := E12{}
	fbCube.FrobeniusCube(cs, &circuit.A, ext)
	fbCube.MustBeEqual(cs, circuit.E)
	return nil
}

func TestFrobeniusFp12(t *testing.T) {

	var circuit, witness fp12Frobenius
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c, d, e bls377.E12
	a.SetRandom()
	c.Frobenius(&a)
	d.FrobeniusSquare(&a)
	e.FrobeniusCube(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)
	witness.D.Assign(&d)
	witness.E.Assign(&e)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12Inverse struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12Inverse) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expected.Inverse(cs, &circuit.A, ext)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestInverseFp12(t *testing.T) {

	var circuit, witness fp12Inverse
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12FixedExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FixedExpo) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expo := uint64(9586122913090633729)
	expected.FixedExponentiation(cs, &circuit.A, expo, ext)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestExpFixedExpoFp12(t *testing.T) {
	var circuit, witness fp12FixedExpo
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12
	expo := uint64(9586122913090633729)

	a.SetRandom()
	c.Exp(&a, *new(big.Int).SetUint64(expo))

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}

type fp12FinalExpo struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12FinalExpo) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E12{}
	ext := GetBLS377ExtensionFp12(cs)
	expo := uint64(9586122913090633729)
	expected.FinalExpoBLS(cs, &circuit.A, expo, ext)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestExpFinalExpoFp12(t *testing.T) {
	var circuit, witness fp12FinalExpo
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E12

	a.SetRandom()
	c = bls377.FinalExponentiation(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)
}
