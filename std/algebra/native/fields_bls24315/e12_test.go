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

package fields_bls24315

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
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
	var a, b, c bls24315.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
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
	var a, b, c bls24315.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
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
	var a, b, c bls24315.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
}

type fp12MulBy01 struct {
	A      E12
	C0, C1 E4
	C      E12 `gnark:",public"`
}

func (circuit *fp12MulBy01) Define(api frontend.API) error {
	expected := circuit.A
	expected.MulBy01(api, circuit.C0, circuit.C1)
	expected.AssertIsEqual(api, circuit.C)

	return nil
}

func TestMulFp12By01(t *testing.T) {

	var circuit, witness fp12MulBy01
	// witness values
	var a, c bls24315.E12
	var C0, C1 bls24315.E4
	_, _ = a.SetRandom()
	_, _ = C0.SetRandom()
	_, _ = C1.SetRandom()
	c.Set(&a)
	c.MulBy01(&C0, &C1)

	witness.A.Assign(&a)
	witness.C0.Assign(&C0)
	witness.C1.Assign(&C1)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type fp12MulByNonResidue struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12MulByNonResidue) Define(api frontend.API) error {
	expected := E12{}

	expected.MulByNonResidue(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByNonResidueFp12(t *testing.T) {

	var circuit, witness fp12MulByNonResidue

	// witness values
	var a, c bls24315.E12
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

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
	var a, b, c bls24315.E12
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e12Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e12Div{}, &witness, test.WithCurves(ecc.BW6_633))
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
	var a, c bls24315.E12
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}
