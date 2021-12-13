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

package fp24

import (
	"fmt"
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
	var a, b, c bls24315.E12
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
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
	var a, b, c bls24315.E12
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
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
	var a, b, c bls24315.E12
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A = FromFp12(a)
	witness.B = FromFp12(b)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp12MulByNonResidue struct {
	A E12
	C E12 `gnark:",public"`
}

func (circuit *fp12MulByNonResidue) Define(api frontend.API) error {
	expected, err := NewFp12Zero(api)
	if err != nil {
		return fmt.Errorf("new expected: %w", err)
	}
	expected.MulByNonResidue(circuit.A)
	expected.MustBeEqual(circuit.C)
	return nil
}

func TestMulByNonResidueFp12(t *testing.T) {

	var circuit, witness fp12MulByNonResidue

	// witness values
	var a, c bls24315.E12
	a.SetRandom()
	c.MulByNonResidue(&a)
	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

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
	var a, c bls24315.E12
	a.SetRandom()
	c.Inverse(&a)

	witness.A = FromFp12(a)
	witness.C = FromFp12(c)

	// cs values
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}
