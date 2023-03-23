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

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type e3Add struct {
	A, B, C E3
}

func (circuit *e3Add) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestAddFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e3Add{
		A: NewE3(a),
		B: NewE3(b),
		C: NewE3(c),
	}

	err := test.IsSolved(&e3Add{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Sub struct {
	A, B, C E3
}

func (circuit *e3Sub) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestSubFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e3Sub{
		A: NewE3(a),
		B: NewE3(b),
		C: NewE3(c),
	}

	err := test.IsSolved(&e3Sub{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Neg struct {
	A, B E3
}

func (circuit *e3Neg) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Neg(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestNegFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Neg(&a)

	witness := e3Neg{
		A: NewE3(a),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3Neg{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Double struct {
	A, B E3
}

func (circuit *e3Double) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Double(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestDoubleFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Double(&a)

	witness := e3Double{
		A: NewE3(a),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3Double{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Mul struct {
	A, B, C E3
}

func (circuit *e3Mul) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(expected, &circuit.C)
	return nil
}

func TestMulFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E3
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e3Mul{
		A: NewE3(a),
		B: NewE3(b),
		C: NewE3(c),
	}

	err := test.IsSolved(&e3Mul{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3MulByNonResidue struct {
	A, B E3
}

func (circuit *e3MulByNonResidue) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestMulByNonResidueFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Set(&a)
	b.MulByNonResidue(&a)

	witness := e3MulByNonResidue{
		A: NewE3(a),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3MulByNonResidue{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3MulByElement struct {
	A E3
	Y BaseField
	B E3
}

func (circuit *e3MulByElement) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.MulByElement(&circuit.A, &circuit.Y)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestMulByElementFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	var y fp.Element
	y.SetRandom()
	b.Set(&a)
	b.MulByElement(&a, &y)

	witness := e3MulByElement{
		A: NewE3(a),
		Y: emulated.ValueOf[emulated.BW6761Fp](y),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3MulByElement{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3MulBy01 struct {
	A      E3
	C0, C1 BaseField
	B      E3
}

func (circuit *e3MulBy01) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.MulBy01(&circuit.A, &circuit.C0, &circuit.C1)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestMulBy01Fp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	var c0, c1 fp.Element
	c0.SetRandom()
	c1.SetRandom()
	b.Set(&a)
	b.MulBy01(&c0, &c1)

	witness := e3MulBy01{
		A:  NewE3(a),
		C0: emulated.ValueOf[emulated.BW6761Fp](c0),
		C1: emulated.ValueOf[emulated.BW6761Fp](c1),
		B:  NewE3(b),
	}

	err := test.IsSolved(&e3MulBy01{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Square struct {
	A, B E3
}

func (circuit *e3Square) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Square(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestSquareFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Square(&a)

	witness := e3Square{
		A: NewE3(a),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3Square{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Inverse struct {
	A, B E3
}

func (circuit *e3Inverse) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Inverse(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestInverseFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Inverse(&a)

	witness := e3Inverse{
		A: NewE3(a),
		B: NewE3(b),
	}

	// add=50605 equals=769 fromBinary=0 mul=50315 sub=558 toBinary=0
	err := test.IsSolved(&e3Inverse{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type e3Conjugate struct {
	A, B E3
}

func (circuit *e3Conjugate) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected := e.Conjugate(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestConjugateFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Conjugate(&a)

	witness := e3Conjugate{
		A: NewE3(a),
		B: NewE3(b),
	}

	err := test.IsSolved(&e3Conjugate{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
