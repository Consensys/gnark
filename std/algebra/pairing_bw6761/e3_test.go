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

import (
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"testing"
)

type e3Add struct {
	A, B, C E3
}

func (circuit *e3Add) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
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
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	err := test.IsSolved(&e3Add{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Sub struct {
	A, B, C E3
}

func (circuit *e3Sub) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
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
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	err := test.IsSolved(&e3Sub{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Neg struct {
	A, B E3
}

func (circuit *e3Neg) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Neg(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestNegFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Neg(&a)

	witness := e3Neg{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3Neg{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Double struct {
	A, B E3
}

func (circuit *e3Double) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Double(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestDoubleFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Double(&a)

	witness := e3Double{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3Double{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Mul struct {
	A, B, C E3
}

func (circuit *e3Mul) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
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
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
		C: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](c.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](c.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](c.A2),
		},
	}

	err := test.IsSolved(&e3Mul{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3MulByNonResidue struct {
	A, B E3
}

func (circuit *e3MulByNonResidue) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.MulByNonResidue(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestMulByNonResidueFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.MulByNonResidue(&a)

	witness := e3MulByNonResidue{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3MulByNonResidue{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3MulBy01 struct {
	A      E3
	C0, C1 baseField
	B      E3
}

func (circuit *e3MulBy01) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	circuit.A = *e.MulBy01(&circuit.A, &circuit.C0, &circuit.C1)
	e.AssertIsEqual(&circuit.A, &circuit.B)
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
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		C0: emulated.NewElement[emulated.BW6761Fp](c0),
		C1: emulated.NewElement[emulated.BW6761Fp](c1),
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3MulBy01{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Square struct {
	A, B E3
}

func (circuit *e3Square) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestSquareFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Square(&a)

	witness := e3Square{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3Square{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e3Inverse struct {
	A, B E3
}

func (circuit *e3Inverse) Define(api frontend.API) error {
	var expected E3
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt3(nfield)
	expected = *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestInverseFp3(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E3
	_, _ = a.SetRandom()
	b.Inverse(&a)

	witness := e3Inverse{
		A: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](a.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](a.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](a.A2),
		},
		B: E3{
			A0: emulated.NewElement[emulated.BW6761Fp](b.A0),
			A1: emulated.NewElement[emulated.BW6761Fp](b.A1),
			A2: emulated.NewElement[emulated.BW6761Fp](b.A2),
		},
	}

	err := test.IsSolved(&e3Inverse{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
