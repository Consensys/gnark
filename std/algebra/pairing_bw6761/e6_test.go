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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"testing"
)

type e6Add struct {
	A, B, C E6
}

func (circuit *e6Add) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Add(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness := e6Add{
		A: NewE6(a),
		B: NewE6(b),
		C: NewE6(c),
	}

	err := test.IsSolved(&e6Add{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Sub struct {
	A, B, C E6
}

func (circuit *e6Sub) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Sub(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness := e6Sub{
		A: NewE6(a),
		B: NewE6(b),
		C: NewE6(c),
	}

	err := test.IsSolved(&e6Sub{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Double struct {
	A, B E6
}

func (circuit *e6Double) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Double(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestDoubleFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Double(&a)

	witness := e6Double{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Double{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Mul struct {
	A, B, C E6
}

func (circuit *e6Mul) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Mul(&circuit.A, &circuit.B)
	e.AssertIsEqual(&expected, &circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b, c bw6761.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness := e6Mul{
		A: NewE6(a),
		B: NewE6(b),
		C: NewE6(c),
	}

	err := test.IsSolved(&e6Mul{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Square struct {
	A, B E6
}

func (circuit *e6Square) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Square(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestSquareFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Square(&a)

	witness := e6Square{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Square{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Inverse struct {
	A, B E6
}

func (circuit *e6Inverse) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Inverse(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestInverseFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Inverse(&a)

	witness := e6Inverse{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Inverse{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6Conjugate struct {
	A, B E6
}

func (circuit *e6Conjugate) Define(api frontend.API) error {
	var expected E6
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected = *e.Conjugate(&circuit.A)
	e.AssertIsEqual(&expected, &circuit.B)
	return nil
}

func TestConjugateFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Conjugate(&a)

	witness := e6Conjugate{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6Conjugate{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6CyclotomicSquareCompressed struct {
	A, B E6
}

func (circuit *e6CyclotomicSquareCompressed) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Set(&circuit.A)
	expected = e.CyclotomicSquareCompressed(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestCyclotomicSquareCompressedFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.CyclotomicSquareCompressed(&a)

	witness := e6CyclotomicSquareCompressed{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6CyclotomicSquareCompressed{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6DecompressKarabina struct {
	A, B E6
}

func (circuit *e6DecompressKarabina) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Zero()
	expected = e.DecompressKarabina(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestDecompressKarabinaFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.DecompressKarabina(&a)

	witness := e6DecompressKarabina{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6DecompressKarabina{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}

type e6CyclotomicSquare struct {
	A, B E6
}

func (circuit *e6CyclotomicSquare) Define(api frontend.API) error {
	nfield, err := emulated.NewField[emulated.BW6761Fp](api)
	if err != nil {
		panic(err)
	}
	e := NewExt6(nfield)
	expected := e.Set(&circuit.A)
	expected = e.CyclotomicSquare(&circuit.A)
	e.AssertIsEqual(expected, &circuit.B)
	return nil
}

func TestCyclotomicSquareFp6(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var a, b bw6761.E6
	_, _ = a.SetRandom()
	b.Set(&a)
	b.CyclotomicSquare(&a)

	witness := e6CyclotomicSquare{
		A: NewE6(a),
		B: NewE6(b),
	}

	err := test.IsSolved(&e6CyclotomicSquare{}, &witness, testCurve.ScalarField())
	assert.NoError(err)
}
