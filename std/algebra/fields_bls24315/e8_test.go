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
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e8Add struct {
	A, B, C E8
}

func (circuit *e8Add) Define(api frontend.API) error {
	var expected E8
	expected.Add(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestAddFp8(t *testing.T) {

	// witness values
	var a, b, c bls24315.E8
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	var witness e8Add
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e8Add{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e8Sub struct {
	A, B, C E8
}

func (circuit *e8Sub) Define(api frontend.API) error {
	var expected E8
	expected.Sub(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestSubFp8(t *testing.T) {

	// witness values
	var a, b, c bls24315.E8
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	var witness e8Sub
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e8Sub{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e8Square struct {
	A, C E8
}

func (circuit *e8Square) Define(api frontend.API) error {
	var expected E8
	ext := Extension{uSquare: 13}
	expected.Square(api, circuit.A, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestSquareFp8(t *testing.T) {

	// witness values
	var a, c bls24315.E8
	a.SetRandom()
	c.Square(&a)

	var witness e8Square
	witness.A.Assign(&a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e8Square{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e8Mul struct {
	A, B, C E8
}

func (circuit *e8Mul) Define(api frontend.API) error {
	var expected E8
	ext := Extension{uSquare: 13}
	expected.Mul(api, circuit.A, circuit.B, ext)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestMulFp8(t *testing.T) {

	// witness values
	var a, b, c bls24315.E8
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	var witness e8Mul
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e8Mul{}, &witness, test.WithCurves(ecc.BW6_633))

}

type fp8MulByFp struct {
	A E8
	B frontend.Variable
	C E8 `gnark:",public"`
}

func (circuit *fp8MulByFp) Define(api frontend.API) error {
	expected := E8{}
	expected.MulByFp(api, circuit.A, circuit.B)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestMulByFpFp8(t *testing.T) {

	var circuit, witness fp8MulByFp

	// witness values
	var a, c bls24315.E8
	var b fp.Element
	a.SetRandom()
	b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B = (fr.Element)(b)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type fp8Conjugate struct {
	A E8
	C E8 `gnark:",public"`
}

func (circuit *fp8Conjugate) Define(api frontend.API) error {
	expected := E8{}
	expected.Conjugate(api, circuit.A)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestConjugateFp8(t *testing.T) {

	var circuit, witness fp8Conjugate

	// witness values
	var a, c bls24315.E8
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type fp8Inverse struct {
	A E8
	C E8 `gnark:",public"`
}

func (circuit *fp8Inverse) Define(api frontend.API) error {
	ext := Extension{uSquare: 13}
	expected := E8{}
	expected.Inverse(api, circuit.A, ext)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestInverseFp8(t *testing.T) {

	var circuit, witness fp8Inverse

	// witness values
	var a, c bls24315.E8
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}
