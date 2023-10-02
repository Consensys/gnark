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

type e4Add struct {
	A, B, C E4
}

func (circuit *e4Add) Define(api frontend.API) error {
	var expected E4
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp4(t *testing.T) {

	// witness values
	var a, b, c bls24315.E4
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	var witness e4Add
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e4Add{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e4Sub struct {
	A, B, C E4
}

func (circuit *e4Sub) Define(api frontend.API) error {
	var expected E4
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp4(t *testing.T) {

	// witness values
	var a, b, c bls24315.E4
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	var witness e4Sub
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e4Sub{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e4Square struct {
	A, C E4
}

func (circuit *e4Square) Define(api frontend.API) error {
	var expected E4

	expected.Square(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSquareFp4(t *testing.T) {

	// witness values
	var a, c bls24315.E4
	_, _ = a.SetRandom()
	c.Square(&a)

	var witness e4Square
	witness.A.Assign(&a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e4Square{}, &witness, test.WithCurves(ecc.BW6_633))

}

type e4Mul struct {
	A, B, C E4
}

func (circuit *e4Mul) Define(api frontend.API) error {
	var expected E4

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp4(t *testing.T) {

	// witness values
	var a, b, c bls24315.E4
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	var witness e4Mul
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e4Mul{}, &witness, test.WithCurves(ecc.BW6_633))

}

type fp4MulByFp struct {
	A E4
	B frontend.Variable
	C E4 `gnark:",public"`
}

func (circuit *fp4MulByFp) Define(api frontend.API) error {
	expected := E4{}
	expected.MulByFp(api, circuit.A, circuit.B)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByFpFp4(t *testing.T) {

	var circuit, witness fp4MulByFp

	// witness values
	var a, c bls24315.E4
	var b fp.Element
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B = (fr.Element)(b)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type fp4Conjugate struct {
	A E4
	C E4 `gnark:",public"`
}

func (circuit *fp4Conjugate) Define(api frontend.API) error {
	expected := E4{}
	expected.Conjugate(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConjugateFp4(t *testing.T) {

	var circuit, witness fp4Conjugate

	// witness values
	var a, c bls24315.E4
	_, _ = a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
}

type e4Div struct {
	A, B, C E4
}

func (circuit *e4Div) Define(api frontend.API) error {
	var expected E4

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp4(t *testing.T) {

	// witness values
	var a, b, c bls24315.E4
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e4Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e4Div{}, &witness, test.WithCurves(ecc.BW6_633))
}

type fp4Inverse struct {
	A E4
	C E4 `gnark:",public"`
}

func (circuit *fp4Inverse) Define(api frontend.API) error {
	var expected E4

	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp4(t *testing.T) {

	var circuit, witness fp4Inverse

	// witness values
	var a, c bls24315.E4
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}
