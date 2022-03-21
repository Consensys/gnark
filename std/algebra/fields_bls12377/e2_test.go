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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type e2Add struct {
	A, B, C E2
}

func (circuit *e2Add) Define(api frontend.API) error {
	var expected E2
	expected.Add(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	var witness e2Add
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Add{}, &witness, test.WithCurves(ecc.BW6_761))

}

type e2Sub struct {
	A, B, C E2
}

func (circuit *e2Sub) Define(api frontend.API) error {
	var expected E2
	expected.Sub(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	var witness e2Sub
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Sub{}, &witness, test.WithCurves(ecc.BW6_761))

}

type e2Mul struct {
	A, B, C E2
}

func (circuit *e2Mul) Define(api frontend.API) error {
	var expected E2

	expected.Mul(api, circuit.A, circuit.B)
	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	// witness values
	var a, b, c bls12377.E2
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	var witness e2Mul
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e2Mul{}, &witness, test.WithCurves(ecc.BW6_761))

}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(api frontend.API) error {
	expected := E2{}
	expected.MulByFp(api, circuit.A, circuit.B)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestMulByFpFp2(t *testing.T) {

	var circuit, witness fp2MulByFp

	// witness values
	var a, c bls12377.E2
	var b fp.Element
	a.SetRandom()
	b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B = (fr.Element)(b)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(api frontend.API) error {
	expected := E2{}
	expected.Conjugate(api, circuit.A)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestConjugateFp2(t *testing.T) {

	var circuit, witness fp2Conjugate

	// witness values
	var a, c bls12377.E2
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(api frontend.API) error {

	expected := E2{}
	expected.Inverse(api, circuit.A)

	expected.MustBeEqual(api, circuit.C)
	return nil
}

func TestInverseFp2(t *testing.T) {

	var circuit, witness fp2Inverse

	// witness values
	var a, c bls12377.E2
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

func TestMulByNonResidueFp2(t *testing.T) {
	// TODO fixme
	t.Skip("missing e2.MulByNonSquare")
	// ext := Extension{uSquare: 5}

	// var circuit, witness XXXX
	// r1cs, err := compiler.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // witness values
	// var a, c bls12377.E2
	// a.SetRandom()

	// // TODO c.MulByNonSquare(&a)

	// fp2a := NewFp2Elmt(&cs, api.SECRET_INPUT("a0"), api.SECRET_INPUT("a1"))

	// fp2c := NewFp2Elmt(&cs, nil, nil)
	// fp2c.MulByNonResidue(&cs, &fp2a)

	// api.Tag(fp2c.X, "c0")
	// api.Tag(fp2c.Y, "c1")

	//
	// witness.A.A0 = (a.A0)
	// witness.A.A1 = (a.A1)

	//
	// witness.C.A0 = (c.A0)
	// witness.C.A1 = (c.A1)

}
