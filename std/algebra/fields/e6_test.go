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
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377"
)

func getBLS377ExtensionFp6(cs *frontend.CS) Extension {
	res := Extension{}
	res.uSquare = 5
	res.vCube = &E2{A0: cs.Allocate(0), A1: cs.Allocate(1)}
	return res
}

//--------------------------------------------------------------------
// test

type fp6Add struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Add) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E6{}
	expected.Add(cs, &circuit.A, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	var circuit, witness fp6Add
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness, nil)
}

type fp6Sub struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Sub) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E6{}
	expected.Sub(cs, &circuit.A, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	var circuit, witness fp6Sub
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness, nil)
}

type fp6Mul struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Mul) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E6{}
	ext := getBLS377ExtensionFp6(cs)
	expected.Mul(cs, &circuit.A, &circuit.B, ext)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	var circuit, witness fp6Mul
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E6
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness, nil)
}

type fp6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6MulByNonResidue) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E6{}
	ext := getBLS377ExtensionFp6(cs)
	expected.MulByNonResidue(cs, &circuit.A, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulByNonResidueFp6(t *testing.T) {

	var circuit, witness fp6MulByNonResidue
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E6
	a.SetRandom()
	c.MulByNonResidue(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness, nil)

}

type fp6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6Inverse) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E6{}
	ext := getBLS377ExtensionFp6(cs)
	expected.Inverse(cs, &circuit.A, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestInverseFp6(t *testing.T) {

	var circuit, witness fp6Inverse
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E6
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness, nil)

}

func TestMulByFp2Fp6(t *testing.T) {
	// TODO fixme
	t.Skip("missing e6.MulByE2")
	// var circuit, witness XXXX
	// r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// ext := getBLS377ExtensionFp6(&cs)

	// // witness values
	// var a, c bls377.E6
	// var b bls377.E2
	// a.SetRandom()
	// b.SetRandom()

	// // TODO c.MulByE2(&a, &b)

	// // cs values
	// fp6a := newOperandFp6(&cs, "a")
	// fp2b := newOperandFp2(&cs, "b")
	// fp6c := NewFp6Elmt(&cs, nil, nil, nil, nil, nil, nil)
	// fp6c.MulByFp2(&cs, &fp6a, &fp2b, ext)
	// tagFp6Elmt(&cs, fp6c, "c")

	// // assign the inputs
	// inputs := make(map[string]interface{})
	// assignOperandFp6(inputs, "a", a)
	// assignOperandFp2(inputs, "b", b)

	// // assign the exepcted values
	// expectedValues := make(map[string]*fp.Element)
	// getExpectedValuesFp6(expectedValues, "c", c)

	// r1cs := cs.ToR1CS().ToR1CS(gurvy.BW761)

	// // inspect and compare the results
	// res, err := r1cs.Inspect(inputs, false)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// for k, v := range res {
	// 	var _v fp.Element
	// 	_v.SetInterface(v)
	// 	if !expectedValues[k].Equal(&_v) {
	// 		t.Fatal("error MulByFp2Fp6")
	// 	}
	// }
}
