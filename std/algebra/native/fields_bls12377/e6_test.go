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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

//--------------------------------------------------------------------
// test

type fp6Add struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Add) Define(api frontend.API) error {
	expected := E6{}
	expected.Add(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddFp6(t *testing.T) {

	var circuit, witness fp6Add

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6Sub struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Sub) Define(api frontend.API) error {
	expected := E6{}
	expected.Sub(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestSubFp6(t *testing.T) {

	var circuit, witness fp6Sub

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6Mul struct {
	A, B E6
	C    E6 `gnark:",public"`
}

func (circuit *fp6Mul) Define(api frontend.API) error {
	expected := E6{}

	expected.Mul(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulFp6(t *testing.T) {

	var circuit, witness fp6Mul

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type fp6MulByNonResidue struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6MulByNonResidue) Define(api frontend.API) error {
	expected := E6{}

	expected.MulByNonResidue(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestMulByNonResidueFp6(t *testing.T) {

	var circuit, witness fp6MulByNonResidue

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.MulByNonResidue(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type fp6Inverse struct {
	A E6
	C E6 `gnark:",public"`
}

func (circuit *fp6Inverse) Define(api frontend.API) error {
	expected := E6{}

	expected.Inverse(api, circuit.A)

	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestInverseFp6(t *testing.T) {

	var circuit, witness fp6Inverse

	// witness values
	var a, c bls12377.E6
	_, _ = a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)
	witness.C.Assign(&c)

	// cs values
	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type e6Div struct {
	A, B, C E6
}

func (circuit *e6Div) Define(api frontend.API) error {
	var expected E6

	expected.DivUnchecked(api, circuit.A, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDivFp6(t *testing.T) {

	// witness values
	var a, b, c bls12377.E6
	_, _ = a.SetRandom()
	_, _ = b.SetRandom()
	c.Inverse(&b).Mul(&c, &a)

	var witness e6Div
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&e6Div{}, &witness, test.WithCurves(ecc.BW6_761))
}

func TestMulByFp2Fp6(t *testing.T) {
	// TODO fixme
	t.Skip("missing e6.MulByE2")
	// var circuit, witness XXXX
	// r1cs, err := compiler.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// ext := getBLS377ExtensionFp6(&gnark)

	// // witness values
	// var a, c bls12377.E6
	// var b bls12377.E2
	// a.SetRandom()
	// b.SetRandom()

	// // TODO c.MulByE2(&a, &b)

	// // cs values
	// fp6a := newOperandFp6(&cs, "a")
	// fp2b := newOperandFp2(&cs, "b")
	// fp6c := NewFp6Elmt(&cs, nil, nil, nil, nil, nil, nil)
	// fp6c.MulByFp2(&cs, &fp6a, &fp2b)
	// tagFp6Elmt(&cs, fp6c, "c")

	// // assign the inputs
	// inputs := make(map[string]interface{})
	// assignOperandFp6(inputs, "a", a)
	// assignOperandFp2(inputs, "b", b)

	// // assign the exepcted values
	// expectedValues := make(map[string]*fp.Element)
	// getExpectedValuesFp6(expectedValues, "c", c)

	// r1cs := api.ToR1CS().ToR1CS(ecc.BW6_761)

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
