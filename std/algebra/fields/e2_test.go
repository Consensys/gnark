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
	"github.com/consensys/gurvy/bls377/fp"
)

type e2TestCircuit struct {
	A, B, C E2
	define  func(curveID gurvy.ID, cs *frontend.ConstraintSystem, A, B, C E2) error
}

func (circuit *e2TestCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	return circuit.define(curveID, cs, circuit.A, circuit.B, circuit.C)
}

func TestAddFp2(t *testing.T) {
	// test circuit
	circuit := e2TestCircuit{
		define: func(curveID gurvy.ID, cs *frontend.ConstraintSystem, A, B, C E2) error {
			expected := E2{}
			expected.Add(cs, &A, &B)
			expected.MustBeEqual(cs, C)
			return nil
		},
	}

	// compile it into a R1CS
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	var witness e2TestCircuit
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)

}

func TestSubFp2(t *testing.T) {
	// test circuit
	circuit := e2TestCircuit{
		define: func(curveID gurvy.ID, cs *frontend.ConstraintSystem, A, B, C E2) error {
			expected := E2{}
			expected.Sub(cs, &A, &B)
			expected.MustBeEqual(cs, C)
			return nil
		},
	}

	// compile it into a R1CS
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	var witness e2TestCircuit
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)

}

func TestMulFp2(t *testing.T) {
	// test circuit
	circuit := e2TestCircuit{
		define: func(curveID gurvy.ID, cs *frontend.ConstraintSystem, A, B, C E2) error {
			ext := Extension{uSquare: 5}
			expected := E2{}
			expected.Mul(cs, &A, &B, ext)
			expected.MustBeEqual(cs, C)
			return nil
		},
	}

	// compile it into a R1CS
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	var witness e2TestCircuit
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)
}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E2{}
	expected.MulByFp(cs, &circuit.A, circuit.B)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestMulByFpFp2(t *testing.T) {

	var circuit, witness fp2MulByFp
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E2
	var b fp.Element
	a.SetRandom()
	b.SetRandom()
	c.MulByElement(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(bls377FpTobw761fr(&b))

	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	expected := E2{}
	expected.Conjugate(cs, &circuit.A)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestConjugateFp2(t *testing.T) {

	var circuit, witness fp2Conjugate
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E2
	a.SetRandom()
	c.Conjugate(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	ext := Extension{uSquare: 5}
	expected := E2{}
	expected.Inverse(cs, &circuit.A, ext)

	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestInverseFp2(t *testing.T) {

	var circuit, witness fp2Inverse
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, c bls377.E2
	a.SetRandom()
	c.Inverse(&a)

	witness.A.Assign(&a)

	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.CorrectExecution(r1cs, &witness)

}

func TestMulByImFp2(t *testing.T) {
	// TODO fixme
	t.Skip("missing e2.MulByNonSquare")
	// ext := Extension{uSquare: 5}

	// var circuit, witness XXXX
	// r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // witness values
	// var a, c bls377.E2
	// a.SetRandom()

	// // TODO c.MulByNonSquare(&a)

	// fp2a := NewFp2Elmt(&cs, cs.SECRET_INPUT("a0"), cs.SECRET_INPUT("a1"))

	// fp2c := NewFp2Elmt(&cs, nil, nil)
	// fp2c.MulByIm(&cs, &fp2a, ext)

	// cs.Tag(fp2c.X, "c0")
	// cs.Tag(fp2c.Y, "c1")

	//
	// witness.A.A0.Assign(a.A0)
	// witness.A.A1.Assign(a.A1)

	//
	// witness.C.A0.Assign(c.A0)
	// witness.C.A1.Assign(c.A1)

}
