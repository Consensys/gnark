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

type fp2Add struct {
	A, B E2
	C    E2 `gnark:",public"`
}

func (circuit *fp2Add) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E2{}
	expected.Add(cs, &circuit.A, &circuit.B)
	expected.MUSTBE_EQ(cs, circuit.C)
	return nil
}

func TestAddFp2(t *testing.T) {

	var circuit, witness fp2Add
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Add(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)

}

type fp2Sub struct {
	A, B E2
	C    E2 `gnark:",public"`
}

func (circuit *fp2Sub) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E2{}
	expected.Sub(cs, &circuit.A, &circuit.B)
	expected.MUSTBE_EQ(cs, circuit.C)
	return nil
}

func TestSubFp2(t *testing.T) {

	var circuit, witness fp2Sub
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Sub(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)

}

type fp2Mul struct {
	A, B E2
	C    E2 `gnark:",public"`
}

func (circuit *fp2Mul) Define(curveID gurvy.ID, cs *frontend.CS) error {
	ext := Extension{uSquare: 5}
	expected := E2{}
	expected.Mul(cs, &circuit.A, &circuit.B, ext)
	expected.MUSTBE_EQ(cs, circuit.C)
	return nil
}

func TestMulFp2(t *testing.T) {

	var circuit, witness fp2Mul
	r1cs, err := frontend.Compile(gurvy.BW761, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// witness values
	var a, b, c bls377.E2
	a.SetRandom()
	b.SetRandom()
	c.Mul(&a, &b)

	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)

}

type fp2MulByFp struct {
	A E2
	B frontend.Variable
	C E2 `gnark:",public"`
}

func (circuit *fp2MulByFp) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E2{}
	expected.MulByFp(cs, &circuit.A, circuit.B)

	expected.MUSTBE_EQ(cs, circuit.C)
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
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)

}

type fp2Conjugate struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Conjugate) Define(curveID gurvy.ID, cs *frontend.CS) error {
	expected := E2{}
	expected.Conjugate(cs, &circuit.A)

	expected.MUSTBE_EQ(cs, circuit.C)
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
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)
}

type fp2Inverse struct {
	A E2
	C E2 `gnark:",public"`
}

func (circuit *fp2Inverse) Define(curveID gurvy.ID, cs *frontend.CS) error {
	ext := Extension{uSquare: 5}
	expected := E2{}
	expected.Inverse(cs, &circuit.A, ext)

	expected.MUSTBE_EQ(cs, circuit.C)
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
	assignment, err := frontend.ToAssignment(&witness)
	if err != nil {
		t.Fatal(err)
	}
	assert.CorrectExecution(r1cs, assignment, nil)

}

func TestMulByImFp2(t *testing.T) {
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
