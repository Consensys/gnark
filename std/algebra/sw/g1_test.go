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

package sw

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// -------------------------------------------------------------------------------------------------
// Add jacobian

type g1AddAssign struct {
	A, B G1Jac
	C    G1Jac `gnark:",public"`
}

func (circuit *g1AddAssign) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := circuit.A
	expected.AddAssign(cs, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestAddAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()
	b := randomPointG1()

	// create the cs
	var circuit, witness g1AddAssign
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	a.AddAssign(&b)
	witness.C.Assign(&a)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// -------------------------------------------------------------------------------------------------
// Add affine

type g1AddAssignAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddAssignAffine) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := circuit.A
	expected.AddAssign(cs, &circuit.B)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestAddAssignAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls12377.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1AddAssignAffine
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// -------------------------------------------------------------------------------------------------
// Double Jacobian

type g1DoubleAssign struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1DoubleAssign) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := circuit.A
	expected.DoubleAssign(cs)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestDoubleAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// create the cs
	var circuit, witness g1DoubleAssign
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	a.DoubleAssign()
	witness.C.Assign(&a)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// -------------------------------------------------------------------------------------------------
// Double affine

type g1DoubleAffine struct {
	A G1Affine
	C G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAffine) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := circuit.A
	expected.Double(cs, &circuit.A)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestDoubleAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1DoubleAffine
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// -------------------------------------------------------------------------------------------------
// Neg

type g1Neg struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1Neg) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := G1Jac{}
	expected.Neg(cs, &circuit.A)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestNegG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// create the cs
	var circuit, witness g1Neg
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	a.Neg(&a)
	witness.C.Assign(&a)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// -------------------------------------------------------------------------------------------------
// Scalar multiplication

type g1ScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	r fr.Element
}

func (circuit *g1ScalarMul) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	expected := G1Affine{}
	expected.ScalarMul(cs, &circuit.A, circuit.r.String(), 256)
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestScalarMulG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// random scalar
	var r fr.Element
	r.SetRandom()

	// create the cs
	var circuit, witness g1ScalarMul
	circuit.r = r
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.ToBigIntRegular(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

func randomPointG1() bls12377.G1Jac {

	p1, _, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.ToBigIntRegular(&b))

	return p1
}
