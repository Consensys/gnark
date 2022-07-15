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

package sw_bls24315

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"

	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
)

// -------------------------------------------------------------------------------------------------
// Add jacobian

type g1AddAssign struct {
	A, B G1Jac
	C    G1Jac `gnark:",public"`
}

func (circuit *g1AddAssign) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()
	b := randomPointG1()

	// create the cs
	var circuit, witness g1AddAssign

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	a.AddAssign(&b)
	witness.C.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Add affine

type g1AddAssignAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddAssignAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls24315.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1AddAssignAffine

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Double Jacobian

type g1DoubleAssign struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1DoubleAssign) Define(api frontend.API) error {
	expected := circuit.A
	expected.DoubleAssign(api)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAssignG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// create the cs
	var circuit, witness g1DoubleAssign

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	a.DoubleAssign()
	witness.C.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Double affine

type g1DoubleAffine struct {
	A G1Affine
	C G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAffineG1(t *testing.T) {

	// sample 2 random points
	_a, _, a, _ := bls24315.Generators()
	var c bls24315.G1Affine

	// create the cs
	var circuit, witness g1DoubleAffine

	// assign the inputs and compute the result
	witness.A.Assign(&a)
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// DoubleAndAdd affine

type g1DoubleAndAddAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAndAddAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.DoubleAndAdd(api, &circuit.A, &circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAndAddAffineG1(t *testing.T) {

	// sample 2 random points
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls24315.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1DoubleAndAddAffine

	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)

	// compute the result
	_a.Double(&_a).AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Neg

type g1Neg struct {
	A G1Jac
	C G1Jac `gnark:",public"`
}

func (circuit *g1Neg) Define(api frontend.API) error {
	expected := G1Jac{}
	expected.Neg(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestNegG1(t *testing.T) {

	// sample 2 random points
	a := randomPointG1()

	// assign the inputs
	var witness g1Neg
	witness.A.Assign(&a)
	a.Neg(&a)
	witness.C.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&g1Neg{}, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Scalar multiplication

type g1constantScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	R *big.Int
}

func (circuit *g1constantScalarMul) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.constScalarMul(api, circuit.A, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConstantScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls24315.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1constantScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	br := new(big.Int)
	r.ToBigIntRegular(br)
	// br is a circuit parameter
	circuit.R = br
	_a.ScalarMul(&_a, br)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type g1varScalarMul struct {
	A G1Affine
	C G1Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g1varScalarMul) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.varScalarMul(api, circuit.A, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestVarScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls24315.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1varScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMul(&_a, r.ToBigIntRegular(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type g1ScalarMul struct {
	A    G1Affine
	C    G1Affine `gnark:",public"`
	Rvar frontend.Variable
	Rcon fr.Element
}

func (circuit *g1ScalarMul) Define(api frontend.API) error {
	var expected, expected2 G1Affine
	expected.ScalarMul(api, circuit.A, circuit.Rvar)
	expected.AssertIsEqual(api, circuit.C)
	expected2.ScalarMul(api, circuit.A, circuit.Rcon)
	expected2.AssertIsEqual(api, circuit.C)
	return nil
}

func TestScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c bls24315.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1ScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.Rvar = r.String()
	circuit.Rcon = r
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMul(&_a, r.ToBigIntRegular(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

func randomPointG1() bls24315.G1Jac {

	p1, _, _, _ := bls24315.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p1.ScalarMul(&p1, r1.ToBigIntRegular(&b))

	return p1
}

var ccsBench frontend.CompiledConstraintSystem

func BenchmarkConstScalarMulG1(b *testing.B) {
	var c g1constantScalarMul
	// this is q - 1
	r, ok := new(big.Int).SetString("660539884262666720468348340822774968888139573360124440321458176", 10)
	if !ok {
		b.Fatal("invalid integer")
	}
	c.R = r
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		var err error
		for i := 0; i < b.N; i++ {
			ccsBench, err = frontend.Compile(ecc.BW6_633.ScalarField(), scs.NewBuilder, &c)
			if err != nil {
				b.Fatal(err)
			}
		}

	})
	b.Log("plonk", ccsBench.GetNbConstraints())

}

func BenchmarkVarScalarMulG1(b *testing.B) {
	var c g1varScalarMul
	// this is q - 1
	r, ok := new(big.Int).SetString("660539884262666720468348340822774968888139573360124440321458176", 10)
	if !ok {
		b.Fatal("invalid integer")
	}
	c.R = r
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
	b.Run("plonk", func(b *testing.B) {
		var err error
		for i := 0; i < b.N; i++ {
			ccsBench, err = frontend.Compile(ecc.BW6_633.ScalarField(), scs.NewBuilder, &c)
			if err != nil {
				b.Fatal(err)
			}
		}

	})
	b.Log("plonk", ccsBench.GetNbConstraints())

}
