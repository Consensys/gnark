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

type g2AddAssign struct {
	A, B G2Jac
	C    G2Jac `gnark:",public"`
}

func (circuit *g2AddAssign) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, &circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()
	b := randomPointG2()

	// create the cs
	var circuit, witness g2AddAssign

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

type g2AddAssignAffine struct {
	A, B G2Affine
	C    G2Affine `gnark:",public"`
}

func (circuit *g2AddAssignAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls24315.G2Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g2AddAssignAffine

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

type g2DoubleAssign struct {
	A G2Jac
	C G2Jac `gnark:",public"`
}

func (circuit *g2DoubleAssign) Define(api frontend.API) error {
	expected := circuit.A
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAssignG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()

	// create the cs
	var circuit, witness g2DoubleAssign

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	a.DoubleAssign()
	witness.C.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// DoubleAndAdd affine

type g2DoubleAndAddAffine struct {
	A, B G2Affine
	C    G2Affine `gnark:",public"`
}

func (circuit *g2DoubleAndAddAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.DoubleAndAdd(api, &circuit.A, &circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAndAddAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls24315.G2Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g2DoubleAndAddAffine

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
// Double affine

type g2DoubleAffine struct {
	A G2Affine
	C G2Affine `gnark:",public"`
}

func (circuit *g2DoubleAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	var a, c bls24315.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2DoubleAffine

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Neg

type g2Neg struct {
	A G2Jac
	C G2Jac `gnark:",public"`
}

func (circuit *g2Neg) Define(api frontend.API) error {
	expected := G2Jac{}
	expected.Neg(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestNegG2(t *testing.T) {

	// sample 2 random points
	a := randomPointG2()

	// create the cs
	var circuit, witness g2Neg

	// assign the inputs
	witness.A.Assign(&a)

	// compute the result
	a.Neg(&a)
	witness.C.Assign(&a)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

// -------------------------------------------------------------------------------------------------
// Scalar multiplication

type g2constantScalarMul struct {
	A G2Affine
	C G2Affine `gnark:",public"`
	R *big.Int
}

func (circuit *g2constantScalarMul) Define(api frontend.API) error {
	expected := G2Affine{}
	expected.constScalarMul(api, circuit.A, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestConstantScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls24315.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2constantScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	br := new(big.Int)
	r.BigInt(br)
	// br is a circuit parameter
	circuit.R = br
	_a.ScalarMultiplication(&_a, br)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))

}

type g2varScalarMul struct {
	A G2Affine
	C G2Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g2varScalarMul) Define(api frontend.API) error {
	expected := G2Affine{}
	expected.varScalarMul(api, circuit.A, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestVarScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls24315.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2varScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}

type g2ScalarMul struct {
	A    G2Affine
	C    G2Affine `gnark:",public"`
	Rvar frontend.Variable
	Rcon fr.Element
}

func (circuit *g2ScalarMul) Define(api frontend.API) error {
	var expected, expected2 G2Affine
	expected.ScalarMul(api, circuit.A, circuit.Rvar)
	expected.AssertIsEqual(api, circuit.C)
	expected2.ScalarMul(api, circuit.A, circuit.Rcon)
	expected2.AssertIsEqual(api, circuit.C)
	return nil
}

func TestScalarMulG2(t *testing.T) {
	// sample random point
	_a := randomPointG2()
	var a, c bls24315.G2Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g2ScalarMul
	var r fr.Element
	_, _ = r.SetRandom()
	witness.Rvar = r.String()
	circuit.Rcon = r
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	var br big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633))
}
func randomPointG2() bls24315.G2Jac {
	_, p2, _, _ := bls24315.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p2.ScalarMultiplication(&p2, r1.BigInt(&b))
	return p2
}

// benches
func BenchmarkDoubleAffineG2(b *testing.B) {
	var c g2DoubleAffine
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkAddAssignAffineG2(b *testing.B) {
	var c g2AddAssignAffine
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkDoubleAndAddAffineG2(b *testing.B) {
	var c g2DoubleAndAddAffine
	b.Run("groth16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			ccsBench, _ = frontend.Compile(ecc.BW6_633.ScalarField(), r1cs.NewBuilder, &c)
		}

	})
	b.Log("groth16", ccsBench.GetNbConstraints())
}

func BenchmarkConstScalarMulG2(b *testing.B) {
	var c g2constantScalarMul
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

func BenchmarkVarScalarMulG2(b *testing.B) {
	var c g2varScalarMul
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
