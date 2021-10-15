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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
	"github.com/consensys/gnark/test"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// -------------------------------------------------------------------------------------------------
// Add jacobian

type g2AddAssign struct {
	A, B G2Jac
	C    G2Jac `gnark:",public"`
}

func (circuit *g2AddAssign) Define(curveID ecc.ID, cs frontend.API) error {
	expected := circuit.A
	expected.AddAssign(cs, &circuit.B, fields.GetBLS377ExtensionFp12(cs))
	expected.MustBeEqual(cs, circuit.C)
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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Add affine

type g2AddAssignAffine struct {
	A, B G2Affine
	C    G2Affine `gnark:",public"`
}

func (circuit *g2AddAssignAffine) Define(curveID ecc.ID, cs frontend.API) error {
	expected := circuit.A
	expected.AddAssign(cs, &circuit.B, fields.GetBLS377ExtensionFp12(cs))
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestAddAssignAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	_b := randomPointG2()
	var a, b, c bls12377.G2Affine
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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Double Jacobian

type g2DoubleAssign struct {
	A G2Jac
	C G2Jac `gnark:",public"`
}

func (circuit *g2DoubleAssign) Define(curveID ecc.ID, cs frontend.API) error {
	expected := circuit.A
	expected.Double(cs, &circuit.A, fields.GetBLS377ExtensionFp12(cs))
	expected.MustBeEqual(cs, circuit.C)
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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Double affine

type g2DoubleAffine struct {
	A G2Affine
	C G2Affine `gnark:",public"`
}

func (circuit *g2DoubleAffine) Define(curveID ecc.ID, cs frontend.API) error {
	expected := circuit.A
	expected.Double(cs, &circuit.A, fields.GetBLS377ExtensionFp12(cs))
	expected.MustBeEqual(cs, circuit.C)
	return nil
}

func TestDoubleAffineG2(t *testing.T) {

	// sample 2 random points
	_a := randomPointG2()
	var a, c bls12377.G2Affine
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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

// -------------------------------------------------------------------------------------------------
// Neg

type g2Neg struct {
	A G2Jac
	C G2Jac `gnark:",public"`
}

func (circuit *g2Neg) Define(curveID ecc.ID, cs frontend.API) error {
	expected := G2Jac{}
	expected.Neg(cs, &circuit.A)
	expected.MustBeEqual(cs, circuit.C)
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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

func randomPointG2() bls12377.G2Jac {
	_, p2, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	r1.SetRandom()
	p2.ScalarMultiplication(&p2, r1.ToBigIntRegular(&b))
	return p2
}
