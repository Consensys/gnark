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

package sw_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
)

// -------------------------------------------------------------------------------------------------
// Marshalling

type MarshalScalarTest struct {
	X Scalar
	R [fr.Bytes * 8]frontend.Variable
}

func (c *MarshalScalarTest) Define(api frontend.API) error {
	ec, err := NewCurve(api)
	if err != nil {
		return err
	}
	r := ec.MarshalScalar(c.X)
	for i := range c.R {
		api.AssertIsEqual(r[i], c.R[i])
	}
	return nil
}

func TestMarshalScalar(t *testing.T) {
	assert := test.NewAssert(t)
	var r fr.Element
	r.SetRandom()
	rBytes := r.Marshal()
	var witness MarshalScalarTest
	witness.X = NewScalar(r)
	for i := 0; i < fr.Bytes; i++ {
		for j := 0; j < 8; j++ {
			witness.R[i*8+j] = (rBytes[i] >> (7 - j)) & 1
		}
	}
	var circuit MarshalScalarTest
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type MarshalG1Test struct {
	P G1Affine
	R [2 * 8 * fp.Bytes]frontend.Variable
}

func (c *MarshalG1Test) Define(api frontend.API) error {
	ec, err := NewCurve(api)
	if err != nil {
		return err
	}
	// the bits are layed out exactly as in gnark-crypto
	r := ec.MarshalG1(c.P)
	for i := range c.R {
		api.AssertIsEqual(r[i], c.R[i])
	}
	return nil
}

func TestMarshalG1(t *testing.T) {
	assert := test.NewAssert(t)

	testfn := func(r fr.Element) {
		var br big.Int
		r.BigInt(&br)
		_, _, g, _ := bls12377.Generators()
		g.ScalarMultiplication(&g, &br)
		gBytes := g.Marshal()
		var witness MarshalG1Test
		witness.P.Assign(&g)
		for i := 0; i < 96; i++ {
			for j := 0; j < 8; j++ {
				witness.R[i*8+j] = (gBytes[i] >> (7 - j)) & 1
			}
		}
		var circuit MarshalG1Test
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
	}
	assert.Run(func(assert *test.Assert) {
		// sample a random point
		var r fr.Element
		r.SetRandom()
		testfn(r)
	})
	assert.Run(func(assert *test.Assert) {
		var r fr.Element
		r.SetZero()
		testfn(r)
	})
}

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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	var a, b, c bls12377.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	_a, _, a, _ := bls12377.Generators()
	var c bls12377.G1Affine

	// create the cs
	var circuit, witness g1DoubleAffine

	// assign the inputs and compute the result
	witness.A.Assign(&a)
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	var a, b, c bls12377.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	assert.SolvingSucceeded(&g1Neg{}, &witness, test.WithCurves(ecc.BW6_761))

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
	var a, c bls12377.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1constantScalarMul
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

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
	var a, c bls12377.G1Affine
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
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
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
	var a, c bls12377.G1Affine
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
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type g1varScalarMulBase struct {
	C G1Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g1varScalarMulBase) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.ScalarMulBase(api, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestVarScalarMulBaseG1(t *testing.T) {
	var c bls12377.G1Affine
	gJac, _, _, _ := bls12377.Generators()

	// create the cs
	var circuit, witness g1varScalarMulBase
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// compute the result
	var br big.Int
	gJac.ScalarMultiplication(&gJac, r.BigInt(&br))
	c.FromJacobian(&gJac)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type MultiScalarMulTest struct {
	Points  []G1Affine
	Scalars []emulated.Element[ScalarField]
	Res     G1Affine
}

func (c *MultiScalarMulTest) Define(api frontend.API) error {
	cr, err := NewCurve(api)
	if err != nil {
		return err
	}
	ps := make([]*G1Affine, len(c.Points))
	for i := range c.Points {
		ps[i] = &c.Points[i]
	}
	ss := make([]*emulated.Element[ScalarField], len(c.Scalars))
	for i := range c.Scalars {
		ss[i] = &c.Scalars[i]
	}
	res, err := cr.MultiScalarMul(ps, ss)
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMul(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]bls12377.G1Affine, nbLen)
	S := make([]fr.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res bls12377.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G1Affine, len(P))
	for i := range cP {
		cP[i] = NewG1Affine(P[i])
	}
	cS := make([]emulated.Element[ScalarField], len(S))
	for i := range cS {
		cS[i] = NewScalar(S[i])
	}
	assignment := MultiScalarMulTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(res),
	}
	err = test.IsSolved(&MultiScalarMulTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment, ecc.BW6_761.ScalarField())
	assert.NoError(err)
}

type g1JointScalarMul struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
	R, S frontend.Variable
}

func (circuit *g1JointScalarMul) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.jointScalarMul(api, circuit.A, circuit.B, circuit.R, circuit.S)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestJointScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls12377.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1JointScalarMul
	var r, s fr.Element
	_, _ = r.SetRandom()
	_, _ = s.SetRandom()
	witness.R = r.String()
	witness.S = s.String()
	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	// compute the result
	var br, bs big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	_b.ScalarMultiplication(&_b, s.BigInt(&bs))
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type g1JointScalarMulNaive struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
	R, S frontend.Variable
}

func (circuit *g1JointScalarMulNaive) Define(api frontend.API) error {
	expected := G1Affine{}
	tmp := G1Affine{}
	tmp.varScalarMul(api, circuit.A, circuit.R)
	expected.varScalarMul(api, circuit.B, circuit.S)
	expected.AddAssign(api, tmp)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestJointScalarMulG1Naive(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c bls12377.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1JointScalarMulNaive
	var r, s fr.Element
	_, _ = r.SetRandom()
	_, _ = s.SetRandom()
	witness.R = r.String()
	witness.S = s.String()
	// assign the inputs
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	// compute the result
	var br, bs big.Int
	_a.ScalarMultiplication(&_a, r.BigInt(&br))
	_b.ScalarMultiplication(&_b, s.BigInt(&bs))
	_a.AddAssign(&_b)
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

func randomPointG1() bls12377.G1Jac {

	p1, _, _, _ := bls12377.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.BigInt(&b))

	return p1
}
