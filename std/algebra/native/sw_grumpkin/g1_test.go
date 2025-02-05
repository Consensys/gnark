// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_grumpkin

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/grumpkin"
	"github.com/consensys/gnark-crypto/ecc/grumpkin/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

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
	var a, b, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

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
	_a, a := grumpkin.Generators()
	var c grumpkin.G1Affine

	// create the cs
	var circuit, witness g1DoubleAffine

	// assign the inputs and compute the result
	witness.A.Assign(&a)
	_a.DoubleAssign()
	c.FromJacobian(&_a)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

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
	var a, b, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

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
	var a, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

}

type g1constantScalarMulEdgeCases struct {
	A, Inf G1Affine
	R      *big.Int
}

func (circuit *g1constantScalarMulEdgeCases) Define(api frontend.API) error {
	expected1 := G1Affine{}
	expected2 := G1Affine{}
	expected1.constScalarMul(api, circuit.A, big.NewInt(0))
	expected2.constScalarMul(api, circuit.Inf, circuit.R, algopts.WithCompleteArithmetic())
	expected1.AssertIsEqual(api, circuit.Inf)
	expected2.AssertIsEqual(api, circuit.Inf)
	return nil
}

func TestConstantScalarMulG1EdgeCases(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a grumpkin.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1constantScalarMulEdgeCases
	var r fr.Element
	_, _ = r.SetRandom()
	// assign the inputs
	witness.A.Assign(&a)
	// compute the result
	br := new(big.Int)
	r.BigInt(br)
	// br is a circuit parameter
	circuit.R = br

	witness.Inf.X = 0
	witness.Inf.Y = 0

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))

}

type g1ScalarMulEdgeCases struct {
	A, Inf  G1Affine
	R, Zero frontend.Variable
}

func (circuit *g1ScalarMulEdgeCases) Define(api frontend.API) error {
	expected1 := G1Affine{}
	expected2 := G1Affine{}
	expected2.ScalarMul(api, circuit.Inf, circuit.R, algopts.WithCompleteArithmetic())
	expected1.ScalarMul(api, circuit.A, circuit.Zero, algopts.WithCompleteArithmetic())
	expected1.AssertIsEqual(api, circuit.Inf)
	expected2.AssertIsEqual(api, circuit.Inf)
	return nil
}

func TestEndoScalarMulG1EdgeCases(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a grumpkin.G1Affine
	a.FromJacobian(&_a)

	// create the cs
	var circuit, witness g1ScalarMulEdgeCases
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// assign the inputs
	witness.A.Assign(&a)
	witness.Inf.X = 0
	witness.Inf.Y = 0
	witness.Zero = 0

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
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
	var a, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

type g1ScalarMulBase struct {
	C G1Affine `gnark:",public"`
	R frontend.Variable
}

func (circuit *g1ScalarMulBase) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.ScalarMulBase(api, circuit.R)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestEndoScalarMulBaseG1(t *testing.T) {
	var c grumpkin.G1Affine
	gJac, _ := grumpkin.Generators()

	// create the cs
	var circuit, witness g1ScalarMulBase
	var r fr.Element
	_, _ = r.SetRandom()
	witness.R = r.String()
	// compute the result
	var br big.Int
	gJac.ScalarMultiplication(&gJac, r.BigInt(&br))
	c.FromJacobian(&gJac)
	witness.C.Assign(&c)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

type MultiScalarMulEdgeCasesTest struct {
	Points  []G1Affine
	Scalars []emulated.Element[ScalarField]
	Res     G1Affine
}

func (c *MultiScalarMulEdgeCasesTest) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMulEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 5
	P := make([]grumpkin.G1Affine, nbLen)
	S := make([]fr.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res, infinity grumpkin.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G1Affine, len(P))
	cS := make([]emulated.Element[ScalarField], len(S))

	// s1 * (0,0) + s2 * (0,0) + s3 * (0,0) + s4 * (0,0)  + s5 * (0,0) == (0,0)
	for i := range cP {
		cP[i] = NewG1Affine(infinity)
	}
	for i := range cS {
		cS[i] = NewScalar(S[i])
	}
	assignment1 := MultiScalarMulEdgeCasesTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(infinity),
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment1, ecc.BN254.ScalarField())
	assert.NoError(err)

	// 0 * P1 + 0 * P2 + 0 * P3 + 0 * P4 + 0 * P5 == (0,0)
	for i := range cP {
		cP[i] = NewG1Affine(P[i])
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.GRUMPKINFr](0)
	}
	assignment2 := MultiScalarMulEdgeCasesTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(infinity),
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment2, ecc.BN254.ScalarField())
	assert.NoError(err)

	// s1 * (0,0) + s2 * P2 + s3 * (0,0) + s4 * P4 + 0 * P5 == s2 * P + s4 * P4
	var res3 grumpkin.G1Affine
	res3.ScalarMultiplication(&P[1], S[1].BigInt(new(big.Int)))
	res.ScalarMultiplication(&P[3], S[3].BigInt(new(big.Int)))
	res3.Add(&res3, &res)
	for i := range cP {
		cP[i] = NewG1Affine(P[i])
	}
	cP[0].X = infinity.X
	cP[0].Y = infinity.Y
	cP[2].X = infinity.X
	cP[2].Y = infinity.Y
	for i := range cS {
		cS[i] = NewScalar(S[i])
	}
	cS[4] = emulated.ValueOf[emparams.GRUMPKINFr](0)

	assignment3 := MultiScalarMulEdgeCasesTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(res3),
	}
	err = test.IsSolved(&MultiScalarMulEdgeCasesTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment3, ecc.BN254.ScalarField())
	assert.NoError(err)
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
	P := make([]grumpkin.G1Affine, nbLen)
	S := make([]fr.Element, nbLen)
	for i := 0; i < nbLen; i++ {
		S[i].SetRandom()
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res grumpkin.G1Affine
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
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type g1JointScalarMulEdgeCases struct {
	A, B, Inf  G1Affine
	C          G1Affine `gnark:",public"`
	R, S, Zero frontend.Variable
}

func (circuit *g1JointScalarMulEdgeCases) Define(api frontend.API) error {
	expected1 := G1Affine{}
	expected2 := G1Affine{}
	expected3 := G1Affine{}
	expected4 := G1Affine{}
	expected1.jointScalarMul(api, circuit.Inf, circuit.Inf, circuit.R, circuit.S, algopts.WithCompleteArithmetic())
	expected2.jointScalarMul(api, circuit.A, circuit.B, circuit.Zero, circuit.Zero, algopts.WithCompleteArithmetic())
	expected3.jointScalarMul(api, circuit.A, circuit.Inf, circuit.R, circuit.S, algopts.WithCompleteArithmetic())
	expected4.jointScalarMul(api, circuit.A, circuit.B, circuit.R, circuit.Zero, algopts.WithCompleteArithmetic())
	_expected := G1Affine{}
	_expected.ScalarMul(api, circuit.A, circuit.R, algopts.WithCompleteArithmetic())
	expected1.AssertIsEqual(api, circuit.Inf)
	expected2.AssertIsEqual(api, circuit.Inf)
	expected3.AssertIsEqual(api, _expected)
	expected4.AssertIsEqual(api, _expected)
	return nil
}

func TestJointScalarMulG1EdgeCases(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c grumpkin.G1Affine
	a.FromJacobian(&_a)
	b.FromJacobian(&_b)

	// create the cs
	var circuit, witness g1JointScalarMulEdgeCases
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

	witness.Inf.X = 0
	witness.Inf.Y = 0
	witness.Zero = 0

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
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
	var a, b, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

type g1JointScalarMulNaive struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
	R, S frontend.Variable
}

func (circuit *g1JointScalarMulNaive) Define(api frontend.API) error {
	expected := G1Affine{}
	tmp := G1Affine{}
	tmp.ScalarMul(api, circuit.A, circuit.R)
	expected.ScalarMul(api, circuit.B, circuit.S)
	expected.AddAssign(api, tmp)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestJointScalarMulG1Naive(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	_b := randomPointG1()
	var a, b, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

type MultiScalarMulFoldedEdgeCasesTest struct {
	Points  []G1Affine
	Scalars []emulated.Element[ScalarField]
	Res     G1Affine
}

func (c *MultiScalarMulFoldedEdgeCasesTest) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithFoldingScalarMul(), algopts.WithCompleteArithmetic())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMulFoldedEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 5
	P := make([]grumpkin.G1Affine, nbLen)
	S := make([]fr.Element, nbLen)
	S[0].SetOne()
	S[1].SetRandom()
	S[2].Square(&S[1])
	S[3].Mul(&S[1], &S[2])
	S[4].Mul(&S[1], &S[3])
	for i := 0; i < nbLen; i++ {
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res, infinity grumpkin.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G1Affine, len(P))
	cS := make([]emulated.Element[ScalarField], len(S))

	// s^0 * (0,0) + s^1 * (0,0) + s^2 * (0,0) + s^3 * (0,0)  + s^4 * (0,0) == (0,0)
	for i := range cP {
		cP[i] = NewG1Affine(infinity)
	}
	// s0 = s
	S[0].Set(&S[1])
	for i := range cS {
		cS[i] = NewScalar(S[i])
	}
	assignment1 := MultiScalarMulFoldedEdgeCasesTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(infinity),
	}
	err = test.IsSolved(&MultiScalarMulFoldedEdgeCasesTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment1, ecc.BN254.ScalarField())
	assert.NoError(err)

	// 0^0 * P1 + 0 * P2 + 0 * P3 + 0 * P4 + 0 * P5 == P1
	for i := range cP {
		cP[i] = NewG1Affine(P[i])
	}
	for i := range cS {
		cS[i] = emulated.ValueOf[emparams.GRUMPKINFr](0)
	}

	assignment3 := MultiScalarMulFoldedEdgeCasesTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(P[0]),
	}
	err = test.IsSolved(&MultiScalarMulFoldedEdgeCasesTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment3, ecc.BN254.ScalarField())
	assert.NoError(err)
}

type MultiScalarMulFoldedTest struct {
	Points  []G1Affine
	Scalars []emulated.Element[ScalarField]
	Res     G1Affine
}

func (c *MultiScalarMulFoldedTest) Define(api frontend.API) error {
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
	res, err := cr.MultiScalarMul(ps, ss, algopts.WithFoldingScalarMul())
	if err != nil {
		return err
	}
	cr.AssertIsEqual(res, &c.Res)
	return nil
}

func TestMultiScalarMulFolded(t *testing.T) {
	assert := test.NewAssert(t)
	nbLen := 4
	P := make([]grumpkin.G1Affine, nbLen)
	S := make([]fr.Element, nbLen)
	// [s^0]P0 + [s^1]P1 + [s^2]P2 + [s^3]P3 = P0 + [s]P1 + [s^2]P2 + [s^3]P3
	S[0].SetOne()
	S[1].SetRandom()
	S[2].Square(&S[1])
	S[3].Mul(&S[1], &S[2])
	for i := 0; i < nbLen; i++ {
		P[i].ScalarMultiplicationBase(S[i].BigInt(new(big.Int)))
	}
	var res grumpkin.G1Affine
	_, err := res.MultiExp(P, S, ecc.MultiExpConfig{})

	assert.NoError(err)
	cP := make([]G1Affine, len(P))
	for i := range cP {
		cP[i] = NewG1Affine(P[i])
	}
	cS := make([]emulated.Element[ScalarField], len(S))
	// s0 = s
	S[0].Set(&S[1])
	for i := range cS {
		cS[i] = NewScalar(S[i])
	}
	assignment := MultiScalarMulFoldedTest{
		Points:  cP,
		Scalars: cS,
		Res:     NewG1Affine(res),
	}
	err = test.IsSolved(&MultiScalarMulFoldedTest{
		Points:  make([]G1Affine, nbLen),
		Scalars: make([]emulated.Element[ScalarField], nbLen),
	}, &assignment, ecc.BN254.ScalarField())
	assert.NoError(err)
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

func TestEndoScalarMulG1(t *testing.T) {
	// sample random point
	_a := randomPointG1()
	var a, c grumpkin.G1Affine
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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BN254))
}

func randomPointG1() grumpkin.G1Jac {

	p1, _ := grumpkin.Generators()

	var r1 fr.Element
	var b big.Int
	_, _ = r1.SetRandom()
	p1.ScalarMultiplication(&p1, r1.BigInt(&b))

	return p1
}
