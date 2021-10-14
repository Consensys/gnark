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

package twistededwards

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type mustBeOnCurve struct {
	P Point
}

func (circuit *mustBeOnCurve) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	circuit.P.MustBeOnCurve(cs, params)

	return nil
}

func TestIsOnCurve(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness mustBeOnCurve

	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}

	witness.P.X.Assign(params.BaseX)
	witness.P.Y.Assign(params.BaseY)

	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}

type add struct {
	P, E Point
}

func (circuit *add) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P.AddFixedPoint(cs, &circuit.P, params.BaseX, params.BaseY, params)

	cs.AssertIsEqual(res.X, circuit.E.X)
	cs.AssertIsEqual(res.Y, circuit.E.Y)

	return nil
}

func TestAddFixedPoint(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness add

	// generate a random point, and compute expected_point = base + random_point
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var base, point, expected twistededwards.PointAffine
	base.X.SetBigInt(&params.BaseX)
	base.Y.SetBigInt(&params.BaseY)
	point.Set(&base)
	r := big.NewInt(5)
	point.ScalarMul(&point, r)
	expected.Add(&base, &point)

	// populate witness
	witness.P.X.Assign(point.X.String())
	witness.P.Y.Assign(point.Y.String())
	witness.E.X.Assign(expected.X.String())
	witness.E.Y.Assign(expected.Y.String())

	// creates r1cs
	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}

type addGeneric struct {
	P1, P2, E Point
}

func (circuit *addGeneric) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P1.AddGeneric(cs, &circuit.P1, &circuit.P2, params)

	cs.AssertIsEqual(res.X, circuit.E.X)
	cs.AssertIsEqual(res.Y, circuit.E.Y)

	return nil
}

func TestAddGeneric(t *testing.T) {

	assert := test.NewAssert(t)
	var circuit, witness addGeneric

	// generate random points, and compute expected_point = point1 + point2s
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var point1, point2, expected twistededwards.PointAffine
	point1.X.SetBigInt(&params.BaseX)
	point1.Y.SetBigInt(&params.BaseY)
	point2.Set(&point1)
	r1 := big.NewInt(5)
	r2 := big.NewInt(12)
	point1.ScalarMul(&point1, r1)
	point2.ScalarMul(&point2, r2)
	expected.Add(&point1, &point2)

	// populate witness
	witness.P1.X.Assign(point1.X.String())
	witness.P1.Y.Assign(point1.Y.String())
	witness.P2.X.Assign(point2.X.String())
	witness.P2.Y.Assign(point2.Y.String())
	witness.E.X.Assign(expected.X.String())
	witness.E.Y.Assign(expected.Y.String())

	// creates r1cs
	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}

type double struct {
	P, E Point
}

func (circuit *double) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	res := circuit.P.Double(cs, &circuit.P, params)

	cs.AssertIsEqual(res.X, circuit.E.X)
	cs.AssertIsEqual(res.Y, circuit.E.Y)

	return nil
}

func TestDouble(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness double

	// generate witness data
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var base, expected twistededwards.PointAffine
	base.X.SetBigInt(&params.BaseX)
	base.Y.SetBigInt(&params.BaseY)
	expected.Double(&base)

	// populate witness
	witness.P.X.Assign(base.X.String())
	witness.P.Y.Assign(base.Y.String())
	witness.E.X.Assign(expected.X.String())
	witness.E.Y.Assign(expected.Y.String())

	// creates r1cs
	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}

type scalarMul struct {
	P, E Point
	S    frontend.Variable
}

func (circuit *scalarMul) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	// get edwards curve params
	params, err := NewEdCurve(curveID)
	if err != nil {
		return err
	}

	resNonFixed := circuit.P.ScalarMulNonFixedBase(cs, &circuit.P, circuit.S, params)
	resFixed := circuit.P.ScalarMulFixedBase(cs, params.BaseX, params.BaseY, circuit.S, params)

	cs.AssertIsEqual(resFixed.X, circuit.E.X)
	cs.AssertIsEqual(resFixed.Y, circuit.E.Y)

	cs.AssertIsEqual(resNonFixed.X, circuit.E.X)
	cs.AssertIsEqual(resNonFixed.Y, circuit.E.Y)

	return nil
}

func TestScalarMul(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness scalarMul

	// generate witness data
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var base, expected twistededwards.PointAffine
	base.X.SetBigInt(&params.BaseX)
	base.Y.SetBigInt(&params.BaseY)
	r := big.NewInt(230928302)
	expected.ScalarMul(&base, r)

	// populate witness
	witness.P.X.Assign("5299619240641551281634865583518297030282874472190772894086521144482721001553")
	witness.P.Y.Assign("16950150798460657717958625567821834550301663161624707787222815936182638968203")
	witness.E.X.Assign(expected.X.String())
	witness.E.Y.Assign(expected.Y.String())
	witness.S.Assign(r)

	// creates r1cs
	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}

type neg struct {
	P, E Point
}

func (circuit *neg) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	circuit.P.Neg(cs, &circuit.P)
	cs.AssertIsEqual(circuit.P.X, circuit.E.X)
	cs.AssertIsEqual(circuit.P.Y, circuit.E.Y)

	return nil
}

func TestNeg(t *testing.T) {

	assert := test.NewAssert(t)

	// generate witness data
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var base, expected twistededwards.PointAffine
	base.X.SetBigInt(&params.BaseX)
	base.Y.SetBigInt(&params.BaseY)
	expected.Neg(&base)

	// generate witness
	var circuit, witness neg
	witness.P.X.Assign(base.X)
	witness.P.Y.Assign(base.Y)
	witness.E.X.Assign(expected.X)
	witness.E.Y.Assign(expected.Y)

	assert.SolvingSucceeded(&circuit, []frontend.Circuit{&witness}, test.WithCurves(ecc.BN254))

}
