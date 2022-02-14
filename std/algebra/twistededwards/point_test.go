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
	tbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	tbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	tbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	tbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type mustBeOnCurve struct {
	P Point
}

func (circuit *mustBeOnCurve) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	circuit.P.MustBeOnCurve(api, params)

	return nil
}

func TestIsOnCurve(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness mustBeOnCurve

	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}

	witness.P.X = (params.Base.X)
	witness.P.Y = (params.Base.Y)

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

}

type add struct {
	P, E Point
}

func (circuit *add) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	p := Point{}
	p.X = params.Base.X
	p.Y = params.Base.Y
	res := circuit.P.Add(api, &circuit.P, &p, params)

	api.AssertIsEqual(res.X, circuit.E.X)
	api.AssertIsEqual(res.Y, circuit.E.Y)

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
	var base, point, expected tbn254.PointAffine
	base.X.SetBigInt(&params.Base.X)
	base.Y.SetBigInt(&params.Base.Y)
	point.Set(&base)
	r := big.NewInt(5)
	point.ScalarMul(&point, r)
	expected.Add(&base, &point)

	// populate witness
	witness.P.X = (point.X.String())
	witness.P.Y = (point.Y.String())
	witness.E.X = (expected.X.String())
	witness.E.Y = (expected.Y.String())

	// creates r1cs
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

}

//-------------------------------------------------------------
// addGeneric

type addGeneric struct {
	P1, P2, E Point
}

func (circuit *addGeneric) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	res := circuit.P1.Add(api, &circuit.P1, &circuit.P2, params)

	api.AssertIsEqual(res.X, circuit.E.X)
	api.AssertIsEqual(res.Y, circuit.E.Y)

	return nil
}

func TestAddGeneric(t *testing.T) {

	assert := test.NewAssert(t)
	var circuit, witness addGeneric

	// generate witness data
	for _, id := range ecc.Implemented() {

		params, err := NewEdCurve(id)
		if err != nil {
			t.Fatal(err)
		}

		switch id {
		case ecc.BN254:
			var op1, op2, expected tbn254.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS12_381:
			var op1, op2, expected tbls12381.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS12_377:
			var op1, op2, expected tbls12377.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS24_315:
			var op1, op2, expected tbls24315.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BW6_633:
			var op1, op2, expected tbw6633.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BW6_761:
			var op1, op2, expected tbw6761.PointAffine
			op1.X.SetBigInt(&params.Base.X)
			op1.Y.SetBigInt(&params.Base.Y)
			op2.Set(&op1)
			r1 := big.NewInt(5)
			r2 := big.NewInt(12)
			op1.ScalarMul(&op1, r1)
			op2.ScalarMul(&op2, r2)
			expected.Add(&op1, &op2)
			witness.P1.X = (op1.X.String())
			witness.P1.Y = (op1.Y.String())
			witness.P2.X = (op2.X.String())
			witness.P2.Y = (op2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		}

		// creates r1cs
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
	}

}

//-------------------------------------------------------------
// Double

type double struct {
	P, E Point
}

func (circuit *double) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	res := circuit.P.Double(api, &circuit.P, params)

	api.AssertIsEqual(res.X, circuit.E.X)
	api.AssertIsEqual(res.Y, circuit.E.Y)

	return nil
}

func TestDouble(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness double

	// generate witness data
	for _, id := range ecc.Implemented() {

		params, err := NewEdCurve(id)
		if err != nil {
			t.Fatal(err)
		}

		switch id {
		case ecc.BN254:
			var base, expected tbn254.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS12_381:
			var base, expected tbls12381.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS12_377:
			var base, expected tbls12377.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BLS24_315:
			var base, expected tbls24315.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BW6_633:
			var base, expected tbw6633.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		case ecc.BW6_761:
			var base, expected tbw6761.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			expected.Double(&base)
			witness.P.X = (base.X.String())
			witness.P.Y = (base.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
		}

		// creates r1cs
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
	}

}

//-------------------------------------------------------------
// scalarMulFixed

type scalarMulFixed struct {
	E Point
	S frontend.Variable
}

func (circuit *scalarMulFixed) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	var resFixed, p Point
	p.X = params.Base.X
	p.Y = params.Base.Y
	resFixed.ScalarMul(api, &p, circuit.S, params)

	api.AssertIsEqual(resFixed.X, circuit.E.X)
	api.AssertIsEqual(resFixed.Y, circuit.E.Y)

	return nil
}

func TestScalarMulFixed(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness scalarMulFixed

	// generate witness data
	for _, id := range ecc.Implemented() {

		params, err := NewEdCurve(id)
		if err != nil {
			t.Fatal(err)
		}

		switch id {
		case ecc.BN254:
			var base, expected tbn254.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS12_381:
			var base, expected tbls12381.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS12_377:
			var base, expected tbls12377.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS24_315:
			var base, expected tbls24315.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BW6_633:
			var base, expected tbw6633.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BW6_761:
			var base, expected tbw6761.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			r := big.NewInt(928323002)
			expected.ScalarMul(&base, r)
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		}

		// creates r1cs
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
	}

}

type scalarMulGeneric struct {
	P, E Point
	S    frontend.Variable
}

func (circuit *scalarMulGeneric) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	resGeneric := circuit.P.ScalarMul(api, &circuit.P, circuit.S, params)

	api.AssertIsEqual(resGeneric.X, circuit.E.X)
	api.AssertIsEqual(resGeneric.Y, circuit.E.Y)

	return nil
}

func TestScalarMulGeneric(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness scalarMulGeneric

	// generate witness data
	for _, id := range ecc.Implemented() {

		params, err := NewEdCurve(id)
		if err != nil {
			t.Fatal(err)
		}

		switch id {
		case ecc.BN254:
			var base, point, expected tbn254.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS12_377:
			var base, point, expected tbls12377.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS12_381:
			var base, point, expected tbls12381.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BLS24_315:
			var base, point, expected tbls24315.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BW6_761:
			var base, point, expected tbw6761.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		case ecc.BW6_633:
			var base, point, expected tbw6633.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s := big.NewInt(902)
			point.ScalarMul(&base, s) // random point
			r := big.NewInt(230928302)
			expected.ScalarMul(&point, r)

			// populate witness
			witness.P.X = (point.X.String())
			witness.P.Y = (point.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S = (r)
		}

		// creates r1cs
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
	}
}

//

type doubleScalarMulGeneric struct {
	P1, P2, E Point
	S1, S2    frontend.Variable
}

func (circuit *doubleScalarMulGeneric) Define(api frontend.API) error {

	// get edwards curve params
	params, err := NewEdCurve(api.Curve())
	if err != nil {
		return err
	}

	resGeneric := circuit.P1.DoubleBaseScalarMul(api, &circuit.P1, &circuit.P2, circuit.S1, circuit.S2, params)

	api.AssertIsEqual(resGeneric.X, circuit.E.X)
	api.AssertIsEqual(resGeneric.Y, circuit.E.Y)

	return nil
}

func TestDoubleScalarMulGeneric(t *testing.T) {

	assert := test.NewAssert(t)

	var circuit, witness doubleScalarMulGeneric

	// generate witness data
	for _, id := range ecc.Implemented() {

		params, err := NewEdCurve(id)
		if err != nil {
			t.Fatal(err)
		}

		switch id {
		case ecc.BN254:
			var base, point1, point2, tmp, expected tbn254.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		case ecc.BLS12_377:
			var base, point1, point2, tmp, expected tbls12377.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		case ecc.BLS12_381:
			var base, point1, point2, tmp, expected tbls12381.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		case ecc.BLS24_315:
			var base, point1, point2, tmp, expected tbls24315.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		case ecc.BW6_761:
			var base, point1, point2, tmp, expected tbw6761.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		case ecc.BW6_633:
			var base, point1, point2, tmp, expected tbw6633.PointAffine
			base.X.SetBigInt(&params.Base.X)
			base.Y.SetBigInt(&params.Base.Y)
			s1 := big.NewInt(902)
			s2 := big.NewInt(891)
			point1.ScalarMul(&base, s1) // random point
			point2.ScalarMul(&base, s2) // random point
			r1 := big.NewInt(230928303)
			r2 := big.NewInt(2830309)
			tmp.ScalarMul(&point1, r1)
			expected.ScalarMul(&point2, r2).
				Add(&expected, &tmp)

			// populate witness
			witness.P1.X = (point1.X.String())
			witness.P1.Y = (point1.Y.String())
			witness.P2.X = (point2.X.String())
			witness.P2.Y = (point2.Y.String())
			witness.E.X = (expected.X.String())
			witness.E.Y = (expected.Y.String())
			witness.S1 = (r1)
			witness.S2 = (r2)
		}

		// creates r1cs
		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
	}
}

type neg struct {
	P, E Point
}

func (circuit *neg) Define(api frontend.API) error {

	circuit.P.Neg(api, &circuit.P)
	api.AssertIsEqual(circuit.P.X, circuit.E.X)
	api.AssertIsEqual(circuit.P.Y, circuit.E.Y)

	return nil
}

func TestNeg(t *testing.T) {

	assert := test.NewAssert(t)

	// generate witness data
	params, err := NewEdCurve(ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	var base, expected tbn254.PointAffine
	base.X.SetBigInt(&params.Base.X)
	base.Y.SetBigInt(&params.Base.Y)
	expected.Neg(&base)

	// generate witness
	var circuit, witness neg
	witness.P.X = (base.X)
	witness.P.Y = (base.Y)
	witness.E.X = (expected.X)
	witness.E.Y = (expected.Y)

	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))

}
