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
	"crypto/rand"
	"math/big"
	"testing"

	tbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	tbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	tbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	tbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	tbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

var curves = []twistededwards.ID{twistededwards.BN254, twistededwards.BLS12_377, twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH, twistededwards.BW6_761, twistededwards.BW6_633, twistededwards.BLS24_315}

type mustBeOnCurve struct {
	curveID twistededwards.ID
	P       Point
}

func (circuit *mustBeOnCurve) Define(api frontend.API) error {

	// get edwards curve curve
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	curve.AssertIsOnCurve(circuit.P)

	return nil
}

func TestIsOnCurve(t *testing.T) {

	assert := test.NewAssert(t)

	for _, curve := range curves {
		var circuit, witness mustBeOnCurve
		circuit.curveID = curve

		// get matching snark curve
		snarkCurve, err := GetSnarkCurve(curve)
		assert.NoError(err)

		// get curve params
		params, err := GetCurveParams(curve)
		assert.NoError(err)

		witness.P.X = params.Base[0]
		witness.P.Y = params.Base[1]

		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))

		witness.P.X = params.Base[0]
		witness.P.Y = params.randomScalar()

		assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve))
	}

}

type addCircuit struct {
	curveID   twistededwards.ID
	P1, P2, R Point
}

func (circuit *addCircuit) Define(api frontend.API) error {

	// get edwards curve curve
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	res := curve.Add(circuit.P1, circuit.P2)

	api.AssertIsEqual(res.X, circuit.R.X)
	api.AssertIsEqual(res.Y, circuit.R.Y)

	return nil
}

func TestAddPoint(t *testing.T) {
	assert := test.NewAssert(t)
	for _, curve := range curves {
		var circuit, witness addCircuit
		circuit.curveID = curve

		if curve == twistededwards.BLS12_381_BANDERSNATCH {
			continue
		}

		// get matching snark curve
		snarkCurve, err := GetSnarkCurve(curve)
		assert.NoError(err)

		// get curve params
		params, err := GetCurveParams(curve)
		assert.NoError(err)

		witness.P1.X, witness.P1.Y, witness.P2.X, witness.P2.Y, witness.R.X, witness.R.Y = add(params, curve)

		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))

		witness.P1.Y = params.randomScalar()

		assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve))
	}

}

// add generates random test data for given curve and returns p1, p2 and r such that p1 + p2 == r
func add(params *CurveParams, curveID twistededwards.ID) (p1X, p1Y, p2X, p2Y, rX, rY frontend.Variable) {
	s1 := params.randomScalar()
	s2 := params.randomScalar()

	switch curveID {
	case twistededwards.BN254:
		var p1, p2, r tbn254.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BLS12_381:
		var p1, p2, r tbls12381.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BLS12_381_BANDERSNATCH:
		var p1, p2, r tbls12381_bandersnatch.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BLS12_377:
		var p1, p2, r tbls12377.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BLS24_315:
		var p1, p2, r tbls24315.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BW6_633:
		var p1, p2, r tbw6633.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	case twistededwards.BW6_761:
		var p1, p2, r tbw6761.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMul(&p1, s1)
		p2.ScalarMul(&p2, s2)
		r.Add(&p1, &p2)
		p1X = p1.X
		p1Y = p1.Y
		p2X = p2.X
		p2Y = p2.Y
		rX = r.X
		rY = r.Y
		return
	default:
		panic("not implemented")
	}
}

// //-------------------------------------------------------------
// // addGeneric

// type addGeneric struct {
// 	P1, P2, E JubjubPoint
// }

// func (circuit *addGeneric) Define(api frontend.API) error {

// 	// get edwards curve params
// 	params, err := NewEdCurve(api.Compiler().Curve())
// 	if err != nil {
// 		return err
// 	}

// 	res := circuit.P1.Add(api, &circuit.P1, &circuit.P2, params)

// 	api.AssertIsEqual(res.X, circuit.E.X)
// 	api.AssertIsEqual(res.Y, circuit.E.Y)

// 	return nil
// }

// func TestAddGeneric(t *testing.T) {

// 	assert := test.NewAssert(t)
// 	var circuit, witness addGeneric

// 	// generate witness data
// 	for _, id := range twistededwards.Implemented() {

// 		params, err := NewEdCurve(id)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		switch id {
// 		case twistededwards.BN254:
// 			var p1, p2, r tbn254.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS12_381:
// 			var p1, p2, r tbls12381.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS12_377:
// 			var p1, p2, r tbls12377.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS24_315:
// 			var p1, p2, r tbls24315.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BW6_633:
// 			var p1, p2, r tbw6633.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BW6_761:
// 			var p1, p2, r tbw6761.PointAffine
// 			p1.X.SetBigInt(params.Base[0])
// 			p1.Y.SetBigInt(params.Base[1])
// 			p2.Set(&p1)
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			p1.ScalarMul(&p1, s1)
// 			p2.ScalarMul(&p2, s2)
// 			r.Add(&p1, &p2)
// 			witness.P1.X = (p1.X.String())
// 			witness.P1.Y = (p1.Y.String())
// 			witness.P2.X = (p2.X.String())
// 			witness.P2.Y = (p2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		}

// 		// creates r1cs
// 		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
// 	}

// }

// //-------------------------------------------------------------
// // Double

// type double struct {
// 	P, E JubjubPoint
// }

// func (circuit *double) Define(api frontend.API) error {

// 	// get edwards curve params
// 	params, err := NewEdCurve(api.Compiler().Curve())
// 	if err != nil {
// 		return err
// 	}

// 	res := circuit.P.Double(api, &circuit.P, params)

// 	api.AssertIsEqual(res.X, circuit.E.X)
// 	api.AssertIsEqual(res.Y, circuit.E.Y)

// 	return nil
// }

// func TestDouble(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	var circuit, witness double

// 	// generate witness data
// 	for _, id := range twistededwards.Implemented() {

// 		params, err := NewEdCurve(id)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		switch id {
// 		case twistededwards.BN254:
// 			var base, r tbn254.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS12_381:
// 			var base, r tbls12381.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS12_377:
// 			var base, r tbls12377.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BLS24_315:
// 			var base, r tbls24315.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BW6_633:
// 			var base, r tbw6633.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		case twistededwards.BW6_761:
// 			var base, r tbw6761.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r.Double(&base)
// 			witness.P.X = (base.X.String())
// 			witness.P.Y = (base.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 		}

// 		// creates r1cs
// 		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
// 	}

// }

// //-------------------------------------------------------------
// // scalarMulFixed

// type scalarMulFixed struct {
// 	E JubjubPoint
// 	S frontend.Variable
// }

// func (circuit *scalarMulFixed) Define(api frontend.API) error {

// 	// get edwards curve params
// 	params, err := NewEdCurve(api.Compiler().Curve())
// 	if err != nil {
// 		return err
// 	}

// 	var resFixed, p JubjubPoint
// 	p.X = params.Base.X
// 	p.Y = params.Base.Y
// 	resFixed.ScalarMul(api, &p, circuit.S, params)

// 	api.AssertIsEqual(resFixed.X, circuit.E.X)
// 	api.AssertIsEqual(resFixed.Y, circuit.E.Y)

// 	return nil
// }

// func TestScalarMulFixed(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	var circuit, witness scalarMulFixed

// 	// generate witness data
// 	for _, id := range twistededwards.Implemented() {

// 		params, err := NewEdCurve(id)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		switch id {
// 		case twistededwards.BN254:
// 			var base, r tbn254.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS12_381:
// 			var base, r tbls12381.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS12_377:
// 			var base, r tbls12377.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS24_315:
// 			var base, r tbls24315.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BW6_633:
// 			var base, r tbw6633.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BW6_761:
// 			var base, r tbw6761.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&base, r)
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		}

// 		// creates r1cs
// 		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
// 	}

// }

// type scalarMulGeneric struct {
// 	P, E JubjubPoint
// 	S    frontend.Variable
// }

// func (circuit *scalarMulGeneric) Define(api frontend.API) error {

// 	// get edwards curve params
// 	params, err := NewEdCurve(api.Compiler().Curve())
// 	if err != nil {
// 		return err
// 	}

// 	resGeneric := circuit.P.ScalarMul(api, &circuit.P, circuit.S, params)

// 	api.AssertIsEqual(resGeneric.X, circuit.E.X)
// 	api.AssertIsEqual(resGeneric.Y, circuit.E.Y)

// 	return nil
// }

// func TestScalarMulGeneric(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	var circuit, witness scalarMulGeneric

// 	// generate witness data
// 	for _, id := range twistededwards.Implemented() {

// 		params, err := NewEdCurve(id)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		switch id {
// 		case twistededwards.BN254:
// 			var base, point, r tbn254.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS12_377:
// 			var base, point, r tbls12377.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS12_381:
// 			var base, point, r tbls12381.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BLS24_315:
// 			var base, point, r tbls24315.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BW6_761:
// 			var base, point, r tbw6761.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		case twistededwards.BW6_633:
// 			var base, point, r tbw6633.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s, _ := rand.Int(rand.Reader, &params.Order)
// 			point.ScalarMul(&base, s) // random point
// 			r, _ := rand.Int(rand.Reader, &params.Order)
// 			r.ScalarMul(&point, r)

// 			// populate witness
// 			witness.P.X = (point.X.String())
// 			witness.P.Y = (point.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S = (r)
// 		}

// 		// creates r1cs
// 		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
// 	}
// }

// //

// type doubleScalarMulGeneric struct {
// 	P1, P2, E JubjubPoint
// 	S1, S2    frontend.Variable
// }

// func (circuit *doubleScalarMulGeneric) Define(api frontend.API) error {

// 	// get edwards curve params
// 	params, err := NewEdCurve(api.Compiler().Curve())
// 	if err != nil {
// 		return err
// 	}

// 	resGeneric := circuit.P1.DoubleBaseScalarMul(api, &circuit.P1, &circuit.P2, circuit.S1, circuit.S2, params)

// 	api.AssertIsEqual(resGeneric.X, circuit.E.X)
// 	api.AssertIsEqual(resGeneric.Y, circuit.E.Y)

// 	return nil
// }

// func TestDoubleScalarMulGeneric(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	var circuit, witness doubleScalarMulGeneric

// 	// generate witness data
// 	for _, id := range twistededwards.Implemented() {

// 		params, err := NewEdCurve(id)
// 		if err != nil {
// 			t.Fatal(err)
// 		}

// 		switch id {
// 		case twistededwards.BN254:
// 			var base, point1, point2, tmp, r tbn254.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		case twistededwards.BLS12_377:
// 			var base, point1, point2, tmp, r tbls12377.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		case twistededwards.BLS12_381:
// 			var base, point1, point2, tmp, r tbls12381.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		case twistededwards.BLS24_315:
// 			var base, point1, point2, tmp, r tbls24315.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		case twistededwards.BW6_761:
// 			var base, point1, point2, tmp, r tbw6761.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		case twistededwards.BW6_633:
// 			var base, point1, point2, tmp, r tbw6633.PointAffine
// 			base.X.SetBigInt(params.Base[0])
// 			base.Y.SetBigInt(params.Base[1])
// 			s1, _ := rand.Int(rand.Reader, &params.Order)
// 			s2, _ := rand.Int(rand.Reader, &params.Order)
// 			point1.ScalarMul(&base, s1) // random point
// 			point2.ScalarMul(&base, s2) // random point
// 			r1, _ := rand.Int(rand.Reader, &params.Order)
// 			r2, _ := rand.Int(rand.Reader, &params.Order)
// 			tmp.ScalarMul(&point1, r1)
// 			r.ScalarMul(&point2, r2).
// 				Add(&r, &tmp)

// 			// populate witness
// 			witness.P1.X = (point1.X.String())
// 			witness.P1.Y = (point1.Y.String())
// 			witness.P2.X = (point2.X.String())
// 			witness.P2.Y = (point2.Y.String())
// 			witness.E.X = (r.X.String())
// 			witness.E.Y = (r.Y.String())
// 			witness.S1 = (r1)
// 			witness.S2 = (r2)
// 		}

// 		// creates r1cs
// 		assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
// 	}
// }

// type neg struct {
// 	P, E JubjubPoint
// }

// func (circuit *neg) Define(api frontend.API) error {

// 	circuit.P.Neg(api, &circuit.P)
// 	api.AssertIsEqual(circuit.P.X, circuit.E.X)
// 	api.AssertIsEqual(circuit.P.Y, circuit.E.Y)

// 	return nil
// }

// func TestNeg(t *testing.T) {

// 	assert := test.NewAssert(t)

// 	// generate witness data
// 	params, err := NewEdCurve(twistededwards.BN254)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	var base, r tbn254.PointAffine
// 	base.X.SetBigInt(params.Base[0])
// 	base.Y.SetBigInt(params.Base[1])
// 	r.Neg(&base)

// 	// generate witness
// 	var circuit, witness neg
// 	witness.P.X = (base.X)
// 	witness.P.Y = (base.Y)
// 	witness.E.X = (r.X)
// 	witness.E.Y = (r.Y)

// 	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(twistededwards.BN254))

// }

// randomScalar returns a scalar <= p.Order
func (p *CurveParams) randomScalar() *big.Int {
	r, _ := rand.Int(rand.Reader, p.Order)
	return r
}
