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
	tbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/twistededwards"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	tbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/test"
)

var curves = []twistededwards.ID{twistededwards.BN254, twistededwards.BLS12_377, twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH, twistededwards.BW6_761, twistededwards.BW6_633, twistededwards.BLS24_315, twistededwards.BLS24_317}

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
		var circuit, validWitness, invalidWitness mustBeOnCurve
		circuit.curveID = curve

		// get matching snark curve
		snarkField, err := GetSnarkField(curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)

		// get curve params
		params, err := GetCurveParams(curve)
		assert.NoError(err)

		// create witness
		validWitness.P.X = params.Base[0]
		validWitness.P.Y = params.Base[1]

		invalidWitness.P.X = params.Base[0]
		invalidWitness.P.Y = params.randomScalar()

		// check circuits.
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(snarkCurve))

	}

}

type addCircuit struct {
	curveID               twistededwards.ID
	P1, P2                Point
	AddResult             Point
	DoubleResult          Point
	ScalarMulResult       Point
	DoubleScalarMulResult Point
	NegResult             Point
	S1, S2                frontend.Variable
	fixedPoint            Point `gnark:"-"`
}

func (circuit *addCircuit) Define(api frontend.API) error {

	// get edwards curve curve
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	{
		// addition 2 variable points
		res := curve.Add(circuit.P1, circuit.P2)
		api.AssertIsEqual(res.X, circuit.AddResult.X)
		api.AssertIsEqual(res.Y, circuit.AddResult.Y)
	}

	{
		// addition 1 fixed + 1 variable point
		res := curve.Add(circuit.fixedPoint, circuit.P1)
		api.AssertIsEqual(res.X, circuit.AddResult.X)
		api.AssertIsEqual(res.Y, circuit.AddResult.Y)
	}

	{
		// doubling
		res := curve.Double(circuit.P1)
		api.AssertIsEqual(res.X, circuit.DoubleResult.X)
		api.AssertIsEqual(res.Y, circuit.DoubleResult.Y)
	}

	{
		// Neg
		res := curve.Neg(circuit.P2)
		api.AssertIsEqual(res.X, circuit.NegResult.X)
		api.AssertIsEqual(res.Y, circuit.NegResult.Y)
	}

	{
		// scalar mul
		res := curve.ScalarMul(circuit.P2, circuit.S2)
		api.AssertIsEqual(res.X, circuit.ScalarMulResult.X)
		api.AssertIsEqual(res.Y, circuit.ScalarMulResult.Y)
	}

	{
		// scalar mul fixed
		res := curve.ScalarMul(circuit.fixedPoint, circuit.S2)
		api.AssertIsEqual(res.X, circuit.ScalarMulResult.X)
		api.AssertIsEqual(res.Y, circuit.ScalarMulResult.Y)
	}

	{
		// double scalar mul
		res := curve.DoubleBaseScalarMul(circuit.P1, circuit.P2, circuit.S1, circuit.S2)
		api.AssertIsEqual(res.X, circuit.DoubleScalarMulResult.X)
		api.AssertIsEqual(res.Y, circuit.DoubleScalarMulResult.Y)
	}

	return nil
}

func TestCurve(t *testing.T) {
	assert := test.NewAssert(t)
	for _, curve := range curves {
		var circuit, witness addCircuit
		circuit.curveID = curve

		// get matching snark curve
		snarkField, err := GetSnarkField(curve)
		assert.NoError(err)
		snarkCurve := utils.FieldToCurve(snarkField)

		// get curve params
		params, err := GetCurveParams(curve)
		assert.NoError(err)

		witness.P1,
			witness.P2,
			witness.AddResult,
			witness.DoubleResult,
			witness.ScalarMulResult,
			witness.DoubleScalarMulResult,
			witness.NegResult,
			witness.S1, witness.S2 = testData(params, curve)

		circuit.fixedPoint = witness.P2

		invalidWitness := witness
		invalidWitness.P1.Y = params.randomScalar()

		assert.CheckCircuit(
			&circuit,

			test.WithValidAssignment(&witness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(snarkCurve),
		)
	}
}

// testData generates random test data for given curve
// returns p1, p2 and r, d such that p1 + p2 == r and p1 + p1 == d
// returns rs1, rs12, s1, s2 such that rs1 = p2 * s2 and rs12 = p1*s1 + p2 * s2
// retunrs n such that n = -p2
func testData(params *CurveParams, curveID twistededwards.ID) (
	_p1,
	_p2,
	_r,
	_d,
	_rs1,
	_rs12,
	_n Point,
	s1, s2 frontend.Variable) {
	scalar1 := params.randomScalar()
	scalar2 := params.randomScalar()

	switch curveID {
	case twistededwards.BN254:
		var p1, p2, r, d, rs1, rs12, n tbn254.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)
		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BLS12_381:
		var p1, p2, r, d, rs1, rs12, n tbls12381.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BLS12_381_BANDERSNATCH:
		var p1, p2, r, d, rs1, rs12, n tbls12381_bandersnatch.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BLS12_377:
		var p1, p2, r, d, rs1, rs12, n tbls12377.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BLS24_317:
		var p1, p2, r, d, rs1, rs12, n tbls24317.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BLS24_315:
		var p1, p2, r, d, rs1, rs12, n tbls24315.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BW6_633:
		var p1, p2, r, d, rs1, rs12, n tbw6633.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	case twistededwards.BW6_761:
		var p1, p2, r, d, rs1, rs12, n tbw6761.PointAffine
		p1.X.SetBigInt(params.Base[0])
		p1.Y.SetBigInt(params.Base[1])
		p2.Set(&p1)

		p1.ScalarMultiplication(&p1, scalar1)
		p2.ScalarMultiplication(&p2, scalar2)
		r.Add(&p1, &p2)
		d.Double(&p1)
		rs1.ScalarMultiplication(&p2, scalar2)
		rs12.ScalarMultiplication(&p1, scalar1)
		rs12.Add(&rs12, &rs1)
		n.Neg(&p2)

		return Point{p1.X, p1.Y},
			Point{p2.X, p2.Y},
			Point{r.X, r.Y},
			Point{d.X, d.Y},
			Point{rs1.X, rs1.Y},
			Point{rs12.X, rs12.Y},
			Point{n.X, n.Y},
			scalar1, scalar2

	default:
		panic("not implemented")
	}
}

// randomScalar returns a scalar <= p.Order
func (p *CurveParams) randomScalar() *big.Int {
	r, _ := rand.Int(rand.Reader, p.Order)
	return r
}
