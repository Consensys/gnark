// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package twistededwards

import (
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	tbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	tbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	tbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	tbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/test"
)

var curves = []twistededwards.ID{twistededwards.BN254, twistededwards.BLS12_377, twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH, twistededwards.BW6_761}

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

		invalidWitness.P = offCurvePoint()

		// check circuits.
		assert.CheckCircuit(&circuit,
			test.WithValidAssignment(&validWitness),
			test.WithInvalidAssignment(&invalidWitness),
			test.WithCurves(snarkCurve))

	}

}

func assertPointEqual(api frontend.API, actual, expected Point) {
	api.AssertIsEqual(actual.X, expected.X)
	api.AssertIsEqual(actual.Y, expected.Y)
}

type addCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	Result  Point
}

func (circuit *addCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Add(circuit.P1, circuit.P2), circuit.Result)
	return nil
}

type addFixedCircuit struct {
	curveID    twistededwards.ID
	P          Point
	Result     Point
	fixedPoint Point `gnark:"-"`
}

func (circuit *addFixedCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Add(circuit.fixedPoint, circuit.P), circuit.Result)
	return nil
}

type doubleCircuit struct {
	curveID twistededwards.ID
	P       Point
	Result  Point
}

func (circuit *doubleCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Double(circuit.P), circuit.Result)
	return nil
}

type negCircuit struct {
	curveID twistededwards.ID
	P       Point
	Result  Point
}

func (circuit *negCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.Neg(circuit.P), circuit.Result)
	return nil
}

type scalarMulCircuit struct {
	curveID twistededwards.ID
	P       Point
	Scalar  frontend.Variable
	Result  Point
}

func (circuit *scalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.ScalarMul(circuit.P, circuit.Scalar), circuit.Result)
	return nil
}

type fixedScalarMulCircuit struct {
	curveID    twistededwards.ID
	Scalar     frontend.Variable
	Result     Point
	fixedPoint Point `gnark:"-"`
}

func (circuit *fixedScalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.ScalarMul(circuit.fixedPoint, circuit.Scalar), circuit.Result)
	return nil
}

type doubleBaseScalarMulCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	S1, S2  frontend.Variable
	Result  Point
}

func (circuit *doubleBaseScalarMulCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.DoubleBaseScalarMul(circuit.P1, circuit.P2, circuit.S1, circuit.S2), circuit.Result)
	return nil
}

type doubleBaseScalarMulNonZeroCircuit struct {
	curveID twistededwards.ID
	P1, P2  Point
	S1, S2  frontend.Variable
	Result  Point
}

func (circuit *doubleBaseScalarMulNonZeroCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}
	assertPointEqual(api, curve.DoubleBaseScalarMulNonZero(circuit.P1, circuit.P2, circuit.S1, circuit.S2), circuit.Result)
	return nil
}

func TestAdd(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &addCircuit{curveID: curveID}
		witness := &addCircuit{P1: data.P1, P2: data.P2, Result: data.AddResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestAddFixed(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &addFixedCircuit{curveID: curveID, fixedPoint: data.P2}
		witness := &addFixedCircuit{P: data.P1, Result: data.AddResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDouble(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleCircuit{curveID: curveID}
		witness := &doubleCircuit{P: data.P1, Result: data.DoubleResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestNeg(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &negCircuit{curveID: curveID}
		witness := &negCircuit{P: data.P2, Result: data.NegResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &scalarMulCircuit{curveID: curveID}
		witness := &scalarMulCircuit{P: data.P2, Scalar: data.S2, Result: data.ScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestFixedScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &fixedScalarMulCircuit{curveID: curveID, fixedPoint: data.P2}
		witness := &fixedScalarMulCircuit{Scalar: data.S2, Result: data.ScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDoubleBaseScalarMul(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleBaseScalarMulCircuit{curveID: curveID}
		witness := &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: data.S1, S2: data.S2, Result: data.DoubleScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestDoubleBaseScalarMulNonZero(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := randomTestData(params, curveID)
		circuit := &doubleBaseScalarMulNonZeroCircuit{curveID: curveID}
		witness := &doubleBaseScalarMulNonZeroCircuit{P1: data.P1, P2: data.P2, S1: data.S1, S2: data.S2, Result: data.DoubleScalarMulResult}
		invalidWitness := *witness
		invalidWitness.Result = offCurvePoint()
		checkCircuitForCurve(t, curveID, circuit, witness, &invalidWitness)
	}
}

func TestAddEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		pPlusIdentity := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(0))
		identityPlusP := testDataForScalars(params, curveID, big.NewInt(0), big.NewInt(1))
		pPlusP := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(1))
		pPlusNegP := testDataForScalars(params, curveID, big.NewInt(1), negScalar(params.Order, big.NewInt(1)))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusIdentity.P1, P2: pPlusIdentity.P2, Result: pPlusIdentity.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: identityPlusP.P1, P2: identityPlusP.P2, Result: identityPlusP.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusP.P1, P2: pPlusP.P2, Result: pPlusP.AddResult})
			assertSolvedForCurve(t, curveID, &addCircuit{curveID: curveID}, &addCircuit{P1: pPlusNegP.P1, P2: pPlusNegP.P2, Result: pPlusNegP.AddResult})
		})
	}
}

func TestAddFixedEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		pPlusIdentity := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(0))
		pPlusNegP := testDataForScalars(params, curveID, big.NewInt(1), negScalar(params.Order, big.NewInt(1)))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &addFixedCircuit{curveID: curveID, fixedPoint: pPlusIdentity.P2}, &addFixedCircuit{P: pPlusIdentity.P1, Result: pPlusIdentity.AddResult})
			assertSolvedForCurve(t, curveID, &addFixedCircuit{curveID: curveID, fixedPoint: pPlusNegP.P2}, &addFixedCircuit{P: pPlusNegP.P1, Result: pPlusNegP.AddResult})
		})
	}
}

func TestDoubleEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &doubleCircuit{curveID: curveID}, &doubleCircuit{P: identityPoint(), Result: identityPoint()})
		})
	}
}

func TestNegEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &negCircuit{curveID: curveID}, &negCircuit{P: identityPoint(), Result: identityPoint()})
		})
	}
}

func TestScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(2))

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: data.P1, Scalar: 0, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: identityPoint(), Scalar: 2, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &scalarMulCircuit{curveID: curveID}, &scalarMulCircuit{P: data.P1, Scalar: 1, Result: data.P1})
		})
	}
}

func TestFixedScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}

		t.Run(curveLabel(curveID), func(t *testing.T) {
			assertSolvedForCurve(t, curveID, &fixedScalarMulCircuit{curveID: curveID, fixedPoint: identityPoint()}, &fixedScalarMulCircuit{Scalar: 2, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, &fixedScalarMulCircuit{curveID: curveID, fixedPoint: Point{X: params.Base[0], Y: params.Base[1]}}, &fixedScalarMulCircuit{Scalar: 0, Result: identityPoint()})
		})
	}
}

// TestDoubleBaseScalarMulEdgeCases covers the complete public method, including
// zero scalars and identity points. The optimized NonZero variant is tested
// separately.
func TestDoubleBaseScalarMulEdgeCases(t *testing.T) {
	for _, curveID := range curves {
		params, err := GetCurveParams(curveID)
		if err != nil {
			t.Fatalf("%s: get curve params: %v", curveLabel(curveID), err)
		}
		data := testDataForScalars(params, curveID, big.NewInt(1), big.NewInt(2))
		base := Point{X: params.Base[0], Y: params.Base[1]}

		t.Run(curveLabel(curveID), func(t *testing.T) {
			circuit := &doubleBaseScalarMulCircuit{curveID: curveID}
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 0, S2: 0, Result: identityPoint()})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 1, S2: 0, Result: data.P1})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: data.P1, P2: data.P2, S1: 0, S2: 1, Result: data.P2})
			assertSolvedForCurve(t, curveID, circuit, &doubleBaseScalarMulCircuit{P1: identityPoint(), P2: base, S1: 1, S2: 2, Result: data.P2})
		})
	}
}

type curveTestData struct {
	P1                    Point
	P2                    Point
	AddResult             Point
	DoubleResult          Point
	ScalarMulResult       Point
	DoubleScalarMulResult Point
	NegResult             Point
	S1                    *big.Int
	S2                    *big.Int
}

func checkCircuitForCurve(t *testing.T, curveID twistededwards.ID, circuit, validWitness, invalidWitness frontend.Circuit) {
	t.Helper()

	assert := test.NewAssert(t)
	snarkField, err := GetSnarkField(curveID)
	assert.NoError(err)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(validWitness),
		test.WithInvalidAssignment(invalidWitness),
		test.WithCurves(utils.FieldToCurve(snarkField)),
	)
}

func assertSolvedForCurve(t *testing.T, curveID twistededwards.ID, circuit, witness frontend.Circuit) {
	t.Helper()

	snarkField, err := GetSnarkField(curveID)
	if err != nil {
		t.Fatalf("%s: get snark field: %v", curveLabel(curveID), err)
	}
	if err := test.IsSolved(circuit, witness, snarkField); err != nil {
		t.Fatalf("%s: %v", curveLabel(curveID), err)
	}
}

func randomTestData(params *CurveParams, curveID twistededwards.ID) curveTestData {
	return testDataForScalars(params, curveID, nonZeroRandomScalar(params), nonZeroRandomScalar(params))
}

func testDataForScalars(params *CurveParams, curveID twistededwards.ID, scalar1, scalar2 *big.Int) curveTestData {
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
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
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
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
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
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
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
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
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
		return curveTestData{
			P1:                    Point{p1.X, p1.Y},
			P2:                    Point{p2.X, p2.Y},
			AddResult:             Point{r.X, r.Y},
			DoubleResult:          Point{d.X, d.Y},
			ScalarMulResult:       Point{rs1.X, rs1.Y},
			DoubleScalarMulResult: Point{rs12.X, rs12.Y},
			NegResult:             Point{n.X, n.Y},
			S1:                    new(big.Int).Set(scalar1),
			S2:                    new(big.Int).Set(scalar2),
		}
	default:
		panic("not implemented")
	}
}

func identityPoint() Point {
	return Point{X: 0, Y: 1}
}

func offCurvePoint() Point {
	return Point{X: 0, Y: 0}
}

func nonZeroRandomScalar(params *CurveParams) *big.Int {
	for {
		scalar := params.randomScalar()
		if scalar.Sign() != 0 {
			return scalar
		}
	}
}

func negScalar(order, scalar *big.Int) *big.Int {
	neg := new(big.Int).Neg(scalar)
	neg.Mod(neg, order)
	return neg
}

func curveLabel(id twistededwards.ID) string {
	switch id {
	case twistededwards.BN254:
		return "bn254"
	case twistededwards.BLS12_377:
		return "bls12-377"
	case twistededwards.BLS12_381:
		return "bls12-381"
	case twistededwards.BLS12_381_BANDERSNATCH:
		return "bandersnatch"
	case twistededwards.BW6_761:
		return "bw6-761"
	default:
		return "unknown"
	}
}

// randomScalar returns a scalar <= p.Order
func (p *CurveParams) randomScalar() *big.Int {
	r, _ := rand.Int(rand.Reader, p.Order)
	return r
}

type scalarMulFakeGLVRegressionCircuit struct {
	Scalar frontend.Variable `gnark:",public"`
}

func (c *scalarMulFakeGLVRegressionCircuit) Define(api frontend.API) error {
	curve, err := NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}
	base := Point{X: curve.Params().Base[0], Y: curve.Params().Base[1]}
	_ = curve.ScalarMul(base, c.Scalar)
	return nil
}

func zeroRationalReconstructHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 {
		return errors.New("expecting two inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	for i := range outputs {
		outputs[i].SetUint64(0)
	}
	return nil
}

// This is a regression for a soundness issue in scalarMulFakeGLV. A malicious
// rationalReconstruct hint can return the trivial decomposition s1=s2=0,
// which makes the internal accumulator check vacuous and lets any scalar-mul
// hint output pass.
func TestScalarMulFakeGLVRegressionTrivialDecomposition(t *testing.T) {
	assert := require.New(t)

	witness := scalarMulFakeGLVRegressionCircuit{Scalar: big.NewInt(1)}

	err := test.IsSolved(&scalarMulFakeGLVRegressionCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

	err = test.IsSolved(
		&scalarMulFakeGLVRegressionCircuit{},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(rationalReconstruct), zeroRationalReconstructHint),
	)
	assert.Error(err)
}

func forgedBN254DoubleBaseScalarMulHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 7 {
		return errors.New("expecting seven inputs")
	}
	if len(outputs) != 4 {
		return errors.New("expecting four outputs")
	}
	var p1, p2, q1, q2 tbn254.PointAffine
	p1.X.SetBigInt(inputs[0])
	p1.Y.SetBigInt(inputs[1])
	p2.X.SetBigInt(inputs[3])
	p2.Y.SetBigInt(inputs[4])
	q1.ScalarMultiplication(&p1, inputs[2])
	q2.ScalarMultiplication(&p2, inputs[5])

	var delta tbn254.PointAffine
	delta.Set(&p1)

	var q1Hint tbn254.PointAffine
	q1Hint.Add(&q1, &delta)

	q1Hint.X.BigInt(outputs[0])
	q1Hint.Y.BigInt(outputs[1])
	q2.X.BigInt(outputs[2])
	q2.Y.BigInt(outputs[3])
	return nil
}

func forgedBN254DoubleBaseResult(params *CurveParams, s1, s2 *big.Int) (Point, error) {
	var p1, p2 tbn254.PointAffine
	p1.X.SetBigInt(params.Base[0])
	p1.Y.SetBigInt(params.Base[1])
	p2.Set(&p1)
	p1.ScalarMultiplication(&p1, s1)
	p2.ScalarMultiplication(&p2, s2)

	p1X, p1Y := new(big.Int), new(big.Int)
	p2X, p2Y := new(big.Int), new(big.Int)
	p1.X.BigInt(p1X)
	p1.Y.BigInt(p1Y)
	p2.X.BigInt(p2X)
	p2.Y.BigInt(p2Y)

	inputs := []*big.Int{
		p1X,
		p1Y,
		new(big.Int).Set(s1),
		p2X,
		p2Y,
		new(big.Int).Set(s2),
		new(big.Int).Set(params.Order),
	}
	outputs := []*big.Int{new(big.Int), new(big.Int), new(big.Int), new(big.Int)}
	if err := forgedBN254DoubleBaseScalarMulHint(nil, inputs, outputs); err != nil {
		return Point{}, err
	}
	var q1, q2, r tbn254.PointAffine
	q1.X.SetBigInt(outputs[0])
	q1.Y.SetBigInt(outputs[1])
	q2.X.SetBigInt(outputs[2])
	q2.Y.SetBigInt(outputs[3])
	r.Add(&q1, &q2)
	rX, rY := new(big.Int), new(big.Int)
	r.X.BigInt(rX)
	r.Y.BigInt(rY)
	return Point{X: rX, Y: rY}, nil
}

func TestDoubleBaseScalarMulNonZeroRejectsForgedPartialHints(t *testing.T) {
	assert := require.New(t)
	params, err := GetCurveParams(twistededwards.BN254)
	assert.NoError(err)

	data := testDataForScalars(params, twistededwards.BN254, big.NewInt(5), big.NewInt(7))
	forged, err := forgedBN254DoubleBaseResult(params, data.S1, data.S2)
	assert.NoError(err)

	witness := doubleBaseScalarMulNonZeroCircuit{
		P1:     data.P1,
		P2:     data.P2,
		S1:     data.S1,
		S2:     data.S2,
		Result: forged,
	}
	err = test.IsSolved(
		&doubleBaseScalarMulNonZeroCircuit{curveID: twistededwards.BN254},
		&witness,
		ecc.BN254.ScalarField(),
		test.WithReplacementHint(solver.GetHintID(doubleBaseScalarMulHint), forgedBN254DoubleBaseScalarMulHint),
	)
	assert.Error(err)
}
