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
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls24315"
	"github.com/consensys/gnark/test"
)

type finalExp struct {
	ML fields_bls24315.E24
	R  bls24315.GT
}

func (circuit *finalExp) Define(api frontend.API) error {

	pairingRes := FinalExponentiation(api, circuit.ML)

	mustbeEq(api, pairingRes, &circuit.R)

	return nil
}

func TestFinalExp(t *testing.T) {

	// pairing test data
	_, _, milRes, pairingRes := pairingData()

	// create cs
	var circuit, witness finalExp
	witness.ML.Assign(&milRes)
	circuit.R = pairingRes

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
}

type pairingBLS24315 struct {
	P          G1Affine `gnark:",public"`
	Q          G2Affine
	pairingRes bls24315.GT
}

func (circuit *pairingBLS24315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingBLS24315(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingBLS24315
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type triplePairingBLS24315 struct {
	P1, P2, P3 G1Affine `gnark:",public"`
	Q1, Q2, Q3 G2Affine
	pairingRes bls24315.GT
}

func (circuit *triplePairingBLS24315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P1, circuit.P2, circuit.P3}, []G2Affine{circuit.Q1, circuit.Q2, circuit.Q3})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestTriplePairingBLS24315(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := triplePairingData()

	// create cs
	var circuit, witness triplePairingBLS24315
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P1.Assign(&P[0])
	witness.P2.Assign(&P[1])
	witness.P3.Assign(&P[2])
	witness.Q1.Assign(&Q[0])
	witness.Q2.Assign(&Q[1])
	witness.Q3.Assign(&Q[2])

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type pairingFixedBLS315 struct {
	P          G1Affine
	Lines      [2]LineEvaluations
	pairingRes bls24315.GT
}

func (circuit *pairingFixedBLS315) Define(api frontend.API) error {

	pairingRes, _ := PairFixedQ(api, []G1Affine{circuit.P}, []*[2]LineEvaluations{&circuit.Lines})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingFixedBLS315(t *testing.T) {

	// pairing test data
	P, _, _, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingFixedBLS315
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)
	witness.Lines = getPrecomputedLines()

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type doublePairingFixedBLS315 struct {
	P0         G1Affine
	P1         G1Affine
	Line0      [2]LineEvaluations
	Line1      [2]LineEvaluations
	pairingRes bls24315.GT
}

func (circuit *doublePairingFixedBLS315) Define(api frontend.API) error {

	pairingRes, _ := PairFixedQ(api, []G1Affine{circuit.P0, circuit.P1}, []*[2]LineEvaluations{&circuit.Line0, &circuit.Line1})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestDoublePairingFixedBLS315(t *testing.T) {

	// pairing test data
	P, _, _, pairingRes := doublePairingFixedQData()

	// create cs
	var circuit, witness doublePairingFixedBLS315
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P0.Assign(&P[0])
	witness.P1.Assign(&P[1])
	witness.Line0 = getPrecomputedLines()
	witness.Line1 = getPrecomputedLines()

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type pairingCheckBLS315 struct {
	P1, P2 G1Affine `gnark:",public"`
	Q1, Q2 G2Affine
}

func (circuit *pairingCheckBLS315) Define(api frontend.API) error {

	err := PairingCheck(api, []G1Affine{circuit.P1, circuit.P2}, []G2Affine{circuit.Q1, circuit.Q2})

	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}

	return nil
}

func TestPairingCheckBLS315(t *testing.T) {

	// pairing test data
	P, Q := pairingCheckData()

	// create cs
	var circuit, witness pairingCheckBLS315

	// assign values to witness
	witness.P1.Assign(&P[0])
	witness.P2.Assign(&P[1])
	witness.Q1.Assign(&Q[0])
	witness.Q2.Assign(&Q[1])

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

// utils
func pairingData() (P bls24315.G1Affine, Q bls24315.G2Affine, milRes bls24315.E24, pairingRes bls24315.GT) {
	_, _, P, Q = bls24315.Generators()
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P}, []bls24315.G2Affine{Q})
	pairingRes = bls24315.FinalExponentiation(&milRes)
	return
}

func doubleFixedPairingData() (P [2]bls24315.G1Affine, Q bls24315.G2Affine, milRes, pairingRes bls24315.GT) {
	_, _, P0, Q0 := bls24315.Generators()
	P[0].Set(&P0)
	var u, v fr.Element
	var _u, _v big.Int
	_, _ = u.SetRandom()
	_, _ = v.SetRandom()
	u.BigInt(&_u)
	v.BigInt(&_v)
	P[1].ScalarMultiplication(&P[0], &_u)
	Q.ScalarMultiplication(&Q0, &_v)
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P[0], P[1]}, []bls24315.G2Affine{Q0, Q})
	pairingRes = bls24315.FinalExponentiation(&milRes)

	return
}

func pairingCheckData() (P [2]bls24315.G1Affine, Q [2]bls24315.G2Affine) {
	_, _, P[0], Q[0] = bls24315.Generators()
	P[1].Neg(&P[0])
	Q[1].Set(&Q[0])

	return
}

func triplePairingData() (P [3]bls24315.G1Affine, Q [3]bls24315.G2Affine, pairingRes bls24315.GT) {
	_, _, P[0], Q[0] = bls24315.Generators()
	var u, v fr.Element
	var _u, _v big.Int
	for i := 1; i < 3; i++ {
		_, _ = u.SetRandom()
		_, _ = v.SetRandom()
		u.BigInt(&_u)
		v.BigInt(&_v)
		P[i].ScalarMultiplication(&P[0], &_u)
		Q[i].ScalarMultiplication(&Q[0], &_v)
	}
	milRes, _ := bls24315.MillerLoop([]bls24315.G1Affine{P[0], P[1], P[2]}, []bls24315.G2Affine{Q[0], Q[1], Q[2]})
	pairingRes = bls24315.FinalExponentiation(&milRes)

	return
}

func doublePairingFixedQData() (P [2]bls24315.G1Affine, Q bls24315.G2Affine, milRes, pairingRes bls24315.GT) {
	_, _, P[0], Q = bls24315.Generators()
	var u fr.Element
	var _u big.Int
	_, _ = u.SetRandom()
	u.BigInt(&_u)
	P[1].ScalarMultiplication(&P[0], &_u)
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P[0], P[1]}, []bls24315.G2Affine{Q, Q})
	pairingRes = bls24315.FinalExponentiation(&milRes)
	return
}

func mustbeEq(api frontend.API, fp24 fields_bls24315.E24, e24 *bls24315.GT) {
	api.AssertIsEqual(fp24.D0.C0.B0.A0, e24.D0.C0.B0.A0)
	api.AssertIsEqual(fp24.D0.C0.B0.A1, e24.D0.C0.B0.A1)
	api.AssertIsEqual(fp24.D0.C0.B1.A0, e24.D0.C0.B1.A0)
	api.AssertIsEqual(fp24.D0.C0.B1.A1, e24.D0.C0.B1.A1)
	api.AssertIsEqual(fp24.D0.C1.B0.A0, e24.D0.C1.B0.A0)
	api.AssertIsEqual(fp24.D0.C1.B0.A1, e24.D0.C1.B0.A1)
	api.AssertIsEqual(fp24.D0.C1.B1.A0, e24.D0.C1.B1.A0)
	api.AssertIsEqual(fp24.D0.C1.B1.A1, e24.D0.C1.B1.A1)
	api.AssertIsEqual(fp24.D0.C2.B0.A0, e24.D0.C2.B0.A0)
	api.AssertIsEqual(fp24.D0.C2.B0.A1, e24.D0.C2.B0.A1)
	api.AssertIsEqual(fp24.D0.C2.B1.A0, e24.D0.C2.B1.A0)
	api.AssertIsEqual(fp24.D0.C2.B1.A1, e24.D0.C2.B1.A1)
	api.AssertIsEqual(fp24.D1.C0.B0.A0, e24.D1.C0.B0.A0)
	api.AssertIsEqual(fp24.D1.C0.B0.A1, e24.D1.C0.B0.A1)
	api.AssertIsEqual(fp24.D1.C0.B1.A0, e24.D1.C0.B1.A0)
	api.AssertIsEqual(fp24.D1.C0.B1.A1, e24.D1.C0.B1.A1)
	api.AssertIsEqual(fp24.D1.C1.B0.A0, e24.D1.C1.B0.A0)
	api.AssertIsEqual(fp24.D1.C1.B0.A1, e24.D1.C1.B0.A1)
	api.AssertIsEqual(fp24.D1.C1.B1.A0, e24.D1.C1.B1.A0)
	api.AssertIsEqual(fp24.D1.C1.B1.A1, e24.D1.C1.B1.A1)
	api.AssertIsEqual(fp24.D1.C2.B0.A0, e24.D1.C2.B0.A0)
	api.AssertIsEqual(fp24.D1.C2.B0.A1, e24.D1.C2.B0.A1)
	api.AssertIsEqual(fp24.D1.C2.B1.A0, e24.D1.C2.B1.A0)
	api.AssertIsEqual(fp24.D1.C2.B1.A1, e24.D1.C2.B1.A1)
}
