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
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/test"
)

type finalExp struct {
	ML fields_bls12377.E12
	R  bls12377.GT
}

func (circuit *finalExp) Define(api frontend.API) error {

	finalExpRes := FinalExponentiation(api, circuit.ML)
	mustbeEq(api, finalExpRes, &circuit.R)

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
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))
}

type pairingBLS377 struct {
	P          G1Affine
	Q          G2Affine
	pairingRes bls12377.GT
}

func (circuit *pairingBLS377) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingBLS377
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type triplePairingBLS377 struct {
	P1, P2, P3 G1Affine
	Q1, Q2, Q3 G2Affine
	pairingRes bls12377.GT
}

func (circuit *triplePairingBLS377) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P1, circuit.P2, circuit.P3}, []G2Affine{circuit.Q1, circuit.Q2, circuit.Q3})

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestTriplePairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := triplePairingData()

	// create cs
	var circuit, witness triplePairingBLS377
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P1.Assign(&P[0])
	witness.P2.Assign(&P[1])
	witness.P3.Assign(&P[2])
	witness.Q1.Assign(&Q[0])
	witness.Q2.Assign(&Q[1])
	witness.Q3.Assign(&Q[2])

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type pairingFixedBLS377 struct {
	P          G1Affine
	pairingRes bls12377.GT
}

func (circuit *pairingFixedBLS377) Define(api frontend.API) error {

	pairingRes, _ := PairFixedQ(api, circuit.P)

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingFixedBLS377(t *testing.T) {

	// pairing test data
	P, _, _, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingFixedBLS377
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type doublePairingFixedBLS377 struct {
	P          [2]G1Affine
	Q          G2Affine
	pairingRes bls12377.GT
}

func (circuit *doublePairingFixedBLS377) Define(api frontend.API) error {

	pairingRes, _ := DoublePairFixedQ(api, circuit.P, circuit.Q)

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestDoublePairingFixedBLS377(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := doubleFixedPairingData()

	// create cs
	var circuit, witness doublePairingFixedBLS377
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P[0].Assign(&P[0])
	witness.P[1].Assign(&P[1])
	witness.Q.Assign(&Q)

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

type pairingCheckBLS377 struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (circuit *pairingCheckBLS377) Define(api frontend.API) error {

	err := PairingCheck(api, []G1Affine{circuit.P1, circuit.P2}, []G2Affine{circuit.Q1, circuit.Q2})

	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}

	return nil
}

func TestPairingCheckBLS377(t *testing.T) {

	// pairing test data
	P, Q := pairingCheckData()

	// create cs
	var circuit, witness pairingCheckBLS377

	// assign values to witness
	witness.P1.Assign(&P[0])
	witness.P2.Assign(&P[1])
	witness.Q1.Assign(&Q[0])
	witness.Q2.Assign(&Q[1])

	assert := test.NewAssert(t)
	assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761))

}

// utils
func pairingData() (P bls12377.G1Affine, Q bls12377.G2Affine, milRes, pairingRes bls12377.GT) {
	_, _, P, Q = bls12377.Generators()
	milRes, _ = bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}

func pairingCheckData() (P [2]bls12377.G1Affine, Q [2]bls12377.G2Affine) {
	_, _, P[0], Q[0] = bls12377.Generators()
	P[1].Neg(&P[0])
	Q[1].Set(&Q[0])

	return
}

func doubleFixedPairingData() (P [2]bls12377.G1Affine, Q bls12377.G2Affine, milRes, pairingRes bls12377.GT) {
	_, _, P0, Q0 := bls12377.Generators()
	P[0].Set(&P0)
	var u, v fr.Element
	var _u, _v big.Int
	_, _ = u.SetRandom()
	_, _ = v.SetRandom()
	u.BigInt(&_u)
	v.BigInt(&_v)
	P[1].ScalarMultiplication(&P[0], &_u)
	Q.ScalarMultiplication(&Q0, &_v)
	milRes, _ = bls12377.MillerLoop([]bls12377.G1Affine{P[0], P[1]}, []bls12377.G2Affine{Q0, Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)

	return
}

func triplePairingData() (P [3]bls12377.G1Affine, Q [3]bls12377.G2Affine, pairingRes bls12377.GT) {
	_, _, P[0], Q[0] = bls12377.Generators()
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
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P[0], P[1], P[2]}, []bls12377.G2Affine{Q[0], Q[1], Q[2]})
	pairingRes = bls12377.FinalExponentiation(&milRes)

	return
}

func mustbeEq(api frontend.API, fp12 fields_bls12377.E12, e12 *bls12377.GT) {
	api.AssertIsEqual(fp12.C0.B0.A0, e12.C0.B0.A0)
	api.AssertIsEqual(fp12.C0.B0.A1, e12.C0.B0.A1)
	api.AssertIsEqual(fp12.C0.B1.A0, e12.C0.B1.A0)
	api.AssertIsEqual(fp12.C0.B1.A1, e12.C0.B1.A1)
	api.AssertIsEqual(fp12.C0.B2.A0, e12.C0.B2.A0)
	api.AssertIsEqual(fp12.C0.B2.A1, e12.C0.B2.A1)
	api.AssertIsEqual(fp12.C1.B0.A0, e12.C1.B0.A0)
	api.AssertIsEqual(fp12.C1.B0.A1, e12.C1.B0.A1)
	api.AssertIsEqual(fp12.C1.B1.A0, e12.C1.B1.A0)
	api.AssertIsEqual(fp12.C1.B1.A1, e12.C1.B1.A1)
	api.AssertIsEqual(fp12.C1.B2.A0, e12.C1.B2.A0)
	api.AssertIsEqual(fp12.C1.B2.A1, e12.C1.B2.A1)
}
