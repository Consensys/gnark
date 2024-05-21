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
	R  GT
}

func (circuit *finalExp) Define(api frontend.API) error {

	finalExpRes := FinalExponentiation(api, circuit.ML)
	finalExpRes.AssertIsEqual(api, circuit.R)

	return nil
}

func TestFinalExp(t *testing.T) {

	// pairing test data
	_, _, milRes, pairingRes := pairingData()

	// create cs
	witness := finalExp{
		ML: NewGTEl(milRes),
		R:  NewGTEl(pairingRes),
	}

	assert := test.NewAssert(t)
	assert.CheckCircuit(&finalExp{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))
}

type pairingBLS315 struct {
	P   G1Affine
	Q   G2Affine
	Res GT
}

func (circuit *pairingBLS315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestPairingBLS315(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	// assign values to witness
	witness := pairingBLS315{
		P:   NewG1Affine(P),
		Q:   NewG2Affine(Q),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingBLS315{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type triplePairingBLS315 struct {
	P1, P2, P3 G1Affine
	Q1, Q2, Q3 G2Affine
	Res        GT
}

func (circuit *triplePairingBLS315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P1, circuit.P2, circuit.P3}, []G2Affine{circuit.Q1, circuit.Q2, circuit.Q3})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestTriplePairingBLS315(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := triplePairingData()

	witness := triplePairingBLS315{
		P1:  NewG1Affine(P[0]),
		P2:  NewG1Affine(P[1]),
		P3:  NewG1Affine(P[2]),
		Q1:  NewG2Affine(Q[0]),
		Q2:  NewG2Affine(Q[1]),
		Q3:  NewG2Affine(Q[2]),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&triplePairingBLS315{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633), test.NoProverChecks())

}

type pairingFixedBLS315 struct {
	P   G1Affine
	Q   G2Affine
	Res GT
}

func (circuit *pairingFixedBLS315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P}, []G2Affine{circuit.Q})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestPairingFixedBLS315(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := pairingData()

	witness := pairingBLS315{
		P:   NewG1Affine(P),
		Q:   NewG2AffineFixed(Q),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingFixedBLS315{Q: NewG2AffineFixedPlaceholder()}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type doublePairingFixedBLS315 struct {
	P0  G1Affine
	P1  G1Affine
	Q0  G2Affine
	Q1  G2Affine
	Res GT
}

func (circuit *doublePairingFixedBLS315) Define(api frontend.API) error {

	pairingRes, _ := Pair(api, []G1Affine{circuit.P0, circuit.P1}, []G2Affine{circuit.Q0, circuit.Q1})
	pairingRes.AssertIsEqual(api, circuit.Res)

	return nil
}

func TestDoublePairingFixedBLS315(t *testing.T) {

	// pairing test data
	P, Q, _, pairingRes := doublePairingFixedQData()

	witness := doublePairingFixedBLS315{
		P0:  NewG1Affine(P[0]),
		P1:  NewG1Affine(P[1]),
		Q0:  NewG2AffineFixed(Q[0]),
		Q1:  NewG2AffineFixed(Q[1]),
		Res: NewGTEl(pairingRes),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&doublePairingFixedBLS315{Q0: NewG2AffineFixedPlaceholder(), Q1: NewG2AffineFixedPlaceholder()}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633))

}

type pairingCheckBLS315 struct {
	P1, P2 G1Affine
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
	witness := pairingCheckBLS315{
		P1: NewG1Affine(P[0]),
		P2: NewG1Affine(P[1]),
		Q1: NewG2Affine(Q[0]),
		Q2: NewG2Affine(Q[1]),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingCheckBLS315{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_633), test.NoProverChecks())

}

// utils
func pairingData() (P bls24315.G1Affine, Q bls24315.G2Affine, milRes, pairingRes bls24315.GT) {
	_, _, P, Q = bls24315.Generators()
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P}, []bls24315.G2Affine{Q})
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

func doublePairingFixedQData() (P [2]bls24315.G1Affine, Q [2]bls24315.G2Affine, milRes, pairingRes bls24315.GT) {
	_, _, P[0], Q[0] = bls24315.Generators()
	var u, v fr.Element
	var _u, _v big.Int
	_, _ = u.SetRandom()
	_, _ = v.SetRandom()
	u.BigInt(&_u)
	v.BigInt(&_v)
	P[1].ScalarMultiplication(&P[0], &_u)
	Q[1].ScalarMultiplication(&Q[0], &_v)
	milRes, _ = bls24315.MillerLoop([]bls24315.G1Affine{P[0], P[1]}, []bls24315.G2Affine{Q[0], Q[1]})
	pairingRes = bls24315.FinalExponentiation(&milRes)
	return
}
