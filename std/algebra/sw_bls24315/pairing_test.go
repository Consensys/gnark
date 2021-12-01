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
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls24315"
	"github.com/consensys/gnark/test"
)

type pairingBLS24315 struct {
	P          G1Affine `gnark:",public"`
	Q          G2Affine
	pairingRes bls24315.GT
}

func (circuit *pairingBLS24315) Define(api frontend.API) error {

	ateLoop := uint64(3218079743)
	ext := fields_bls24315.GetBLS24315ExtensionFp24(api)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.B0.A0 = 0
	pairingInfo.BTwistCoeff.B0.A1 = 0
	pairingInfo.BTwistCoeff.B1.A0 = 0
	pairingInfo.BTwistCoeff.B1.A1 = "6108483493771298205388567675447533806912846525679192205394505462405828322019437284165171866703"

	milRes := fields_bls24315.E24{}
	MillerLoop(api, circuit.P, circuit.Q, &milRes, pairingInfo)

	pairingRes := fields_bls24315.E24{}
	pairingRes.FinalExponentiation(api, milRes, ateLoop, ext)

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingBLS24315(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingBLS24315
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633), test.WithBackends(backend.GROTH16))

}

func pairingData() (P bls24315.G1Affine, Q bls24315.G2Affine, pairingRes bls24315.GT) {
	_, _, P, Q = bls24315.Generators()
	milRes, _ := bls24315.MillerLoop([]bls24315.G1Affine{P}, []bls24315.G2Affine{Q})
	pairingRes = bls24315.FinalExponentiation(&milRes)
	return
}

func triplePairingData() (P [3]bls24315.G1Affine, Q [3]bls24315.G2Affine, pairingRes bls24315.GT) {
	_, _, P[0], Q[0] = bls24315.Generators()
	var u, v fr.Element
	var _u, _v big.Int
	for i := 1; i < 3; i++ {
		u.SetRandom()
		v.SetRandom()
		u.ToBigIntRegular(&_u)
		v.ToBigIntRegular(&_v)
		P[i].ScalarMultiplication(&P[0], &_u)
		Q[i].ScalarMultiplication(&Q[0], &_v)
	}
	milRes, _ := bls24315.MillerLoop([]bls24315.G1Affine{P[0], P[1], P[2]}, []bls24315.G2Affine{Q[0], Q[1], Q[2]})
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

type triplePairingBLS24315 struct {
	P1, P2, P3 G1Affine `gnark:",public"`
	Q1, Q2, Q3 G2Affine
	pairingRes bls24315.GT
}

func (circuit *triplePairingBLS24315) Define(api frontend.API) error {

	ateLoop := uint64(3218079743)
	ext := fields_bls24315.GetBLS24315ExtensionFp24(api)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.B0.A0 = 0
	pairingInfo.BTwistCoeff.B0.A1 = 0
	pairingInfo.BTwistCoeff.B1.A0 = 0
	pairingInfo.BTwistCoeff.B1.A1 = "6108483493771298205388567675447533806912846525679192205394505462405828322019437284165171866703"

	milRes := fields_bls24315.E24{}
	TripleMillerLoop(api, [3]G1Affine{circuit.P1, circuit.P2, circuit.P3}, [3]G2Affine{circuit.Q1, circuit.Q2, circuit.Q3}, &milRes, pairingInfo)

	pairingRes := fields_bls24315.E24{}
	pairingRes.FinalExponentiation(api, milRes, ateLoop, ext)

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
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_633), test.WithBackends(backend.GROTH16))

}

func BenchmarkPairing(b *testing.B) {
	var c pairingBLS24315
	ccsBench, _ = frontend.Compile(ecc.BW6_633, backend.GROTH16, &c)
	b.Log("groth16", ccsBench.GetNbConstraints())
}
