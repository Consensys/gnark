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

package sw

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
	"github.com/consensys/gnark/test"
)

type pairingBLS377 struct {
	P          G1Affine `gnark:",public"`
	Q          G2Affine
	pairingRes bls12377.GT
}

func (circuit *pairingBLS377) Define(api frontend.API) error {

	ateLoop := uint64(9586122913090633729)
	ext := fields.GetBLS377ExtensionFp12(api)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.A0 = 0
	pairingInfo.BTwistCoeff.A1 = "155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906"

	milRes := fields.E12{}
	//MillerLoop(cs, circuit.P, circuit.Q, &milRes, pairingInfo)
	//MillerLoopAffine(cs, circuit.P, circuit.Q, &milRes, pairingInfo)
	MillerLoop(api, circuit.P, circuit.Q, &milRes, pairingInfo)

	pairingRes := fields.E12{}
	pairingRes.FinalExponentiation(api, milRes, ateLoop, ext)

	mustbeEq(api, pairingRes, &circuit.pairingRes)

	return nil
}

func TestPairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingBLS377
	circuit.pairingRes = pairingRes

	// assign values to witness
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

type ml struct {
	P G1Affine `gnark:",public"`
	Q G2Affine
}

func (circuit *ml) Define(api frontend.API) error {

	ateLoop := uint64(9586122913090633729)
	ext := fields.GetBLS377ExtensionFp12(api)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.A0 = 0
	pairingInfo.BTwistCoeff.A1 = "155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906"

	milRes := fields.E12{}
	MillerLoop(api, circuit.P, circuit.Q, &milRes, pairingInfo)

	return nil

}

func TestMillerLoop(t *testing.T) {

	var circuit ml

	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("%d constraints\n", r1cs.GetNbConstraints())

}

func pairingData() (P bls12377.G1Affine, Q bls12377.G2Affine, pairingRes bls12377.GT) {
	_, _, P, Q = bls12377.Generators()
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}

func triplePairingData() (P bls12377.G1Affine, Q bls12377.G2Affine, pairingRes bls12377.GT) {
	_, _, P, Q = bls12377.Generators()
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P, P, P}, []bls12377.G2Affine{Q, Q, Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}

func mustbeEq(api frontend.API, fp12 fields.E12, e12 *bls12377.GT) {
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

type triplePairingBLS377 struct {
	P1, P2, P3 G1Affine `gnark:",public"`
	Q1, Q2, Q3 G2Affine
	pairingRes bls12377.GT
}

func (circuit *triplePairingBLS377) Define(api frontend.API) error {

	ateLoop := uint64(9586122913090633729)
	ext := fields.GetBLS377ExtensionFp12(api)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.A0 = 0
	pairingInfo.BTwistCoeff.A1 = "155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906"

	milRes := fields.E12{}
	TripleMillerLoop(api, [3]G1Affine{circuit.P1, circuit.P2, circuit.P3}, [3]G2Affine{circuit.Q1, circuit.Q2, circuit.Q3}, &milRes, pairingInfo)

	pairingRes := fields.E12{}
	pairingRes.FinalExponentiation(api, milRes, ateLoop, ext)

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
	witness.P1.Assign(&P)
	witness.P2.Assign(&P)
	witness.P3.Assign(&P)
	witness.Q1.Assign(&Q)
	witness.Q2.Assign(&Q)
	witness.Q3.Assign(&Q)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(ecc.BW6_761))

}

func BenchmarkPairing(b *testing.B) {
	var c pairingBLS377
	ccsBench, _ = frontend.Compile(ecc.BW6_761, backend.GROTH16, &c)
	b.Log("groth16", ccsBench.GetNbConstraints())
}
