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
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
)

type pairingBLS377 struct {
	P          G1Affine `gnark:",public"`
	Q          G2Affine
	pairingRes bls12377.GT
}

func (circuit *pairingBLS377) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	ateLoop := uint64(9586122913090633729)
	ext := fields.GetBLS377ExtensionFp12(cs)
	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
	pairingInfo.BTwistCoeff.A0 = cs.Constant(0)
	pairingInfo.BTwistCoeff.A1 = cs.Constant("155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906")

	milRes := fields.E12{}
	//MillerLoop(cs, circuit.P, circuit.Q, &milRes, pairingInfo)
	MillerLoopAffine(cs, circuit.P, circuit.Q, &milRes, pairingInfo)

	pairingRes := fields.E12{}
	pairingRes.FinalExponentiation(cs, &milRes, ateLoop, ext)

	mustbeEq(cs, pairingRes, &circuit.pairingRes)

	return nil
}

type untwistLine struct {
	Line     LineEvaluation
	Acc      fields.E12
	Expected fields.E12 `gnark:",public"`
}

func (circuit *untwistLine) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

	ext := fields.GetBLS377ExtensionFp12(cs)
	acc := mulByUntwistedLineEval(cs, circuit.Line, circuit.Acc, ext)
	acc.MustBeEqual(cs, circuit.Expected)
	return nil
}

func TestMulByUntwistedLineEval(t *testing.T) {

	var circuit, witness untwistLine

	// prepare data (it does not form a line, but it doesn't matter for the test it's
	// purely computational)
	var a, b, c bls12377.E2
	a.SetRandom()
	b.SetRandom()
	c.SetRandom()

	var untwistedLine bls12377.E12
	untwistedLine.C0.B1.Set(&b)
	untwistedLine.C1.B1.Set(&a)
	untwistedLine.C1.B2.Set(&c)

	var acc, expected bls12377.E12
	acc.SetRandom()
	expected.Mul(&acc, &untwistedLine)

	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign values
	witness.Line.R0.Assign(&a)
	witness.Line.R1.Assign(&b)
	witness.Line.R2.Assign(&c)
	witness.Acc.Assign(&acc)
	witness.Expected.Assign(&expected)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

// type ml struct {
// 	P G1Affine `gnark:",public"`
// 	Q G2Affine
// }

// func (circuit *ml) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {

// 	ateLoop := uint64(9586122913090633729)
// 	ext := fields.GetBLS377ExtensionFp12(cs)
// 	pairingInfo := PairingContext{AteLoop: ateLoop, Extension: ext}
// 	pairingInfo.BTwistCoeff.A0 = cs.Constant(0)
// 	pairingInfo.BTwistCoeff.A1 = cs.Constant("155198655607781456406391640216936120121836107652948796323930557600032281009004493664981332883744016074664192874906")

// 	milRes := fields.E12{}
// 	//MillerLoopAffine(cs, circuit.P, circuit.Q, &milRes, pairingInfo)
// 	MillerLoop(cs, circuit.P, circuit.Q, &milRes, pairingInfo)

// 	return nil

// }

// func TestMillerLoop(t *testing.T) {

// 	var circuit ml

// 	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	fmt.Printf("%d constraints\n", r1cs.GetNbConstraints())

// }

func TestPairingBLS377(t *testing.T) {

	// pairing test data
	P, Q, pairingRes := pairingData()

	// create cs
	var circuit, witness pairingBLS377
	circuit.pairingRes = pairingRes
	r1cs, err := frontend.Compile(ecc.BW6_761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// assign values to witness
	witness.P.Assign(&P)
	witness.Q.Assign(&Q)

	assert := groth16.NewAssert(t)
	assert.SolvingSucceeded(r1cs, &witness)

}

func pairingData() (P bls12377.G1Affine, Q bls12377.G2Affine, pairingRes bls12377.GT) {
	_, _, P, Q = bls12377.Generators()
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes = bls12377.FinalExponentiation(&milRes)
	return
}

func mustbeEq(cs *frontend.ConstraintSystem, fp12 fields.E12, e12 *bls12377.GT) {
	cs.AssertIsEqual(fp12.C0.B0.A0, e12.C0.B0.A0)
	cs.AssertIsEqual(fp12.C0.B0.A1, e12.C0.B0.A1)
	cs.AssertIsEqual(fp12.C0.B1.A0, e12.C0.B1.A0)
	cs.AssertIsEqual(fp12.C0.B1.A1, e12.C0.B1.A1)
	cs.AssertIsEqual(fp12.C0.B2.A0, e12.C0.B2.A0)
	cs.AssertIsEqual(fp12.C0.B2.A1, e12.C0.B2.A1)
	cs.AssertIsEqual(fp12.C1.B0.A0, e12.C1.B0.A0)
	cs.AssertIsEqual(fp12.C1.B0.A1, e12.C1.B0.A1)
	cs.AssertIsEqual(fp12.C1.B1.A0, e12.C1.B1.A0)
	cs.AssertIsEqual(fp12.C1.B1.A1, e12.C1.B1.A1)
	cs.AssertIsEqual(fp12.C1.B2.A0, e12.C1.B2.A0)
	cs.AssertIsEqual(fp12.C1.B2.A1, e12.C1.B2.A1)
}
