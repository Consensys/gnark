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

package groth16

import (
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bls377 "github.com/consensys/gnark/backend/bls377"
	groth16_bls377 "github.com/consensys/gnark/backend/bls377/groth16"
	backend_bw761 "github.com/consensys/gnark/backend/bw761"
	groth16_bw761 "github.com/consensys/gnark/backend/bw761/groth16"
	mimcbls377 "github.com/consensys/gnark/crypto/hash/mimc/bls377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
	"github.com/consensys/gnark/gadgets/algebra/sw"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377"
	fr_bls377 "github.com/consensys/gurvy/bls377/fr"
)

//--------------------------------------------------------------------
// utils

const preimage string = "7808462342289447506325013279997289618334122576263655295146895675168642919487"
const publicHash string = "3099878450984161311009646042471309119414969843610576449039352395499643096414"

// Prepare the data for the inner proof.
// Returns the public inputs string of the inner proof
func generateBls377InnerProof(t *testing.T, vk *groth16_bls377.VerifyingKey, proof *groth16_bls377.Proof) []string {

	// create a mock circuit: knowing the preimage of a hash using mimc
	circuit := frontend.New()
	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BLS377)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
	}
	res := hFunc.Hash(&circuit, circuit.SECRET_INPUT("private_data"))
	circuit.MUSTBE_EQ(res, circuit.PUBLIC_INPUT("public_hash"))

	// build the r1cs from the circuit
	r1cs := backend_bls377.New(&circuit)

	// compute the public/private inputs using a real mimc
	var preimage, publicHash fr_bls377.Element
	b := mimcbls377.Sum("seed", preimage.Bytes())
	publicHash.SetBytes(b)

	// create the correct assignment
	correctAssignment := backend.NewAssignment()
	correctAssignment.Assign(backend.Secret, "private_data", preimage)
	correctAssignment.Assign(backend.Public, "public_hash", publicHash)

	// generate the data to return for the bls377 proof
	var pk groth16_bls377.ProvingKey
	groth16_bls377.Setup(&r1cs, &pk, vk)
	_proof, err := groth16_bls377.Prove(&r1cs, &pk, correctAssignment)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
	}
	proof.Ar = _proof.Ar
	proof.Bs = _proof.Bs
	proof.Krs = _proof.Krs

	// before returning verifies that the proof passes on bls377
	proofOk, err := groth16_bls377.Verify(proof, vk, correctAssignment)
	if err != nil {
		if t != nil {
			t.Fatal(err)
		}
	}
	if !proofOk {
		if t != nil {
			t.Fatal("error during bls377 proof verification")
		}
	}

	return r1cs.PublicWires

}

func newPointAffineCircuitG2(circuit *frontend.CS, s string) *sw.G2Aff {
	x := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"x0"), circuit.SECRET_INPUT(s+"x1"))
	y := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"y0"), circuit.SECRET_INPUT(s+"y1"))
	return sw.NewPointG2Aff(circuit, x, y)
}

func newPointCircuitG1(circuit *frontend.CS, s string) *sw.G1Aff {
	return sw.NewPointG1Aff(circuit,
		circuit.SECRET_INPUT(s+"0"),
		circuit.SECRET_INPUT(s+"1"),
	)
}

func allocateInnerVk(circuit *frontend.CS, vk *groth16_bls377.VerifyingKey, innerVk *VerifyingKey) {

	innerVk.E.C0.B0.X = circuit.ALLOCATE(vk.E.C0.B0.A0)
	innerVk.E.C0.B0.Y = circuit.ALLOCATE(vk.E.C0.B0.A1)
	innerVk.E.C0.B1.X = circuit.ALLOCATE(vk.E.C0.B1.A0)
	innerVk.E.C0.B1.Y = circuit.ALLOCATE(vk.E.C0.B1.A1)
	innerVk.E.C0.B2.X = circuit.ALLOCATE(vk.E.C0.B2.A0)
	innerVk.E.C0.B2.Y = circuit.ALLOCATE(vk.E.C0.B2.A1)
	innerVk.E.C1.B0.X = circuit.ALLOCATE(vk.E.C1.B0.A0)
	innerVk.E.C1.B0.Y = circuit.ALLOCATE(vk.E.C1.B0.A1)
	innerVk.E.C1.B1.X = circuit.ALLOCATE(vk.E.C1.B1.A0)
	innerVk.E.C1.B1.Y = circuit.ALLOCATE(vk.E.C1.B1.A1)
	innerVk.E.C1.B2.X = circuit.ALLOCATE(vk.E.C1.B2.A0)
	innerVk.E.C1.B2.Y = circuit.ALLOCATE(vk.E.C1.B2.A1)

	allocateG2(circuit, &innerVk.G2.DeltaNeg, &vk.G2.DeltaNeg)
	allocateG2(circuit, &innerVk.G2.GammaNeg, &vk.G2.GammaNeg)

	innerVk.G1 = make([]sw.G1Aff, len(vk.G1.K))
	for i := 0; i < len(vk.G1.K); i++ {
		allocateG1(circuit, &innerVk.G1[i], &vk.G1.K[i])
	}
}

func allocateInnerProof(circuit *frontend.CS, innerProof *Proof) {
	var Ar, Krs *sw.G1Aff
	var Bs *sw.G2Aff
	Ar = newPointCircuitG1(circuit, "Ar")
	Krs = newPointCircuitG1(circuit, "Krs")
	Bs = newPointAffineCircuitG2(circuit, "Bs")
	innerProof.Ar = *Ar
	innerProof.Krs = *Krs
	innerProof.Bs = *Bs
}

func allocateG2(circuit *frontend.CS, g2 *sw.G2Aff, g2Circuit *bls377.G2Affine) {
	g2.X.X = circuit.ALLOCATE(g2Circuit.X.A0)
	g2.X.Y = circuit.ALLOCATE(g2Circuit.X.A1)
	g2.Y.X = circuit.ALLOCATE(g2Circuit.Y.A0)
	g2.Y.Y = circuit.ALLOCATE(g2Circuit.Y.A1)
}

func allocateG1(circuit *frontend.CS, g1 *sw.G1Aff, g1Circuit *bls377.G1Affine) {
	g1.X = circuit.ALLOCATE(g1Circuit.X)
	g1.Y = circuit.ALLOCATE(g1Circuit.Y)
}

func assignPointAffineG2(inputs backend.Assignments, g bls377.G2Affine, s string) {
	inputs.Assign(backend.Secret, s+"x0", g.X.A0)
	inputs.Assign(backend.Secret, s+"x1", g.X.A1)
	inputs.Assign(backend.Secret, s+"y0", g.Y.A0)
	inputs.Assign(backend.Secret, s+"y1", g.Y.A1)
}

func assignPointAffineG1(inputs backend.Assignments, g bls377.G1Affine, s string) {
	inputs.Assign(backend.Secret, s+"0", g.X)
	inputs.Assign(backend.Secret, s+"1", g.Y)
}

//--------------------------------------------------------------------
// test

func TestVerifier(t *testing.T) {

	// get the data
	var innerVk groth16_bls377.VerifyingKey
	var innerProof groth16_bls377.Proof
	inputNamesInnerProof := generateBls377InnerProof(t, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty circuit
	circuit := frontend.New()

	// pairing data
	var pairingInfo sw.PairingContext
	pairingInfo.Extension = fields.GetBLS377ExtensionFp12(&circuit)
	pairingInfo.AteLoop = 9586122913090633729

	// allocate the verifying key
	var innerVkCircuit VerifyingKey
	allocateInnerVk(&circuit, &innerVk, &innerVkCircuit)

	// create secret inputs corresponding to the proof
	var innerProofCircuit Proof
	allocateInnerProof(&circuit, &innerProofCircuit)

	// create the verifier circuit
	Verify(&circuit, pairingInfo, innerVkCircuit, innerProofCircuit, inputNamesInnerProof)

	// create r1cs
	r1cs := backend_bw761.New(&circuit)

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	correctAssignment := backend.NewAssignment()
	assignPointAffineG1(correctAssignment, innerProof.Ar, "Ar")
	assignPointAffineG1(correctAssignment, innerProof.Krs, "Krs")
	assignPointAffineG2(correctAssignment, innerProof.Bs, "Bs")
	correctAssignment.Assign(backend.Public, "public_hash", publicHash)

	// verifies the circuit
	assertbw761 := groth16_bw761.NewAssert(t)

	assertbw761.CorrectExecution(&r1cs, correctAssignment, nil)

	// TODO uncommenting the lines below yield incredibly long testing time (due to the setup)
	// generate groth16 instance on bw761 (setup, prove, verify)
	// var vk groth16_bw761.VerifyingKey
	// var pk groth16_bw761.ProvingKey

	// groth16_bw761.Setup(&r1cs, &pk, &vk)
	// proof, err := groth16_bw761.Prove(&r1cs, &pk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// res, err := groth16_bw761.Verify(proof, &vk, correctAssignment)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// if !res {
	// 	t.Fatal("correct proof should pass")
	// }

}

//--------------------------------------------------------------------
// bench

func BenchmarkVerifier(b *testing.B) {

	// get the data
	var innerVk groth16_bls377.VerifyingKey
	var innerProof groth16_bls377.Proof
	inputNamesInnerProof := generateBls377InnerProof(nil, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty circuit
	circuit := frontend.New()

	// pairing data
	var pairingInfo sw.PairingContext
	pairingInfo.Extension = fields.GetBLS377ExtensionFp12(&circuit)
	pairingInfo.AteLoop = 9586122913090633729

	// allocate the verifying key
	var innerVkCircuit VerifyingKey
	allocateInnerVk(&circuit, &innerVk, &innerVkCircuit)

	// create secret inputs corresponding to the proof
	var innerProofCircuit Proof
	allocateInnerProof(&circuit, &innerProofCircuit)

	// create the verifier circuit
	Verify(&circuit, pairingInfo, innerVkCircuit, innerProofCircuit, inputNamesInnerProof)

	// create r1cs
	r1cs := backend_bw761.New(&circuit)

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	correctAssignment := backend.NewAssignment()
	assignPointAffineG1(correctAssignment, innerProof.Ar, "Ar")
	assignPointAffineG1(correctAssignment, innerProof.Krs, "Krs")
	assignPointAffineG2(correctAssignment, innerProof.Bs, "Bs")
	correctAssignment.Assign(backend.Public, "public_hash", publicHash)

	// verifies the circuit
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r1cs.Inspect(correctAssignment, false)
	}

}
