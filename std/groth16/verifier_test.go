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
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	backend_bls377 "github.com/consensys/gnark/internal/backend/bls377/cs"
	groth16_bls377 "github.com/consensys/gnark/internal/backend/bls377/groth16"
	"github.com/consensys/gnark/internal/backend/bls377/witness"
	backend_bw761 "github.com/consensys/gnark/internal/backend/bw761/cs"
	"github.com/consensys/gnark/std/algebra/fields"
	"github.com/consensys/gnark/std/algebra/sw"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bls377"
)

//--------------------------------------------------------------------
// utils

const preimage string = "4992816046196248432836492760315135318126925090839638585255611512962528270024"
const publicHash string = "5100653184692120205048160297349714747883651904319528520089825735266585689318"

type mimcCircuit struct {
	Data frontend.Variable
	Hash frontend.Variable `gnark:",public"`
}

func (circuit *mimcCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	mimc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	result := mimc.Hash(cs, circuit.Data)
	cs.AssertIsEqual(result, circuit.Hash)
	return nil
}

// Prepare the data for the inner proof.
// Returns the public inputs string of the inner proof
func generateBls377InnerProof(t *testing.T, vk *groth16_bls377.VerifyingKey, proof *groth16_bls377.Proof) {

	// create a mock cs: knowing the preimage of a hash using mimc
	var circuit, w mimcCircuit
	r1cs, err := frontend.Compile(gurvy.BLS377, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	w.Data.Assign(preimage)
	w.Hash.Assign(publicHash)

	correctAssignment, err := witness.Full(&w)
	if err != nil {
		t.Fatal(err)
	}

	// generate the data to return for the bls377 proof
	var pk groth16_bls377.ProvingKey
	groth16_bls377.Setup(r1cs.(*backend_bls377.R1CS), &pk, vk)
	_proof, err := groth16_bls377.Prove(r1cs.(*backend_bls377.R1CS), &pk, correctAssignment, false)
	if err != nil {
		t.Fatal(err)
	}
	proof.Ar = _proof.Ar
	proof.Bs = _proof.Bs
	proof.Krs = _proof.Krs

	correctAssignmentPublic, err := witness.Public(&w)
	if err != nil {
		t.Fatal(err)
	}

	// before returning verifies that the proof passes on bls377
	if err := groth16_bls377.Verify(proof, vk, correctAssignmentPublic); err != nil {
		t.Fatal(err)
	}
}

type verifierCircuit struct {
	InnerProof Proof
	InnerVk    VerifyingKey
	Hash       frontend.Variable
}

func (circuit *verifierCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {

	// pairing data
	var pairingInfo sw.PairingContext
	pairingInfo.Extension = fields.GetBLS377ExtensionFp12(cs)
	pairingInfo.AteLoop = 9586122913090633729

	// create the verifier cs
	Verify(cs, pairingInfo, circuit.InnerVk, circuit.InnerProof, []frontend.Variable{circuit.Hash})

	return nil
}

func TestVerifier(t *testing.T) {

	// get the data
	var innerVk groth16_bls377.VerifyingKey
	var innerProof groth16_bls377.Proof
	generateBls377InnerProof(t, &innerVk, &innerProof) // get public inputs of the inner proof

	// create an empty cs
	var circuit verifierCircuit
	circuit.InnerVk.G1 = make([]sw.G1Affine, len(innerVk.G1.K))
	r1cs, err := frontend.Compile(gurvy.BW761, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	// create assignment, the private part consists of the proof,
	// the public part is exactly the public part of the inner proof,
	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
	var witness verifierCircuit
	witness.InnerProof.Ar.Assign(&innerProof.Ar)
	witness.InnerProof.Krs.Assign(&innerProof.Krs)
	witness.InnerProof.Bs.Assign(&innerProof.Bs)

	// compute vk.e
	e, err := bls377.Pair([]bls377.G1Affine{innerVk.G1.Alpha}, []bls377.G2Affine{innerVk.G2.Beta})
	if err != nil {
		t.Fatal(err)
	}
	witness.InnerVk.E.Assign(&e)

	witness.InnerVk.G1 = make([]sw.G1Affine, len(innerVk.G1.K))
	for i, vkg := range innerVk.G1.K {
		witness.InnerVk.G1[i].Assign(&vkg)
	}
	var deltaNeg, gammaNeg bls377.G2Affine
	deltaNeg.Neg(&innerVk.G2.Delta)
	gammaNeg.Neg(&innerVk.G2.Gamma)
	witness.InnerVk.G2.DeltaNeg.Assign(&deltaNeg)
	witness.InnerVk.G2.GammaNeg.Assign(&gammaNeg)
	witness.Hash.Assign(publicHash)

	// verifies the cs
	assertbw761 := groth16.NewAssert(t)

	assertbw761.SolvingSucceeded(r1cs.(*backend_bw761.R1CS), &witness)

	/* comment from here */

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

// TODO fixme
// func BenchmarkVerifier(b *testing.B) {

// 	// get the data
// 	var innerVk groth16_bls377.VerifyingKey
// 	var innerProof groth16_bls377.Proof
// 	inputNamesInnerProof := generateBls377InnerProof(nil, &innerVk, &innerProof) // get public inputs of the inner proof

// 	// create an empty cs
// 	var circuit XXXX
// 	r1cs, err := frontend.Compile(gurvy.XXXX, &circuit)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	// pairing data
// 	var pairingInfo sw.PairingContext
// 	pairingInfo.Extension = fields.GetBLS377ExtensionFp12(&cs)
// 	pairingInfo.AteLoop = 9586122913090633729

// 	// allocate the verifying key
// 	var innerVkCircuit VerifyingKey
// 	allocateInnerVk(&cs, &innerVk, &innerVkCircuit)

// 	// create secret inputs corresponding to the proof
// 	var innerProofCircuit Proof
// 	allocateInnerProof(&cs, &innerProofCircuit)

// 	// create the verifier cs
// 	Verify(&cs, pairingInfo, innerVkCircuit, innerProofCircuit, inputNamesInnerProof)

// 	// create r1cs
// 	r1cs := cs.ToR1CS().ToR1CS(gurvy.BW761)

// 	// create assignment, the private part consists of the proof,
// 	// the public part is exactly the public part of the inner proof,
// 	// up to the renaming of the inner ONE_WIRE to not conflict with the one wire of the outer proof.
// 	correctAssignment := make(map[string]interface{})
// 	assignPointAffineG1(correctAssignment, innerProof.Ar, "Ar")
// 	assignPointAffineG1(correctAssignment, innerProof.Krs, "Krs")
// 	assignPointAffineG2(correctAssignment, innerProof.Bs, "Bs")
// 	correctAssignment["public_hash"] = publicHash

// 	// verifies the cs
// 	b.ResetTimer()
// 	for i := 0; i < b.N; i++ {
// 		r1cs.Inspect(correctAssignment, false)
// 	}

// }
