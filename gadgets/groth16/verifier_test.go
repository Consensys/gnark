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
	mimcbls377 "github.com/consensys/gnark/crypto/hash/mimc/bls377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/fields"
	"github.com/consensys/gnark/gadgets/algebra/sw"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
	fr_bls377 "github.com/consensys/gurvy/bls377/fr"
)

//--------------------------------------------------------------------
// utils

const preimage string = "7808462342289447506325013279997289618334122576263655295146895675168642919487"

func prepareData(t *testing.T, vk *groth16_bls377.VerifyingKey, proof *groth16_bls377.Proof) {

	// create a mock circuit: knowing the preimage of a hash using mimc
	circuit := frontend.New()
	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BLS377)
	if err != nil {
		t.Fatal(err)
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
	proof, err = groth16_bls377.Prove(&r1cs, &pk, correctAssignment)
	if err != nil {
		t.Fatal(err)
	}

	// before returning verifies that the proof passes on bls377
	proofOk, err := groth16_bls377.Verify(proof, vk, correctAssignment)
	if err != nil {
		t.Fatal(err)
	}
	if !proofOk {
		t.Fatal("error during bls377 proof verification")
	}
}

func newPointAffineCircuitG2(circuit *frontend.CS, s string) *sw.G2Aff {
	x := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"x0"), circuit.SECRET_INPUT(s+"x1"))
	y := fields.NewFp2Elmt(circuit, circuit.SECRET_INPUT(s+"y0"), circuit.SECRET_INPUT(s+"y1"))
	return sw.NewPointG2Aff(circuit, x, y)
}

func newPointCircuitG1(circuit *frontend.CS, s string) *sw.G1Jac {
	return sw.NewPointG1(circuit,
		circuit.SECRET_INPUT(s+"0"),
		circuit.SECRET_INPUT(s+"1"),
		circuit.SECRET_INPUT(s+"2"),
	)
}

//--------------------------------------------------------------------
// test

func TestVerifier(t *testing.T) {

	// get the data
	var vk groth16_bls377.VerifyingKey
	var proof groth16_bls377.Proof
	prepareData(t, &vk, &proof)

	// get the groth16 verifier circuit
	// circuit := frontend.New()
	// var embeddedProof Proof
	// var embeddedVK VerifyingKey

}
