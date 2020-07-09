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

package merkle

import (
	"bytes"
	"os"
	"testing"

	backend_common "github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gnark/backend/bn256/groth16"
	"github.com/consensys/gnark/crypto/accumulator/merkletree"
	"github.com/consensys/gnark/crypto/hash/mimc/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

func TestVerify(t *testing.T) {

	// generate random data
	// makes sure that each chunk of 64 bits fits in a fr modulus, otherwise there are bugs due to the padding (domain separation)
	// TODO since when using mimc the user should be aware of this fact (otherwise one can easily finds collision), I am not sure we should take care of that in the code
	var buf bytes.Buffer
	for i := 0; i < 10; i++ {
		var leaf fr.Element
		leaf.SetRandom()
		buf.Write(leaf.Bytes())
	}

	// build & verify proof for an elmt in the file
	proofIndex := uint64(0)
	segmentSize := 32
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn256.NewMiMC("seed"), segmentSize, proofIndex)
	if err != nil {
		t.Fatal(err)
		os.Exit(-1)
	}
	proofHelper := GenerateProofHelper(proof, proofIndex, numLeaves)

	verified := merkletree.VerifyProof(bn256.NewMiMC("seed"), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The merkle proof in plain go should pass")
	}

	// create circuit
	circuit := frontend.New()

	// public root hash
	rh := circuit.PUBLIC_INPUT("rootHash")

	// private
	path := make([]frontend.CircuitVariable, len(proof))
	for i := 0; i < len(proof); i++ {
		path[i] = circuit.SECRET_INPUT("path" + string(i))
	}
	helper := make([]frontend.CircuitVariable, len(proof)-1)
	for i := 0; i < len(proof)-1; i++ {
		helper[i] = circuit.SECRET_INPUT("helper" + string(i))
	}

	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}
	VerifyProof(&circuit, hFunc, rh, path, helper)

	// compilation of the circuit
	r1cs := circuit.ToR1CS().ToR1CS(gurvy.BN256).(*backend_bn256.R1CS)

	assignment := backend_common.NewAssignment()
	assignment.Assign(backend_common.Public, "rootHash", merkleRoot)
	for i := 0; i < len(proof); i++ {
		assignment.Assign(backend_common.Secret, "path"+string(i), proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		assignment.Assign(backend_common.Secret, "helper"+string(i), proofHelper[i])
	}

	assert := groth16.NewAssert(t)
	assert.Solved(r1cs, assignment, nil)
}
