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
	"fmt"
	"os"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/crypto/accumulator/merkletree"
	"github.com/consensys/gnark/crypto/hash/mimc/bn256"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *merkleCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	hFunc, err := mimc.NewMiMC("seed", curveID)
	if err != nil {
		return err
	}
	VerifyProof(cs, hFunc, circuit.RootHash, circuit.Path, circuit.Helper)
	return nil
}

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

	// create cs
	var circuit merkleCircuit
	circuit.Path = make([]frontend.Variable, len(proof))
	circuit.Helper = make([]frontend.Variable, len(proof)-1)
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	assignment := make(map[string]interface{})
	assignment["RootHash"] = merkleRoot
	for i := 0; i < len(proof); i++ {
		assignment[fmt.Sprintf("Path_%d", i)] = proof[i]
	}
	for i := 0; i < len(proof)-1; i++ {
		assignment[fmt.Sprintf("Helper_%d", i)] = proofHelper[i]
	}

	assert := groth16.NewAssert(t)
	assert.Solved(r1cs, assignment, nil)
}
