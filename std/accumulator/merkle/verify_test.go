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

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
}

func (circuit *merkleCircuit) Define(curveID ecc.ID, cs *frontend.ConstraintSystem) error {
	hFunc, err := mimc.NewMiMC("seed", curveID, cs)
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
		if _, err := leaf.SetRandom(); err != nil {
			t.Fatal(err)
		}
		b := leaf.Bytes()
		buf.Write(b[:])
	}

	// build & verify proof for an elmt in the file
	proofIndex := uint64(0)
	segmentSize := 32
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC("seed"), segmentSize, proofIndex)
	if err != nil {
		t.Fatal(err)
		os.Exit(-1)
	}
	proofHelper := GenerateProofHelper(proof, proofIndex, numLeaves)

	verified := merkletree.VerifyProof(bn254.NewMiMC("seed"), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The merkle proof in plain go should pass")
	}

	// create cs
	var circuit, witness merkleCircuit
	circuit.Path = make([]frontend.Variable, len(proof))
	circuit.Helper = make([]frontend.Variable, len(proof)-1)
	witness.Path = make([]frontend.Variable, len(proof))
	witness.Helper = make([]frontend.Variable, len(proof)-1)
	r1cs, err := frontend.Compile(ecc.BN254, backend.GROTH16, &circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness.RootHash.Assign(merkleRoot)

	for i := 0; i < len(proof); i++ {
		witness.Path[i].Assign(proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		witness.Helper[i].Assign(proofHelper[i])
	}

	assert := groth16.NewAssert(t)
	assert.ProverSucceeded(r1cs, &witness)
}
