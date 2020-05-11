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

// func TestLeaf(t *testing.T) {

// 	// computation of expected result
// 	leafPrefix := []byte{0x00}
// 	var leaf fr.Element
// 	leaf.SetRandom()
// 	h := bn256.NewMiMC("seed")
// 	h.Write(leafPrefix)
// 	h.Write(leaf.Bytes())
// 	binExpectedRes := h.Sum([]byte{})

// 	var tmp fr.Element
// 	tmp.SetBytes(binExpectedRes)
// 	expectedRes := make(map[string]fr.Element)
// 	expectedRes["res"] = tmp

// 	// computation of leafNode using gadget
// 	circuit := frontend.New()
// 	hg, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	res := leafSum(&circuit, hg, circuit.SECRET_INPUT("leaf"))
// 	res.Tag("res")
// 	assignment := backend_common.NewAssignment()
// 	assignment.Assign(backend_common.Secret, "leaf", leaf)

// 	r1cs := backend_bn256.New(&circuit)

// 	assert := groth16.NewAssert(t)
// 	assert.CorrectExecution(&r1cs, assignment, expectedRes)
// }

// func TestNode(t *testing.T) {

// 	// computation of expected result
// 	nodePrefix := []byte{0x01}
// 	var node1, node2 fr.Element
// 	node1.SetRandom()
// 	node2.SetRandom()
// 	h := bn256.NewMiMC("seed")
// 	h.Write(nodePrefix)
// 	h.Write(node1.Bytes())
// 	h.Write(node2.Bytes())
// 	binExpectedRes := h.Sum([]byte{})
// 	var tmp fr.Element
// 	tmp.SetBytes(binExpectedRes)
// 	expectedRes := make(map[string]fr.Element)
// 	expectedRes["res"] = tmp

// 	// computation of leafNode using gadget
// 	circuit := frontend.New()
// 	hg, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	res := nodeSum(&circuit, hg, circuit.SECRET_INPUT("node1"), circuit.SECRET_INPUT("node2"))
// 	res.Tag("res")
// 	assignment := backend_common.NewAssignment()
// 	assignment.Assign(backend_common.Secret, "node1", node1)
// 	assignment.Assign(backend_common.Secret, "node2", node2)

// 	r1cs := backend_bn256.New(&circuit)

// 	assert := groth16.NewAssert(t)
// 	assert.CorrectExecution(&r1cs, assignment, expectedRes)
// }

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
	path := make([]*frontend.Constraint, len(proof))
	for i := 0; i < len(proof); i++ {
		path[i] = circuit.SECRET_INPUT("path" + string(i))
	}
	helper := make([]*frontend.Constraint, len(proof)-1)
	for i := 0; i < len(proof)-1; i++ {
		helper[i] = circuit.SECRET_INPUT("helper" + string(i))
	}

	hFunc, err := mimc.NewMiMCGadget("seed", gurvy.BN256)
	if err != nil {
		t.Fatal(err)
	}
	VerifyProof(&circuit, hFunc, rh, path, helper)

	// compilation of the circuit
	r1cs := backend_bn256.New(&circuit)

	assignment := backend_common.NewAssignment()
	assignment.Assign(backend_common.Public, "rootHash", merkleRoot)
	for i := 0; i < len(proof); i++ {
		assignment.Assign(backend_common.Secret, "path"+string(i), proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		assignment.Assign(backend_common.Secret, "helper"+string(i), proofHelper[i])
	}

	assert := groth16.NewAssert(t)
	assert.Solved(&r1cs, assignment, nil)
}
