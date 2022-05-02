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
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type merkleCircuit struct {
	RootHash     frontend.Variable `gnark:",public"`
	Path, Helper []frontend.Variable
	// Leaf         frontend.Variable `gnark:",public"`
}

func (circuit *merkleCircuit) Define(api frontend.API) error {
	hFunc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	VerifyProof(api, &hFunc, circuit.RootHash, circuit.Path, circuit.Helper)
	return nil
}

func TestVerifyVV(t *testing.T) {

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
	merkleRoot, proof, numLeaves, err := merkletree.BuildReaderProof(&buf, bn254.NewMiMC(), segmentSize, proofIndex)
	if err != nil {
		t.Fatal(err)
		os.Exit(-1)
	}
	proofHelper := GenerateProofHelper(proof, proofIndex, numLeaves)

	//
	verified := merkletree.VerifyProof(bn254.NewMiMC(), merkleRoot, proof, proofIndex, numLeaves)
	if !verified {
		t.Fatal("The merkle proof in plain go should pass")
	}

	// create cs
	circuit := merkleCircuit{
		Path:   make([]frontend.Variable, len(proof)),
		Helper: make([]frontend.Variable, len(proof)-1),
	}

	witness := merkleCircuit{
		Path:     make([]frontend.Variable, len(proof)),
		Helper:   make([]frontend.Variable, len(proof)-1),
		RootHash: (merkleRoot),
	}

	for i := 0; i < len(proof); i++ {
		witness.Path[i] = (proof[i])
	}
	for i := 0; i < len(proof)-1; i++ {
		witness.Helper[i] = (proofHelper[i])
	}

	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
}

// MerkleProofTest used for testing onlys
type MerkleProofTest struct {
	M MerkleProof
}

func (mp *MerkleProofTest) Define(api frontend.API) error {

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProofBis(api, &h)

	return nil
}

func TestVerifyBis(t *testing.T) {

	assert := test.NewAssert(t)
	numLeaves := 64
	depth := 6

	type testData struct {
		hash        hash.Hash
		segmentSize int
		curve       ecc.ID
		leaves      []uint64
	}

	confs := []testData{
		{hash.MIMC_BN254, 32, ecc.BN254, []uint64{0, 30, 31, 10}},
	}

	rand.Seed(time.Now().UTC().UnixNano())
	for _, tData := range confs {

		// create the circuit
		var circuit MerkleProofTest
		circuit.M.Path = make([]frontend.Variable, depth+1)
		cc, err := frontend.Compile(tData.curve, r1cs.NewBuilder, &circuit)
		if err != nil {
			t.Fatal(err)
		}

		// generate the proof in plain go
		for _, proofIndex := range tData.leaves {

			// generate random data, the Merkle tree will be of depth log(64) = 6
			var buf bytes.Buffer
			for i := 0; i < numLeaves; i++ {
				for j := 0; j < tData.segmentSize; j++ {
					r := byte(rand.Int())
					buf.Write([]byte{r})
				}
			}

			// create the proof using the go code
			hGo := tData.hash.New()
			merkleRoot, proofPath, numLeaves, err := merkletree.BuildReaderProof(&buf, hGo, tData.segmentSize, proofIndex)
			if err != nil {
				t.Fatal(err)
				os.Exit(-1)
			}

			// verfiy the proof in plain go
			verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, proofIndex, numLeaves)
			if !verified {
				t.Fatal("The merkle proof in plain go should pass")
			}

			// witness
			var witness MerkleProofTest
			witness.M.Leaf = proofIndex
			witness.M.RootHash = merkleRoot
			witness.M.Path = make([]frontend.Variable, depth+1)
			for i := 0; i < depth+1; i++ {
				witness.M.Path[i] = proofPath[i]
			}

			w, err := frontend.NewWitness(&witness, tData.curve)
			if err != nil {
				t.Fatal(err)
			}
			logger.SetOutput(os.Stdout)
			err = cc.IsSolved(w, backend.IgnoreSolverError(), backend.WithCircuitLogger(logger.Logger()))
			if err != nil {
				t.Fatal(err)
			}

			// verify the circuit
			assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(tData.curve))
		}

	}

}
