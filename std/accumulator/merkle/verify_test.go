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
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

// MerkleProofTest used for testing onlys
type MerkleProofTest struct {
	M    MerkleProof
	Leaf frontend.Variable
}

func (mp *MerkleProofTest) Define(api frontend.API) error {

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	mp.M.VerifyProof(api, &h, mp.Leaf)

	return nil
}

func TestVerify(t *testing.T) {

	assert := test.NewAssert(t)
	numLeaves := 32
	depth := 5

	type testData struct {
		hash        hash.Hash
		segmentSize int
		curve       ecc.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, 32, ecc.BN254},
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

		// we test the circuit for all leaves...
		for proofIndex := uint64(0); proofIndex < 32; proofIndex++ {

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
			witness.Leaf = proofIndex
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
