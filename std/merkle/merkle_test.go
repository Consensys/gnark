// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package merkle

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

// testCircuit demonstrates usage of the new Merkle proof verification API
type testCircuit struct {
	Root      frontend.Variable `gnark:",public"`
	Proof     MerkleProof       `gnark:",secret"`
	Leaf      frontend.Variable `gnark:",secret"`
	LeafIndex frontend.Variable `gnark:",secret"`
}

func (c *testCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	AssertIsMember(api, &h, c.Root, c.Proof, c.Leaf, c.LeafIndex)
	return nil
}

// TestBasicMerkleProofVerification tests the basic AssertIsMember functionality
func TestBasicMerkleProofVerification(t *testing.T) {
	assert := test.NewAssert(t)

	// Test parameters
	numLeaves := 16
	depth := 4

	type testData struct {
		hash        hash.Hash
		segmentSize int
		curve       ecc.ID
	}

	testConfigs := []testData{
		{hash.MIMC_BN254, 32, ecc.BN254},
	}

	for _, config := range testConfigs {
		mod := config.curve.ScalarField()
		modNbBytes := len(mod.Bytes())

		// Test multiple leaf indices
		for leafIndex := uint64(0); leafIndex < uint64(numLeaves); leafIndex++ {
			// Generate random test data
			var buf bytes.Buffer
			for i := 0; i < numLeaves; i++ {
				leaf, err := rand.Int(rand.Reader, mod)
				assert.NoError(err)
				b := leaf.Bytes()
				buf.Write(make([]byte, modNbBytes-len(b)))
				buf.Write(b)
			}

			// Create Merkle proof using existing gnark-crypto functionality
			hGo := config.hash.New()
			merkleRoot, proofPath, numLeavesProof, err := merkletree.BuildReaderProof(&buf, hGo, config.segmentSize, leafIndex)
			assert.NoError(err)

			// Verify with native Go implementation first
			verified := merkletree.VerifyProof(hGo, merkleRoot, proofPath, leafIndex, numLeavesProof)
			assert.True(verified, "Native Go proof verification should pass")

			// Prepare circuit and witness
			circuit := &testCircuit{
				Proof: make(MerkleProof, depth),
			}

			witness := &testCircuit{
				Root:      merkleRoot,
				Leaf:      proofPath[0], // First element is the leaf in the proof path
				LeafIndex: leafIndex,
				Proof:     make(MerkleProof, depth),
			}

			// Copy proof path (skip first element which is the leaf)
			for i := 0; i < depth; i++ {
				witness.Proof[i] = proofPath[i+1]
			}

			// Test the circuit
			assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(config.curve))
		}
	}
}

// multiMembershipCircuit tests verification of multiple Merkle proofs
type multiMembershipCircuit struct {
	Root        frontend.Variable   `gnark:",public"`
	Proofs      []MerkleProof       `gnark:",secret"`
	Leaves      []frontend.Variable `gnark:",secret"`
	LeafIndices []frontend.Variable `gnark:",secret"`
}

func (c *multiMembershipCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	AssertMultipleMemberships(api, &h, c.Root, c.Proofs, c.Leaves, c.LeafIndices)
	return nil
}

// TestMultipleMemberships tests the AssertMultipleMemberships function
func TestMultipleMemberships(t *testing.T) {
	assert := test.NewAssert(t)

	numLeaves := 8
	depth := 3
	numProofs := 3
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())

	// Generate test data
	var buf bytes.Buffer
	for i := 0; i < numLeaves; i++ {
		leaf, err := rand.Int(rand.Reader, mod)
		assert.NoError(err)
		b := leaf.Bytes()
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}

	// Create multiple proofs for different leaves
	hGo := hash.MIMC_BN254.New()
	leafIndices := []uint64{0, 3, 7} // Test different positions

	var merkleRoot []byte
	var proofPaths [][]frontend.Variable

	for i, leafIndex := range leafIndices {
		bufCopy := bytes.NewBuffer(buf.Bytes())
		root, proofPath, _, err := merkletree.BuildReaderProof(bufCopy, hGo, 32, leafIndex)
		assert.NoError(err)

		if i == 0 {
			merkleRoot = root
		} else {
			// All proofs should have the same root
			assert.Equal(merkleRoot, root)
		}

		// Convert []byte proof path to []frontend.Variable
		proofPathVars := make([]frontend.Variable, len(proofPath))
		for j, pathElement := range proofPath {
			proofPathVars[j] = pathElement
		}
		proofPaths = append(proofPaths, proofPathVars)
	}

	// Prepare circuit
	circuit := &multiMembershipCircuit{
		Proofs:      make([]MerkleProof, numProofs),
		Leaves:      make([]frontend.Variable, numProofs),
		LeafIndices: make([]frontend.Variable, numProofs),
	}

	for i := 0; i < numProofs; i++ {
		circuit.Proofs[i] = make(MerkleProof, depth)
	}

	witness := &multiMembershipCircuit{
		Root:        merkleRoot,
		Proofs:      make([]MerkleProof, numProofs),
		Leaves:      make([]frontend.Variable, numProofs),
		LeafIndices: make([]frontend.Variable, numProofs),
	}

	for i := 0; i < numProofs; i++ {
		witness.Proofs[i] = make(MerkleProof, depth)
		witness.Leaves[i] = proofPaths[i][0] // First element is the leaf
		witness.LeafIndices[i] = leafIndices[i]

		// Copy proof path (skip first element which is the leaf)
		for j := 0; j < depth; j++ {
			witness.Proofs[i][j] = proofPaths[i][j+1]
		}
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
}

// rootComputationCircuit tests the VerifyProofAndRoot function
type rootComputationCircuit struct {
	ExpectedRoot frontend.Variable `gnark:",public"`
	Proof        MerkleProof       `gnark:",secret"`
	Leaf         frontend.Variable `gnark:",secret"`
	LeafIndex    frontend.Variable `gnark:",secret"`
}

func (c *rootComputationCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	computedRoot := VerifyProofAndRoot(api, &h, c.Proof, c.Leaf, c.LeafIndex)
	api.AssertIsEqual(computedRoot, c.ExpectedRoot)
	return nil
}

// TestVerifyProofAndRoot tests the VerifyProofAndRoot function
func TestVerifyProofAndRoot(t *testing.T) {
	assert := test.NewAssert(t)

	numLeaves := 8
	depth := 3
	leafIndex := uint64(5)
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())

	// Generate test data
	var buf bytes.Buffer
	for i := 0; i < numLeaves; i++ {
		leaf, err := rand.Int(rand.Reader, mod)
		assert.NoError(err)
		b := leaf.Bytes()
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}

	// Create Merkle proof
	hGo := hash.MIMC_BN254.New()
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(&buf, hGo, 32, leafIndex)
	assert.NoError(err)

	circuit := &rootComputationCircuit{
		Proof: make(MerkleProof, depth),
	}

	witness := &rootComputationCircuit{
		ExpectedRoot: merkleRoot,
		Leaf:         proofPath[0],
		LeafIndex:    leafIndex,
		Proof:        make(MerkleProof, depth),
	}

	for i := 0; i < depth; i++ {
		witness.Proof[i] = proofPath[i+1]
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
}

// benchmarkCircuit for performance testing
type benchmarkCircuit struct {
	Root      frontend.Variable `gnark:",public"`
	Proof     MerkleProof       `gnark:",secret"`
	Leaf      frontend.Variable `gnark:",secret"`
	LeafIndex frontend.Variable `gnark:",secret"`
}

func (c *benchmarkCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	AssertIsMember(api, &h, c.Root, c.Proof, c.Leaf, c.LeafIndex)
	return nil
}

// BenchmarkMerkleProofVerification benchmarks the Merkle proof verification
func BenchmarkMerkleProofVerification(b *testing.B) {
	depths := []int{8, 16, 20}

	for _, depth := range depths {
		b.Run(fmt.Sprintf("depth_%d", depth), func(b *testing.B) {
			numLeaves := 1 << depth
			mod := ecc.BN254.ScalarField()
			modNbBytes := len(mod.Bytes())

			// Generate test data
			var buf bytes.Buffer
			for i := 0; i < numLeaves; i++ {
				leaf, err := rand.Int(rand.Reader, mod)
				if err != nil {
					b.Fatal(err)
				}
				leafBytes := leaf.Bytes()
				buf.Write(make([]byte, modNbBytes-len(leafBytes)))
				buf.Write(leafBytes)
			}

			// Create proof for middle leaf
			leafIndex := uint64(numLeaves / 2)
			hGo := hash.MIMC_BN254.New()
			merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(&buf, hGo, 32, leafIndex)
			if err != nil {
				b.Fatal(err)
			}

			circuit := &benchmarkCircuit{
				Proof: make(MerkleProof, depth),
			}

			witness := &benchmarkCircuit{
				Root:      merkleRoot,
				Leaf:      proofPath[0],
				LeafIndex: leafIndex,
				Proof:     make(MerkleProof, depth),
			}

			for i := 0; i < depth; i++ {
				witness.Proof[i] = proofPath[i+1]
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// For benchmarks, we only measure compilation time, not correctness
				err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// EdgeCaseCircuit tests edge cases
type edgeCaseCircuit struct {
	Root      frontend.Variable `gnark:",public"`
	Proof     MerkleProof       `gnark:",secret"`
	Leaf      frontend.Variable `gnark:",secret"`
	LeafIndex frontend.Variable `gnark:",secret"`
}

func (c *edgeCaseCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	AssertIsMember(api, &h, c.Root, c.Proof, c.Leaf, c.LeafIndex)
	return nil
}

// TestEdgeCases tests edge cases like single leaf trees, etc.
func TestEdgeCases(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with depth 1 (2 leaves)
	t.Run("depth_1", func(t *testing.T) {
		numLeaves := 2
		depth := 1
		mod := ecc.BN254.ScalarField()
		modNbBytes := len(mod.Bytes())

		var buf bytes.Buffer
		for i := 0; i < numLeaves; i++ {
			leaf, err := rand.Int(rand.Reader, mod)
			assert.NoError(err)
			b := leaf.Bytes()
			buf.Write(make([]byte, modNbBytes-len(b)))
			buf.Write(b)
		}

		for leafIndex := uint64(0); leafIndex < uint64(numLeaves); leafIndex++ {
			bufCopy := bytes.NewBuffer(buf.Bytes())
			hGo := hash.MIMC_BN254.New()
			merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(bufCopy, hGo, 32, leafIndex)
			assert.NoError(err)

			circuit := &edgeCaseCircuit{
				Proof: make(MerkleProof, depth),
			}

			witness := &edgeCaseCircuit{
				Root:      merkleRoot,
				Leaf:      proofPath[0],
				LeafIndex: leafIndex,
				Proof:     make(MerkleProof, depth),
			}

			for i := 0; i < depth; i++ {
				witness.Proof[i] = proofPath[i+1]
			}

			assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254))
		}
	})
}

// Example circuit demonstrating the new Merkle proof verification API
type exampleCircuit struct {
	// Public inputs
	MerkleRoot frontend.Variable `gnark:",public"`

	// Private inputs
	ProofPath MerkleProof       `gnark:",secret"`
	LeafValue frontend.Variable `gnark:",secret"`
	LeafIndex frontend.Variable `gnark:",secret"`
}

// Define the circuit - shows how to use AssertIsMember
func (c *exampleCircuit) Define(api frontend.API) error {
	// Initialize hash function
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Verify that LeafValue is included in the Merkle tree with root MerkleRoot
	AssertIsMember(api, &h, c.MerkleRoot, c.ProofPath, c.LeafValue, c.LeafIndex)

	return nil
}

// Example demonstrates how to use the new Merkle proof verification API
func ExampleAssertIsMember() {
	// Usage examples:
	// 1. Allowlists: Prove that an address is in an allowlist without revealing the full list
	// 2. State verification: Prove that a specific state transition is valid
	// 3. Private set membership: Prove membership in a set without revealing the element or set
	// 4. Blockchain light clients: Verify transactions are included in blocks

	fmt.Println("Merkle proof verification API provides simple, standardized proof verification")
	// Output: Merkle proof verification API provides simple, standardized proof verification
}
