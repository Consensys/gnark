// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package merkle provides high-level gadgets for Merkle proof verification in ZK circuits.
//
// This package offers a standardized, easy-to-use API for verifying Merkle proofs,
// abstracting the complexity of path calculations and hash operations.
//
// Example usage:
//
//	import (
//		"github.com/consensys/gnark/frontend"
//		"github.com/consensys/gnark/std/hash/mimc"
//		"github.com/consensys/gnark/std/merkle"
//	)
//
//	func (circuit *MyCircuit) Define(api frontend.API) error {
//		h, err := mimc.NewMiMC(api)
//		if err != nil {
//			return err
//		}
//
//		// Verify that 'leaf' is included in the Merkle tree with 'root'
//		merkle.AssertIsMember(api, &h, circuit.Root, circuit.Proof, circuit.Leaf, circuit.LeafIndex)
//		return nil
//	}
package merkle

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// MerkleProof represents a Merkle inclusion proof consisting of sibling hashes
// along the path from a leaf to the root.
type MerkleProof []frontend.Variable

// AssertIsMember verifies that a leaf is included in a Merkle tree with the given root.
// It takes the tree root, a Merkle proof (path of sibling hashes), the leaf value,
// and the leaf's index in the tree.
//
// This function abstracts the complex loop of hash calculations and provides a
// standardized way to verify Merkle proofs in ZK circuits.
//
// Parameters:
//   - api: The frontend API for circuit operations
//   - h: The hash function to use (must implement hash.FieldHasher)
//   - root: The expected Merkle tree root
//   - proof: Slice of sibling hashes along the path from leaf to root
//   - leaf: The leaf value to verify inclusion for
//   - leafIndex: The index of the leaf in the tree (used to determine path direction)
//
// The function will constraint the circuit to fail if the proof is invalid.
func AssertIsMember(api frontend.API, h hash.FieldHasher, root frontend.Variable, proof MerkleProof, leaf frontend.Variable, leafIndex frontend.Variable) {
	// Start with the leaf hash
	h.Reset()
	h.Write(leaf)
	currentHash := h.Sum()

	// Get the binary representation of the leaf index to determine path direction
	// The length should match the proof length (tree depth)
	indexBits := api.ToBinary(leafIndex, len(proof))

	// Traverse up the tree using the proof
	for i, sibling := range proof {
		h.Reset()

		// Use the index bit to determine hash order:
		// - If bit is 0: hash(currentHash, sibling) - we're the left child
		// - If bit is 1: hash(sibling, currentHash) - we're the right child
		left := api.Select(indexBits[i], sibling, currentHash)
		right := api.Select(indexBits[i], currentHash, sibling)

		h.Write(left, right)
		currentHash = h.Sum()
	}

	// Assert that the computed root matches the expected root
	api.AssertIsEqual(currentHash, root)
}

// AssertIsMemberVariableDepth verifies Merkle inclusion for trees with variable depth.
// This is useful when the tree depth is not known at compile time.
//
// Parameters:
//   - api: The frontend API for circuit operations
//   - h: The hash function to use
//   - root: The expected Merkle tree root
//   - proof: Slice of sibling hashes (may contain padding for unused levels)
//   - leaf: The leaf value to verify inclusion for
//   - leafIndex: The index of the leaf in the tree
//   - depth: The actual depth of the tree (proof elements beyond this are ignored)
//
// Note: The proof slice must be at least 'depth' elements long.
func AssertIsMemberVariableDepth(api frontend.API, h hash.FieldHasher, root frontend.Variable, proof MerkleProof, leaf frontend.Variable, leafIndex frontend.Variable, depth frontend.Variable) {
	// Start with the leaf hash
	h.Reset()
	h.Write(leaf)
	currentHash := h.Sum()

	// We need to determine the maximum possible depth for ToBinary
	maxDepth := len(proof)
	indexBits := api.ToBinary(leafIndex, maxDepth)

	// Traverse up the tree, but only for the specified depth
	for i := 0; i < maxDepth; i++ {
		// Check if we should process this level
		iVariable := frontend.Variable(i)
		shouldProcess := api.IsZero(api.Sub(api.Sub(depth, iVariable), 1))

		h.Reset()

		// Determine hash order based on index bit
		left := api.Select(indexBits[i], proof[i], currentHash)
		right := api.Select(indexBits[i], currentHash, proof[i])

		h.Write(left, right)
		newHash := h.Sum()

		// Only update currentHash if we should process this level
		currentHash = api.Select(shouldProcess, newHash, currentHash)
	}

	// Assert that the computed root matches the expected root
	api.AssertIsEqual(currentHash, root)
}

// AssertMultipleMemberships efficiently verifies multiple Merkle inclusion proofs
// for the same tree root. This can be more efficient than calling AssertIsMember
// multiple times when verifying many leaves.
//
// Parameters:
//   - api: The frontend API for circuit operations
//   - h: The hash function to use
//   - root: The expected Merkle tree root
//   - proofs: Slice of Merkle proofs, one for each leaf
//   - leaves: Slice of leaf values to verify
//   - leafIndices: Slice of leaf indices corresponding to each leaf
//
// All slices must have the same length.
func AssertMultipleMemberships(api frontend.API, h hash.FieldHasher, root frontend.Variable, proofs []MerkleProof, leaves []frontend.Variable, leafIndices []frontend.Variable) {
	// Verify that all slices have the same length
	if len(proofs) != len(leaves) || len(leaves) != len(leafIndices) {
		panic("AssertMultipleMemberships: mismatched slice lengths")
	}

	// Verify each proof independently
	for i := 0; i < len(leaves); i++ {
		AssertIsMember(api, h, root, proofs[i], leaves[i], leafIndices[i])
	}
}

// VerifyProofAndRoot computes and returns the Merkle root for a given leaf and proof,
// without asserting equality to an expected root. This can be useful when you want
// to compute the root and use it in further calculations.
//
// Parameters:
//   - api: The frontend API for circuit operations
//   - h: The hash function to use
//   - proof: The Merkle proof (sibling hashes)
//   - leaf: The leaf value
//   - leafIndex: The index of the leaf in the tree
//
// Returns:
//   - The computed Merkle root
func VerifyProofAndRoot(api frontend.API, h hash.FieldHasher, proof MerkleProof, leaf frontend.Variable, leafIndex frontend.Variable) frontend.Variable {
	// Start with the leaf hash
	h.Reset()
	h.Write(leaf)
	currentHash := h.Sum()

	// Get the binary representation of the leaf index
	indexBits := api.ToBinary(leafIndex, len(proof))

	// Traverse up the tree using the proof
	for i, sibling := range proof {
		h.Reset()

		// Determine hash order based on index bit
		left := api.Select(indexBits[i], sibling, currentHash)
		right := api.Select(indexBits[i], currentHash, sibling)

		h.Write(left, right)
		currentHash = h.Sum()
	}

	return currentHash
}
