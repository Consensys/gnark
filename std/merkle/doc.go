// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

/*
Package merkle provides standardized, high-level gadgets for Merkle proof verification in gnark circuits.

This package addresses the need for a simple, consistent API for verifying Merkle proofs in ZK circuits,
as identified in GitHub issue #1528. It abstracts the complexity of manual proof verification and provides
a user-friendly interface that reduces boilerplate code and potential developer errors.

The main function, AssertIsMember, provides a clean API similar to the proposed:

	merkle.AssertIsMember(api, hasher, root, proof, leaf, leafIndex)

Example usage:

	import (
	    "github.com/consensys/gnark/frontend"
	    "github.com/consensys/gnark/std/hash/mimc"
	    "github.com/consensys/gnark/std/merkle"
	)

	type MyCircuit struct {
	    Root      frontend.Variable `gnark:",public"`
	    Proof     merkle.MerkleProof `gnark:",secret"`
	    Leaf      frontend.Variable `gnark:",secret"`
	    LeafIndex frontend.Variable `gnark:",secret"`
	}

	func (c *MyCircuit) Define(api frontend.API) error {
	    h, err := mimc.NewMiMC(api)
	    if err != nil {
	        return err
	    }

	    // Verify that the leaf is included in the Merkle tree
	    merkle.AssertIsMember(api, &h, c.Root, c.Proof, c.Leaf, c.LeafIndex)
	    return nil
	}

Common use cases include:

1. Allowlists: Prove that an address is in an allowlist without revealing the full list
2. State verification: Prove that a specific state transition is valid
3. Private set membership: Prove membership in a set without revealing the element or set
4. Blockchain light clients: Verify transactions are included in blocks
5. Privacy-preserving authentication: Prove access rights without revealing identity

The package provides several functions for different scenarios:
- AssertIsMember: Basic Merkle proof verification
- AssertIsMemberVariableDepth: For trees with variable depth
- AssertMultipleMemberships: Efficient verification of multiple proofs for the same tree
- VerifyProofAndRoot: Compute the root without assertion (useful for further calculations)

All functions are designed to work with the gnark frontend API and support any hash function
that implements the hash.FieldHasher interface.
*/
package merkle
