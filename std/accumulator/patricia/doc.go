// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

/*
Package patricia provides zero-knowledge proof circuits for verifying Ethereum Merkle-Patricia tree proofs.

Merkle-Patricia trees are the core data structure used by Ethereum to store and verify state data,
including account balances, storage slots, and transaction receipts. This package enables
zero-knowledge verification of Ethereum state inclusion proofs.

# Key Features

- Ethereum Merkle-Patricia Trie proof verification
- Support for all node types (empty, leaf, branch, extension)
- Keccak-256 hash function compatibility
- RLP encoding/decoding utilities
- Compact path encoding (hex-prefix encoding)

# Usage

The main entry point is the PatriciaVerifier which can verify inclusion proofs:

	// Create a Keccak-256 hasher for Ethereum compatibility
	hasher, err := sha3.NewKeccak256(api)
	if err != nil {
		return err
	}

	// Create Patricia tree verifier
	verifier := NewPatriciaVerifier(api, hasher)

	// Verify a proof
	result := verifier.VerifyProof(proof)

# Ethereum Compatibility

This implementation is designed to be compatible with Ethereum's modified Merkle-Patricia Trie.
It supports:

- State trie proofs (account data verification)
- Storage trie proofs (contract storage verification)
- Transaction trie proofs
- Receipt trie proofs

# Patricia Tree Structure

Ethereum uses a modified Merkle-Patricia Trie with four node types:

1. Empty Node: Represents an empty subtree
2. Leaf Node: Contains [encodedPath, value] where the path is compact-encoded
3. Extension Node: Contains [encodedPath, nextNodeHash] for path compression
4. Branch Node: Contains 17 elements [v0, v1, ..., v15, value] for 16-way branching

# Compact Encoding (Hex-Prefix Encoding)

Path fragments are encoded using hex-prefix encoding to handle odd/even length paths
and distinguish between leaf and extension nodes:

	| First nibble | Meaning |
	|--------------|---------|
	| 0000         | Extension node, even path length |
	| 0001         | Extension node, odd path length |
	| 0010         | Leaf node, even path length |
	| 0011         | Leaf node, odd path length |

# Performance Considerations

Patricia tree verification in zero-knowledge circuits is computationally expensive due to:

1. Keccak-256 hash function cost (hundreds of thousands of constraints per hash)
2. RLP decoding complexity
3. Variable-length data handling

For production use, consider:
- Limiting proof depth
- Batching multiple proofs
- Using more efficient hash functions when possible
- Migrating to Verkle trees when Ethereum adopts them

# Security Considerations

This implementation provides cryptographic verification that:
- The provided value exists at the specified key in the trie
- The trie has the specified root hash
- The proof path is valid and complete

However, users must ensure:
- The root hash comes from a trusted source (e.g., verified block header)
- The proof data is correctly formatted
- The key corresponds to the intended query

# Future Work

Ethereum is planning to migrate to Verkle trees, which will provide:
- Much smaller proof sizes
- More efficient verification
- Better scalability for light clients

This Patricia tree implementation serves as a bridge until that migration is complete.

# Example

Here's a complete example of verifying an Ethereum account balance:

	type AccountProofCircuit struct {
		AccountAddress []uints.U8    `gnark:",public"`
		StateRoot      []uints.U8    `gnark:",public"`
		AccountData    []uints.U8    `gnark:",public"`
		Proof          PatriciaProof `gnark:",secret"`
	}

	func (circuit *AccountProofCircuit) Define(api frontend.API) error {
		hasher, err := sha3.NewKeccak256(api)
		if err != nil {
			return err
		}

		verifier := NewPatriciaVerifier(api, hasher)

		// Hash the account address to get the trie key
		hasher.Write(circuit.AccountAddress)
		accountKey := hasher.Sum()

		// Set up the proof
		proof := circuit.Proof
		proof.Key = accountKey
		proof.Value = circuit.AccountData
		proof.RootHash = circuit.StateRoot
		proof.KeyNibbles = verifier.KeyToNibbles(accountKey)

		// Verify the proof
		result := verifier.VerifyProof(proof)
		api.AssertIsEqual(result, 1)

		return nil
	}

# References

- Ethereum Yellow Paper: https://ethereum.github.io/yellowpaper/paper.pdf
- Patricia Tree Specification: https://ethereum.org/en/developers/docs/data-structures-and-encoding/patricia-merkle-trie/
- RLP Encoding: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
- Verkle Trees: https://vitalik.ca/general/2021/06/18/verkle.html
*/
package patricia
