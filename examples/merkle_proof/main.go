// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Package main demonstrates the new simplified Merkle proof verification API.
//
// This example showcases how the new std/merkle package provides a much cleaner
// and easier-to-use interface compared to the previous approach.
package main

import (
	"bytes"
	"crypto/rand"
	"fmt"

	"github.com/consensys/gnark-crypto/accumulator/merkletree"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/merkle"
)

// AllowlistCircuit demonstrates a common use case: proving membership in an allowlist
// without revealing the full allowlist or the specific member's position.
type AllowlistCircuit struct {
	// Public inputs
	AllowlistRoot frontend.Variable `gnark:",public"` // The Merkle root of the allowlist

	// Private inputs - these remain secret
	MembershipProof merkle.MerkleProof `gnark:",secret"` // Proof that the address is in the allowlist
	Address         frontend.Variable  `gnark:",secret"` // The address to verify
	AddressIndex    frontend.Variable  `gnark:",secret"` // Position in the allowlist
}

// Define implements the circuit logic using the new simplified API
func (c *AllowlistCircuit) Define(api frontend.API) error {
	// Initialize the hash function
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// This is the entire verification logic with the new API!
	// Just one simple function call that handles all the complexity internally.
	merkle.AssertIsMember(api, &h, c.AllowlistRoot, c.MembershipProof, c.Address, c.AddressIndex)

	return nil
}

// PrivacyPreservingVotingCircuit demonstrates another use case: private voting
type PrivacyPreservingVotingCircuit struct {
	// Public inputs
	EligibleVotersRoot frontend.Variable `gnark:",public"` // Root of eligible voters tree
	Vote               frontend.Variable `gnark:",public"` // The vote (e.g., 0 or 1)

	// Private inputs
	VoterProof merkle.MerkleProof `gnark:",secret"` // Proof of voting eligibility
	VoterID    frontend.Variable  `gnark:",secret"` // Voter's ID
	VoterIndex frontend.Variable  `gnark:",secret"` // Position in eligible voters list
}

func (c *PrivacyPreservingVotingCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Prove the voter is eligible without revealing their identity
	merkle.AssertIsMember(api, &h, c.EligibleVotersRoot, c.VoterProof, c.VoterID, c.VoterIndex)

	// Additional constraints could be added here, such as:
	// - Ensuring the vote is valid (0 or 1)
	// - Nullifier checks to prevent double voting
	// - etc.

	return nil
}

func main() {
	fmt.Println("🌳 Merkle Proof Verification Example")
	fmt.Println("=====================================")

	// Step 1: Create a sample allowlist (Merkle tree)
	fmt.Println("\n1. Creating sample allowlist...")

	addresses := []string{
		"0x1234567890123456789012345678901234567890",
		"0x2345678901234567890123456789012345678901",
		"0x3456789012345678901234567890123456789012",
		"0x4567890123456789012345678901234567890123",
		"0x5678901234567890123456789012345678901234",
		"0x6789012345678901234567890123456789012345",
		"0x7890123456789012345678901234567890123456",
		"0x8901234567890123456789012345678901234567",
	}

	// Convert addresses to field elements and build Merkle tree
	mod := ecc.BN254.ScalarField()
	modNbBytes := len(mod.Bytes())

	var buf bytes.Buffer
	for range addresses {
		// In a real application, you'd hash the address properly
		// For this example, we'll use random values to represent hashed addresses
		leaf, err := rand.Int(rand.Reader, mod)
		if err != nil {
			panic(err)
		}
		b := leaf.Bytes()
		buf.Write(make([]byte, modNbBytes-len(b)))
		buf.Write(b)
	}

	// Step 2: Generate Merkle proof for a specific address
	fmt.Println("2. Generating Merkle proof for address at index 3...")

	targetIndex := uint64(3)
	hGo := hash.MIMC_BN254.New()
	merkleRoot, proofPath, _, err := merkletree.BuildReaderProof(&buf, hGo, 32, targetIndex)
	if err != nil {
		panic(err)
	}

	fmt.Printf("   Merkle root: %x\n", merkleRoot[:8]) // Show first 8 bytes
	fmt.Printf("   Proof depth: %d\n", len(proofPath)-1)

	// Step 3: Setup circuit and witness
	fmt.Println("3. Setting up circuit and witness...")

	depth := 3 // log2(8) = 3
	circuit := &AllowlistCircuit{
		MembershipProof: make(merkle.MerkleProof, depth),
	}

	witness := &AllowlistCircuit{
		AllowlistRoot:   merkleRoot,
		Address:         proofPath[0], // First element is the leaf
		AddressIndex:    targetIndex,
		MembershipProof: make(merkle.MerkleProof, depth),
	}

	// Copy proof path (skip first element which is the leaf)
	for i := 0; i < depth; i++ {
		witness.MembershipProof[i] = proofPath[i+1]
	}

	// Step 4: Compile the circuit
	fmt.Println("4. Compiling circuit...")

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		panic(err)
	}

	fmt.Printf("   Circuit constraints: %d\n", ccs.GetNbConstraints())

	// Step 5: Generate proving and verifying keys
	fmt.Println("5. Generating proving and verifying keys...")

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}

	// Step 6: Create witness and generate proof
	fmt.Println("6. Creating witness and generating proof...")

	witnessAssignment, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}

	proof, err := groth16.Prove(ccs, pk, witnessAssignment)
	if err != nil {
		panic(err)
	}

	// Step 7: Verify the proof
	fmt.Println("7. Verifying proof...")

	publicWitness, err := witnessAssignment.Public()
	if err != nil {
		panic(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("   ❌ Verification failed: %v\n", err)
	} else {
		fmt.Println("   ✅ Proof verified successfully!")
	}

	fmt.Println("\n🎉 Success!")
	fmt.Println("=============")
	fmt.Println("The new std/merkle package provides:")
	fmt.Println("• Simple, one-line API: merkle.AssertIsMember()")
	fmt.Println("• Reduced boilerplate code")
	fmt.Println("• Less chance for developer errors")
	fmt.Println("• Standardized Merkle proof verification")
	fmt.Println("• Easy integration into any gnark circuit")

	fmt.Println("\nCommon use cases:")
	fmt.Println("• 🔐 Allowlists and access control")
	fmt.Println("• 🗳️  Private voting systems")
	fmt.Println("• 🏦 State verification in blockchains")
	fmt.Println("• 🔒 Privacy-preserving authentication")
	fmt.Println("• 💰 Private set membership proofs")
}
