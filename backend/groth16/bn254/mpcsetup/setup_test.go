// Copyright 2020-2024 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	cs "github.com/consensys/gnark/constraint/bn254"
	"io"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/require"

	native_mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
)

// TestSetupCircuit a full integration test of the MPC setup
func TestSetupCircuit(t *testing.T) {
	const (
		nbContributionsPhase1 = 3
		nbContributionsPhase2 = 3
	)

	assert := require.New(t)

	// Compile the circuit
	var circuit Circuit
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)

	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var (
		bb         bytes.Buffer // simulating network communications
		serialized [max(nbContributionsPhase1, nbContributionsPhase2)][]byte
		phase1     [nbContributionsPhase1]*Phase1
		p1         Phase1
		phase2     [nbContributionsPhase2]*Phase2
		p2         Phase2
	)

	serialize := func(v io.WriterTo) []byte {
		bb.Reset()
		_, err = v.WriteTo(&bb)
		assert.NoError(err)
		return bb.Bytes()
	}
	deserialize := func(v io.ReaderFrom, b []byte) {
		n, err := v.ReadFrom(bytes.NewReader(b))
		assert.NoError(err)
		assert.Equal(len(b), int(n))
	}

	// Make contributions for serialized
	for i := range phase1 {
		if i == 0 { // no "predecessor" to the first contribution
			p1.Initialize(domainSize)
		}

		p1.Contribute()
		serialized[i] = serialize(&p1)
	}

	// read all Phase1 objects
	for i := range phase1 {
		phase1[i] = new(Phase1)
		deserialize(phase1[i], serialized[i])
	}

	// Verify contributions for phase 1 and generate non-circuit-specific parameters
	srsCommons, err := VerifyPhase1(domainSize, []byte("testing phase1"), phase1[:]...)
	{
		var commonsRead SrsCommons
		deserialize(&commonsRead, serialize(&srsCommons))
		srsCommons = commonsRead
	}

	r1cs := ccs.(*cs.R1CS)

	// Prepare for phase-2
	for i := range phase2 {
		if i == 0 {
			p2.Initialize(r1cs, &srsCommons)
		}
		p2.Contribute()
		serialized[i] = serialize(&p2)
	}

	for i := range phase2 {
		phase2[i] = new(Phase2)
		deserialize(phase2[i], serialized[i])
	}

	pk, vk, err := VerifyPhase2(r1cs, &srsCommons, []byte("testing phase2"), phase2[:]...)
	assert.NoError(err)

	// Build the witness
	var preImage, hash fr.Element
	{
		m := native_mimc.NewMiMC()
		m.Write(preImage.Marshal())
		hash.SetBytes(m.Sum(nil))
	}

	witness, err := frontend.NewWitness(&Circuit{PreImage: preImage, Hash: hash}, curve.ID.ScalarField())
	assert.NoError(err)

	pubWitness, err := witness.Public()
	assert.NoError(err)

	// groth16: ensure proof is verified
	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err)

	err = groth16.Verify(proof, vk, pubWitness)
	assert.NoError(err)
}

/*
func BenchmarkPhase1(b *testing.B) {
	const power = 14

	b.Run("init", func(b *testing.B) {
		b.ResetTimer()
		var srs1 Phase1
		for i := 0; i < b.N; i++ {
			srs1.Initialize(1 << power)
		}
	})

	b.Run("contrib", func(b *testing.B) {
		var srs1 Phase1
		srs1.Initialize(1 << power)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srs1.Contribute()
		}
	})

}

func BenchmarkPhase2(b *testing.B) {
	const power = 14
	var srs1 Phase1
	srs1.Initialize(1 << power)
	srs1.Contribute()

	var myCircuit Circuit
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		b.Fatal(err)
	}

	r1cs := ccs.(*cs.R1CS)

	b.Run("init", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = InitPhase2(r1cs, &srs1)
		}
	})

	b.Run("contrib", func(b *testing.B) {
		srs2, _ := InitPhase2(r1cs, &srs1)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srs2.Contribute()
		}
	})

}
*/
// Circuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type Circuit struct {
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *Circuit) Define(api frontend.API) error {
	// hash function
	mimc, _ := mimc.NewMiMC(api)

	// specify constraints
	mimc.Write(circuit.PreImage)
	api.AssertIsEqual(circuit.Hash, mimc.Sum())

	c, err := api.(frontend.Committer).Commit(circuit.PreImage, circuit.Hash)
	api.AssertIsDifferent(c, 0)

	return err
}
