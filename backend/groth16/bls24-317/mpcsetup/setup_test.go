// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bls24-317"
	"github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	cs "github.com/consensys/gnark/constraint/bls24-317"
	"io"
	"slices"
	"sync"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/require"

	native_mimc "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/mimc"
)

// TestAll a full integration test of the MPC setup
func TestAll(t *testing.T) {
	testAll(t, 3, 3)
}

func testAll(t *testing.T, nbContributionsPhase1, nbContributionsPhase2 int) {
	assert := require.New(t)

	// Compile the circuit
	ccs := getTestCircuit()

	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var (
		bb bytes.Buffer // simulating network communications
		p1 Phase1
		p2 Phase2
	)
	serialized := make([][]byte, max(nbContributionsPhase1, nbContributionsPhase2))
	phase1 := make([]*Phase1, nbContributionsPhase1)
	phase2 := make([]*Phase2, nbContributionsPhase2)

	serialize := func(v io.WriterTo) []byte {
		bb.Reset()
		_, err := v.WriteTo(&bb)
		assert.NoError(err)
		return slices.Clone(bb.Bytes())
	}
	deserialize := func(v io.ReaderFrom, b []byte) {
		n, err := v.ReadFrom(bytes.NewReader(b))
		assert.NoError(err)
		assert.Equal(len(b), int(n))
	}

	p1.Initialize(domainSize)
	for i := range phase1 {
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
	assert.NoError(err)
	{
		var commonsRead SrsCommons
		deserialize(&commonsRead, serialize(&srsCommons))
		srsCommons = commonsRead
	}

	p2.Initialize(ccs, &srsCommons)
	for i := range phase2 {
		p2.Contribute()
		serialized[i] = serialize(&p2)
	}

	for i := range phase2 {
		phase2[i] = new(Phase2)
		deserialize(phase2[i], serialized[i])
	}

	pk, vk, err := VerifyPhase2(ccs, &srsCommons, []byte("testing phase2"), phase2[:]...)
	assert.NoError(err)

	proveVerifyCircuit(t, pk, vk)
}

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
	var p1 Phase1
	p1.Initialize(1 << power)
	p1.Contribute()
	commons := p1.Seal([]byte("testing"))

	var myCircuit Circuit
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	if err != nil {
		b.Fatal(err)
	}

	r1cs := ccs.(*cs.R1CS)

	b.Run("init", func(b *testing.B) {
		var p Phase2
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p.Initialize(r1cs, &commons)
		}
	})

	b.Run("contrib", func(b *testing.B) {
		var p Phase2
		p.Initialize(r1cs, &commons)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p.Contribute()
		}
	})

}

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

func assignCircuit() frontend.Circuit {

	// Build the witness
	var preImage, hash fr.Element

	m := native_mimc.NewMiMC()
	m.Write(preImage.Marshal())
	hash.SetBytes(m.Sum(nil))

	return &Circuit{PreImage: preImage, Hash: hash}

}

var onceCircuit = sync.OnceValue(func() *cs.R1CS {
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		panic(err)
	}
	return ccs.(*cs.R1CS)
})

func getTestCircuit() *cs.R1CS {
	return onceCircuit()
}

func proveVerifyCircuit(t *testing.T, pk groth16.ProvingKey, vk groth16.VerifyingKey) {

	witness, err := frontend.NewWitness(assignCircuit(), curve.ID.ScalarField())
	require.NoError(t, err)

	pubWitness, err := witness.Public()
	require.NoError(t, err)

	// groth16: ensure proof is verified
	proof, err := groth16.Prove(getTestCircuit(), pk, witness)
	require.NoError(t, err)

	err = groth16.Verify(proof, vk, pubWitness)
	require.NoError(t, err)
}
