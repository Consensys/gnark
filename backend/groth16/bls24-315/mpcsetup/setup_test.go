// Copyright 2020 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	curve "github.com/consensys/gnark-crypto/ecc/bls24-315"
	"github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	cs "github.com/consensys/gnark/constraint/bls24-315"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/require"

	native_mimc "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/mimc"
)

func TestSetupCircuit(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 9
	)

	assert := require.New(t)

	srs1 := InitPhase1(power)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		// we clone test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.
		prev := srs1.clone()

		srs1.Contribute()
		assert.NoError(VerifyPhase1(&prev, &srs1))
	}

	// Compile the circuit
	var myCircuit Circuit
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)

	var evals Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)

	// Prepare for phase-2
	srs2, evals := InitPhase2(r1cs, &srs1)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase2; i++ {
		// we clone for test purposes; but in practice, participant will receive a []byte, deserialize it,
		// add his contribution and send back to coordinator.
		prev := srs2.clone()

		srs2.Contribute()
		assert.NoError(VerifyPhase2(&prev, &srs2))
	}

	// Extract the proving and verifying keys
	pk, vk := ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())

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
	proof, err := groth16.Prove(ccs, &pk, witness)
	assert.NoError(err)

	err = groth16.Verify(proof, &vk, pubWitness)
	assert.NoError(err)
}

func BenchmarkPhase1(b *testing.B) {
	const power = 14

	b.Run("init", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = InitPhase1(power)
		}
	})

	b.Run("contrib", func(b *testing.B) {
		srs1 := InitPhase1(power)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			srs1.Contribute()
		}
	})

}

func BenchmarkPhase2(b *testing.B) {
	const power = 14
	srs1 := InitPhase1(power)
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

	return nil
}

func (phase1 *Phase1) clone() Phase1 {
	r := Phase1{}
	r.Parameters.G1.Tau = append(r.Parameters.G1.Tau, phase1.Parameters.G1.Tau...)
	r.Parameters.G1.AlphaTau = append(r.Parameters.G1.AlphaTau, phase1.Parameters.G1.AlphaTau...)
	r.Parameters.G1.BetaTau = append(r.Parameters.G1.BetaTau, phase1.Parameters.G1.BetaTau...)

	r.Parameters.G2.Tau = append(r.Parameters.G2.Tau, phase1.Parameters.G2.Tau...)
	r.Parameters.G2.Beta = phase1.Parameters.G2.Beta

	r.PublicKeys = phase1.PublicKeys
	r.Hash = append(r.Hash, phase1.Hash...)

	return r
}

func (phase2 *Phase2) clone() Phase2 {
	r := Phase2{}
	r.Parameters.G1.Delta = phase2.Parameters.G1.Delta
	r.Parameters.G1.L = append(r.Parameters.G1.L, phase2.Parameters.G1.L...)
	r.Parameters.G1.Z = append(r.Parameters.G1.Z, phase2.Parameters.G1.Z...)
	r.Parameters.G2.Delta = phase2.Parameters.G2.Delta
	r.PublicKey = phase2.PublicKey
	r.Hash = append(r.Hash, phase2.Hash...)

	return r
}
