// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package mpcsetup

import (
	"bytes"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-633"
	"github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	groth16Impl "github.com/consensys/gnark/backend/groth16/bw6-633"
	cs "github.com/consensys/gnark/constraint/bw6-633"
	"io"
	"math/big"
	"slices"
	"sync"
	"testing"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/utils/test_utils"
	gnarkio "github.com/consensys/gnark/io"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/require"

	native_mimc "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/mimc"
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

var getTestCircuit = sync.OnceValue(func() *cs.R1CS {
	ccs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		panic(err)
	}
	return ccs.(*cs.R1CS)
})

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

// TestSetupBeaconOnly tests the setup/key extraction
// as well as the random beacon contribution
// without any untrusted contributors
func TestSetupBeaconOnly(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	// Compile the circuit
	ccs := getTestCircuit()
	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var (
		p1 Phase1
		p2 Phase2
	)
	p1.Initialize(domainSize)
	commons := p1.Seal([]byte("beacon 1"))

	evals := p2.Initialize(ccs, &commons)
	pk, vk := p2.Seal(&commons, &evals, []byte("beacon 2"))

	_pk := pk.(*groth16Impl.ProvingKey)

	rpk, rvk, err := groth16.Setup(ccs)
	require.NoError(t, err)
	_rpk := rpk.(*groth16Impl.ProvingKey)

	// assert everything is of the same size
	require.Equal(t, _rpk.Domain.Cardinality, _pk.Domain.Cardinality)
	require.Equal(t, len(_rpk.G1.A), len(_pk.G1.A))
	require.Equal(t, len(_rpk.G1.B), len(_pk.G1.B))
	require.Equal(t, len(_rpk.G1.K), len(_pk.G1.K))
	require.Equal(t, len(_rpk.G1.Z), len(_pk.G1.Z))
	require.Equal(t, len(_rpk.G2.B), len(_pk.G2.B))
	require.Equal(t, len(_rpk.CommitmentKeys), len(_pk.CommitmentKeys))
	for i := range _rpk.CommitmentKeys {
		require.Equal(t, len(_rpk.CommitmentKeys[i].BasisExpSigma), len(_pk.CommitmentKeys[i].BasisExpSigma))
		require.Equal(t, len(_rpk.CommitmentKeys[i].Basis), len(_pk.CommitmentKeys[i].Basis))
	}

	proveVerifyCircuit(t, rpk, rvk)
	fmt.Println("regular proof verified")
	proveVerifyCircuit(t, pk, vk)
	fmt.Println("mpc proof verified")
}

// TestNoContributors tests the beacon and some of the serialization
func TestNoContributors(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	testAll(t, 0, 0)
}

func TestOnePhase1Contribute(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	testAll(t, 2, 0)
}

func commonsSmallValues(N, tau, alpha, beta uint64) SrsCommons {
	var (
		res   SrsCommons
		I     big.Int
		coeff fr.Element
	)
	_, _, g1, g2 := curve.Generators()
	tauPowers := powersI(tau, int(2*N-1))
	res.G1.Tau = make([]curve.G1Affine, 2*N-1)
	for i := range res.G1.Tau {
		tauPowers[i].BigInt(&I)
		res.G1.Tau[i].ScalarMultiplication(&g1, &I)
	}

	res.G2.Tau = make([]curve.G2Affine, N)
	for i := range res.G2.Tau {
		tauPowers[i].BigInt(&I)
		res.G2.Tau[i].ScalarMultiplication(&g2, &I)
	}

	res.G1.AlphaTau = make([]curve.G1Affine, N)
	coeff.SetUint64(alpha)
	for i := range res.G1.AlphaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.AlphaTau[i].ScalarMultiplication(&g1, &I)
	}

	res.G1.BetaTau = make([]curve.G1Affine, N)
	coeff.SetUint64(beta)
	for i := range res.G1.BetaTau {
		var x fr.Element
		x.Mul(&tauPowers[i], &coeff)
		x.BigInt(&I)
		res.G1.BetaTau[i].ScalarMultiplication(&g1, &I)
	}

	I.SetUint64(beta)
	res.G2.Beta.ScalarMultiplication(&g2, &I)

	return res
}

func powersI(x uint64, n int) []fr.Element {
	var y fr.Element
	y.SetUint64(x)
	return powers(&y, n)
}

func TestPowers(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	var x fr.Element
	x.SetUint64(2)
	x2 := powers(&x, 10)
	for i := range x2 {
		require.True(t, x2[i].IsUint64())
		require.Equal(t, x2[i].Uint64(), uint64(1<<i))
	}
}

func TestCommons(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	// Compile the circuit
	ccs := getTestCircuit()
	domainSize := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	var p1 Phase1
	p1.Initialize(domainSize)

	assertG1G2Equal(t, p1.parameters.G1.BetaTau[0], p1.parameters.G2.Beta)

	commons := p1.Seal([]byte("beacon 1"))

	for i := range commons.G2.Tau {
		assertG1G2Equal(t, commons.G1.Tau[i], commons.G2.Tau[i])
	}

	assertG1G2Equal(t, commons.G1.BetaTau[0], commons.G2.Beta)
}

func TestCommonsUpdate(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	var c SrsCommons
	c.setOne(1)
	assertG1G2Equal(t, c.G1.BetaTau[0], c.G2.Beta)
	one := fr.One()
	var zero fr.Element
	c.update(&zero, &zero, &one)
	assertG1G2Equal(t, c.G1.BetaTau[0], c.G2.Beta)
}

func assertG1G2Equal(t *testing.T, p1 curve.G1Affine, p2 curve.G2Affine) {
	_, _, g1, g2 := curve.Generators()
	assertPairingsEqual(t, p1, g2, g1, p2)
}

// asserts e(p1, q1) = r(p2, q2)
func assertPairingsEqual(t *testing.T, p1 curve.G1Affine, p2 curve.G2Affine, q1 curve.G1Affine, q2 curve.G2Affine) {
	q1.Neg(&q1)
	ok, err := curve.PairingCheck([]curve.G1Affine{p1, q1}, []curve.G2Affine{p2, q2})
	require.NoError(t, err)
	require.True(t, ok)
}

func TestPedersen(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	cs := getTestCircuit()
	domainSize := ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints()))

	commons := commonsSmallValues(domainSize, 2, 3, 4)
	var p Phase2
	evals := p.Initialize(cs, &commons)
	contributions := make([]fr.Element, 1+len(p.Sigmas))
	for i := range contributions {
		contributions[i].SetOne()
	}
	contributions[1].SetUint64(2)
	p.update(&contributions[0], contributions[1:])
	_, _, _, g2 := curve.Generators()
	for i := range p.Sigmas {
		assertPairingsEqual(t, evals.G1.CKK[0][i], p.Parameters.G2.Sigma[i], p.Parameters.G1.SigmaCKK[0][i], g2)
	}
}

func TestPhase2Serialization(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	testRoundtrip := func(_cs constraint.ConstraintSystem) {
		var (
			p1 Phase1
			p2 Phase2
		)
		p1.Initialize(ecc.NextPowerOfTwo(uint64(_cs.GetNbConstraints())))
		commons := p1.Seal([]byte("beacon 1"))

		p2.Initialize(_cs.(*cs.R1CS), &commons)
		p2.Contribute()
		require.NoError(t, gnarkio.RoundTripCheck(&p2, func() interface{} { return new(Phase2) }))
	}

	_cs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, &tinyCircuit{})
	require.NoError(t, err)
	testRoundtrip(_cs)

	testRoundtrip(getTestCircuit())
}

type tinyCircuit struct {
	X [4]frontend.Variable `gnark:",public"`
}

func (c *tinyCircuit) Define(api frontend.API) error {
	for i := range c.X {
		api.AssertIsEqual(c.X[i], i)
	}
	return nil
}

func (p *Phase2) Equal(o *Phase2) bool {

	if p.Parameters.G2.Delta != o.Parameters.G2.Delta {
		print("g2 delta")
	}

	if p.Delta != o.Delta {
		print("proof delta")
	}

	if p.Parameters.G1.Delta != o.Parameters.G1.Delta {
		print("g1 delta")
	}

	return p.Parameters.G2.Delta == o.Parameters.G2.Delta &&
		slices.Equal(p.Sigmas, o.Sigmas) &&
		// bytes.Equal(p.Challenge, o.Challenge) && This function is used in serialization round-trip testing, and we deliberately don't write the challenges
		p.Delta == o.Delta &&
		sliceSliceEqual(p.Parameters.G1.SigmaCKK, o.Parameters.G1.SigmaCKK) &&
		p.Parameters.G1.Delta == o.Parameters.G1.Delta &&
		slices.Equal(p.Parameters.G1.Z, o.Parameters.G1.Z) &&
		slices.Equal(p.Parameters.G1.PKK, o.Parameters.G1.PKK) &&
		slices.Equal(p.Parameters.G2.Sigma, o.Parameters.G2.Sigma)
}

func sliceSliceEqual[T comparable](a, b [][]T) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

func getSimplePhase2(t *testing.T, circuit frontend.Circuit) Phase2 {
	_cs, err := frontend.Compile(curve.ID.ScalarField(), r1cs.NewBuilder, circuit)
	require.NoError(t, err)
	cs := _cs.(*cs.R1CS)
	var commons SrsCommons
	commons.setOne(ecc.NextPowerOfTwo(uint64(cs.GetNbConstraints())))
	var p Phase2
	p.Initialize(cs, &commons)
	return p
}

func TestPhase2(t *testing.T) {
	t.Skip("skipping unit test for BW6-633 so as not to clog the CI")
	p0 := getSimplePhase2(t, &Circuit{})

	var p1 Phase2
	test_utils.CopyThruSerialization(t, &p1, &p0)
	p1.Contribute()

	require.NoError(t, p0.Verify(&p1))
}
