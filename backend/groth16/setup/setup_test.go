package setup

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/stretchr/testify/require"
)

func TestSetupCircuit(t *testing.T) {
	const (
		nContributionsPhase1 = 3
		nContributionsPhase2 = 3
		power                = 9
	)

	assert := require.New(t)

	srs1 := InitPhase1(power)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase1; i++ {
		prev := srs1.clone()
		srs1.Contribute()
		assert.NoError(VerifyPhase1(&prev, &srs1))
	}

	// Compile the circuit
	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)

	var evals Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)

	// Prepare for phase-2
	srs2, evals := InitPhase2(r1cs, &srs1)

	// Make and verify contributions for phase1
	for i := 1; i < nContributionsPhase2; i++ {
		prev := srs2.clone()
		srs2.Contribute()
		assert.NoError(VerifyPhase2(&prev, &srs2))
	}

	// Extract the proving and verifying keys
	pk, vk := ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())

	// Build the witness
	assignment := &Circuit{
		PreImage: "16130099170765464552823636852555369511329944820189892919423002775646948828469",
		Hash:     "12886436712380113721405259596386800092738845035233065858332878701083870690753",
	}
	witness, err := frontend.NewWitness(assignment, bn254.ID.ScalarField())
	assert.NoError(err)

	pubWitness, err := witness.Public()
	assert.NoError(err)

	// groth16: ensure proof is verified
	proof, err := groth16.Prove(ccs, &pk, witness)
	assert.NoError(err)

	err = groth16.Verify(proof, &vk, pubWitness)
	assert.NoError(err)
}

func BenchmarkPhase1Contribution(b *testing.B) {
	const power = 16
	srs1 := InitPhase1(power)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		srs1.Contribute()
	}

}

func BenchmarkPhase2Contribution(b *testing.B) {
	const power = 16
	srs1 := InitPhase1(power)
	srs1.Contribute()

	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
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
