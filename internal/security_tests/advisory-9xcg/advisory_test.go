// Package advisory9xcg implements a test for advisory GHSA-9xcg-3q8v-7fq6.
package advisory9xcg

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type Circuit struct {
	SecretWitness frontend.Variable `gnark:",private"`
}

func (circuit *Circuit) Define(api frontend.API) error {
	// the goal of the test is to show that we are able to predict the private
	// input solely from the stored commitment.
	commitCompiler, ok := api.Compiler().(frontend.Committer)
	if !ok {
		return fmt.Errorf("compiler does not commit")
	}

	commit, err := commitCompiler.Commit(circuit.SecretWitness)
	if err != nil {
		return err
	}

	api.AssertIsDifferent(commit, 0)
	api.AssertIsDifferent(circuit.SecretWitness, 0)
	return nil
}

func TestAdvisory_ghsa_9xcg_3q8v_7fq6(t *testing.T) {
	assert := test.NewAssert(t)
	// the goal of the test is to show that we are able to predict the private
	// input solely from the stored commitment

	// Generating a random secret witness.
	var bound int64 = 1024 // ten bits of entropy for testing
	secretWitness, err := rand.Int(rand.Reader, big.NewInt(bound))
	assert.NoError(err, "random generation failed")
	assert.Log("random secret witness: ", secretWitness)

	// Assigning some values.
	assignment := Circuit{SecretWitness: secretWitness}
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err, "witness creation failed")
	witnessPublic, err := witness.Public()
	assert.NoError(err, "witness public failed")

	// Setup circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	assert.NoError(err, "compilation failed")

	// run the setup and prover
	pk, vk, err := groth16.Setup(ccs)
	assert.NoError(err, "setup failed")
	proof, err := groth16.Prove(ccs, pk, witness)
	assert.NoError(err, "proof failed")

	// sanity check, check that the proof verifies
	err = groth16.Verify(proof, vk, witnessPublic)
	assert.NoError(err, "verification failed")

	// we're ready to set up the attack. For that first we need to assert the
	// exact types for being able to extract the proving key information.
	pkConcrete, ok := pk.(*groth16_bn254.ProvingKey)
	assert.True(ok, "unexpected type for proving key")
	proofConcrete, ok := proof.(*groth16_bn254.Proof)
	assert.True(ok, "unexpected type for proof")

	var guessedCommitment bn254.G1Affine
	for i := int64(0); i < bound; i++ {
		// We check our guess for the secret witness.
		guessedCommitment.ScalarMultiplication(&pkConcrete.CommitmentKeys[0].Basis[0], big.NewInt(int64(i)))
		if guessedCommitment.Equal(&proofConcrete.Commitments[0]) {
			assert.Fail("secret witness found: ", i)
			return
		}
	}
}
