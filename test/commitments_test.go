package test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/consensys/gnark/backend/plonk"
	cs "github.com/consensys/gnark/constraint/bn254"
)

type commitmentCircuit struct {
	X []frontend.Variable
}

func (c *commitmentCircuit) Define(api frontend.API) error {
	commitment, err := api.Compiler().Commit(c.X...)
	if err == nil {
		api.AssertIsDifferent(commitment, 0)
	}
	return err
}

func TestSingleCommitmentPlonkBn254(t *testing.T) {

	assignment := commitmentCircuit{[]frontend.Variable{1}}

	// // building the circuit...
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &commitmentCircuit{make([]frontend.Variable, 1)})
	assert.NoError(t, err)

	_r1cs := ccs.(*cs.SparseR1CS)
	srs, err := NewKZGSRS(_r1cs)
	assert.NoError(t, err)

	// Witnesses instantiation. Witness is known only by the prover,
	// while public w is a public data known by the verifier.

	witnessFull, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)

	witnessPublic, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	assert.NoError(t, err)

	// public data consists the polynomials describing the constants involved
	// in the constraints, the polynomial describing the permutation ("grand
	// product argument"), and the FFT domains.
	pk, vk, err := plonk.Setup(ccs, srs)
	//_, err := plonk.Setup(r1cs, kate, &publicWitness)
	assert.NoError(t, err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}
