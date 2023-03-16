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
	commitment, err := api.Commit(c.X...)
	if err == nil {
		api.AssertIsDifferent(commitment, 0)
	}
	return err
}

func plonkTestBn254(t *testing.T, assignment frontend.Circuit) {
	witnessFull, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)
	witnessPublic, err := witnessFull.Public()
	assert.NoError(t, err)

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, assignment)
	assert.NoError(t, err)

	_r1cs := ccs.(*cs.SparseR1CS)
	srs, err := NewKZGSRS(_r1cs)
	assert.NoError(t, err)

	pk, vk, err := plonk.Setup(ccs, srs)
	assert.NoError(t, err)

	proof, err := plonk.Prove(ccs, pk, witnessFull)
	assert.NoError(t, err)

	err = plonk.Verify(proof, vk, witnessPublic)
	assert.NoError(t, err)

}

func TestSingleCommitmentPlonkBn254(t *testing.T) {
	plonkTestBn254(t, &commitmentCircuit{[]frontend.Variable{1}})
}

type noCommitmentCircuit struct {
	X frontend.Variable
}

func (c *noCommitmentCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	api.AssertIsEqual(c.X, 1)
	return nil
}

func TestNoCommitmentCircuit(t *testing.T) {
	plonkTestBn254(t, &noCommitmentCircuit{1})
}
