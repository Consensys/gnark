package multicommit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type noRecursionCircuit struct {
	X frontend.Variable
}

func (c *noRecursionCircuit) Define(api frontend.API) error {
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error { return nil }, commitment)
		return nil
	}, c.X)
	return nil
}

func TestNoRecursion(t *testing.T) {
	circuit := noRecursionCircuit{}
	assert := test.NewAssert(t)
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.Error(err)
}

type multipleCommitmentCircuit struct {
	X frontend.Variable
}

func (c *multipleCommitmentCircuit) Define(api frontend.API) error {
	var stored frontend.Variable
	// first callback receives first unique commitment derived from the root commitment
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsDifferent(c.X, commitment)
		stored = commitment
		return nil
	}, c.X)
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsDifferent(stored, commitment)
		return nil
	}, c.X)
	return nil
}

func TestMultipleCommitments(t *testing.T) {
	circuit := multipleCommitmentCircuit{}
	assignment := multipleCommitmentCircuit{X: 10}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16)) // right now PLONK doesn't implement commitment
}

type noCommitVariable struct {
	X frontend.Variable
}

func (c *noCommitVariable) Define(api frontend.API) error {
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error { return nil })
	return nil
}

func TestNoCommitVariable(t *testing.T) {
	circuit := noCommitVariable{}
	assert := test.NewAssert(t)
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.Error(err)
}
