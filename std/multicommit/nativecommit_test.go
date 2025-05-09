package multicommit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/fieldextension"
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
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254))
}

type noCommitVariable struct {
	X frontend.Variable
}

func (c *noCommitVariable) Define(api frontend.API) error {
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error { return nil })
	return nil
}

// TestNoCommitVariable checks that a circuit that doesn't use the commitment variable
// compiles and prover succeeds. This is due to the randomization of the commitment.
func TestNoCommitVariable(t *testing.T) {
	circuit := noCommitVariable{}
	assignment := noCommitVariable{X: 10}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &assignment, test.WithCurves(ecc.BN254))
}

type wideCommitment struct {
	X frontend.Variable
}

func (c *wideCommitment) Define(api frontend.API) error {
	WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		api.AssertIsDifferent(commitment, 0)
		return nil
	}, c.X)
	WithWideCommitment(api, func(api frontend.API, commitment []frontend.Variable) error {
		fe, err := fieldextension.NewExtension(api, fieldextension.WithDegree(8))
		if err != nil {
			return err
		}
		res := fe.Mul(commitment, commitment)
		for i := range res {
			api.AssertIsDifferent(res[i], 0)
		}
		return nil
	}, 8, c.X)
	return nil
}

func TestWideCommitment(t *testing.T) {
	assert := test.NewAssert(t)
	err := test.IsSolved(&wideCommitment{}, &wideCommitment{X: 10}, babybear.Modulus())
	// TODO: when we have implemented for PLONK, then also check for that. We're never going to implement for Groth16
	assert.NoError(err)
}
