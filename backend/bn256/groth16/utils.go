package groth16

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend"
	backend_bn256 "github.com/consensys/gnark/backend/bn256"
	"github.com/consensys/gurvy/bn256/fr"
	"github.com/stretchr/testify/require"
)

// assert helpers

// Assert is a helper to test circuits
// it embeds a frontend.Assert object (see gnark/cs/assert)
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// NotSolved check that a solution does NOT solve a circuit
// error may be missing inputs or unsatisfied constraints
// it runs frontend.Assert.NotSolved and ensure running groth16.Prove and groth16.Verify doesn't return true
func (assert *Assert) NotSolved(r1cs *backend_bn256.R1CS, solution backend.Assignments) {
	// setup

	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// prover
	_, err := Prove(r1cs, &pk, solution)
	assert.Error(err, "proving with bad solution should output an error")
}

// Solved check that a solution solves a circuit
// for each expectedValues, this helper compares the output from backend.Inspect() after Solving.
// this helper also ensure the result vectors a*b=c
// it runs frontend.Assert.Solved and ensure running groth16.Prove and groth16.Verify returns true
func (assert *Assert) Solved(r1cs *backend_bn256.R1CS, solution backend.Assignments, expectedValues map[string]fr.Element) {
	// setup

	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// ensure random sampling; calliung setup twice should produce != pk and vk
	{
		var pk2 ProvingKey
		var vk2 VerifyingKey
		Setup(r1cs, &pk2, &vk2)

		assert.False(pk.G1.Alpha.Equal(&pk2.G1.Alpha), "groth16 setup with same input should produce different outputs (alpha)")
		assert.False(pk.G1.Beta.Equal(&pk2.G1.Beta), "groth16 setup with same input should produce different outputs (beta)")
		assert.False(pk.G1.Delta.Equal(&pk2.G1.Delta), "groth16 setup with same input should produce different outputs (delta)")

		for i := 0; i < len(pk.G1.K); i++ {
			if !pk.G1.K[i].IsInfinity() {
				assert.False(pk.G1.K[i].Equal(&pk2.G1.K[i]), "groth16 setup with same input should produce different outputs (pk.K)")
			}
		}

		for i := 0; i < len(vk.G1.K); i++ {
			if !vk.G1.K[i].IsInfinity() {
				assert.False(vk.G1.K[i].Equal(&vk2.G1.K[i]), "groth16 setup with same input should produce different outputs (vk.K)")
			}
		}
	}

	// ensure expected Values are computed correctly
	{
		// TODO Solve should not require to  create by hand a, b, c etc... it should return it, super annoying to create variables before solving the r1cs
		var root fr.Element
		fftDomain := backend_bn256.NewDomain(root, backend_bn256.MaxOrder, r1cs.NbConstraints)

		wireValues := make([]fr.Element, r1cs.NbWires)
		a := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
		b := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)
		c := make([]fr.Element, r1cs.NbConstraints, fftDomain.Cardinality)

		r1cs.Solve(solution, a, b, c, wireValues)
		res, _ := r1cs.Inspect(wireValues)

		for k, v := range expectedValues {
			val, ok := res[k]
			assert.True(ok, "Variable to test ("+k+") is not tagged")
			assert.True(val.Equal(&v), "Tagged variable "+k+" does not have the expected value")

		}

	}

	// prover
	proof, err := Prove(r1cs, &pk, solution)
	assert.Nil(err, "proving with good solution should not output an error")

	// ensure random sampling; calling prove twice with same input should produce different proof
	{
		proof2, err := Prove(r1cs, &pk, solution)
		assert.Nil(err, "proving with good solution should not output an error")
		assert.False(reflect.DeepEqual(proof, proof2), "calling prove twice with same input should produce different proof")
	}

	// verifier
	{
		isValid, err := Verify(proof, &vk, solution.DiscardSecrets())
		assert.Nil(err, "verifying proof with good solution should not output an error")
		assert.True(isValid, "unexpected Verify(proof) result")
	}
}
