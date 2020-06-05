package zkpschemes

const Groth16Assert = `
import (
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend"
	{{ template "import_backend" . }}
	{{ template "import_fr" . }}
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
func (assert *Assert) NotSolved(r1cs *backend_{{toLower .Curve}}.R1CS, solution backend.Assignments) {
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
func (assert *Assert) Solved(r1cs *backend_{{toLower .Curve}}.R1CS, solution backend.Assignments, expectedValues map[string]fr.Element) {
	// setup

	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// ensure random sampling; calling setup twice should produce != pk and vk
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
	assert.CorrectExecution(r1cs, solution, expectedValues)

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

// CorrectExecution Verifies that the expected solution matches the solved variables
// CorrectExecution Verifies that the expected solution matches the solved variables
func (assert *Assert) CorrectExecution(r1cs *backend_{{toLower .Curve}}.R1CS, solution backend.Assignments, expectedValues map[string]fr.Element) {

	// In inspect the r1cs is solved, if an error occurs it is caught here
	res, err := r1cs.Inspect(solution, true)
	assert.Nil(err, "Inspecting the tagged variables of a constraint system with correct inputs should not output an error")

	for k, v := range expectedValues {
		val, ok := res[k]
		assert.True(ok, "Variable to test <"+k+"> (backend_{{toLower .Curve}}) is not tagged")
		assert.True(val.Equal(&v), "Tagged variable <"+k+"> (backend_{{toLower .Curve}}) does not have the expected value\nexpected: "+v.String()+"\ngot:\t  "+val.String())
	}
}


`
