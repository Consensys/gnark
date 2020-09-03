package groth16

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
type Assert struct {
	*require.Assertions
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	return &Assert{require.New(t)}
}

// NotSolved check that a solution does NOT solve a circuit
// error may be missing inputs or unsatisfied constraints
// it creates a groth16.ProvingKey for the r1cs
// run groth16.Prove (which solves the R1CS) and expects an error
// provided _solution must either implements frontend.Circuit or be
// a map[string]interface{}
func (assert *Assert) NotSolved(r1cs r1cs.R1CS, _solution interface{}) {
	// setup
	pk := DummySetup(r1cs)
	solution := assert.parseSolution(_solution)

	_, err := Prove(r1cs, pk, solution)
	assert.Error(err, "proving with bad solution should output an error")
}

// Solved check that a solution solves a circuit
// for each expectedValues, this helper compares the output from backend.Inspect() after Solving.
// this helper also ensure the result vectors a*b=c
// it ensures running groth16.Prove and groth16.Verify returns true
// provided _solution must either implements frontend.Circuit or be
// a map[string]interface{}
func (assert *Assert) Solved(r1cs r1cs.R1CS, _solution interface{}, expectedValues map[string]interface{}) {
	solution := assert.parseSolution(_solution)

	// setup
	pk, vk := Setup(r1cs)

	// ensure random sampling; calling setup twice should produce != pk and vk
	{
		// setup
		pk2, vk2 := Setup(r1cs)

		assert.True(pk2.IsDifferent(pk), "groth16 setup with same input should produce different outputs ")
		assert.True(vk2.IsDifferent(vk), "groth16 setup with same input should produce different outputs ")
	}

	// ensure expected Values are computed correctly
	assert.CorrectExecution(r1cs, solution, expectedValues)

	// prover
	proof, err := Prove(r1cs, pk, solution)
	assert.NoError(err, "proving with good solution should not output an error")

	// ensure random sampling; calling prove twice with same input should produce different proof
	{
		proof2, err := Prove(r1cs, pk, solution)
		assert.NoError(err, "proving with good solution should not output an error")
		assert.False(reflect.DeepEqual(proof, proof2), "calling prove twice with same input should produce different proof")
	}

	// verifier
	{
		err := Verify(proof, vk, solution)
		assert.NoError(err, "verifying proof with good solution should not output an error")
	}
}

// CorrectExecution Verifies that the expected solution matches the solved variables
func (assert *Assert) CorrectExecution(r1cs r1cs.R1CS, _solution interface{}, expectedValues map[string]interface{}) {
	solution := assert.parseSolution(_solution)

	// In inspect the r1cs is solved, if an error occurs it is caught here
	res, err := r1cs.Inspect(solution, true)
	assert.NoError(err, "Inspecting the tagged variables of a constraint system with correct inputs should not output an error")
	for k, v := range expectedValues {
		val, ok := res[k]
		_v := backend.FromInterface(v)
		_val := backend.FromInterface(val)
		assert.True(ok, "Variable to test <"+k+"> is not tagged")
		assert.True(_val.Cmp(&_v) == 0, "Tagged variable <"+k+"> does not have the expected value\nexpected: "+_v.String()+"\ngot:\t  "+_val.String())
	}
}

func (assert *Assert) parseSolution(_solution interface{}) map[string]interface{} {
	var solution map[string]interface{}
	var err error
	switch s := _solution.(type) {
	case map[string]interface{}:
		solution = s
	case frontend.Circuit:
		solution, err = frontend.ToAssignment(s)
		assert.NoError(err)
	default:
		panic("solution must be map[string]interface{} or implement frontend.Circuit (is it a pointer?)")
	}
	return solution
}
