package zkpschemes

const Groth16Assert = `


{{ template "header" . }}

package groth16

import (
	"reflect"
	"testing"

	{{ template "import_backend" . }}
	"github.com/stretchr/testify/require"
)



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
func (assert *Assert) NotSolved(r1cs *backend.R1CS, solution backend.Assignments) {
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
func (assert *Assert) Solved(r1cs *backend.R1CS, solution backend.Assignments, expectedValues map[string]interface{}) {
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
			assert.False(pk.G1.K[i].Equal(&pk2.G1.K[i]), "groth16 setup with same input should produce different outputs (pk.K)")
		}

		for i := 0; i < len(vk.G1.K); i++ {
			// TODO why is that commented?
			// assert.False(vk.G1.K[i].Equal(&vk2.G1.K[i]), "groth16 setup with same input should produce different outputs (vk.K)")
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
	assert.checkProof(true, proof, &vk, filterOutPrivateAssignment(solution))

	// fuzz testing
	// TODO need to fuzz inputs once code is genrated and we have fixed size arrays
	{
		// goodPk := pk
		// // 1. computing with empty proving key the proof
		// pk = ProvingKey{}
		// proof, err := Prove(r1cs, &pk, solution)
		// assert.Nil(err, "proving with good solution should not output an error")
		// assert.checkProof(false, proof, &vk, filterOutPrivateAssignment(solution))

		// // 2. fuzzing the pk
		// assert.fuzz.Fuzz(&pk)
		// pk.G1.A[0].X.SetRandom()
		// proof, err = Prove(r1cs, &pk, solution)
		// assert.Nil(err, "proving with good solution should not output an error")
		// assert.checkProof(false, proof, &vk, filterOutPrivateAssignment(solution))

		// // 3. fuzzing the vk
		// vk = VerifyingKey{}
		// assert.fuzz.Fuzz(&vk)
		// proof, err = Prove(r1cs, &goodPk, solution)
		// assert.Nil(err, "proving with good solution should not output an error")
		// assert.checkProof(false, proof, &vk, filterOutPrivateAssignment(solution))

	}
}

func (assert *Assert) checkProof(expected bool, proof *Proof, vk *VerifyingKey, solution backend.Assignments) {
	isValid, err := Verify(proof, vk, filterOutPrivateAssignment(solution))
	assert.Nil(err, "verifying proof with good solution should not output an error")
	assert.True(isValid == expected, "unexpected Verify(proof) result")
}

// TODO this need to be done somewhere else
// func (assert *Assert) serializeRoundTrip(r1cs *backend.R1CS) {
// 	rawR1CS := circuit.ToR1CS()
// 	var bytes bytes.Buffer
// 	err := gob.Serialize(&bytes, rawR1CS)
// 	assert.Nil(err, "serializing R1CS shouldn't output an error")
// 	var r1cs r1cs.R1CS
// 	err = gob.Deserialize(&bytes, &r1cs)
// 	assert.Nil(err, "deserializing R1CS shouldn't output an error")

// 	assert.True(reflect.DeepEqual(rawR1CS, &r1cs), "round trip (de)serialization of R1CS failed")
// }

// TODO this is a duplicate with groth16_test
func filterOutPrivateAssignment(assignments map[string]backend.Assignment) map[string]backend.Assignment {
	toReturn := backend.NewAssignment()
	for k, v := range assignments {
		if v.IsPublic {
			toReturn[k] = v
		}
	}
	return toReturn
}

`
