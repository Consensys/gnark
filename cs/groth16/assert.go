package groth16

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/encoding/gob"
	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/require"
)

// Assert is a helper to test circuits
// it embeds a cs.Assert object (see gnark/cs/assert)
type Assert struct {
	*require.Assertions
	a    *cs.Assert
	fuzz *fuzz.Fuzzer
}

// NewAssert returns an Assert helper
func NewAssert(t *testing.T) *Assert {
	a := cs.NewAssert(t)
	return &Assert{a.Assertions, a, fuzz.New()}
}

// NotSolved check that a solution does NOT solve a circuit
// error may be missing inputs or unsatisfied constraints
// it runs cs.Assert.NotSolved and ensure running groth16.Prove and groth16.Verify doesn't return true
func (assert *Assert) NotSolved(circuit cs.CS, solution cs.Assignments) {
	// ensure the R1CS is not solved
	assert.a.NotSolved(circuit, solution)
	assert.serializeRoundTrip(circuit)

	// setup
	r1cs := cs.NewR1CS(&circuit)
	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	// prover
	_, err := Prove(r1cs, &pk, solution)
	assert.Error(err, "proving with bad solution should output an error")
}

// Solved check that a solution solves a circuit
// for each expectedValues, this helper compares the output from r1cs.Inspect() after Solving.
// this helper also ensure the result vectors a*b=c
// it runs cs.Assert.Solved and ensure running groth16.Prove and groth16.Verify returns true
func (assert *Assert) Solved(circuit cs.CS, solution cs.Assignments, expectedValues map[string]interface{}) {
	// ensure the R1CS is solved
	assert.a.Solved(circuit, solution, expectedValues)
	assert.serializeRoundTrip(circuit)

	// setup
	r1cs := cs.NewR1CS(&circuit)
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
			// assert.False(vk.G1Jac.K[i].Equal(&vk2.G1Jac.K[i]), "groth16 setup with same input should produce different outputs (vk.K)")
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

		// TODO need to fuzz inputs
	}
}

func (assert *Assert) checkProof(expected bool, proof *Proof, vk *VerifyingKey, solution cs.Assignments) {
	isValid, err := Verify(proof, vk, filterOutPrivateAssignment(solution))
	assert.Nil(err, "verifying proof with good solution should not output an error")
	assert.True(isValid == expected, "unexpected Verify(proof) result")
}

func (assert *Assert) serializeRoundTrip(circuit cs.CS) {
	rawR1CS := cs.NewR1CS(&circuit)
	var bytes bytes.Buffer
	err := gob.Serialize(&bytes, rawR1CS)
	assert.Nil(err, "serializing R1CS shouldn't output an error")
	var r1cs cs.R1CS
	err = gob.Deserialize(&bytes, &r1cs)
	assert.Nil(err, "deserializing R1CS shouldn't output an error")

	assert.True(reflect.DeepEqual(rawR1CS, &r1cs), "round trip (de)serialization of R1CS failed")
}
