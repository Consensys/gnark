package groth16

import (
	"runtime/debug"
	"testing"

	"github.com/consensys/gnark/cs"
)

// BenchmarkSetup is a helper to benchmark groth16.Setup on a given circuit
func BenchmarkSetup(b *testing.B, circuit cs.CS) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	r1cs := cs.NewR1CS(&circuit)
	var pk ProvingKey
	var vk VerifyingKey
	b.ResetTimer()

	b.Run("setup", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			Setup(r1cs, &pk, &vk)
		}
	})
}

// BenchmarkProver is a helper to benchmark groth16.Prove on a given circuit
// it will run the Setup, reset the benchmark timer and benchmark the prover
func BenchmarkProver(b *testing.B, circuit cs.CS, solution cs.Assignments) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	r1cs := cs.NewR1CS(&circuit)
	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)

	b.ResetTimer()
	b.Run("prover", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Prove(r1cs, &pk, solution)
		}
	})
}

// BenchmarkVerifier is a helper to benchmark groth16.Verify on a given circuit
// it will run the Setup, the Prover and reset the benchmark timer and benchmark the verifier
// the provided solution will be filtered to keep only public inputs
func BenchmarkVerifier(b *testing.B, circuit cs.CS, solution cs.Assignments) {
	defer debug.SetGCPercent(debug.SetGCPercent(-1))
	r1cs := cs.NewR1CS(&circuit)
	var pk ProvingKey
	var vk VerifyingKey
	Setup(r1cs, &pk, &vk)
	proof, err := Prove(r1cs, &pk, solution)
	if err != nil {
		panic(err)
	}

	solution = filterOutPrivateAssignment(solution)
	b.ResetTimer()
	b.Run("verifier", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Verify(proof, &vk, solution)
		}
	})
}

func filterOutPrivateAssignment(assignments map[string]cs.Assignment) map[string]cs.Assignment {
	toReturn := cs.NewAssignment()
	for k, v := range assignments {
		if v.IsPublic {
			toReturn[k] = v
		}
	}

	return toReturn
}
