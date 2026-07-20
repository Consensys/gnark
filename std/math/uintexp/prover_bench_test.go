package uintexp

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// BenchmarkProverEndToEnd times the actual prover (witness solving included)
// on BN254 for the exponent method vs the width-matched u8 limb baseline, on
// two workloads: a dependent add chain and a constant counter.
//
// NB: there is no small-field prover in gnark yet, so BN254 is used as the
// end-to-end proxy: it exercises the same lookup/commitment machinery
// (including the extra committed columns the limb method needs) with a real
// prover behind it.
func BenchmarkProverEndToEnd(b *testing.B) {
	const n = 5000

	expChain := func() (frontend.Circuit, frontend.Circuit) {
		return &expOpCircuit[U8]{Op: "add", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "add", N: n, In: zeros(n), A: 1, B: 2, Sel: 0, Expected: (1 + 2*n) % 256}
	}
	expCounter := func() (frontend.Circuit, frontend.Circuit) {
		return &expOpCircuit[U8]{Op: "add-constant", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "add-constant", N: n, In: zeros(n), A: 1, B: 0, Sel: 0, Expected: (1 + 3*n) % 256}
	}
	limbChain := func() (frontend.Circuit, frontend.Circuit) {
		return &limbOpCircuit{K: 8, Op: "add", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "add", N: n, In: zeros(n), A: 1, B: 2, Sel: 0, Expected: 0}
	}
	limbCounter := func() (frontend.Circuit, frontend.Circuit) {
		return &limbOpCircuit{K: 8, Op: "add-constant", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "add-constant", N: n, In: zeros(n), A: 1, B: 0, Sel: 0, Expected: 0}
	}

	expMul := func() (frontend.Circuit, frontend.Circuit) {
		return &expOpCircuit[U8]{Op: "mul", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "mul", N: n, In: zeros(n), A: 1, B: 3, Sel: 0, Expected: powMod(3, n, 256)}
	}
	limbMul := func() (frontend.Circuit, frontend.Circuit) {
		return &limbOpCircuit{K: 8, Op: "mul", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "mul", N: n, In: zeros(n), A: 1, B: 3, Sel: 0, Expected: 0}
	}

	workloads := []struct {
		name string
		mk   func() (frontend.Circuit, frontend.Circuit)
	}{
		{"chain/exp", expChain},
		{"chain/limb", limbChain},
		{"counter/exp", expCounter},
		{"counter/limb", limbCounter},
		{"mul/exp", expMul},
		{"mul/limb", limbMul},
	}

	for _, w := range workloads {
		circuit, assignment := w.mk()
		fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			b.Fatal(w.name, err)
		}

		b.Run("plonk/"+w.name, func(b *testing.B) {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
			if err != nil {
				b.Fatal(err)
			}
			srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
			if err != nil {
				b.Fatal(err)
			}
			pk, _, err := plonk.Setup(ccs, srs, srsLagrange)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := plonk.Prove(ccs, pk, fullWitness); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(ccs.GetNbConstraints()), "gates")
			b.ReportMetric(float64(ccs.GetNbInternalVariables()), "wires")
		})

		b.Run("groth16/"+w.name, func(b *testing.B) {
			ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				b.Fatal(err)
			}
			pk, _, err := groth16.Setup(ccs)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := groth16.Prove(ccs, pk, fullWitness); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(ccs.GetNbConstraints()), "constraints")
			b.ReportMetric(float64(ccs.GetNbInternalVariables()), "wires")
			b.ReportMetric(float64(len(ccs.GetCommitments().CommitmentIndexes())), "commitments")
		})
	}
}

func powMod(b, e, m int) int {
	r := 1 % m
	for i := 0; i < e; i++ {
		r = r * b % m
	}
	return r
}

func zeros(n int) []frontend.Variable {
	vs := make([]frontend.Variable, n)
	for i := range vs {
		vs[i] = 0
	}
	return vs
}
