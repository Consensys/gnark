package uintexp

import (
	"testing"

	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
)

// BenchmarkKoalaBearSolver measures what is measurable end-to-end over
// KoalaBear today: witness solving time (the prover's witness-generation
// phase, with all hints -- dlog decodes for the exponent method, partition
// and lookup hints for the limb method) and the committed-area metrics of
// the compiled SparseR1CS (the dominant cost driver of the eventual
// small-field Plonk prover, for which only Setup exists in gnark so far).
func BenchmarkKoalaBearSolver(b *testing.B) {
	const n = 5000

	workloads := []struct {
		name       string
		circuit    frontend.Circuit
		assignment frontend.Circuit
		wide       bool // limb method needs the wide-committer shim
	}{
		{
			"chain/exp",
			&expOpCircuit[U8]{Op: "add", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "add", N: n, In: zeros(n), A: 1, B: 2, Sel: 0, Expected: (1 + 2*n) % 256},
			false,
		},
		{
			"chain/limb",
			&limbOpCircuit{K: 8, Op: "add", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "add", N: n, In: zeros(n), A: 1, B: 2, Sel: 0, Expected: 0},
			true,
		},
		{
			"counter/exp",
			&expOpCircuit[U8]{Op: "add-constant", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "add-constant", N: n, In: zeros(n), A: 1, B: 0, Sel: 0, Expected: (1 + 3*n) % 256},
			false,
		},
		{
			"counter/limb",
			&limbOpCircuit{K: 8, Op: "add-constant", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "add-constant", N: n, In: zeros(n), A: 1, B: 0, Sel: 0, Expected: 0},
			true,
		},
		{
			"mul/exp",
			&expOpCircuit[U8]{Op: "mul", N: n, In: make([]frontend.Variable, n)},
			&expOpCircuit[U8]{Op: "mul", N: n, In: zeros(n), A: 1, B: 3, Sel: 0, Expected: powMod(3, n, 256)},
			false,
		},
		{
			"mul/limb",
			&limbOpCircuit{K: 8, Op: "mul", N: n, In: make([]frontend.Variable, n)},
			&limbOpCircuit{K: 8, Op: "mul", N: n, In: zeros(n), A: 1, B: 3, Sel: 0, Expected: 0},
			true,
		},
	}

	for _, w := range workloads {
		b.Run(w.name, func(b *testing.B) {
			wit, err := frontend.NewWitness(w.assignment, koalabear.Modulus())
			if err != nil {
				b.Fatal(err)
			}
			var newBuilder frontend.NewBuilderU32 = scs.NewBuilder
			if w.wide {
				newBuilder = widecommitter.From(scs.NewBuilder)
			}
			ccs, err := frontend.CompileU32(koalabear.Modulus(), newBuilder, w.circuit)
			if err != nil {
				b.Fatal(err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := ccs.IsSolved(wit); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(ccs.GetNbConstraints()), "gates")
			b.ReportMetric(float64(ccs.GetNbInternalVariables()), "wires")
		})
	}
}
