package gkr

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/gkr/gkrcore"
	"github.com/consensys/gnark/std/gkrapi/gkr"
	"github.com/stretchr/testify/require"
)

// powGate returns a single-input gate computing x^n.
// The gate degree equals n and is confirmed by compilation.
func powGate(n int) gkr.GateFunction {
	switch n {
	case 1:
		return gkrcore.Identity
	case 2:
		return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			return api.Mul(in[0], in[0])
		}
	case 3:
		return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			sq := api.Mul(in[0], in[0])
			return api.Mul(sq, in[0])
		}
	case 4:
		return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			sq := api.Mul(in[0], in[0])
			return api.Mul(sq, sq)
		}
	case 5:
		return func(api gkr.GateAPI, in ...frontend.Variable) frontend.Variable {
			sq := api.Mul(in[0], in[0])
			p4 := api.Mul(sq, sq)
			return api.Mul(p4, in[0])
		}
	default:
		panic(fmt.Sprintf("powGate: unsupported degree %d", n))
	}
}

// benchmarkFirstRoundSumcheck benchmarks proveSumcheckLevel for a circuit where
// the hot wire (pow_n) has two claim sources, forcing GkrSumcheckLevel dispatch.
//
// Topology:
//
//	Wire 0 (in):    input
//	Wire 1 (pow_n): x^n, exported (→ 2 claim sources: initial challenge + feeds wire 2's level)
//	Wire 2 (out):   identity(pow_n), exported
//
// Wire 1 gets addSumcheckLevel because it has two distinct claim sources.
func benchmarkFirstRoundSumcheck(b *testing.B, degree, nbInstances int) {
	b.Helper()
	field := ecc.BLS12_377.ScalarField()

	rawCircuit := gkrcore.RawCircuit{
		{},
		{Gate: powGate(degree), Inputs: []int{0}, Exported: true},
		{Gate: gkrcore.Identity, Inputs: []int{1}, Exported: true},
	}
	_, sCircuit, err := rawCircuit.Compile(field)
	require.NoError(b, err)

	schedule, err := gkrcore.DefaultProvingSchedule(sCircuit)
	require.NoError(b, err)

	assignment := make(WireAssignment, len(sCircuit))
	assignment[0] = make([]fr.Element, nbInstances)
	fr.Vector(assignment[0]).MustSetRandom()
	assignment.Complete(sCircuit)

	b.ResetTimer()
	for b.Loop() {
		_, err = Prove(sCircuit, schedule, assignment, mimc.NewMiMC())
		require.NoError(b, err)
	}
}

func BenchmarkFirstRoundSumcheck(b *testing.B) {
	const nbInstances = 1 << 15
	for _, d := range []int{1, 2, 3, 4, 5} {
		b.Run(fmt.Sprintf("degree%d", d), func(b *testing.B) {
			benchmarkFirstRoundSumcheck(b, d, nbInstances)
		})
	}
}
