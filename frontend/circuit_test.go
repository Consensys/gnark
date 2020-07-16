package frontend_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const n = 100000

type _nbConstraintKey int

var nbConstraintKey _nbConstraintKey

type benchCircuit struct {
	X frontend.Variable
	Y frontend.Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	nbConstraints, _ := ctx.Value(nbConstraintKey)
	for i := 0; i < nbConstraints.(int); i++ {
		circuit.X = cs.MUL(circuit.X, circuit.X)
	}
	cs.MUSTBE_EQ(circuit.X, circuit.Y)
	return nil
}

func (circuit *benchCircuit) PostInit(ctx *frontend.Context) error {
	return nil
}

func BenchmarkCircuit(b *testing.B) {
	var circuit benchCircuit
	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, n)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = frontend.Compile(ctx, &circuit)
	}

}
