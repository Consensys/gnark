package frontend_test

import (
	"testing"

	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const n = 1000000

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

var res r1cs.R1CS

func BenchmarkCircuit(b *testing.B) {

	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, n)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var circuit benchCircuit
		res, _ = frontend.Compile(ctx, &circuit)
	}

}
