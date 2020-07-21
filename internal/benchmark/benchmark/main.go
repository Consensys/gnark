// Package benchmark internal benchmarks
package main

import (
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/r1cs"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
	"github.com/consensys/gurvy/bn256/fr"
)

const benchCount = 10000

// /!\ internal use /!\
// running it with "trace" will output trace.out file
const n = 5000000

// else will output average proving times, in csv format
func main() {
	var circuit benchCircuit
	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, n)

	r1cs, err := frontend.Compile(ctx, &circuit)

	if err != nil {
		panic(err)
	}
	frontend.Save(ctx, r1cs, "circuit.r1cs")
}

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

type _nbConstraintKey int

var nbConstraintKey _nbConstraintKey

func generateCircuit(nbConstraints int) (groth16.ProvingKey, r1cs.R1CS, map[string]interface{}) {
	var circuit benchCircuit
	ctx := frontend.NewContext(gurvy.BN256)
	ctx.Set(nbConstraintKey, nbConstraints)
	r1cs, err := frontend.Compile(ctx, &circuit)
	if err != nil {
		panic(err)
	}

	// compute expected Y
	var expectedY fr.Element
	expectedY.SetInterface(2)
	for i := 0; i < nbConstraints; i++ {
		expectedY.MulAssign(&expectedY)
	}
	solution := make(map[string]interface{})
	solution["X"] = 2
	solution["Y"] = expectedY

	// ---------------------------------------------------------------------------------------------
	//  setup
	pk := groth16.DummySetup(r1cs)
	return pk, r1cs, solution
}
