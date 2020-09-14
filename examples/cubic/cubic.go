package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/io"
	"github.com/consensys/gurvy"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:"y, public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(circuit.X, circuit.X, circuit.X)
	cs.AssertIsEqual(circuit.Y, cs.Add(x3, circuit.X, 5))
	return nil
}

func main() {
	var circuit CubicCircuit

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = io.WriteFile("circuit.r1cs", r1cs); err != nil {
		panic(err)
	}

}
