package cubic

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// CubicCircuit defines a simple circuit
// x**3 + x + 5 == y
type CubicCircuit struct {
	// struct tags on a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:",public"`
}

// Define declares the circuit constraints
// x**3 + x + 5 == y
func (circuit *CubicCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	x3 := cs.Mul(circuit.X, circuit.X, circuit.X)
	cs.AssertIsEqual(circuit.Y, cs.Add(x3, circuit.X, 5))
	return nil
}
