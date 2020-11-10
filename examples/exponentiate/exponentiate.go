package exponentiate

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := cs.Constant(1)
	bits := cs.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		// cs.Println(fmt.Sprintf("e[%d]", i), bits[i]) // we may print a variable for testing and / or debugging purposes

		if i != 0 {
			output = cs.Mul(output, output)
		}
		multiply := cs.Mul(output, circuit.X)
		output = cs.Select(bits[len(bits)-1-i], multiply, output)

	}

	cs.AssertIsEqual(circuit.Y, output)

	return nil
}
