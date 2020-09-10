package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const bitSize = 8 // number of bits of exponent

// ExponentiateCircuit y == x**e
// only the bitSize least significant bits of e are used
type ExponentiateCircuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *ExponentiateCircuit) Define(curveID gurvy.ID, cs *frontend.ConstraintSystem) error {
	// specify constraints
	output := cs.Constant(1)
	bits := cs.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		cs.Tag(bits[i], fmt.Sprintf("e[%d]", i)) // we can tag a variable for testing and / or debugging purposes

		if i != 0 {
			output = cs.Mul(output, output)
		}
		multiply := cs.Mul(output, circuit.X)
		output = cs.Select(bits[len(bits)-1-i], multiply, output)

		cs.Tag(output, fmt.Sprintf("output after processing exponent bit %d", len(bits)-1-i))
	}

	cs.MustBeEqual(circuit.Y, output)

	return nil
}

func main() {
	var expCircuit ExponentiateCircuit
	// init slices if any
	// ex: cubicCircuit.bar = make([]foo, 12)

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &expCircuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = frontend.Save(r1cs, "circuit.r1cs"); err != nil {
		panic(err)
	}
}
