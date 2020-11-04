package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/io"
	"github.com/consensys/gurvy"
)

func main() {
	var circuit ExponentiateCircuit

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &circuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = io.WriteFile("circuit.r1cs", r1cs); err != nil {
		panic(err)
	}

	// good solution
	var witness ExponentiateCircuit
	witness.X.Assign(2)
	witness.E.Assign(12)
	witness.Y.Assign(4096)
	assignment, _ := frontend.ParseWitness(&witness)

	if err = io.WriteWitness("input.json", assignment); err != nil {
		panic(err)
	}
}

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
