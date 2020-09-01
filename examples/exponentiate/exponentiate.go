package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

const bitSize = 8 // number of bits of exponent

// ExponentiateCircuit
// y == x**e
// only the bitSize least significant bits of e are used
type ExponentiateCircuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

func (circuit *ExponentiateCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// specify constraints
	output := cs.ALLOCATE(1)
	bits := cs.TO_BINARY(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		cs.Tag(bits[i], fmt.Sprintf("e[%d]", i)) // we can tag a variable for testing and / or debugging purposes, it has no impact on performances

		if i != 0 {
			output = cs.MUL(output, output)
		}
		multiply := cs.MUL(output, circuit.X)
		output = cs.SELECT(bits[len(bits)-1-i], multiply, output)

		cs.Tag(output, fmt.Sprintf("output after processing exponent bit %d", len(bits)-1-i))
	}

	cs.MUSTBE_EQ(circuit.Y, output)

	return nil
}

func (circuit *ExponentiateCircuit) PostInit(curveID gurvy.ID) error {
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
