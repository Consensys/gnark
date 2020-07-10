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

func (circuit *ExponentiateCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	// specify constraints
	output := cs.ALLOCATE(1)
	bits := cs.TO_BINARY(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {

		bits[i].Tag(fmt.Sprintf("e[%d]", i)) // we can tag a variable for testing and / or debugging purposes, it has no impact on performances

		if i != 0 {
			output = cs.MUL(output, output)
		}
		multiply := cs.MUL(output, circuit.X)
		output = cs.SELECT(bits[len(bits)-1-i], multiply, output)

		output.Tag(fmt.Sprintf("output after processing exponent bit %d", len(bits)-1-i))
	}

	cs.MUSTBE_EQ(circuit.Y, output)

	return nil
}

func (circuit *ExponentiateCircuit) PostInit(ctx *frontend.Context) error {
	return nil
}

func main() {
	var expCircuit ExponentiateCircuit
	// init slices if any
	// ex: cubicCircuit.bar = make([]foo, 12)

	// init context
	ctx := frontend.NewContext(gurvy.BN256)
	// add key values to context, usable by circuit and all used gadgets
	// ex: ctx.Set(rho, new(big.Int).Set("..."))

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ctx, &expCircuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = frontend.Save(ctx, r1cs, "circuit.r1cs"); err != nil {
		panic(err)
	}
}
