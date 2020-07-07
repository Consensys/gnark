package main

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

type CubicCircuit struct {
	// tagging a constraint is optional
	// default uses variable name and secret visibility.
	X *frontend.Constraint `gnark:"x"`
	Y *frontend.Constraint `gnark:"y, public"`
}

func (cubic *CubicCircuit) PostInit(ctx *frontend.Context) error {
	// nothing to do here, this is a post init hook.
	// this is not a mandatory method to implement.
	fmt.Println("init hook called")
	return nil
}

func (circuit *CubicCircuit) Circuit(ctx *frontend.Context, cs *frontend.CS) error {
	//  x**3 + x + 5 == y
	x3 := cs.MUL(circuit.X, circuit.X, circuit.X)
	cs.MUSTBE_EQ(circuit.Y, cs.ADD(x3, circuit.X, 5))

	// we can tag a variable for testing and / or debugging purposes, it has no impact on performances
	x3.Tag("x^3")

	return nil
}

func main() {
	var cubicCircuit CubicCircuit
	// init slices if any
	// ex: cubicCircuit.bar = make([]foo, 12)

	// init context
	ctx := frontend.NewContext(gurvy.BN256)
	// add key values to context, usable by circuit and all used gadgets
	// ex: ctx.Set(rho, new(big.Int).Set("..."))

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ctx, &cubicCircuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = frontend.Save(ctx, r1cs, "circuit.r1cs"); err != nil {
		panic(err)
	}
}
