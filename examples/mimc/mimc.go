package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/hash/mimc"
	"github.com/consensys/gurvy"
)

type MiMCCircuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

func (circuit *MiMCCircuit) Define(ctx *frontend.Context, cs *frontend.CS) error {
	// hash function
	mimc, _ := mimc.NewMiMCGadget("seed", ctx.CurveID())

	// specify constraints
	// mimc(preImage) == hash
	cs.MUSTBE_EQ(circuit.Hash, mimc.Hash(cs, circuit.PreImage))

	return nil
}

func (circuit *MiMCCircuit) PostInit(ctx *frontend.Context) error {
	return nil
}

func main() {
	var mimcCircuit MiMCCircuit
	// init slices if any
	// ex: cubicCircuit.bar = make([]foo, 12)

	// init context
	ctx := frontend.NewContext(gurvy.BN256)
	// add key values to context, usable by circuit and all used gadgets
	// ex: ctx.Set(rho, new(big.Int).Set("..."))

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(ctx, &mimcCircuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = frontend.Save(ctx, r1cs, "circuit.r1cs"); err != nil {
		panic(err)
	}
}
