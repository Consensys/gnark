package main

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gurvy"
)

// MiMCCircuit defines a pre-image knowledge proof
// mimc(secret preImage) = public hash
type MiMCCircuit struct {
	// struct tag on a variable is optional
	// default uses variable name and secret visibility.
	PreImage frontend.Variable
	Hash     frontend.Variable `gnark:",public"`
}

// Define declares the circuit's constraints
// Hash = mimc(PreImage)
func (circuit *MiMCCircuit) Define(curveID gurvy.ID, cs *frontend.CS) error {
	// hash function
	mimc, _ := mimc.NewMiMC("seed", curveID)

	// specify constraints
	// mimc(preImage) == hash
	cs.MustBeEqual(circuit.Hash, mimc.Hash(cs, circuit.PreImage))

	return nil
}

func main() {
	var mimcCircuit MiMCCircuit
	// init slices if any
	// ex: cubicCircuit.bar = make([]foo, 12)

	// compiles our circuit into a R1CS
	r1cs, err := frontend.Compile(gurvy.BN256, &mimcCircuit)
	if err != nil {
		panic(err)
	}

	// save the R1CS to disk
	if err = frontend.Save(r1cs, "circuit.r1cs"); err != nil {
		panic(err)
	}
}
