package selector_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/selector"
)

// adderCircuit adds first Count number of its input array In.
type adderCircuit struct {
	Count       frontend.Variable
	In          [10]frontend.Variable
	ExpectedSum frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *adderCircuit) Define(api frontend.API) error {
	selectedPart := selector.Partition(api, c.Count, false, c.In[:])
	sum := api.Add(selectedPart[0], selectedPart[1], selectedPart[2:]...)
	api.AssertIsEqual(sum, c.ExpectedSum)
	return nil
}

// ExamplePartition gives an example on how to use selector.Partition to make a circuit that accepts a Count and an
// input array In, and then calculates the sum of first Count numbers of the input array.
func ExamplePartition() {
	circuit := adderCircuit{}
	witness := adderCircuit{
		Count:       6,
		In:          [10]frontend.Variable{0, 2, 4, 6, 8, 10, 12, 14, 16, 18},
		ExpectedSum: 30,
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	secretWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	}
	fmt.Println("done")
	// Output: done
}
