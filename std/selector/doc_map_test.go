package selector_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/selector"
)

// MapCircuit is a minimal circuit using a selector map.
type MapCircuit struct {
	QueryKey      frontend.Variable
	Keys          [10]frontend.Variable // we use array in witness to allocate sufficiently sized vector
	Values        [10]frontend.Variable // we use array in witness to allocate sufficiently sized vector
	ExpectedValue frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *MapCircuit) Define(api frontend.API) error {
	result := selector.Map(api, c.QueryKey, c.Keys[:], c.Values[:])
	api.AssertIsEqual(result, c.ExpectedValue)
	return nil
}

// ExampleMap gives an example on how to use map selector.
func ExampleMap() {
	circuit := MapCircuit{}
	witness := MapCircuit{
		QueryKey:      55,
		Keys:          [10]frontend.Variable{0, 11, 22, 33, 44, 55, 66, 77, 88, 99},
		Values:        [10]frontend.Variable{0, 2, 4, 6, 8, 10, 12, 14, 16, 18},
		ExpectedValue: 10, // element in values which corresponds to the position of 55 in keys
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
