package selector_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/selector"
)

// MuxCircuit is a minimal circuit using a selector mux.
type MuxCircuit struct {
	Selector frontend.Variable
	In       [10]frontend.Variable // we use array in witness to allocate sufficiently sized vector
	Expected frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *MuxCircuit) Define(api frontend.API) error {
	result := selector.Mux(api, c.Selector, c.In[:]...) // Note Mux takes var-arg input, need to expand the input vector
	api.AssertIsEqual(result, c.Expected)
	return nil
}

// ExampleMux gives an example on how to use mux selector.
func ExampleMux() {
	circuit := MuxCircuit{}
	witness := MuxCircuit{
		Selector: 5,
		In:       [10]frontend.Variable{0, 2, 4, 6, 8, 10, 12, 14, 16, 18},
		Expected: 10, // 5-th element in vector
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
