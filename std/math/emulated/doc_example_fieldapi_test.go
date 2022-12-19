package emulated_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

type ExampleFieldAPICircuit struct {
	InNative    frontend.Variable // must be integer-like, not [Element]
	InNonnative emulated.Element[emulated.BN254Fp]
	Res         emulated.Element[emulated.BN254Fp]
}

func (c *ExampleFieldAPICircuit) Define(api frontend.API) error {
	api, err := emulated.NewAPI[emulated.BN254Fp](api)
	if err != nil {
		return fmt.Errorf("new api: %w", err)
	}
	// now use API as would use native frontend.API
	res := api.Mul(c.InNative, c.InNonnative) // native element is converted to non-native on-the-fly
	api.AssertIsEqual(res, c.Res)
	return nil
}

// Example of using [FieldAPI] for drop-in replacement of native API.
//
// Witness elements must be [Element] type for successful compiling and parsing
// of the circuit.
func ExampleFieldAPI_api() {
	// compiling the circuit
	circuit := ExampleFieldAPICircuit{}
	witness := ExampleFieldAPICircuit{
		InNative:    3,
		InNonnative: emulated.NewElement[emulated.BN254Fp](5),
		Res:         emulated.NewElement[emulated.BN254Fp](15),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	witnessData, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness parsed")
	}
	publicWitnessData, err := witnessData.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness parsed")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	proof, err := groth16.Prove(ccs, pk, witnessData, backend.WithHints(emulated.GetHints()...))
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proved")
	}
	err = groth16.Verify(proof, vk, publicWitnessData)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verified")
	}
	// Output: compiled
	// secret witness parsed
	// public witness parsed
	// setup done
	// proved
	// verified
}
