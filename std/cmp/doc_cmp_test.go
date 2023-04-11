package cmp_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/cmp"
	"github.com/consensys/gnark/std/math/bits"
)

type apiCircuit struct {
	A, B frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *apiCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(c.A, c.B)
	return nil
}

type isLessCircuit struct {
	A, B frontend.Variable
	// Expected frontend.Variable
}

func (c *isLessCircuit) Define(api frontend.API) error {
	result := cmp.BinaryIsLessEq(api, bits.ToBinary(api, c.A), bits.ToBinary(api, c.B))
	api.AssertIsEqual(result, 1)
	return nil
}

func ExampleBinaryIsLessEq() {
	ccs, _ := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &apiCircuit{})
	fmt.Println("api.AssertIsLessOrEqual:", ccs.GetNbConstraints())

	ccs, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &isLessCircuit{})
	fmt.Println("cmp.BinaryIsLessEq:", ccs.GetNbConstraints())

	// Output:
	// api.AssertIsLessOrEqual: 1270
	// cmp.BinaryIsLessEq: 1019
}
