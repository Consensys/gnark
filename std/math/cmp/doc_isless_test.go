package cmp_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/cmp"
	"math/big"
)

// MapCircuit is a circuit that uses BoundedComparator.IsLess method to verify that an input array
// is sorted. We assume that the input array contains 16bit unsigned integers. If the input array is
// sorted and is ascending, SortErrors will be zero, otherwise it will be nonzero and equal to the
// number of adjacent non-ascending pairs.
type sortCheckerCircuit struct {
	UInt16Array [10]frontend.Variable
	SortErrors  frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *sortCheckerCircuit) Define(api frontend.API) error {
	// constructing a 16bit comparator,
	// the maximum possible difference between 16bit numbers is 2^16-1.
	cmp16bit := cmp.NewBoundedComparator(api, big.NewInt(1<<16-1))
	res := frontend.Variable(0)
	for i := 0; i < len(c.UInt16Array)-1; i++ {
		res = api.Add(res, cmp16bit.IsLess(c.UInt16Array[i+1], c.UInt16Array[i]))
	}
	api.AssertIsEqual(res, c.SortErrors)
	return nil
}

func ExampleBoundedComparator_IsLess() {
	circuit := sortCheckerCircuit{}
	witness := sortCheckerCircuit{
		UInt16Array: [10]frontend.Variable{0, 11, 22, 22, 33, 44, 55, 66, 77, 65535},
		SortErrors:  0, // is zero when UInt16Array is sorted and ascending.
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled")
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("setup done")
	}
	secretWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	} else {
		fmt.Println("secret witness")
	}
	publicWitness, err := secretWitness.Public()
	if err != nil {
		panic(err)
	} else {
		fmt.Println("public witness")
	}
	proof, err := groth16.Prove(ccs, pk, secretWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("proof")
	}
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		panic(err)
	} else {
		fmt.Println("verify")
	}
	// Output: compiled
	// setup done
	// secret witness
	// public witness
	// proof
	// verify
}
