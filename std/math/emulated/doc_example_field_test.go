package emulated_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

type ExampleFieldCircuit[T emulated.FieldParams] struct {
	In1 emulated.Element[T]
	In2 emulated.Element[T]
	Res emulated.Element[T]
}

func (c *ExampleFieldCircuit[T]) Define(api frontend.API) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}
	res := f.Mul(&c.In1, &c.In2) // non-reducing
	res = f.Reduce(res)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

// Example of using [Field] instance. The witness elements must be [Element]
// type.
func ExampleField() {
	circuit := ExampleFieldCircuit[emulated.BN254Fp]{}
	witness := ExampleFieldCircuit[emulated.BN254Fp]{
		In1: emulated.ValueOf[emulated.BN254Fp](3),
		In2: emulated.ValueOf[emulated.BN254Fp](5),
		Res: emulated.ValueOf[emulated.BN254Fp](15),
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		panic(err)
	}
	witnessData, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	publicWitnessData, err := witnessData.Public()
	if err != nil {
		panic(err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		panic(err)
	}
	proof, err := groth16.Prove(ccs, pk, witnessData, backend.WithSolverOptions(solver.WithHints(emulated.GetHints()...)))
	if err != nil {
		panic(err)
	}
	err = groth16.Verify(proof, vk, publicWitnessData)
	if err != nil {
		panic(err)
	}
	fmt.Println("done")
	// Output: done
}
