package emulated_test

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
)

// HintExample is a hint for field emulation which returns the division of the
// first and second input.
func HintExample(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	// nativeInputs are the limbs of the input non-native elements. We wrap the
	// actual hint function with [emulated.UnwrapHint] to get actual [*big.Int]
	// values of the non-native elements.
	return emulated.UnwrapHint(nativeInputs, nativeOutputs, func(mod *big.Int, inputs, outputs []*big.Int) error {
		// this hint computes the division of first and second input and returns it.
		nominator := inputs[0]
		denominator := inputs[1]
		res := new(big.Int).ModInverse(denominator, mod)
		if res == nil {
			return fmt.Errorf("no modular inverse")
		}
		res.Mul(res, nominator)
		res.Mod(res, mod)
		outputs[0].Set(res)
		return nil
	})
	// when the internal hint function returns, the UnwrapHint function
	// decomposes the non-native value into limbs.
}

type emulationHintCircuit[T emulated.FieldParams] struct {
	Nominator   emulated.Element[T]
	Denominator emulated.Element[T]
	Expected    emulated.Element[T]
}

func (c *emulationHintCircuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHint(HintExample, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	m := field.Mul(res[0], &c.Denominator)
	field.AssertIsEqual(m, &c.Nominator)
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

// Example of using hints with emulated elements.
func ExampleField_NewHint() {
	var a, b, c fr.Element
	a.SetRandom()
	b.SetRandom()
	c.Div(&a, &b)

	circuit := emulationHintCircuit[emulated.BN254Fr]{}
	witness := emulationHintCircuit[emulated.BN254Fr]{
		Nominator:   emulated.ValueOf[emulated.BN254Fr](a),
		Denominator: emulated.ValueOf[emulated.BN254Fr](b),
		Expected:    emulated.ValueOf[emulated.BN254Fr](c),
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
	proof, err := groth16.Prove(ccs, pk, witnessData, backend.WithSolverOptions(solver.WithHints(HintExample)))
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
