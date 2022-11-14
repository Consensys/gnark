package emulated_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type ExampleFieldAPIBuilderCircuit struct {
	In1 frontend.Variable
	In2 frontend.Variable
	Res frontend.Variable
}

func (c *ExampleFieldAPIBuilderCircuit) Define(api frontend.API) error {
	// now use API as would use native frontend.API
	res := api.Mul(c.In1, c.In2) // native element is converted to non-native on-the-fly
	api.AssertIsEqual(res, c.Res)
	return nil
}

// Example of using [FieldAPI] implementing [frontend.Builder] interface. The
// witness elements may be of any type, they are converted to [Element] type
// instance by the built-in hooks of the wrapped builder during parsing.
func ExampleFieldAPI_builder() {
	circuit := ExampleFieldAPIBuilderCircuit{}
	witness := ExampleFieldAPIBuilderCircuit{
		In1: emulated.NewElement[emulated.BN254Fp](3),
		In2: emulated.NewElement[emulated.BN254Fp](5),
		Res: emulated.NewElement[emulated.BN254Fp](15),
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(func(b frontend.Builder) frontend.Builder {
		wb, err := emulated.NewBuilder[emulated.BN254Fp](b)
		if err != nil {
			panic(err)
		}
		return wb
	}))
	if err != nil {
		panic(err)
	} else {
		fmt.Println("compiled using builder wrapper")
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField(), test.WithApiWrapper(func(a frontend.API) frontend.API {
		wa, err := emulated.NewAPI[emulated.BN254Fp](a)
		if err != nil {
			panic(err)
		}
		return wa
	}))
	if err != nil {
		panic(err)
	} else {
		fmt.Println("solved using test engine")
	}
	// Output: compiled using builder wrapper
	// solved using test engine
}
