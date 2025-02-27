package selector

import (
	binary "math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
)

type binarymux struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable

	Length int
}

func (c *binarymux) Define(api frontend.API) error {
	if len(c.Input) != c.Length {
		panic("invalid length")
	}
	s := func(api frontend.API, sel frontend.Variable, inputs ...frontend.Variable) frontend.Variable {
		// this function replicates the replaced function Mux
		// we use BinaryMux when len(inputs) is a power of 2.
		if binary.OnesCount(uint(len(inputs))) == 1 {
			selBits := bits.ToBinary(api, sel, bits.WithNbDigits(binary.Len(uint(len(inputs)))-1))
			return BinaryMux(api, selBits, inputs)
		}
		return dotProduct(api, inputs, Decoder(api, len(inputs), sel))
	}(api, c.Sel, c.Input...)
	api.AssertIsEqual(s, c.Expected)
	return nil
}

type dotProductCircuit struct {
	Sel      frontend.Variable
	Input    []frontend.Variable
	Expected frontend.Variable

	Length int
}

func (c *dotProductCircuit) Define(api frontend.API) error {
	if len(c.Input) != c.Length {
		panic("invalid length")
	}
	s := dotProduct(api, c.Input, Decoder(api, len(c.Input), c.Sel))
	api.AssertIsEqual(s, c.Expected)
	return nil
}
