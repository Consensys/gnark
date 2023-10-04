package huffman

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestDecodeOneOne(t *testing.T) {
	assignment := huffmanTestCircuit{
		lengths:    []int{1},
		Bits:       []frontend.Variable{0},
		Symbols:    []frontend.Variable{0},
		BitsLen:    1,
		SymbolsLen: 1,
	}
	test.NewAssert(t).SolvingSucceeded(assignment.hollow(), &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type huffmanTestCircuit struct {
	lengths             []int
	Bits, Symbols       []frontend.Variable
	BitsLen, SymbolsLen frontend.Variable
}

func (c *huffmanTestCircuit) hollow() frontend.Circuit {
	return &huffmanTestCircuit{
		lengths: c.lengths,
		Bits:    make([]frontend.Variable, len(c.Bits)),
		Symbols: make([]frontend.Variable, len(c.Symbols)),
	}
}

func (c *huffmanTestCircuit) Define(api frontend.API) error {
	symbols := make([]frontend.Variable, len(c.Symbols))
	l, err := Decode(api, c.Bits, c.BitsLen, c.lengths, symbols)
	if err != nil {
		return err
	}
	api.AssertIsEqual(l, c.SymbolsLen)
	assert := frontend.Variable(1)
	for i := range symbols {
		assert = api.MulAcc(assert, api.Neg(assert), api.IsZero(api.Sub(l, i)))
		api.AssertIsEqual(api.Mul(api.Sub(symbols[i], c.Symbols[i]), assert), 0)
	}
	return nil
}
