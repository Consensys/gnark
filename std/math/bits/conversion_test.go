package bits_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
)

type toBinaryCircuit struct {
	A          frontend.Variable
	B0, B1, B2 frontend.Variable
}

func (c *toBinaryCircuit) Define(api frontend.API) error {
	// binary decomposition
	nA := bits.FromBinary(api, []frontend.Variable{c.B0, c.B1, c.B2})

	api.AssertIsEqual(nA, c.A)

	// to binary
	b := bits.ToBinary(api, c.A, bits.WithNbDigits(3))
	api.AssertIsEqual(b[0], c.B0)
	api.AssertIsEqual(b[1], c.B1)
	api.AssertIsEqual(b[2], c.B2)

	return nil
}

func TestToBinary(t *testing.T) {
	assert := test.NewAssert(t)

	assert.CheckCircuit(&toBinaryCircuit{},
		test.WithValidAssignment(&toBinaryCircuit{A: 5, B0: 1, B1: 0, B2: 1}),
		test.WithValidAssignment(&toBinaryCircuit{A: 3, B0: 1, B1: 1, B2: 0}),
		test.WithInvalidAssignment(&toBinaryCircuit{A: 8, B0: 0, B1: 0, B2: 0}),
		test.WithInvalidAssignment(&toBinaryCircuit{A: 10, B0: 0, B1: 1, B2: 0}),
	)

}

type toTernaryCircuit struct {
	A          frontend.Variable
	T0, T1, T2 frontend.Variable
}

func (c *toTernaryCircuit) Define(api frontend.API) error {
	// ternary decomposition
	nA := bits.FromTernary(api, []frontend.Variable{c.T0, c.T1, c.T2})

	api.AssertIsEqual(nA, c.A)

	// to ternary
	t := bits.ToTernary(api, c.A, bits.WithNbDigits(3))
	api.AssertIsEqual(t[0], c.T0)
	api.AssertIsEqual(t[1], c.T1)
	api.AssertIsEqual(t[2], c.T2)

	return nil
}

func TestToTernary(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(&toTernaryCircuit{}, test.WithValidAssignment(&toTernaryCircuit{A: 5, T0: 2, T1: 1, T2: 0}))
}
