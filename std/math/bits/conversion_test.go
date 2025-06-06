package bits_test

import (
	"crypto/rand"
	"errors"
	"math/big"
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

type toBinaryCircuitConstantInput struct {
	A         frontend.Variable
	constantA *big.Int
	nbBits    int
}

func (c *toBinaryCircuitConstantInput) Define(api frontend.API) error {
	opts := []bits.BaseConversionOption{}
	if c.nbBits > 0 {
		opts = append(opts, bits.WithNbDigits(c.nbBits))
	}
	decomposedA := bits.ToBinary(api, c.A, opts...)
	constantA := new(big.Int).Set(c.constantA)
	if _, ok := api.Compiler().ConstantValue(constantA); !ok {
		// we work inside a test engine. It doesn't differentiate between a constant and a variable. We manually reduce for now.
		constantA.Mod(constantA, api.Compiler().Field())
	}
	decomposedAConstant := bits.ToBinary(api, constantA, opts...)
	if len(decomposedA) != len(decomposedAConstant) {
		return errors.New("decomposedA and decomposedAConstant must have the same length")
	}
	for i := 0; i < len(decomposedA); i++ {
		api.AssertIsEqual(decomposedA[i], decomposedAConstant[i])
	}

	return nil
}

func TestToBinaryConstantInput(t *testing.T) {
	assert := test.NewAssert(t)

	for _, v := range []int{0, 1, 2, 10, 100, 300} {
		val, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(v)))
		assert.NoError(err)
		assert.CheckCircuit(&toBinaryCircuitConstantInput{constantA: val, nbBits: v}, test.WithValidAssignment(&toBinaryCircuitConstantInput{A: val}))
	}
}
