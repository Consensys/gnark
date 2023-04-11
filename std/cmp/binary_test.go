package cmp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
	"testing"
)

type isLessRecursiveCircuit struct {
	A, B                 frontend.Variable
	WantLess, WantLessEq frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *isLessRecursiveCircuit) Define(api frontend.API) error {
	aBits := bits.ToBinary(api, c.A, bits.WithNbDigits(4))
	bBits := bits.ToBinary(api, c.B, bits.WithNbDigits(4))
	gotLess := isLessRecursive(api, aBits, bBits, false)
	gotLessEq := isLessRecursive(api, aBits, bBits, true)
	api.AssertIsEqual(gotLess, c.WantLess)
	api.AssertIsEqual(gotLessEq, c.WantLessEq)
	return nil
}

func Test_isLess(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          10,
		B:          11,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          11,
		B:          11,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          12,
		B:          11,
		WantLess:   0,
		WantLessEq: 0,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          0,
		B:          1,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          0,
		B:          0,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          14,
		B:          15,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          4,
		B:          12,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          6,
		B:          2,
		WantLess:   0,
		WantLessEq: 0,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          8,
		B:          8,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursiveCircuit{}, &isLessRecursiveCircuit{
		A:          2,
		B:          1,
		WantLess:   0,
		WantLessEq: 0,
	})
}
