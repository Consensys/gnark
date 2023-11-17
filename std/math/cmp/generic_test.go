package cmp

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/test"
	"math/big"
	"testing"
)

type isLessRecursive4BitCircuit struct {
	A, B                 frontend.Variable
	WantLess, WantLessEq frontend.Variable
}

// Define defines the arithmetic circuit.
func (c *isLessRecursive4BitCircuit) Define(api frontend.API) error {
	aBits := bits.ToBinary(api, c.A, bits.WithNbDigits(4))
	bBits := bits.ToBinary(api, c.B, bits.WithNbDigits(4))

	api.AssertIsEqual(c.WantLess, isLessRecursive(api, aBits, bBits, false, false))
	api.AssertIsEqual(c.WantLess, isLessRecursive(api, aBits, bBits, false, true))

	api.AssertIsEqual(c.WantLessEq, isLessRecursive(api, aBits, bBits, true, false))
	api.AssertIsEqual(c.WantLessEq, isLessRecursive(api, aBits, bBits, true, true))

	return nil
}

func Test_isLessRecursive(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          10,
		B:          11,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          11,
		B:          11,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          12,
		B:          11,
		WantLess:   0,
		WantLessEq: 0,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          0,
		B:          1,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          0,
		B:          0,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          14,
		B:          15,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          4,
		B:          12,
		WantLess:   1,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          6,
		B:          2,
		WantLess:   0,
		WantLessEq: 0,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          8,
		B:          8,
		WantLess:   0,
		WantLessEq: 1,
	})

	assert.ProverSucceeded(&isLessRecursive4BitCircuit{}, &isLessRecursive4BitCircuit{
		A:          2,
		B:          1,
		WantLess:   0,
		WantLessEq: 0,
	})
}

type isLessUnsignedCircuit struct {
	A, B                 frontend.Variable
	WantLess, WantLessEq frontend.Variable
}

func (c *isLessUnsignedCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.WantLess, IsLess(api, c.A, c.B))
	api.AssertIsEqual(c.WantLessEq, IsLessOrEqual(api, c.A, c.B))
	return nil
}

func Test_IsLessUnsigned(t *testing.T) {
	assert := test.NewAssert(t)
	bigNum := new(big.Int).Lsh(big.NewInt(1), 253)

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Sub(bigNum, big.NewInt(59)),
		B:          new(big.Int).Add(bigNum, big.NewInt(10)),
		WantLess:   1,
		WantLessEq: 1,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Add(bigNum, big.NewInt(1267)),
		B:          new(big.Int).Add(bigNum, big.NewInt(1267)),
		WantLess:   0,
		WantLessEq: 1,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Sub(bigNum, big.NewInt(1)),
		B:          new(big.Int).Sub(bigNum, big.NewInt(2)),
		WantLess:   0,
		WantLessEq: 0,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Sub(bigNum, big.NewInt(3)),
		B:          new(big.Int).Sub(bigNum, big.NewInt(2)),
		WantLess:   1,
		WantLessEq: 1,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Sub(bigNum, big.NewInt(1)),
		B:          new(big.Int).Sub(bigNum, big.NewInt(1)),
		WantLess:   0,
		WantLessEq: 1,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          new(big.Int).Add(bigNum, big.NewInt(200)),
		B:          new(big.Int).Add(bigNum, big.NewInt(100)),
		WantLess:   0,
		WantLessEq: 0,
	}, test.WithCurves(ecc.BN254))

	assert.ProverSucceeded(&isLessUnsignedCircuit{}, &isLessUnsignedCircuit{
		A:          12345,
		B:          new(big.Int).Sub(bigNum, big.NewInt(4568794)),
		WantLess:   1,
		WantLessEq: 1,
	}, test.WithCurves(ecc.BN254))
}
