package maptocurve_increment

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	grumpkinfp "github.com/consensys/gnark-crypto/ecc/grumpkin/fp"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type yIncrementCircuit struct {
	M frontend.Variable
}

func (c *yIncrementCircuit) Define(api frontend.API) error {
	_, _, err := YIncrement(api, c.M)
	return err
}

func TestYIncrement(t *testing.T) {
	assert := test.NewAssert(t)

	// largest message with the documented 8-bit headroom (bitlen(q)−8 bits).
	q := grumpkinfp.Modulus()
	maxSafe := new(big.Int).Lsh(big.NewInt(1), uint(q.BitLen()-8))
	maxSafe.Sub(maxSafe, big.NewInt(1))

	assert.CheckCircuit(
		&yIncrementCircuit{},
		test.WithValidAssignment(&yIncrementCircuit{M: 0}),
		test.WithValidAssignment(&yIncrementCircuit{M: 1}),
		test.WithValidAssignment(&yIncrementCircuit{M: 42}),
		test.WithValidAssignment(&yIncrementCircuit{M: 123456789}),
		test.WithValidAssignment(&yIncrementCircuit{M: maxSafe}),
		test.WithCurves(ecc.BN254),
	)
}
