package maptocurve_bls12377

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
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
	assert.CheckCircuit(
		&yIncrementCircuit{},
		test.WithValidAssignment(&yIncrementCircuit{M: 0}),
		test.WithValidAssignment(&yIncrementCircuit{M: 1}),
		test.WithValidAssignment(&yIncrementCircuit{M: 42}),
		test.WithValidAssignment(&yIncrementCircuit{M: 123456789}),
		test.WithCurves(ecc.BW6_761),
	)
}

func BenchmarkYIncrement(b *testing.B) {
	b.Run("r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &yIncrementCircuit{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), scs.NewBuilder, &yIncrementCircuit{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
}
