package maptocurve

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// --- X-Increment tests ---

type xIncrementCircuit[F emulated.FieldParams] struct {
	M emulated.Element[F]
}

func (c *xIncrementCircuit[F]) Define(api frontend.API) error {
	m, err := NewMapper[F](api)
	if err != nil {
		return err
	}
	_, _, err = m.XIncrement(&c.M)
	return err
}

func TestXIncrementEmulatedBN254(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &xIncrementCircuit[emulated.BN254Fp]{
		M: emulated.ValueOf[emulated.BN254Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&xIncrementCircuit[emulated.BN254Fp]{},
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// --- Y-Increment tests ---

type yIncrementCircuit[F emulated.FieldParams] struct {
	M emulated.Element[F]
}

func (c *yIncrementCircuit[F]) Define(api frontend.API) error {
	m, err := NewMapper[F](api)
	if err != nil {
		return err
	}
	_, _, err = m.YIncrement(&c.M)
	return err
}

func TestYIncrementEmulatedBN254(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &yIncrementCircuit[emulated.BN254Fp]{
		M: emulated.ValueOf[emulated.BN254Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&yIncrementCircuit[emulated.BN254Fp]{},
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

// --- Benchmarks ---

func BenchmarkXIncrementEmulated(b *testing.B) {
	b.Run("BN254/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xIncrementCircuit[emulated.BN254Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("BN254/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &xIncrementCircuit[emulated.BN254Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
}

func BenchmarkYIncrementEmulated(b *testing.B) {
	b.Run("BN254/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &yIncrementCircuit[emulated.BN254Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("BN254/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &yIncrementCircuit[emulated.BN254Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
}
