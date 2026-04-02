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

func TestXIncrementEmulatedSecp256k1(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &xIncrementCircuit[emulated.Secp256k1Fp]{
		M: emulated.ValueOf[emulated.Secp256k1Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&xIncrementCircuit[emulated.Secp256k1Fp]{},
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

func TestXIncrementEmulatedP256(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &xIncrementCircuit[emulated.P256Fp]{
		M: emulated.ValueOf[emulated.P256Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&xIncrementCircuit[emulated.P256Fp]{},
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

func TestYIncrementEmulatedSecp256k1(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &yIncrementCircuit[emulated.Secp256k1Fp]{
		M: emulated.ValueOf[emulated.Secp256k1Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&yIncrementCircuit[emulated.Secp256k1Fp]{},
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254),
	)
}

func TestYIncrementEmulatedP256(t *testing.T) {
	assert := test.NewAssert(t)
	witness := &yIncrementCircuit[emulated.P256Fp]{
		M: emulated.ValueOf[emulated.P256Fp](big.NewInt(1)),
	}
	assert.CheckCircuit(
		&yIncrementCircuit[emulated.P256Fp]{},
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
	b.Run("secp256k1/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xIncrementCircuit[emulated.Secp256k1Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("secp256k1/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &xIncrementCircuit[emulated.Secp256k1Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("P256/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &xIncrementCircuit[emulated.P256Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("P256/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &xIncrementCircuit[emulated.P256Fp]{})
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
	b.Run("secp256k1/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &yIncrementCircuit[emulated.Secp256k1Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("secp256k1/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &yIncrementCircuit[emulated.Secp256k1Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("P256/r1cs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &yIncrementCircuit[emulated.P256Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
	b.Run("P256/scs", func(b *testing.B) {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &yIncrementCircuit[emulated.P256Fp]{})
		if err != nil {
			b.Fatal(err)
		}
		b.Logf("%d constraints", ccs.GetNbConstraints())
	})
}
