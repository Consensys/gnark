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

// test message values
var testMessages = []*big.Int{
	big.NewInt(0),
	big.NewInt(1),
	big.NewInt(42),
	big.NewInt(123456789),
}

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

func testXIncrement[F emulated.FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages {
		opts = append(opts, test.WithValidAssignment(&xIncrementCircuit[F]{
			M: emulated.ValueOf[F](msg),
		}))
	}
	assert.CheckCircuit(&xIncrementCircuit[F]{}, opts...)
}

func TestXIncrementEmulatedBN254(t *testing.T)     { testXIncrement[emulated.BN254Fp](t) }
func TestXIncrementEmulatedSecp256k1(t *testing.T) { testXIncrement[emulated.Secp256k1Fp](t) }
func TestXIncrementEmulatedP256(t *testing.T)      { testXIncrement[emulated.P256Fp](t) }

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

func testYIncrement[F emulated.FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages {
		opts = append(opts, test.WithValidAssignment(&yIncrementCircuit[F]{
			M: emulated.ValueOf[F](msg),
		}))
	}
	assert.CheckCircuit(&yIncrementCircuit[F]{}, opts...)
}

func TestYIncrementEmulatedBN254(t *testing.T)     { testYIncrement[emulated.BN254Fp](t) }
func TestYIncrementEmulatedSecp256k1(t *testing.T) { testYIncrement[emulated.Secp256k1Fp](t) }
func TestYIncrementEmulatedP256(t *testing.T)      { testYIncrement[emulated.P256Fp](t) }

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
