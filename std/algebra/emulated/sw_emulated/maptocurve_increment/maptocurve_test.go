package maptocurve_increment

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

// testMessages exercises:
//   - small constants (0, 1, 42, 123456789),
//   - the largest "safe" message: 2^(bitlen(q)-8) − 1 (exactly bitlen(q)−8 bits),
//   - a message with the top 8 bits set (violates the msg < q/256
//     precondition; the circuit still solves — non-uniqueness is documented).
func testMessages[F emulated.FieldParams]() []*big.Int {
	var t F
	q := t.Modulus()
	bitlen := q.BitLen()

	maxSafe := new(big.Int).Lsh(big.NewInt(1), uint(bitlen-8))
	maxSafe.Sub(maxSafe, big.NewInt(1))

	overflow := new(big.Int).Sub(q, big.NewInt(1))
	overflow.Rsh(overflow, 8) // (q-1)/256
	overflow.Lsh(overflow, 4) // a value with non-zero bits in the top window

	return []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(42),
		big.NewInt(123456789),
		maxSafe,
		overflow,
	}
}

// --- supported-field gating ---

// TestIsSupportedField pins the compile-time guard in NewMapper: only the
// curves the hints can solve (BN254, secp256k1, P-256) are accepted; any other
// base field must be rejected at circuit-definition time rather than at proving
// time.
func TestIsSupportedField(t *testing.T) {
	if !isSupportedField[emulated.BN254Fp]() {
		t.Error("BN254 should be supported")
	}
	if !isSupportedField[emulated.Secp256k1Fp]() {
		t.Error("secp256k1 should be supported")
	}
	if !isSupportedField[emulated.P256Fp]() {
		t.Error("P-256 should be supported")
	}
	if isSupportedField[emulated.P384Fp]() {
		t.Error("P-384 should not be supported")
	}
	if isSupportedField[emulated.BLS12381Fp]() {
		t.Error("BLS12-381 should not be supported")
	}
}

// --- X-Increment tests ---

type xIncrementCircuit[B, S emulated.FieldParams] struct {
	M emulated.Element[B]
}

func (c *xIncrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper[B, S](api, crv)
	if err != nil {
		return err
	}
	p, err := m.XIncrement(&c.M)
	if err != nil {
		return err
	}
	// touch the returned point so the compiler keeps it constrained.
	crv.AssertIsOnCurve(p)
	return nil
}

func testXIncrement[B, S emulated.FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		opts = append(opts, test.WithValidAssignment(&xIncrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
		}))
	}
	assert.CheckCircuit(&xIncrementCircuit[B, S]{}, opts...)
}

func TestXIncrementEmulatedBN254(t *testing.T) {
	testXIncrement[emulated.BN254Fp, emulated.BN254Fr](t)
}
func TestXIncrementEmulatedSecp256k1(t *testing.T) {
	testXIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t)
}
func TestXIncrementEmulatedP256(t *testing.T) {
	testXIncrement[emulated.P256Fp, emulated.P256Fr](t)
}

// --- Y-Increment tests ---

type yIncrementCircuit[B, S emulated.FieldParams] struct {
	M emulated.Element[B]
}

func (c *yIncrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper[B, S](api, crv)
	if err != nil {
		return err
	}
	p, err := m.YIncrement(&c.M)
	if err != nil {
		return err
	}
	crv.AssertIsOnCurve(p)
	return nil
}

func testYIncrement[B, S emulated.FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		opts = append(opts, test.WithValidAssignment(&yIncrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
		}))
	}
	assert.CheckCircuit(&yIncrementCircuit[B, S]{}, opts...)
}

func TestYIncrementEmulatedBN254(t *testing.T) {
	testYIncrement[emulated.BN254Fp, emulated.BN254Fr](t)
}
func TestYIncrementEmulatedSecp256k1(t *testing.T) {
	testYIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t)
}
func TestYIncrementEmulatedP256(t *testing.T) {
	testYIncrement[emulated.P256Fp, emulated.P256Fr](t)
}

// --- Increment dispatcher tests ---

type incrementCircuit[B, S emulated.FieldParams] struct {
	M emulated.Element[B]
}

func (c *incrementCircuit[B, S]) Define(api frontend.API) error {
	crv, err := sw_emulated.New[B, S](api, sw_emulated.GetCurveParams[B]())
	if err != nil {
		return err
	}
	m, err := NewMapper[B, S](api, crv)
	if err != nil {
		return err
	}
	p, err := m.Increment(&c.M)
	if err != nil {
		return err
	}
	crv.AssertIsOnCurve(p)
	return nil
}

func testIncrement[B, S emulated.FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	opts := []test.TestingOption{test.WithCurves(ecc.BN254)}
	for _, msg := range testMessages[B]() {
		opts = append(opts, test.WithValidAssignment(&incrementCircuit[B, S]{
			M: emulated.ValueOf[B](msg),
		}))
	}
	assert.CheckCircuit(&incrementCircuit[B, S]{}, opts...)
}

func TestIncrementEmulatedBN254(t *testing.T) {
	testIncrement[emulated.BN254Fp, emulated.BN254Fr](t)
}
func TestIncrementEmulatedSecp256k1(t *testing.T) {
	testIncrement[emulated.Secp256k1Fp, emulated.Secp256k1Fr](t)
}
func TestIncrementEmulatedP256(t *testing.T) {
	testIncrement[emulated.P256Fp, emulated.P256Fr](t)
}
