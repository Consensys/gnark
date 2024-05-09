package evmprecompiles

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func TestSignForRecoverCorrectness(t *testing.T) {
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	_, r, s, err := sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	var sig ecdsa.Signature
	r.FillBytes(sig.R[:fr.Bytes])
	s.FillBytes(sig.S[:fr.Bytes])
	sigM := sig.Bytes()
	ok, err := pk.Verify(sigM, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	if !ok {
		t.Fatal("not verified")
	}
}

type ecrecoverCircuit struct {
	Message   emulated.Element[emulated.Secp256k1Fr]
	V         frontend.Variable
	R         emulated.Element[emulated.Secp256k1Fr]
	S         emulated.Element[emulated.Secp256k1Fr]
	Strict    frontend.Variable
	IsFailure frontend.Variable
	Expected  sw_emulated.AffinePoint[emulated.Secp256k1Fp]
}

func (c *ecrecoverCircuit) Define(api frontend.API) error {
	curve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return fmt.Errorf("new curve: %w", err)
	}
	res := ECRecover(api, c.Message, c.V, c.R, c.S, c.Strict, c.IsFailure)
	curve.AssertIsEqual(&c.Expected, res)
	return nil
}

func testRoutineECRecover(t *testing.T, wantStrict bool) (circ, wit *ecrecoverCircuit, largeS bool) {
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))

	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	for {
		v, r, s, err = sk.SignForRecover(msg, nil)
		if err != nil {
			t.Fatal("sign", err)
		}
		if !wantStrict || halfFr.Cmp(s) > 0 {
			break
		}
	}
	strict := 0
	if wantStrict {
		strict = 1
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    strict,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	return &circuit, &witness, halfFr.Cmp(s) <= 0
}

func TestECRecoverCircuitShortStrict(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, true)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortLax(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, false)
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestECRecoverCircuitShortMismatch(t *testing.T) {
	assert := test.NewAssert(t)
	halfFr := new(big.Int).Sub(fr.Modulus(), big.NewInt(1))
	halfFr.Div(halfFr, big.NewInt(2))
	var circuit, witness *ecrecoverCircuit
	var largeS bool
	for {
		circuit, witness, largeS = testRoutineECRecover(t, false)
		if largeS {
			witness.Strict = 1
			break
		}
	}
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
}

func TestECRecoverCircuitFull(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, false)

	assert.CheckCircuit(
		circuit,
		test.WithValidAssignment(witness),
		test.WithCurves(ecc.BN254, ecc.BLS12_377),
		test.NoProverChecks(),
	)
}

func TestECRecoverQNR(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverQNRWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	_, err := sk.SetBytes([]byte{0x80, 0x95, 0xb4, 0x19, 0x78, 0xe3, 0x7c, 0xb2, 0x44, 0x76, 0xd3, 0x76, 0x90, 0x87, 0x33, 0x61, 0x89, 0xcf, 0xac, 0xc2, 0x60, 0x2d, 0xf9, 0x83, 0xcc, 0xb5, 0xb2, 0x5c, 0x84, 0xe9, 0x41, 0x76, 0x7e, 0xe7, 0x47, 0x4b, 0x89, 0xbb, 0x50, 0xe0, 0x6, 0xf6, 0x11, 0x25, 0xf2, 0xe8, 0xf7, 0xb2, 0x59, 0x9d, 0xa8, 0x7, 0x48, 0x2b, 0x6d, 0x8c, 0x3e, 0x28, 0x5, 0x93, 0xf8, 0x5c, 0xcc, 0xc9, 0xe, 0x40, 0x3d, 0x19, 0x13, 0xad, 0x7f, 0xc1, 0x63, 0x93, 0x71, 0xb6, 0x8d, 0x3d, 0x43, 0x7a, 0x7f, 0x8, 0x9f, 0xaa, 0x8f, 0xc, 0xf6, 0xf8, 0x5, 0xad, 0xaf, 0x23, 0x93, 0x34, 0x97, 0xba})
	assert.NoError(err)
	msg := []byte("test")
	v := 1
	r, _ := new(big.Int).SetString("115792089237316195423570985008687907853269984665640564039457584007908834671662", 10)
	s, _ := new(big.Int).SetString("31110821449234674195879853497860775923588666272130120981349127974920000247897", 10)
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](0),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](0),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestECRecoverInfinity(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 1,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestECRecoverInfinityWoFailure(t *testing.T) {
	assert := test.NewAssert(t)
	var sk ecdsa.PrivateKey
	var err error
	pk := sk.Public().(*ecdsa.PublicKey)
	msg := []byte("test")
	var r, s *big.Int
	var v uint
	v, r, s, err = sk.SignForRecover(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	circuit := ecrecoverCircuit{}
	witness := ecrecoverCircuit{
		Message:   emulated.ValueOf[emulated.Secp256k1Fr](ecdsa.HashToInt(msg)),
		V:         v + 27, // EVM constant
		R:         emulated.ValueOf[emulated.Secp256k1Fr](r),
		S:         emulated.ValueOf[emulated.Secp256k1Fr](s),
		Strict:    0,
		IsFailure: 0,
		Expected: sw_emulated.AffinePoint[emulated.Secp256k1Fp]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](pk.A.Y),
		},
	}
	err = test.IsSolved(&circuit, &witness, ecc.BLS12_377.ScalarField())
	assert.Error(err)
}

func TestInvalidFailureTag(t *testing.T) {
	assert := test.NewAssert(t)
	circuit, witness, _ := testRoutineECRecover(t, false)
	witness.IsFailure = 1
	err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
	assert.Error(err)
}
