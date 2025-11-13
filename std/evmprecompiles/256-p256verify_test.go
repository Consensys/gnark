package evmprecompiles

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256r1/ecdsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type p256verifyCircuit struct {
	MsgHash  emulated.Element[emulated.P256Fr]
	R        emulated.Element[emulated.P256Fr]
	S        emulated.Element[emulated.P256Fr]
	Qx, Qy   emulated.Element[emulated.P256Fp]
	Expected frontend.Variable
}

func (c *p256verifyCircuit) Define(api frontend.API) error {
	res := P256Verify(api, c.MsgHash, c.R, c.S, c.Qx, c.Qy)
	api.AssertIsEqual(c.Expected, res)
	return nil
}

func TestP256VerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)
	// key generation
	sk, err := ecdsa.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate", err)
	}
	pk := sk.PublicKey
	// signing
	msg := []byte("test")
	sigBuf, err := sk.Sign(msg, nil)
	if err != nil {
		t.Fatal("sign", err)
	}
	// verification
	verified, err := sk.PublicKey.Verify(sigBuf, msg, nil)
	if err != nil {
		t.Fatal("verify", err)
	}
	// marshalling
	var sig ecdsa.Signature
	sig.SetBytes(sigBuf[:])
	var r, s big.Int
	r.SetBytes(sig.R[:])
	s.SetBytes(sig.S[:])
	hash := ecdsa.HashToInt(msg)
	var expected frontend.Variable
	if verified {
		expected = 1
	}

	circuit := p256verifyCircuit{}
	witness := p256verifyCircuit{
		MsgHash:  emulated.ValueOf[emulated.P256Fr](hash),
		R:        emulated.ValueOf[emulated.P256Fr](r),
		S:        emulated.ValueOf[emulated.P256Fr](s),
		Qx:       emulated.ValueOf[emulated.P256Fp](pk.A.X),
		Qy:       emulated.ValueOf[emulated.P256Fp](pk.A.Y),
		Expected: expected,
	}
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
