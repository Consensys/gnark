package evmprecompiles

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
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

func TestP256VerifyCircuitWithEIPVectors(t *testing.T) {
	assert := test.NewAssert(t)
	data, err := os.ReadFile("test_vectors/p256verify_vectors_clean.json")
	if err != nil {
		t.Fatalf("read vectors.json: %v", err)
	}

	var vecs []vector
	if err := json.Unmarshal(data, &vecs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for i, v := range vecs {
		h, r, s, qx, qy := splitInput160(v.Input)
		verified := expectedBool(v.Expected)
		expected := frontend.Variable(0)
		if verified {
			expected = 1
		}
		witness := p256verifyCircuit{
			MsgHash:  emulated.ValueOf[emulated.P256Fr](*h),
			R:        emulated.ValueOf[emulated.P256Fr](*r),
			S:        emulated.ValueOf[emulated.P256Fr](*s),
			Qx:       emulated.ValueOf[emulated.P256Fp](*qx),
			Qy:       emulated.ValueOf[emulated.P256Fp](*qy),
			Expected: expected,
		}

		circuit := p256verifyCircuit{}

		t.Run(fmt.Sprintf("vector_%03d_%s", i, v.Name), func(t *testing.T) {
			err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
			assert.NoError(err)
		})
	}
}

// --- utils
type vector struct {
	Name     string `json:"Name,omitempty"`
	Input    string `json:"Input"`
	Expected string `json:"Expected"`
}

func splitInput160(hexInput string) (h, r, s, qx, qy *big.Int) {
	raw, err := hex.DecodeString(hexInput)
	if err != nil {
		panic(err)
	}
	if len(raw) != 160 {
		return nil, nil, nil, nil, nil
	}
	h = new(big.Int).SetBytes(raw[0:32])
	r = new(big.Int).SetBytes(raw[32:64])
	s = new(big.Int).SetBytes(raw[64:96])
	qx = new(big.Int).SetBytes(raw[96:128])
	qy = new(big.Int).SetBytes(raw[128:160])
	return
}

func expectedBool(s string) bool {
	raw, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	one := make([]byte, 32)
	one[31] = 1
	return bytes.Equal(raw, one)
}
