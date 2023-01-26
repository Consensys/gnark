package ecdsa

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/weierstrass"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/ethereum/go-ethereum/crypto"
)

var testPrivHex = "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"

func sign(t *testing.T) ([]byte, []byte, error) {
	t.Helper()
	key, _ := crypto.HexToECDSA(testPrivHex)
	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}
	return sig, msg, nil
}

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig Signature[S]
	Msg emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, weierstrass.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func TestEcdsa(t *testing.T) {
	// generate a valid signature
	sig, msg, err := sign(t)
	if err != nil {
		t.Fatal(err)
	}

	// check that the signature is correct
	pub, err := crypto.Ecrecover(msg, sig)
	if err != nil {
		t.Fatal(err)
	}
	sig = sig[:len(sig)-1]
	if !crypto.VerifySignature(pub, msg, sig) {
		t.Errorf("can't verify signature with uncompressed key")
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	m := new(big.Int).SetBytes(msg)

	_pub, err := crypto.UnmarshalPubkey(pub)
	if err != nil {
		t.Fatal(err)
	}

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.FromConstant[emulated.Secp256k1Fr](r),
			S: emulated.FromConstant[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.FromConstant[emulated.Secp256k1Fr](m),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.FromConstant[emulated.Secp256k1Fp](_pub.X),
			Y: emulated.FromConstant[emulated.Secp256k1Fp](_pub.Y),
		},
	}
	assert := test.NewAssert(t)
	err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
	// _, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	// assert.NoError(err)
}

// Example how to verify the signature inside the circuit.
func ExamplePublicKey_Verify() {
	api := frontend.API(nil) // provider by the builder
	r, s := 0x01, 0x02       // usually given in the witness
	pubx, puby := 0x03, 0x04 // usually given in the witness
	m := 0x1337              // usually given in the witness

	// can be done in or out-circuit.
	Sig := Signature[emulated.Secp256k1Fr]{
		R: emulated.FromConstant[emulated.Secp256k1Fr](r),
		S: emulated.FromConstant[emulated.Secp256k1Fr](s),
	}
	Msg := emulated.FromConstant[emulated.Secp256k1Fr](m)
	Pub := PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.FromConstant[emulated.Secp256k1Fp](pubx),
		Y: emulated.FromConstant[emulated.Secp256k1Fp](puby),
	}
	// signature verification assertion is done in-circuit
	Pub.Verify(api, weierstrass.GetCurveParams[emulated.Secp256k1Fp](), &Msg, &Sig)
}

// Example how to create a valid signature for secp256k1
func ExamplePublicKey_Verify_create() {
	testPrivHex := "289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032"
	key, _ := crypto.HexToECDSA(testPrivHex)
	msg := crypto.Keccak256([]byte("foo"))
	sig, err := crypto.Sign(msg, key)
	if err != nil {
		panic("sign")
	}
	_pub, err := crypto.Ecrecover(msg, sig)
	if err != nil {
		panic("ecrecover")
	}
	sig = sig[:len(sig)-1]

	pub, err := crypto.UnmarshalPubkey(_pub)
	if err != nil {
		panic("unmarshal")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	m := new(big.Int).SetBytes(msg)
	pubx := pub.X
	puby := pub.Y
	// can continue in the PublicKey Verify example
	_, _, _, _, _ = r, s, m, pubx, puby
}
