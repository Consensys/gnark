package ecdsa

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/weierstrass"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

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

	// generate parameters
	_, g := secp256k1.Generators()
	var pp ecdsa.Params
	pp.Base.Set(&g)
	pp.Order = fr.Modulus()
	privKey, _ := pp.GenerateKey(rand.Reader)

	// sign
	hash := []byte("testing ECDSA")
	sig, _ := pp.Sign(hash, *privKey, rand.Reader)

	// check that the signature is correct
	if !pp.Verify(hash, sig, privKey.PublicKey.Q) {
		t.Errorf("can't verify signature")
	}

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.NewElement[emulated.Secp256k1Fr](sig.R),
			S: emulated.NewElement[emulated.Secp256k1Fr](sig.S),
		},
		Msg: emulated.NewElement[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.NewElement[emulated.Secp256k1Fp](privKey.PublicKey.Q.X),
			Y: emulated.NewElement[emulated.Secp256k1Fp](privKey.PublicKey.Q.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

// Example how to verify the signature inside the circuit.
func ExamplePublicKey_Verify() {
	api := frontend.API(nil) // provider by the builder
	r, s := 0x01, 0x02       // usually given in the witness
	pubx, puby := 0x03, 0x04 // usually given in the witness
	m := 0x1337              // usually given in the witness

	// can be done in or out-circuit.
	Sig := Signature[emulated.Secp256k1Fr]{
		R: emulated.NewElement[emulated.Secp256k1Fr](r),
		S: emulated.NewElement[emulated.Secp256k1Fr](s),
	}
	Msg := emulated.NewElement[emulated.Secp256k1Fr](m)
	Pub := PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.NewElement[emulated.Secp256k1Fp](pubx),
		Y: emulated.NewElement[emulated.Secp256k1Fp](puby),
	}
	// signature verification assertion is done in-circuit
	Pub.Verify(api, weierstrass.GetCurveParams[emulated.Secp256k1Fp](), &Msg, &Sig)
}

// Example how to create a valid signature for secp256k1
func ExamplePublicKey_Verify_create() {

	// generate parameters
	_, g := secp256k1.Generators()
	var pp ecdsa.Params
	pp.Base.Set(&g)
	pp.Order = fr.Modulus()
	privKey, _ := pp.GenerateKey(rand.Reader)

	// sign
	hash := []byte("testing ECDSA")
	sig, _ := pp.Sign(hash, *privKey, rand.Reader)

	pubx := privKey.PublicKey.Q.X
	puby := privKey.PublicKey.Q.Y
	// can continue in the PublicKey Verify example
	_, _, _, _, _ = sig.R, sig.S, hash, pubx, puby
}
