package ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	fr_secp256k1 "github.com/consensys/gnark-crypto/ecc/secp256k1/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type EcdsaCircuit[T, S emulated.FieldParams] struct {
	Sig Signature[S]
	Msg emulated.Element[S]
	Pub PublicKey[T, S]
}

func (c *EcdsaCircuit[T, S]) Define(api frontend.API) error {
	c.Pub.Verify(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	return nil
}

func TestEcdsaPreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, _ := privKey.Sign(msg, nil)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, nil)
	if !flag {
		t.Errorf("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}

func TestEcdsaSHA256(t *testing.T) {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (sha256)")
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	// check that the signature is correct
	flag, _ := publicKey.Verify(sigBin, msg, md)
	if !flag {
		t.Errorf("can't verify signature")
	}

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	// compute the hash of the message as an integer
	dataToHash := make([]byte, len(msg))
	copy(dataToHash[:], msg[:])
	md.Reset()
	md.Write(dataToHash[:])
	hramBin := md.Sum(nil)
	hash := ecdsa.HashToInt(hramBin)

	circuit := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		Sig: Signature[emulated.Secp256k1Fr]{
			R: emulated.ValueOf[emulated.Secp256k1Fr](r),
			S: emulated.ValueOf[emulated.Secp256k1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
		Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
			Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
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
		R: emulated.ValueOf[emulated.Secp256k1Fr](r),
		S: emulated.ValueOf[emulated.Secp256k1Fr](s),
	}
	Msg := emulated.ValueOf[emulated.Secp256k1Fr](m)
	Pub := PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: emulated.ValueOf[emulated.Secp256k1Fp](pubx),
		Y: emulated.ValueOf[emulated.Secp256k1Fp](puby),
	}
	// signature verification assertion is done in-circuit
	Pub.Verify(api, sw_emulated.GetCurveParams[emulated.Secp256k1Fp](), &Msg, &Sig)
}

// Example how to create a valid signature for secp256k1
func ExamplePublicKey_Verify_create() {

	// generate parameters
	privKey, _ := ecdsa.GenerateKey(rand.Reader)

	// sign
	msg := []byte("testing ECDSA")
	md := sha256.New()
	sigBin, _ := privKey.Sign(msg, md)

	pubx := privKey.PublicKey.A.X
	puby := privKey.PublicKey.A.Y

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)

	// can continue in the PublicKey Verify example
	_, _, _, _, _ = sig.R, sig.S, msg, pubx, puby
}

type EcdsaIsValidCircuit[T, S emulated.FieldParams] struct {
	Sig     Signature[S]
	Msg     emulated.Element[S]
	Pub     PublicKey[T, S]
	IsValid frontend.Variable `gnark:",public"`
}

func (c *EcdsaIsValidCircuit[T, S]) Define(api frontend.API) error {
	verified := c.Pub.IsValid(api, sw_emulated.GetCurveParams[T](), &c.Msg, &c.Sig)
	api.AssertIsEqual(verified, c.IsValid)
	return nil
}

func TestEcdsaPublicKeyIsValid(t *testing.T) {
	assert := test.NewAssert(t)
	// generate parameters
	privKey, err := ecdsa.GenerateKey(rand.Reader)
	assert.NoError(err, "failed to generate ecdsa key")
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	sigBin, err := privKey.Sign(msg, nil)
	assert.NoError(err, "failed to sign message")

	// check that the signature is correct
	flag, err := publicKey.Verify(sigBin, msg, nil)
	assert.NoError(err, "failed to verify signature")
	assert.True(flag, "can't verify signature")

	// unmarshal signature
	var sig ecdsa.Signature
	sig.SetBytes(sigBin)
	r, s := new(big.Int), new(big.Int)
	r.SetBytes(sig.R[:32])
	s.SetBytes(sig.S[:32])

	hash := ecdsa.HashToInt(msg)

	circuit := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{}

	assert.Run(func(assert *test.Assert) {
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 1,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=valid")

	assert.Run(func(assert *test.Assert) {
		r, err := rand.Int(rand.Reader, fr_secp256k1.Modulus())
		assert.NoError(err, "failed to generate random r")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-r")

	assert.Run(func(assert *test.Assert) {
		s, err := rand.Int(rand.Reader, fr_secp256k1.Modulus())
		assert.NoError(err, "failed to generate random r")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-s")

	assert.Run(func(assert *test.Assert) {
		hash := ecdsa.HashToInt([]byte("invalid message"))
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-msg")

	assert.Run(func(assert *test.Assert) {
		privKey, err := ecdsa.GenerateKey(rand.Reader)
		assert.NoError(err, "failed to generate ecdsa key")
		witness := EcdsaIsValidCircuit[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
			Sig: Signature[emulated.Secp256k1Fr]{
				R: emulated.ValueOf[emulated.Secp256k1Fr](r),
				S: emulated.ValueOf[emulated.Secp256k1Fr](s),
			},
			Msg: emulated.ValueOf[emulated.Secp256k1Fr](hash),
			Pub: PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
				X: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.X),
				Y: emulated.ValueOf[emulated.Secp256k1Fp](privKey.PublicKey.A.Y),
			},
			IsValid: 0,
		}
		err = test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "solving failed")
	}, "case=invalid-pub")
}
