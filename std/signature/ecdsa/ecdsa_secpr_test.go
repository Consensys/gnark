package ecdsa

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestEcdsaP256PreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := cryptoecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	msgHash := sha256.Sum256(msg)
	sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

	// check that the signature is correct
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigBin)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		panic("invalid sig")
	}
	flag := cryptoecdsa.Verify(&publicKey, msgHash[:], r, s)
	if !flag {
		t.Errorf("can't verify signature")
	}

	circuit := EcdsaCircuit[emparams.P256Fp, emparams.P256Fr]{}
	witness := EcdsaCircuit[emparams.P256Fp, emparams.P256Fr]{
		Sig: Signature[emparams.P256Fr]{
			R: emulated.ValueOf[emparams.P256Fr](r),
			S: emulated.ValueOf[emparams.P256Fr](s),
		},
		Msg: emulated.ValueOf[emparams.P256Fr](msgHash[:]),
		Pub: PublicKey[emparams.P256Fp, emparams.P256Fr]{
			X: emulated.ValueOf[emparams.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emparams.P256Fp](privKey.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

func TestEcdsaP384PreHashed(t *testing.T) {

	// generate parameters
	privKey, _ := cryptoecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	publicKey := privKey.PublicKey

	// sign
	msg := []byte("testing ECDSA (pre-hashed)")
	msgHash := sha512.Sum384(msg)
	sigBin, _ := privKey.Sign(rand.Reader, msgHash[:], nil)

	// check that the signature is correct
	var (
		r, s  = &big.Int{}, &big.Int{}
		inner cryptobyte.String
	)
	input := cryptobyte.String(sigBin)
	if !input.ReadASN1(&inner, asn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(r) ||
		!inner.ReadASN1Integer(s) ||
		!inner.Empty() {
		panic("invalid sig")
	}
	flag := cryptoecdsa.Verify(&publicKey, msgHash[:], r, s)
	if !flag {
		t.Errorf("can't verify signature")
	}

	circuit := EcdsaCircuit[emparams.P384Fp, emparams.P384Fr]{}
	witness := EcdsaCircuit[emparams.P384Fp, emparams.P384Fr]{
		Sig: Signature[emparams.P384Fr]{
			R: emulated.ValueOf[emparams.P384Fr](r),
			S: emulated.ValueOf[emparams.P384Fr](s),
		},
		Msg: emulated.ValueOf[emparams.P384Fr](msgHash[:]),
		Pub: PublicKey[emparams.P384Fp, emparams.P384Fr]{
			X: emulated.ValueOf[emparams.P384Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emparams.P384Fp](privKey.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
