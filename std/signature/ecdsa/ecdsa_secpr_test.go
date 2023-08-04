package ecdsa

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"math/big"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/pkg/profile"
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

	circuit := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{}
	witness := EcdsaCircuit[emulated.P256Fp, emulated.P256Fr]{
		Sig: Signature[emulated.P256Fr]{
			R: emulated.ValueOf[emulated.P256Fr](r),
			S: emulated.ValueOf[emulated.P256Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P256Fr](msgHash[:]),
		Pub: PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P256Fp](privKey.PublicKey.Y),
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

	circuit := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{}
	witness := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{
		Sig: Signature[emulated.P384Fr]{
			R: emulated.ValueOf[emulated.P384Fr](r),
			S: emulated.ValueOf[emulated.P384Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P384Fr](msgHash[:]),
		Pub: PublicKey[emulated.P384Fp, emulated.P384Fr]{
			X: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}

func BenchmarkECDSAP384VerifyPLONK(t *testing.B) {

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

	circuit := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{}
	witness := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{
		Sig: Signature[emulated.P384Fr]{
			R: emulated.ValueOf[emulated.P384Fr](r),
			S: emulated.ValueOf[emulated.P384Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P384Fr](msgHash[:]),
		Pub: PublicKey[emulated.P384Fp, emulated.P384Fr]{
			X: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.Y),
		},
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ccs.GetNbConstraints())
	PrintMemUsage("before setup")
	srs, err := test.NewKZGSRS(ccs)
	if err != nil {
		t.Fatal(err)
	}
	pk, _, err := plonk.Setup(ccs, srs)
	if err != nil {
		t.Fatal(err)
	}
	ass, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	PrintMemUsage("before prove")
	p := profile.Start(profile.CPUProfile)
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		t.Log("proving", i)
		proof, err = plonk.Prove(ccs, pk, ass)
		PrintMemUsage("after prove")
		if err != nil {
			t.Fatal(err)
		}
	}
	p.Stop()

	runtime.GC()
	PrintMemUsage("after GC collect")
}

func BenchmarkECDSAP384VerifyGroth16(t *testing.B) {
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

	circuit := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{}
	witness := EcdsaCircuit[emulated.P384Fp, emulated.P384Fr]{
		Sig: Signature[emulated.P384Fr]{
			R: emulated.ValueOf[emulated.P384Fr](r),
			S: emulated.ValueOf[emulated.P384Fr](s),
		},
		Msg: emulated.ValueOf[emulated.P384Fr](msgHash[:]),
		Pub: PublicKey[emulated.P384Fp, emulated.P384Fr]{
			X: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.P384Fp](privKey.PublicKey.Y),
		},
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ccs.GetNbConstraints())
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}
	ass, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		t.Log("proving", i)
		proof, err = groth16.Prove(ccs, pk, ass)
		if err != nil {
			t.Fatal(err)
		}
	}
}
