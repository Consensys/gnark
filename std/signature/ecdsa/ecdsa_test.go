package ecdsa

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/secp256k1/ecdsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"github.com/pkg/profile"
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

var proof plonk.Proof
var proof2 groth16.Proof

func BenchmarkECDSASecp256k1VerifyPLONK(t *testing.B) {
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
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(ccs.GetNbConstraints())
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
	t.ResetTimer()
	p := profile.Start(profile.CPUProfile)
	for i := 0; i < 1; i++ {
		t.Log("proving", i)
		proof, err = plonk.Prove(ccs, pk, ass)
		if err != nil {
			t.Fatal(err)
		}
	}
	p.Stop()
}

func BenchmarkECDSASecp256k1VerifyGroth16(t *testing.B) {
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
		proof2, err = groth16.Prove(ccs, pk, ass)
		if err != nil {
			t.Fatal(err)
		}
	}
}
