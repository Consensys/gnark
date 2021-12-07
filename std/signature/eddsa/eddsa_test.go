/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package eddsa

import (
	"math/big"
	"math/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	eddsabls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards/eddsa"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	eddsabls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards/eddsa"
	edwardsbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	eddsabls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards/eddsa"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	eddsabn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	edwardsbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	eddsabw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards/eddsa"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	eddsabw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards/eddsa"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	PublicKey PublicKey   `gnark:",public"`
	Signature Signature   `gnark:",public"`
	Message   cs.Variable `gnark:",public"`
}

//func parseSignature(id ecc.ID, buf []byte) ([]byte, []byte, []byte) {
func parseSignature(id ecc.ID, buf []byte) ([]byte, []byte, []byte) {

	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine

	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		s := buf[32:]
		return a[:], b[:], s
	case ecc.BLS12_381:
		pointbls12381.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		s := buf[32:]
		return a[:], b[:], s
	case ecc.BLS12_377:
		pointbls12377.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		s := buf[32:]
		return a[:], b[:], s
	case ecc.BW6_761:
		pointbw6761.SetBytes(buf[:48])
		a, b := parsePoint(id, buf)
		s := buf[48:]
		return a[:], b[:], s
	case ecc.BLS24_315:
		pointbls24315.SetBytes(buf[:32])
		a, b := parsePoint(id, buf)
		s := buf[32:]
		return a[:], b[:], s
	case ecc.BW6_633:
		pointbw6633.SetBytes(buf[:40])
		a, b := parsePoint(id, buf)
		s := buf[40:]
		return a[:], b[:], s
	default:
		return buf, buf, buf
	}
}

func parsePoint(id ecc.ID, buf []byte) ([]byte, []byte) {
	var pointbn254 edwardsbn254.PointAffine
	var pointbls12381 edwardsbls12381.PointAffine
	var pointbls12377 edwardsbls12377.PointAffine
	var pointbw6761 edwardsbw6761.PointAffine
	var pointbls24315 edwardsbls24315.PointAffine
	var pointbw6633 edwardsbw6633.PointAffine
	switch id {
	case ecc.BN254:
		pointbn254.SetBytes(buf[:32])
		a := pointbn254.X.Bytes()
		b := pointbn254.Y.Bytes()
		return a[:], b[:]
	case ecc.BLS12_381:
		pointbls12381.SetBytes(buf[:32])
		a := pointbls12381.X.Bytes()
		b := pointbls12381.Y.Bytes()
		return a[:], b[:]
	case ecc.BLS12_377:
		pointbls12377.SetBytes(buf[:32])
		a := pointbls12377.X.Bytes()
		b := pointbls12377.Y.Bytes()
		return a[:], b[:]
	case ecc.BW6_761:
		pointbw6761.SetBytes(buf[:48])
		a := pointbw6761.X.Bytes()
		b := pointbw6761.Y.Bytes()
		return a[:], b[:]
	case ecc.BLS24_315:
		pointbls24315.SetBytes(buf[:32])
		a := pointbls24315.X.Bytes()
		b := pointbls24315.Y.Bytes()
		return a[:], b[:]
	case ecc.BW6_633:
		pointbw6633.SetBytes(buf[:40])
		a := pointbw6633.X.Bytes()
		b := pointbw6633.Y.Bytes()
		return a[:], b[:]
	default:
		return buf, buf
	}
}

func (circuit *eddsaCircuit) Define(api frontend.API) error {

	params, err := twistededwards.NewEdCurve(api.Curve())
	if err != nil {
		return err
	}
	circuit.PublicKey.Curve = params

	// verify the signature in the cs
	Verify(api, circuit.Signature, circuit.Message, circuit.PublicKey)

	return nil
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type confSig struct {
		h hash.Hash
		s signature.SignatureScheme
	}

	signature.Register(signature.EDDSA_BN254, eddsabn254.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_381, eddsabls12381.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS12_377, eddsabls12377.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_761, eddsabw6761.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BLS24_315, eddsabls24315.GenerateKeyInterfaces)
	signature.Register(signature.EDDSA_BW6_633, eddsabw6633.GenerateKeyInterfaces)

	confs := map[ecc.ID]confSig{
		ecc.BN254:     {hash.MIMC_BN254, signature.EDDSA_BN254},
		ecc.BLS12_381: {hash.MIMC_BLS12_381, signature.EDDSA_BLS12_381},
		ecc.BLS12_377: {hash.MIMC_BLS12_377, signature.EDDSA_BLS12_377},
		ecc.BW6_761:   {hash.MIMC_BW6_761, signature.EDDSA_BW6_761},
		ecc.BLS24_315: {hash.MIMC_BLS24_315, signature.EDDSA_BLS24_315},
		ecc.BW6_633:   {hash.MIMC_BW6_633, signature.EDDSA_BW6_633},
	}
	for id, conf := range confs {

		// generate parameters for the signatures
		hFunc := conf.h.New("seed")
		src := rand.NewSource(0)
		r := rand.New(src)
		privKey, err := conf.s.New(r)
		if err != nil {
			t.Fatal(err)
		}
		pubKey := privKey.Public()

		// pick a message to sign
		var frMsg big.Int
		frMsg.SetString("44717650746155748460101257525078853138837311576962212923649547644148297035978", 10)
		msgBin := frMsg.Bytes()

		// generate signature
		signature, err := privKey.Sign(msgBin[:], hFunc)
		if err != nil {
			t.Fatal(err)
		}

		// check if there is no problem in the signature
		checkSig, err := pubKey.Verify(signature, msgBin[:], hFunc)
		if err != nil {
			t.Fatal(err)
		}
		if !checkSig {
			t.Fatal("Unexpected failed signature verification")
		}

		// create and compile the circuit for signature verification
		var circuit eddsaCircuit

		// verification with the correct Message
		{
			var witness eddsaCircuit
			witness.Message = frMsg

			pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())
			var pbAx, pbAy big.Int
			pbAx.SetBytes(pubkeyAx)
			pbAy.SetBytes(pubkeyAy)
			witness.PublicKey.A.X = pubkeyAx
			witness.PublicKey.A.Y = pubkeyAy

			// sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signature)
			sigRx, sigRy, sigS := parseSignature(id, signature)
			witness.Signature.R.X = sigRx
			witness.Signature.R.Y = sigRy
			// witness.Signature.S1 = sigS1
			// witness.Signature.S2 = sigS2
			witness.Signature.S = sigS

			assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(id))
		}

		// verification with incorrect Message
		{
			var witness eddsaCircuit
			witness.Message = "44717650746155748460101257525078853138837311576962212923649547644148297035979"

			pubkeyAx, pubkeyAy := parsePoint(id, pubKey.Bytes())
			witness.PublicKey.A.X = pubkeyAx
			witness.PublicKey.A.Y = pubkeyAy

			// sigRx, sigRy, sigS1, sigS2 := parseSignature(id, signature)
			sigRx, sigRy, sigS := parseSignature(id, signature)
			witness.Signature.R.X = sigRx
			witness.Signature.R.Y = sigRy
			witness.Signature.S = sigS

			assert.SolvingFailed(&circuit, &witness, test.WithCurves(id))
		}

	}
}
