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
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	edwardsbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	edwardsbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edwardsbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edwardsbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edwardsbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
)

type eddsaCircuit struct {
	curveID   tedwards.ID
	PublicKey PublicKey         `gnark:",public"`
	Signature Signature         `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
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

	curve, err := twistededwards.NewEdCurve(api, circuit.curveID)
	if err != nil {
		return err
	}

	mimc, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// verify the signature in the cs
	return Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &mimc)
}

func TestEddsa(t *testing.T) {

	assert := test.NewAssert(t)

	type testData struct {
		hash  hash.Hash
		curve tedwards.ID
	}

	confs := []testData{
		{hash.MIMC_BN254, tedwards.BN254},
		{hash.MIMC_BLS12_381, tedwards.BLS12_381},
		// {hash.MIMC_BLS12_381, tedwards.BLS12_381_BANDERSNATCH},
		{hash.MIMC_BLS12_377, tedwards.BLS12_377},
		{hash.MIMC_BW6_761, tedwards.BW6_761},
		{hash.MIMC_BLS24_315, tedwards.BLS24_315},
		{hash.MIMC_BW6_633, tedwards.BW6_633},
	}

	bound := 5
	if testing.Short() {
		bound = 1
	}

	for i := 0; i < bound; i++ {
		seed := time.Now().Unix()
		t.Logf("setting seed in rand %d", seed)
		randomness := rand.New(rand.NewSource(seed))

		for _, conf := range confs {

			snarkCurve, err := twistededwards.GetSnarkCurve(conf.curve)
			assert.NoError(err)

			// generate parameters for the signatures
			privKey, err := eddsa.New(conf.curve, randomness)
			assert.NoError(err, "generating eddsa key pair")

			// pick a message to sign
			var msg big.Int
			msg.Rand(randomness, snarkCurve.Info().Fr.Modulus())
			t.Log("msg to sign", msg.String())
			msgData := msg.Bytes()

			// generate signature
			signature, err := privKey.Sign(msgData[:], conf.hash.New())
			assert.NoError(err, "signing message")

			// check if there is no problem in the signature
			pubKey := privKey.Public()
			checkSig, err := pubKey.Verify(signature, msgData[:], conf.hash.New())
			assert.NoError(err, "verifying signature")
			assert.True(checkSig, "signature verification failed")

			// create and compile the circuit for signature verification
			var circuit eddsaCircuit
			circuit.curveID = conf.curve

			// verification with the correct Message
			{
				var witness eddsaCircuit
				witness.Message = msg

				pubkeyAx, pubkeyAy := parsePoint(snarkCurve, pubKey.Bytes())
				witness.PublicKey.A.X = pubkeyAx
				witness.PublicKey.A.Y = pubkeyAy

				sigRx, sigRy, sigS := parseSignature(snarkCurve, signature)
				witness.Signature.R.X = sigRx
				witness.Signature.R.Y = sigRy
				witness.Signature.S = sigS

				assert.SolvingSucceeded(&circuit, &witness, test.WithCurves(snarkCurve))
			}

			// verification with incorrect Message
			{
				var witness eddsaCircuit
				msg.Rand(randomness, snarkCurve.Info().Fr.Modulus())
				witness.Message = msg

				pubkeyAx, pubkeyAy := parsePoint(snarkCurve, pubKey.Bytes())
				witness.PublicKey.A.X = pubkeyAx
				witness.PublicKey.A.Y = pubkeyAy

				sigRx, sigRy, sigS := parseSignature(snarkCurve, signature)
				witness.Signature.R.X = sigRx
				witness.Signature.R.Y = sigRy
				witness.Signature.S = sigS

				assert.SolvingFailed(&circuit, &witness, test.WithCurves(snarkCurve))
			}

		}
	}

}
