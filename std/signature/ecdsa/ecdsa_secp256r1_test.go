/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package ecdsa

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"testing"
)

func TestEcdsaSecp256r1PreHashed(t *testing.T) {

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

	circuit := EcdsaCircuit[emulated.Secp256r1Fp, emulated.Secp256r1Fr]{}
	witness := EcdsaCircuit[emulated.Secp256r1Fp, emulated.Secp256r1Fr]{
		Sig: Signature[emulated.Secp256r1Fr]{
			R: emulated.ValueOf[emulated.Secp256r1Fr](r),
			S: emulated.ValueOf[emulated.Secp256r1Fr](s),
		},
		Msg: emulated.ValueOf[emulated.Secp256r1Fr](msgHash[:]),
		Pub: PublicKey[emulated.Secp256r1Fp, emulated.Secp256r1Fr]{
			X: emulated.ValueOf[emulated.Secp256r1Fp](privKey.PublicKey.X),
			Y: emulated.ValueOf[emulated.Secp256r1Fp](privKey.PublicKey.Y),
		},
	}
	assert := test.NewAssert(t)
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)

}
