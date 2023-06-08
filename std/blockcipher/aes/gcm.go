/*
Copyright 2023 Jan Lauinger

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

package aes

import (
	"github.com/consensys/gnark/frontend"
)

// AES gcm testing
type GCMWrapper struct {
	Key          [16]frontend.Variable
	PlainChunks  []frontend.Variable
	Iv           [12]frontend.Variable `gnark:",public"`
	ChunkIndex   frontend.Variable     `gnark:",public"`
	CipherChunks []frontend.Variable   `gnark:",public"`
}

// Define declares the circuit's constraints
func (circuit *GCMWrapper) Define(api frontend.API) error {

	// init aes gadget
	aes := NewAES128(api)

	// init gcm gadget
	gcm := NewGCM(api, &aes)

	// verify aes gcm of chunks
	gcm.Assert(circuit.Key, circuit.Iv, circuit.ChunkIndex, circuit.PlainChunks, circuit.CipherChunks)

	return nil
}

type AES interface {
	Encrypt(key [16]frontend.Variable, pt [16]frontend.Variable) [16]frontend.Variable
}

func NewGCM(api frontend.API, aes AES) GCM {
	return GCM{api: api, aes: aes}
}

type GCM struct {
	api frontend.API
	aes AES
}

// aes gcm encryption
func (gcm *GCM) Assert(key [16]frontend.Variable, iv [12]frontend.Variable, chunkIndex frontend.Variable, plaintext, ciphertext []frontend.Variable) {

	inputSize := len(plaintext)
	numberBlocks := int(inputSize / 16)
	var epoch int
	for epoch = 0; epoch < numberBlocks; epoch++ {

		idx := gcm.api.Add(chunkIndex, frontend.Variable(epoch))
		eIndex := epoch * 16

		var ptBlock [16]frontend.Variable
		var ctBlock [16]frontend.Variable

		for j := 0; j < 16; j++ {
			ptBlock[j] = plaintext[eIndex+j]
			ctBlock[j] = ciphertext[eIndex+j]
		}

		ivCounter := gcm.GetIV(iv, idx)
		intermediate := gcm.aes.Encrypt(key, ivCounter)
		ct := gcm.Xor16(intermediate, ptBlock)

		// check ciphertext to plaintext constraints
		for i := 0; i < 16; i++ {
			gcm.api.AssertIsEqual(ctBlock[i], ct[i])
		}
	}
}

// required for aes_gcm
func (gcm *GCM) GetIV(nonce [12]frontend.Variable, ctr frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	var i int
	for i = 0; i < len(nonce); i++ {
		out[i] = nonce[i]
	}
	bits := gcm.api.ToBinary(ctr, 32)
	remain := 12
	for j := 3; j >= 0; j-- {
		start := 8 * j
		// little endian order chunk parsing from back to front
		out[remain] = gcm.api.FromBinary(bits[start : start+8]...)
		remain += 1
	}

	return out
}

// required for plaintext xor encrypted counter blocks
func (gcm *GCM) Xor16(a [16]frontend.Variable, b [16]frontend.Variable) [16]frontend.Variable {

	var out [16]frontend.Variable
	for i := 0; i < 16; i++ {
		out[i] = gcm.VariableXor(a[i], b[i], 8)
	}
	return out
}

func (gcm *GCM) VariableXor(a frontend.Variable, b frontend.Variable, size int) frontend.Variable {
	bitsA := gcm.api.ToBinary(a, size)
	bitsB := gcm.api.ToBinary(b, size)
	x := make([]frontend.Variable, size)
	for i := 0; i < size; i++ {
		x[i] = gcm.api.Xor(bitsA[i], bitsB[i])
	}
	return gcm.api.FromBinary(x...)
}
