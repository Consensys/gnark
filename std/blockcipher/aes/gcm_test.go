/*
Copyright © 2023 Jan Lauinger

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
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type gcmData struct {
	key        string
	chunkIndex int
	iv         string
	plaintext  string
	ciphertext string
}

func TestGCM(t *testing.T) {
	assert := test.NewAssert(t)

	// aes gcm test data
	gcmDataList := []gcmData{
		{
			key:        "ab72c77b97cb5fe9a382d9fe81ffdbed",
			chunkIndex: 2,
			iv:         "54cc7dc2c37ec006bcc6d1da",
			plaintext:  "007c5e5b3e59df24a7c355584fc1518d",
			ciphertext: "0e1bde206a07a9c2c1b65300f8c64997",
		},
		{
			key:        "fe47fcce5fc32665d2ae399e4eec72ba",
			chunkIndex: 2,
			iv:         "5adb9609dbaeb58cbd6e7275",
			plaintext:  "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429",
			ciphertext: "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269", // authtag=f5f6e7d0b3d0418b82296ac7dd951d0e

		},
	}
	for _, gcmData := range gcmDataList {

		// convert to bytes
		byteSlice, _ := hex.DecodeString(gcmData.key)
		keyByteLen := len(byteSlice)
		byteSlice, _ = hex.DecodeString(gcmData.iv)
		nonceByteLen := len(byteSlice)
		byteSlice, _ = hex.DecodeString(gcmData.plaintext)
		ptByteLen := len(byteSlice)
		byteSlice, _ = hex.DecodeString(gcmData.ciphertext)
		ctByteLen := len(byteSlice)

		// witness definition
		keyAssign := StrToIntSlice(gcmData.key, true)
		nonceAssign := StrToIntSlice(gcmData.iv, true)
		ptAssign := StrToIntSlice(gcmData.plaintext, true)
		ctAssign := StrToIntSlice(gcmData.ciphertext, true)

		// witness values preparation
		assignment := GCMWrapper{
			PlainChunks:  make([]frontend.Variable, ptByteLen),
			CipherChunks: make([]frontend.Variable, ctByteLen),
			ChunkIndex:   gcmData.chunkIndex,
			Iv:           [12]frontend.Variable{},
			Key:          [16]frontend.Variable{},
		}

		// assign values here because required to use make in assignment
		for i := 0; i < ptByteLen; i++ {
			assignment.PlainChunks[i] = ptAssign[i]
		}
		for i := 0; i < ctByteLen; i++ {
			assignment.CipherChunks[i] = ctAssign[i]
		}
		for i := 0; i < nonceByteLen; i++ {
			assignment.Iv[i] = nonceAssign[i]
		}
		for i := 0; i < keyByteLen; i++ {
			assignment.Key[i] = keyAssign[i]
		}

		// var circuit GCM
		circuit := GCMWrapper{
			PlainChunks:  make([]frontend.Variable, ptByteLen),
			CipherChunks: make([]frontend.Variable, ctByteLen),
			ChunkIndex:   gcmData.chunkIndex,
		}

		assert.SolvingSucceeded(&circuit, &assignment)
	}
}
