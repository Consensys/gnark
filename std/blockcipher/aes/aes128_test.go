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

func TestAES128(t *testing.T) {
	assert := test.NewAssert(t)

	key := "ab72c77b97cb5fe9a382d9fe81ffdbed"
	plaintext := "54cc7dc2c37ec006bcc6d1da00000002"
	ciphertext := "0e67807b545e76e666750658b707181a"

	byteSlice, _ := hex.DecodeString(key)
	keyByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(plaintext)
	ptByteLen := len(byteSlice)
	byteSlice, _ = hex.DecodeString(ciphertext)
	ctByteLen := len(byteSlice)

	keyAssign := StrToIntSlice(key, true)
	ptAssign := StrToIntSlice(plaintext, true)
	ctAssign := StrToIntSlice(ciphertext, true)

	// witness values preparation
	assignment := AES128Wrapper{
		Key:        [16]frontend.Variable{},
		Plaintext:  [16]frontend.Variable{},
		Ciphertext: [16]frontend.Variable{},
	}

	// assign values here because required to use make in assignment
	for i := 0; i < keyByteLen; i++ {
		assignment.Key[i] = keyAssign[i]
	}
	for i := 0; i < ptByteLen; i++ {
		assignment.Plaintext[i] = ptAssign[i]
	}
	for i := 0; i < ctByteLen; i++ {
		assignment.Ciphertext[i] = ctAssign[i]
	}

	// var circuit SHA256
	var circuit AES128Wrapper

	assert.SolvingSucceeded(&circuit, &assignment)
}

func StrToIntSlice(inputData string, hexRepresentation bool) []int {
	var byteSlice []byte
	if hexRepresentation {
		hexBytes, _ := hex.DecodeString(inputData)
		byteSlice = hexBytes
	} else {
		byteSlice = []byte(inputData)
	}

	var data []int
	for i := 0; i < len(byteSlice); i++ {
		data = append(data, int(byteSlice[i]))
	}
	return data
}
