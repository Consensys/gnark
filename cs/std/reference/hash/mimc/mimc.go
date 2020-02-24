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

package mimc

import (
	"math/big"

	"github.com/consensys/gnark/cs/internal/curve"
	"golang.org/x/crypto/sha3"
)

// MiMC reference implementation (pure Go)
type MiMC struct {
	Params
}

// Params constants for the mimc hash function
type Params []curve.Element

// NewMiMC returns a MiMCImpl object, pure-go reference implementation
func NewMiMC(seed string) MiMC {
	return MiMC{NewParams(seed)}
}

func NewParams(seed string) Params {

	// set the constants
	res := make(Params, mimcNbRounds)

	rnd := sha3.Sum256([]byte(seed))
	value := new(big.Int).SetBytes(rnd[:])

	for i := 0; i < mimcNbRounds; i++ {
		rnd = sha3.Sum256(value.Bytes())
		value.SetBytes(rnd[:])
		res[i].SetBigInt(value)
	}

	return res
}

// Hash hash using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition, data is in Montgomery form
func (h MiMC) Hash(data ...curve.Element) curve.Element {

	var digest curve.Element

	for _, stream := range data {
		digest = h.encrypt(stream, digest)
		digest.Add(&stream, &digest)
	}

	return digest
}
