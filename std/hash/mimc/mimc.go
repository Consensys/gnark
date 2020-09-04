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
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"

	"github.com/consensys/gurvy"
)

// MiMC contains the params of the Mimc hash func and the curves on which it is implemented
type MiMC struct {
	params []big.Int
	id     gurvy.ID
}

// NewMiMC returns a MiMC instance, than can be used in a gnark circuit
func NewMiMC(seed string, id gurvy.ID) (MiMC, error) {
	if constructor, ok := newMimc[id]; ok {
		return constructor(seed), nil
	}
	return MiMC{}, errors.New("unknown curve id")
}

// Hash hash (in r1cs form) using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition
func (h MiMC) Hash(cs *frontend.CS, data ...frontend.Variable) frontend.Variable {

	var digest frontend.Variable
	digest = cs.Allocate(0)

	for _, stream := range data {
		digest = encryptFuncs[h.id](cs, h, stream, digest)
		digest = cs.Add(digest, stream)
	}

	return digest

}
