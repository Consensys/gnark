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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/std/reference/hash/mimc"
)

// MiMC gadget
type MiMC struct {
	mimc.Params
}

// NewMiMC returns a MiMC gadget, than can be used in a circuit
func NewMiMC(seed string) MiMC {
	return MiMC{mimc.NewParams(seed)}
}

// Hash hash (in r1cs form) using Miyaguchi–Preneel:
// https://en.wikipedia.org/wiki/One-way_compression_function
// The XOR operation is replaced by field addition
func (h MiMC) Hash(circuit *frontend.CS, data ...*frontend.Constraint) *frontend.Constraint {

	digest := circuit.ALLOCATE(0)

	for _, stream := range data {
		digest = h.encrypt(circuit, stream, digest)
		digest = circuit.ADD(digest, stream)
	}

	return digest

}
