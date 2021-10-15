// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exponentiate

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// Circuit y == x**e
// only the bitSize least significant bits of e are used
type Circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

// Define declares the circuit's constraints
// y == x**e
func (circuit *Circuit) Define(curveID ecc.ID, gnark frontend.API) error {

	// number of bits of exponent
	const bitSize = 8

	// specify constraints
	output := gnark.Constant(1)
	bits := gnark.ToBinary(circuit.E, bitSize)
	gnark.ToBinary(circuit.E, bitSize)

	for i := 0; i < len(bits); i++ {
		// gnark.Println(fmt.Sprintf("e[%d]", i), bits[i]) // we may print a variable for testing and / or debugging purposes

		if i != 0 {
			output = gnark.Mul(output, output)
		}
		multiply := gnark.Mul(output, circuit.X)
		output = gnark.Select(bits[len(bits)-1-i], multiply, output)

	}

	gnark.AssertIsEqual(circuit.Y, output)

	return nil
}
