/*
Copyright © 2021 ConsenSys Software Inc.

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
package frontend

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
)

const benchSize = 1 << 20

func BenchmarkCompileReferenceGroth16(b *testing.B) {
	var c benchCircuit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compile(ecc.BN254, backend.GROTH16, &c, WithCapacity(benchSize))
	}
}

func BenchmarkCompileReferencePlonk(b *testing.B) {
	var c benchCircuit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Compile(ecc.BN254, backend.PLONK, &c, WithCapacity(benchSize))
	}
}

// benchCircuit is a simple circuit that checks X*X*X*X*X... == Y
type benchCircuit struct {
	X Variable
	Y Variable `gnark:",public"`
}

func (circuit *benchCircuit) Define(curveID ecc.ID, cs API) error {
	for i := 0; i < benchSize; i++ {
		circuit.X = cs.Mul(circuit.X, circuit.X)
	}
	cs.AssertIsEqual(circuit.X, circuit.Y)
	return nil
}
