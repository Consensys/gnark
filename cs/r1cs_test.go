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

package cs

import (
	"testing"
)

//--------------------//
//     benches		  //
//--------------------//

func benchCircuit() CS {
	// init constraint system / circuit
	s := New()

	// declare inputs
	x := s.SECRET_INPUT("x")
	y := s.PUBLIC_INPUT("y")

	for i := 0; i < 2000; i++ {
		x = s.MUL(x, x)
	}
	s.MUSTBE_EQ(x, y)

	return s
}

func BenchmarkCStoR1CS(b *testing.B) {
	s := benchCircuit()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NewR1CS(&s)
	}
}

func BenchmarkSolveR1CS(b *testing.B) {
	s := benchCircuit()
	assignment := NewAssignment()
	assignment.Assign(Secret, "x", 2)
	assignment.Assign(Public, "y", 4294967296)

	r1cs := NewR1CS(&s)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = r1cs.Solve(assignment)
	}
}
