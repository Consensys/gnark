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

package frontend

import (
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

// Visibility gives the visibilty of a wire
type Visibility int

// Internal variable created via a computation, Secret/Public secret (resp. public) inputs
// The order is important: if Secret or Public is first, when writing
// "var a frontend.Variable", default visibility would be secret or public,
// and the id 0, this would tamper the indexation. For Internal Variables,
// the id 0 is reserved, so there is no risk of tampering the variable indexation.
const (
	Internal Visibility = iota
	Secret
	Public
)

// Variable of circuit. The type is exported so a user can
// write "var a frontend.Variable". However, when doing so
// the variable is not registered in the circuit, so to record
// it one has to call "cs.Allocate(a)" (it's the equivalent
// of declaring a pointer, and allocatign the memory to store it).
type Variable struct {
	isBoolean  bool
	visibility Visibility
	id         int // index of the wire in the corresponding list of wires (private, public or intermediate)
	val        interface{}
}

// LinearTerm linear expression
type LinearTerm struct {
	Variable Variable
	Coeff    int // index of the associated coefficient in c.coeffs
}

// LinearCombination sum of linear expression
type LinearCombination []LinearTerm

// gate Groth16 gate
type gate struct {
	L, R, O LinearCombination
	S       r1c.SolvingMethod
}

// Assign value to self.
func (v *Variable) Assign(value interface{}) {
	if v.val != nil {
		panic("variable already assigned")
	}
	// if v.visibility == Internal {
	// 	panic("only inputs (public or private) can be assigned")
	// }
	v.val = value
}

// changes the ID of the variables of reach a in the gate to id+offset
func (g *gate) updateID(offset int, a Visibility) {
	for i := 0; i < len(g.L); i++ {
		if g.L[i].Variable.visibility == a {
			g.L[i].Variable.id += offset
		}
	}
	for i := 0; i < len(g.R); i++ {
		if g.R[i].Variable.visibility == a {
			g.R[i].Variable.id += offset
		}
	}
	for i := 0; i < len(g.O); i++ {
		if g.O[i].Variable.visibility == a {
			g.O[i].Variable.id += offset
		}
	}
}
