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

// Access gives the reach of a wire
type Access int

const (
	SecretInput Access = iota
	PublicInput
	IntermediateVariable
)

// Variable of circuit
type Variable struct {
	IsBoolean bool
	Reach     Access
	ID        int // index of the wire in the corresponding list of wires (private, public or intermediate)
	val       interface{}
}

// LinearTerm linear expression
type LinearTerm struct {
	Variable Variable
	Coeff    int // index of the associated coefficient in c.Coeffs
}

// LinearCombination sum of linear expression
type LinearCombination []LinearTerm

// Gate Groth16 gate
type Gate struct {
	L, R, O LinearCombination
	S       r1c.SolvingMethod
}

// Assign value to self.
func (v *Variable) Assign(value interface{}) {
	if v.val != nil {
		panic("variable already assigned")
	}
	if v.Reach == IntermediateVariable {
		panic("only inputs (public or private) can be assigned")
	}
	v.val = value
}

// changes the ID of the variables of reach a in the gate to id+offset
func (g *Gate) updateID(offset int, a Access) {
	for i := 0; i < len(g.L); i++ {
		if g.L[i].Variable.Reach == a {
			g.L[i].Variable.ID += offset
		}
	}
	for i := 0; i < len(g.R); i++ {
		if g.R[i].Variable.Reach == a {
			g.R[i].Variable.ID += offset
		}
	}
	for i := 0; i < len(g.O); i++ {
		if g.O[i].Variable.Reach == a {
			g.O[i].Variable.ID += offset
		}
	}
}
