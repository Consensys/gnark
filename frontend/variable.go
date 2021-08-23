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
	"github.com/consensys/gnark/internal/backend/compiled"
)

// Wire of a circuit
// They represent secret or public inputs in a circuit struct{} / definition (see circuit.Define(), type Tag)
type Wire struct {
	visibility compiled.Visibility
	id         int // index of the wire in the corresponding list of wires (private, public or intermediate)
	val        interface{}
}

// Variable of a circuit
// represents a Variable to a circuit, plus the  linear combination leading to it.
// the linExp is always non empty, the PartialVariabl can be unset. It is set and allocated in the
// circuit when there is no other choice (to avoid wasting wires doing only linear expressions)
type Variable struct {
	Wire
	linExp compiled.LinearExpression
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a Variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func (v *Variable) assertIsSet() {
	if len(v.linExp) == 0 {
		panic(ErrInputNotSet)
	}
}

// GetAssignedValue returns the assigned value (or nil) to the variable
// This is used for witness preparation internally
// and not exposed on Variable struct to avoid confusion in circuit definition.
func GetAssignedValue(v Variable) interface{} {
	return v.val
}

// Assign v = value . This must called when using a Circuit as a witness data structure
func (v *Variable) Assign(value interface{}) {
	if v.val != nil {
		panic("variable already assigned")
	}
	v.val = value
}
