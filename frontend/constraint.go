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

// Constraint list of expressions that must be equal+an output wire, that can be computed out of the inputs wire.
// A Constraint is a list of expressions that are equal.
// Each expression yields the value of another wire.
// A Constraint contains only one wire expression, and at least one expression,
// unless the wire expression is an input.
// under the constraintID i are all the expressions that must be equal
// under the constraintID i, exactly one Constraint can be single wire and there is at least a linear Constraint or a single wire
type constraint struct {
	wire
	// exp can be nil. If it is nil, it is "unconstrained"
	// meaning it's not a constraint but only the computed output wire of a constraint.
	// for exp == nil, we still need a constraint to reference inside the Variable and re-constraint later on
	// in a circuit.
	exp expression
	ID  int
}

// addConstraint initialize a c with a single wire and adds it to the Constraint System (CS)
func (cs *CS) addConstraint(exp expression) Variable {
	c := constraint{
		exp: exp,
		ID:  len(cs.constraints),
	}
	cs.constraints = append(cs.constraints, c)

	return Variable{constraintID: c.ID}
}
