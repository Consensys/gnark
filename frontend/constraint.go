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
	"math/big"

	"github.com/consensys/gnark/backend/r1cs"
)

// Constraint list of expressions that must be equal+an output wire, that can be computed out of the inputs wire.
// A Constraint is a list of expressions that are equal.
// Each expression yields the value of another wire.
// A Constraint contains only one wire expression, and at least one expression,
// unless the wire expression is an input.
// under the constraintID i are all the expressions that must be equal
// under the constraintID i, exactly one Constraint can be single wire and there is at least a linear Constraint or a single wire
type constraint struct {
	wire
	// note to self:
	// exp can be nil. If it is nil, it is "unconstrained"
	// meaning it's not a constraint but the output wire of a constraint.
	// seems like a confusing double purpose for this struct.
	exp expression
	ID  int
}

// TODO keeping that for retrocompatibility purposes.
// if we're sure of ourselves, then, no need to have "unitialized" wire, we will loop through them all
// and initialize them.
var uninitializedWire = wire{-1, -1}

type wire struct {
	// ex wire
	// Wire is analogous to a circuit's physical Wire
	// each constraint (ie gate) will have a single output Wire
	// when the circuit is instantiated and fed an input
	// each Wire will have a Value enabling the solver to determine a solution vector
	// to the rank 1 constraint system
	wIDOrdered int
	cIDOrdered int // ID of the constraint from which the wire is computed (for an input it's -1)
}

// Term coeff*c
type Term struct {
	Variable Variable
	Coeff    big.Int
}

// LinearCombination linear combination of constraints
type LinearCombination []Term

// newConstraint initialize a c with a single wire and adds it to the Constraint System (CS)
func newConstraint(cs *CS, exp expression) Variable {
	c := constraint{
		wire: uninitializedWire,
		exp:  exp,
	}

	return Variable{constraintID: cs.addConstraint(c)}
}

func (c *constraint) toR1CS(uR1CS *r1cs.UntypedR1CS, cs *CS) []r1cs.R1C {
	if c.exp == nil {
		return make([]r1cs.R1C, 0)
	}
	var toReturn [1]r1cs.R1C
	toReturn[0] = c.exp.toR1CS(uR1CS, cs, cs.constraints[oneWireID].wIDOrdered, c.ID)

	return toReturn[:]
}
