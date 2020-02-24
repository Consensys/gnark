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

import "github.com/consensys/gnark/cs/internal/curve"

// Constraint list of expressions that must be equal+an output wire, that can be computed out of the inputs wire.
// A Constraint is a list of expressions that are equal.
// Each expression yields the value of another wire.
// A Constraint contains only one wire expression, and at least one expression,
// unless the wire expression is an input.
// under the constraintID i are all the expressions that must be equal
// under the constraintID i, exactly one Constraint can be single wire and there is at least a linear Constraint or a single wire
type Constraint struct {
	expressions  []expression
	outputWire   *wire
	constraintID uint64 // key in CS.Constraints[] map
}

// Term coeff*constraint
type Term struct {
	Constraint *Constraint
	Coeff      curve.Element
}

// LinearCombination linear combination of constraints
type LinearCombination []Term

// newConstraint initialize a constraint with a single wire and adds it to the Constraint System (CS)
func newConstraint(cs *CS, expressions ...expression) *Constraint {
	toReturn := &Constraint{
		outputWire: &wire{
			IsPrivate:    true,
			ConstraintID: -1,
			WireID:       -1,
		},
		expressions: expressions,
	}

	cs.addConstraint(toReturn)

	return toReturn
}

// Tag adds a tag to the constraint's singleWire
// once the R1CS system is solved
// r1cs.Inspect() may return a map[string]value of constraints with Tags
func (c *Constraint) Tag(tag string) {
	for i := 0; i < len(c.outputWire.Tags); i++ {
		if c.outputWire.Tags[i] == tag {
			return
		}
	}
	c.outputWire.Tags = append(c.outputWire.Tags, tag)
}

func (c *Constraint) toR1CS(s *CS) []r1c {
	oneWire := s.Constraints[0].outputWire

	toReturn := make([]r1c, len(c.expressions))
	for i := 0; i < len(c.expressions); i++ {
		toReturn[i] = c.expressions[i].toR1CS(oneWire, c.outputWire)
	}

	return toReturn
}
