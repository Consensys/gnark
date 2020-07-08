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
)

// Constraint list of expressions that must be equal+an output wire, that can be computed out of the inputs wire.
// A Constraint is a list of expressions that are equal.
// Each expression yields the value of another wire.
// A Constraint contains only one wire expression, and at least one expression,
// unless the wire expression is an input.
// under the constraintID i are all the expressions that must be equal
// under the constraintID i, exactly one Constraint can be single wire and there is at least a linear Constraint or a single wire
type constraint struct {
	expressions  []expression
	outputWire   *wire
	constraintID uint64 // key in CS.Constraints[] map
}

func (c *constraint) Set(other CircuitVariable) {
	c.expressions = other.getExpressions()
	c.outputWire = other.getOutputWire()
	c.constraintID = other.id()
}

func (c *constraint) getExpressions() []expression {
	return c.expressions
}
func (c *constraint) addExpressions(e ...expression) {
	c.expressions = append(c.expressions, e...)
}
func (c *constraint) setID(id uint64) {
	c.constraintID = id
}
func (c *constraint) id() uint64 {
	return c.constraintID
}
func (c *constraint) setOutputWire(w *wire) {
	c.outputWire = w
}
func (c *constraint) getOutputWire() *wire {
	return c.outputWire
}

func (c *constraint) Assign(value interface{}) {
	panic("can't assign a value on a *frontend.Constraint object.")
}

// Term coeff*c
type Term struct {
	Constraint CircuitVariable
	Coeff      big.Int
}

// LinearCombination linear combination of constraints
type LinearCombination []Term

// newConstraint initialize a c with a single wire and adds it to the Constraint System (CS)
func newConstraint(cs *CS, expressions ...expression) CircuitVariable {
	toReturn := &constraint{
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

// Tag adds a tag to the c's singleWire
// once the R1CS system is solved
// r1cs.Inspect() may return a map[string]value of constraints with Tags
func (c *constraint) Tag(tag string) {
	for i := 0; i < len(c.outputWire.Tags); i++ {
		if c.outputWire.Tags[i] == tag {
			return
		}
	}
	c.outputWire.Tags = append(c.outputWire.Tags, tag)
}

func (c *constraint) toR1CS(s *CS) []R1C {
	oneWire := s.Constraints[0].getOutputWire()

	toReturn := make([]R1C, len(c.expressions))
	for i := 0; i < len(c.expressions); i++ {
		toReturn[i] = c.expressions[i].toR1CS(oneWire, c.outputWire)
	}

	return toReturn
}
