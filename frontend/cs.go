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

// package frontend contains Constraint System representation and R1CS to be used with zero knowledge proof systems in gnark
package frontend

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/utils/debug"
)

var (
	ErrInconsistantConstraint = errors.New("inconsistant constraint")
)

// TODO find a home for this
func bigOne() big.Int {
	var val big.Int
	val.SetUint64(1)
	return val
}

// CS Constraint System
type CS struct {

	// under the key i are all the expressions that must be equal to a single wire
	Constraints map[uint64]*constraint

	// constraints yielding multiple outputs (eg unpacking)
	MOConstraints []moExpression

	// constraints yielding no outputs (eg boolean constraints)
	NOConstraints []expression

	// keep track of the number of constraints (ensure each constraint has a unique ID)
	nbConstraints uint64
}

// New returns a new constraint system
func New() CS {
	// initialize constraint system
	cs := CS{
		Constraints: make(map[uint64]*constraint),
	}

	// The first constraint corresponds to the declaration of
	// the unconstrained precomputed wire equal to 1
	oneConstraint := &constraint{
		outputWire: &wire{
			Name:         backend.OneWire,
			WireID:       -1,
			ConstraintID: -1,
			IsConsumed:   true, // if false it means it is the last wire of the computational graph
			Tags:         []string{},
		},
	}

	cs.addConstraint(oneConstraint)

	return cs
}

func (cs *CS) addConstraint(c *constraint) {
	debug.Assert(c.id() == 0)
	c.setID(cs.nbConstraints)
	cs.Constraints[c.id()] = c
	cs.nbConstraints++
}

// MUL multiplies two constraints
func (cs *CS) mul(c1, c2 Variable) Variable {

	expression := &quadraticExpression{
		left:      linearExpression{term{Wire: c1.getOutputWire(), Coeff: bigOne()}},
		right:     linearExpression{term{Wire: c2.getOutputWire(), Coeff: bigOne()}},
		operation: mul,
	}

	return newConstraint(cs, expression)
}

// mulConstant multiplies by a constant
func (cs *CS) mulConstant(c Variable, constant big.Int) Variable {
	expression := &term{
		Wire:      c.getOutputWire(),
		Coeff:     constant,
		Operation: mul,
	}
	return newConstraint(cs, expression)
}

// DIV divides two constraints (c1/c2)
func (cs *CS) div(c1, c2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{term{Wire: c2.getOutputWire(), Coeff: bigOne()}},
		right:     linearExpression{term{Wire: c1.getOutputWire(), Coeff: bigOne()}},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// divConstantRight c1, c2 -> c1/c2, where the right (c2) is a constant
func (cs *CS) divConstantRight(c1 Variable, c2 big.Int) Variable {

	expression := quadraticExpression{
		left:      linearExpression{term{Wire: cs.Constraints[0].getOutputWire(), Coeff: c2}},
		right:     linearExpression{term{Wire: c1.getOutputWire(), Coeff: bigOne()}},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// divConstantLeft c1, c2 -> c1/c2, where the left (c1) is a constant
func (cs *CS) divConstantLeft(c1 big.Int, c2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{term{Wire: c2.getOutputWire(), Coeff: bigOne()}},
		right:     linearExpression{term{Wire: cs.Constraints[0].getOutputWire(), Coeff: c1}},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// inv (e*c1)**-1
func (cs *CS) inv(c1 Variable, e big.Int) Variable {
	expression := &term{
		Wire:      c1.getOutputWire(),
		Coeff:     e,
		Operation: div,
	}
	return newConstraint(cs, expression)
}

// ADD generic version for adding 2 constraints
func (cs *CS) add(c1 Variable, c2 Variable) Variable {

	expression := &linearExpression{
		term{Wire: c1.getOutputWire(), Coeff: bigOne()},
		term{Wire: c2.getOutputWire(), Coeff: bigOne()},
	}

	return newConstraint(cs, expression)
}

// ADDCST adds a constant to a variable
func (cs *CS) addConstant(c Variable, constant big.Int) Variable {

	expression := &linearExpression{
		term{Wire: c.getOutputWire(), Coeff: bigOne()},
		term{Wire: cs.Constraints[0].getOutputWire(), Coeff: constant},
	}

	return newConstraint(cs, expression)
}

// SUB generic version for substracting 2 constraints
func (cs *CS) sub(c1 Variable, c2 Variable) Variable {

	var minusOne big.Int
	one := bigOne()
	minusOne.Neg(&one)

	expression := &linearExpression{
		term{Wire: c1.getOutputWire(), Coeff: one},
		term{Wire: c2.getOutputWire(), Coeff: minusOne},
	}

	return newConstraint(cs, expression)
}

func (cs *CS) subConstant(c Variable, constant big.Int) Variable {

	var minusOne big.Int
	one := bigOne()
	minusOne.Neg((&constant))

	expression := &linearExpression{
		term{Wire: c.getOutputWire(), Coeff: one},
		term{Wire: cs.Constraints[0].getOutputWire(), Coeff: minusOne},
	}

	return newConstraint(cs, expression)

}

func (cs *CS) subConstraint(constant big.Int, c Variable) Variable {

	var minusOne big.Int
	one := bigOne()
	minusOne.Neg((&one))

	expression := &linearExpression{
		term{Wire: cs.Constraints[0].getOutputWire(), Coeff: constant},
		term{Wire: c.getOutputWire(), Coeff: minusOne},
	}

	return newConstraint(cs, expression)

}

// divlc divides two linear combination of constraints
func (cs *CS) divlc(num, den LinearCombination) Variable {

	var left, right linearExpression
	for _, t := range den {
		left = append(left, term{Wire: t.Constraint.getOutputWire(), Coeff: t.Coeff, Operation: mul})
	}
	for _, t := range num {
		right = append(right, term{Wire: t.Constraint.getOutputWire(), Coeff: t.Coeff, Operation: mul})
	}

	expression := &quadraticExpression{
		left:      left,
		right:     right,
		operation: div,
	}

	return newConstraint(cs, expression)
}

// mullc multiplies two linear combination of constraints
func (cs *CS) mullc(l1, l2 LinearCombination) Variable {
	var left, right linearExpression
	for _, t := range l1 {
		left = append(left, term{Wire: t.Constraint.getOutputWire(), Coeff: t.Coeff, Operation: mul})
	}
	for _, t := range l2 {
		right = append(right, term{Wire: t.Constraint.getOutputWire(), Coeff: t.Coeff, Operation: mul})
	}

	expression := &quadraticExpression{
		left:  left,
		right: right,
	}

	return newConstraint(cs, expression)
}

// mullcinterface multiplies a linear combination with a coeff (represented as an interface)
func (cs *CS) mullcinterface(l LinearCombination, c interface{}) Variable {
	var coeff big.Int
	coeff.SetUint64(1)
	right := LinearCombination{Term{Constraint: cs.ALLOCATE(c), Coeff: coeff}}
	return cs.mullc(l, right)
}

// equal equal constraints
func (cs *CS) equal(c1, c2 Variable) error {
	if c1.constraint == nil || c2.constraint == nil {
		return errors.New("variable is not compiled")
	}
	// ensure we're not doing v1.MUST_EQ(v1)
	if c1.constraint == c2.constraint {
		return fmt.Errorf("%w: %q", ErrInconsistantConstraint, "(user input 1 == user input 1) is invalid")
	}

	// ensure we are not doing x.MUST_EQ(y) , {x, y} being user inputs
	if c1.getOutputWire() != nil && c2.getOutputWire() != nil {
		if c1.getOutputWire().isUserInput() && c2.getOutputWire().isUserInput() {
			return fmt.Errorf("%w: %q", ErrInconsistantConstraint, "(user input 1 == user input 2) is invalid")
		}
	}

	// Since we copy c2's single wire into c1's, the order matters:
	// if there is an input constraint, make sure it's c2's
	if c2.getOutputWire() != nil && c1.getOutputWire() != nil {
		if c1.getOutputWire().isUserInput() {
			c2, c1 = c1, c2
		}
	}

	// Merge C1 constraints with C2's into C1
	c1.addExpressions(c2.getExpressions()...)

	// put c2's single wire in c1's single wire
	if c2.getOutputWire() != nil && c1.getOutputWire() != nil {
		wireToReplace := c1.getOutputWire()

		c2.getOutputWire().Tags = append(c2.getOutputWire().Tags, c1.getOutputWire().Tags...)
		c1.setOutputWire(c2.getOutputWire())

		// replace all occurences of c1's single wire in all expressions by c2's single wire
		for _, c := range cs.Constraints {
			for _, e := range c.getExpressions() {
				e.replaceWire(wireToReplace, c2.getOutputWire())
			}
		}
		for _, moe := range cs.MOConstraints {
			moe.replaceWire(wireToReplace, c2.getOutputWire())
		}
		for _, noe := range cs.NOConstraints {
			noe.replaceWire(wireToReplace, c2.getOutputWire())
		}
	}

	// delete C2 from the list
	delete(cs.Constraints, c2.id())

	// c2.key = c1.key
	c2.Set(c1)
	// *c2 = *c1

	// update c1 in the Constraint System
	cs.Constraints[c1.id()] = c1.constraint

	return nil
}

// equalConstant Equal a constraint to a constant
func (cs *CS) equalConstant(c Variable, constant big.Int) error {
	// ensure we're not doing x.MUST_EQ(a), x being a user input
	if c.getOutputWire().isUserInput() {
		return fmt.Errorf("%w: %q", ErrInconsistantConstraint, "(user input == VALUE) is invalid")
	}

	c.addExpressions(&eqConstantExpression{v: constant})

	return nil
}

func (cs *CS) mustBeLessOrEqConstant(a Variable, constant big.Int, nbBits int) error {

	// TODO assumes fr is alaws 256 bit long, should this elsewhere
	ci := make([]int, nbBits)

	// query the decomposition of constant, ensuring it's 256 bits long (this constant should set elsewhere)
	words := constant.Bits()
	if len(words) < 4 {
		for i := 0; i < 4-len(words); i++ {
			words = append(words, big.Word(0))
		}
	}
	nbWords := len(words)

	for i := 0; i < nbWords; i++ {
		for j := 0; j < 64; j++ {
			// TODO fix me assumes big.Int.Word is 64 bits
			ci[i*64+j] = int(uint64(words[i]) >> uint64(j) & uint64(1))
		}
	}

	// unpacking the Constraint c
	ai := cs.TO_BINARY(a, nbBits) // TODO assumes fr is alaws 256 bit long, should this elsewhere

	// building the product (assume bit length is 257 so highest bit is set to 1 for the cst & the variable for consistancy comparison)
	pi := make([]Variable, nbBits+1)
	pi[nbBits] = cs.constVar(1)

	// Setting the product
	for i := nbBits - 1; i >= 0; i-- {
		if ci[i] == 1 {
			pi[i] = cs.MUL(pi[i+1], ai[i])
		} else {
			pi[i] = pi[i+1]
		}
	}

	// constrain the bi
	for i := nbBits - 1; i >= 0; i-- {
		if ci[i] == 0 {
			constraintRes := &implyExpression{b: pi[i+1].getOutputWire(), a: ai[i].getOutputWire()}
			cs.NOConstraints = append(cs.NOConstraints, constraintRes)
		} else {
			cs.MUSTBE_BOOLEAN(ai[i])
		}
	}
	return nil
}

func (cs *CS) mustBeLessOrEq(a Variable, c Variable, nbBits int) error {

	// unpacking the constant bound c and the variable to test a
	ci := cs.TO_BINARY(c, nbBits) // TODO assumes fr is alaws 256 bit long, should this elsewhere
	ai := cs.TO_BINARY(a, nbBits)

	// building the product (assume bit length is 257 so highest bit is set to 1 for the cst & the variable for consistancy comparison)
	pi := make([]Variable, nbBits+1)
	pi[nbBits] = cs.ALLOCATE(1)

	//spi := "pi_"
	sci := "ci_"

	// Setting the product
	for i := nbBits - 1; i >= 0; i-- {
		ci[i].Tag(sci + strconv.Itoa(i))
		pi[i] = cs.SELECT(ci[i], cs.MUL(pi[i+1], ai[i]), pi[i+1])
		//pi[i].Tag(spi + strconv.Itoa(i))
	}

	// constrain the bi
	zero := cs.ALLOCATE(0)
	for i := nbBits - 1; i >= 0; i-- {
		notci := cs.SUB(1, ci[i])
		t1 := cs.MUL(notci, ai[i])
		t2 := cs.SUB(1, pi[i+1])
		lin1 := LinearCombination{
			Term{t1, bigOne()},
		}
		lin2 := LinearCombination{
			Term{cs.SUB(t2, ai[i]), bigOne()},
		}
		res := cs.MUL(lin1, lin2)
		cs.MUSTBE_EQ(res, zero)
	}
	return nil
}

func (cs *CS) String() string {
	res := ""
	res += "SO constraints: \n"
	res += "----------------\n"
	for _, c := range cs.Constraints {
		for _, e := range c.getExpressions() {
			res += e.string()
			res += "="
		}
		res = res + c.getOutputWire().String() + "\n"
	}
	res += "\nMO constraints: \n"
	res += "----------------\n"
	for _, c := range cs.MOConstraints {
		res += c.string()
		res += "\n"
	}
	res += "\nNO constraints: \n"
	res += "----------------\n"
	for _, c := range cs.NOConstraints {
		res += c.string()
		res += "\n"
	}
	return res
}

func (cs *CS) registerNamedInput(name string) bool {
	// checks if the name already exists
	for _, c := range cs.Constraints {
		if c.getOutputWire().Name == name {
			return false
		}
	}
	return true
}

// constVar creates a new variable set to a prescribed value
func (cs *CS) constVar(i1 interface{}) Variable {
	// parse input
	constant := backend.FromInterface(i1)

	// if constant == 1, we return the ONE_WIRE
	one := bigOne()

	if constant.Cmp(&one) == 0 {
		return Variable{constraint: cs.Constraints[0]}
	}

	return newConstraint(cs, &eqConstantExpression{v: constant})
}

// util function to count the wires of a constraint system
func (cs *CS) countWires() int {

	var wires []*wire

	for _, c := range cs.Constraints {
		isCounted := false
		for _, w := range wires {
			if w == c.getOutputWire() {
				isCounted = true
				continue
			}
		}
		if !isCounted {
			wires = append(wires, c.getOutputWire())
		}
	}

	return len(wires)
}
