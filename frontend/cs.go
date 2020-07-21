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

// Package frontend contains Constraint System representation and R1CS to be used with zero knowledge proof systems in gnark
package frontend

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs/term"
	"github.com/consensys/gnark/internal/utils/debug"
)

var errInconsistantConstraint = errors.New("inconsistant constraint")

const oneWireID = 1
const initialCapacity = 1e6 // TODO that must be tuned. -build tags?

// CS Constraint System
type CS struct {
	// under the key i are all the expressions that must be equal to a single wire
	constraints []constraint

	// constraints yielding multiple outputs (eg unpacking)
	moConstraints []moExpression

	// constraints yielding no outputs (eg boolean constraints)
	noConstraints []expression

	// coeffs for terms
	coeffs    []big.Int
	coeffsIDs map[string]int

	// wire tags and names
	wireTags        map[int][]string // optional tags -- debug info
	secretWireNames map[int]string
	publicWireNames map[int]string
	wireNames       map[string]struct{} // ensure no duplicates in input names
}

// NewConstraintSystem returns a new constraint system
func NewConstraintSystem() CS {
	// initialize constraint system
	cs := CS{
		constraints:     make([]constraint, 1, initialCapacity),
		coeffs:          make([]big.Int, 1, initialCapacity),
		wireNames:       make(map[string]struct{}),
		secretWireNames: make(map[int]string),
		publicWireNames: make(map[int]string),
		coeffsIDs:       make(map[string]int),
		wireTags:        make(map[int][]string),
	}

	// The first constraint corresponds to the declaration of
	// the unconstrained precomputed wire equal to 1
	oneConstraint := constraint{
		wire: uninitializedWire,
	}

	cID := cs.addConstraint(oneConstraint)
	// ensure name is not overwritten by inputs
	cs.wireNames[backend.OneWire] = struct{}{}
	cs.publicWireNames[oneWireID] = backend.OneWire

	if cID != oneWireID {
		panic("one wire id is incorrect")
	}

	return cs
}

var (
	bZero     = new(big.Int)
	bOne      = new(big.Int).SetInt64(1)
	bTwo      = new(big.Int).SetInt64(2)
	bMinusOne = new(big.Int).SetInt64(-1)
)

func (cs *CS) term(constraintID int, b big.Int, _isDivision ...bool) term.Term {
	const maxInt = int(^uint(0) >> 1)

	isDivision := false
	if len(_isDivision) > 0 {
		isDivision = _isDivision[0]
	}
	specialValue := maxInt
	// let's check if wwe have a special value mod fr modulus
	if b.Cmp(bZero) == 0 {
		specialValue = 0
		return term.NewTerm(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bOne) == 0 {
		specialValue = 1
		return term.NewTerm(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bMinusOne) == 0 {
		specialValue = -1
		return term.NewTerm(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bTwo) == 0 {
		specialValue = 2
		return term.NewTerm(constraintID, 0, specialValue, isDivision)
	}

	// no special value, let's check if we have encountered the coeff already
	// note: this is slow. but "offline"
	var coeffID int
	key := hex.EncodeToString(b.Bytes())
	if idx, ok := cs.coeffsIDs[key]; ok {
		coeffID = idx
		return term.NewTerm(constraintID, coeffID, specialValue, isDivision)
	}

	// we didn't find it, let's add it to our coefficients
	coeffID = len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, b)
	cs.coeffsIDs[key] = coeffID
	return term.NewTerm(constraintID, coeffID, specialValue, isDivision)
}

func (cs *CS) isUserInput(wireID int) bool {
	if _, ok := cs.publicWireNames[wireID]; ok {
		return ok
	} else {
		_, ok := cs.secretWireNames[wireID]
		return ok
	}
}

func (cs *CS) nbConstraints() int {
	return len(cs.constraints) - 1 // - 1 because we reserve cs.Constraints[0] for uncompiled variables
}

func (cs *CS) addConstraint(c constraint) int {
	c.ID = len(cs.constraints)
	cs.constraints = append(cs.constraints, c)
	return c.ID
}

// MUL multiplies two constraints
func (cs *CS) mul(c1, c2 Variable) Variable {
	expression := &quadraticExpression{
		left:      linearExpression{cs.term(c1.id(cs), *bOne)},
		right:     linearExpression{cs.term(c2.id(cs), *bOne)},
		operation: mul,
	}

	return newConstraint(cs, expression)
}

// mulConstant multiplies by a constant
func (cs *CS) mulConstant(c Variable, constant big.Int) Variable {
	expression := &singleTermExpression{
		cs.term(c.id(cs), constant),
	}
	return newConstraint(cs, expression)
}

// DIV divides two constraints (c1/c2)
func (cs *CS) div(c1, c2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(c2.id(cs), *bOne)},
		right:     linearExpression{cs.term(c1.id(cs), *bOne)},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// divConstantRight c1, c2 -> c1/c2, where the right (c2) is a constant
func (cs *CS) divConstantRight(c1 Variable, c2 big.Int) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(oneWireID, c2)},
		right:     linearExpression{cs.term(c1.id(cs), *bOne)},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// divConstantLeft c1, c2 -> c1/c2, where the left (c1) is a constant
func (cs *CS) divConstantLeft(c1 big.Int, c2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(c2.id(cs), *bOne)},
		right:     linearExpression{cs.term(oneWireID, c1)},
		operation: div,
	}

	return newConstraint(cs, &expression)
}

// inv (e*c1)**-1
func (cs *CS) inv(c1 Variable, e big.Int) Variable {
	expression := &singleTermExpression{
		cs.term(c1.id(cs), e, true),
	}
	return newConstraint(cs, expression)
}

// ADD generic version for adding 2 constraints
func (cs *CS) add(c1 Variable, c2 Variable) Variable {

	expression := &linearExpression{
		cs.term(c1.id(cs), *bOne),
		cs.term(c2.id(cs), *bOne),
	}

	return newConstraint(cs, expression)
}

// ADDCST adds a constant to a variable
func (cs *CS) addConstant(c Variable, constant big.Int) Variable {

	expression := &linearExpression{
		cs.term(c.id(cs), *bOne),
		cs.term(oneWireID, constant),
	}

	return newConstraint(cs, expression)
}

// SUB generic version for substracting 2 constraints
func (cs *CS) sub(c1 Variable, c2 Variable) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg(&one)

	expression := &linearExpression{
		cs.term(c1.id(cs), one),
		cs.term(c2.id(cs), minusOne),
	}

	return newConstraint(cs, expression)
}

func (cs *CS) subConstant(c Variable, constant big.Int) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg((&constant))

	expression := &linearExpression{
		cs.term(c.id(cs), one),
		cs.term(oneWireID, minusOne),
	}

	return newConstraint(cs, expression)

}

func (cs *CS) subConstraint(constant big.Int, c Variable) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg((&one))

	expression := &linearExpression{
		cs.term(oneWireID, constant),
		cs.term(c.id(cs), minusOne),
	}

	return newConstraint(cs, expression)

}

// divlc divides two linear combination of constraints
func (cs *CS) divlc(num, den LinearCombination) Variable {

	var left, right linearExpression
	for _, t := range den {
		left = append(left, cs.term(t.Variable.id(cs), t.Coeff))
	}
	for _, t := range num {
		right = append(right, cs.term(t.Variable.id(cs), t.Coeff))
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
		left = append(left, cs.term(t.Variable.id(cs), t.Coeff))
	}
	for _, t := range l2 {
		right = append(right, cs.term(t.Variable.id(cs), t.Coeff))
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
	right := LinearCombination{Term{Variable: cs.ALLOCATE(c), Coeff: coeff}}
	return cs.mullc(l, right)
}

// equal equal constraints
func (cs *CS) equal(c1, c2 Variable) error {
	if c1.constraintID == 0 || c2.constraintID == 0 {
		return errors.New("variable is not compiled")
	}
	// ensure we're not doing v1.MUST_EQ(v1)
	if c1.constraintID == c2.constraintID {
		return fmt.Errorf("%w: %q", errInconsistantConstraint, "(user input 1 == user input 1) is invalid")
	}

	w1, w2 := c1.id(cs), c2.id(cs)
	debug.Assert(w1 != 0 && w2 != 0, "wires are not set")

	c1IsUserInput := cs.isUserInput(w1)
	if c1IsUserInput && cs.isUserInput(w2) {
		return fmt.Errorf("%w: %q", errInconsistantConstraint, "(user input 1 == user input 2) is invalid")
	}

	expression := &equalExpression{
		a: w1,
		b: w2,
	}

	cs.noConstraints = append(cs.noConstraints, expression)

	return nil
}

// equalConstant Equal a constraint to a constant
func (cs *CS) equalConstant(c Variable, constant big.Int) error {
	// ensure we're not doing x.MUST_EQ(a), x being a user input
	if cs.isUserInput(c.id(cs)) {
		return fmt.Errorf("%w: %q", errInconsistantConstraint, "(user input == VALUE) is invalid")
	}

	cs.noConstraints = append(cs.noConstraints, &equalConstantExpression{a: c.id(cs), v: constant})

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
			constraintRes := &implyExpression{b: pi[i+1].id(cs), a: ai[i].id(cs)}
			cs.noConstraints = append(cs.noConstraints, constraintRes)
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
	// sci := "ci_"

	// Setting the product
	for i := nbBits - 1; i >= 0; i-- {
		// TODO
		// ci[i].Tag(cs, sci+strconv.Itoa(i))
		pi[i] = cs.SELECT(ci[i], cs.MUL(pi[i+1], ai[i]), pi[i+1])
		//pi[i].Tag(spi + strconv.Itoa(i))
	}

	// constrain the bi
	zero := cs.ALLOCATE(0)
	for i := nbBits - 1; i >= 0; i-- {
		notci := cs.SUB(1, ci[i])
		t1 := cs.MUL(notci, ai[i])
		t2 := cs.SUB(1, pi[i+1])
		res := cs.MUL(t1, cs.SUB(t2, ai[i]))
		cs.MUSTBE_EQ(res, zero)
	}
	return nil
}

func (cs *CS) String() string {
	res := ""
	res += "SO constraints: \n"
	// TODO
	// res += "----------------\n"
	// for _, c := range cs.Constraints {
	// 	for _, e := range c.getExpressions() {
	// 		res += e.string()
	// 		res += "="
	// 	}
	// 	w := cs.Wires[c.wireID]
	// 	res = res + w.String() + "\n"
	// }
	// res += "\nMO constraints: \n"
	// res += "----------------\n"
	// for _, c := range cs.MOConstraints {
	// 	res += c.string()
	// 	res += "\n"
	// }
	// res += "\nNO constraints: \n"
	// res += "----------------\n"
	// for _, c := range cs.NOConstraints {
	// 	res += c.string()
	// 	res += "\n"
	// }
	return res
}

// constVar creates a new variable set to a prescribed value
func (cs *CS) constVar(i1 interface{}) Variable {
	// parse input
	constant := backend.FromInterface(i1)

	// if constant == 1, we return the ONE_WIRE
	if constant.Cmp(bOne) == 0 {
		return Variable{constraintID: oneWireID}
	}

	return newConstraint(cs, &equalConstantExpression{v: constant})
}
