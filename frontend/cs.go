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
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

const oneWireID = 1
const initialCapacity = 1e6 // TODO that must be tuned. -build tags?

func init() {
	if bits.UintSize != 64 {
		panic("gnark only support 64bits architectures")
	}
}

// CS Constraint System
type CS struct {
	// under the key i are all the expressions that must be equal to a single wire
	constraints []constraint

	// constraints yielding multiple outputs (eg unpacking)
	moExpressions []moExpression

	// constraints yielding no outputs (eg boolean constraints)
	noExpressions []expression

	// coeffs for terms
	coeffs    []big.Int
	coeffsIDs map[string]int

	// wire tags and names
	wireTags        map[int][]string // optional tags -- debug info
	secretWireNames map[int]string
	publicWireNames map[int]string
	wireNames       map[string]struct{} // ensure no duplicates in input names
}

// newConstraintSystem returns a new constraint system
func newConstraintSystem() CS {
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

	cID := cs.addConstraint(nil).id()
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

func (cs *CS) term(constraintID int, b big.Int, _isDivision ...bool) r1c.Term {
	const maxInt = int(^uint(0) >> 1)

	isDivision := false
	if len(_isDivision) > 0 {
		isDivision = _isDivision[0]
	}
	specialValue := maxInt
	// let's check if wwe have a special value mod fr modulus
	if b.Cmp(bZero) == 0 {
		specialValue = 0
		return r1c.Pack(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bOne) == 0 {
		specialValue = 1
		return r1c.Pack(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bMinusOne) == 0 {
		specialValue = -1
		return r1c.Pack(constraintID, 0, specialValue, isDivision)
	} else if b.Cmp(bTwo) == 0 {
		specialValue = 2
		return r1c.Pack(constraintID, 0, specialValue, isDivision)
	}

	// no special value, let's check if we have encountered the coeff already
	// note: this is slow. but "offline"
	var coeffID int
	key := hex.EncodeToString(b.Bytes())
	if idx, ok := cs.coeffsIDs[key]; ok {
		coeffID = idx
		return r1c.Pack(constraintID, coeffID, specialValue, isDivision)
	}

	// we didn't find it, let's add it to our coefficients
	coeffID = len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, b)
	cs.coeffsIDs[key] = coeffID
	return r1c.Pack(constraintID, coeffID, specialValue, isDivision)
}

func (cs *CS) isUserInput(wireID int) bool {
	if _, ok := cs.publicWireNames[wireID]; ok {
		return ok
	}
	_, ok := cs.secretWireNames[wireID]
	return ok
}

func (cs *CS) nbConstraints() int {
	return len(cs.constraints) - 1 // - 1 because we reserve cs.Constraints[0] for uncompiled variables
}

func (cs *CS) mul(v1, v2 Variable) Variable {
	expression := &mulExpression{
		left:  cs.term(v1.id(), *bOne),
		right: cs.term(v2.id(), *bOne),
	}

	return cs.addConstraint(expression)
}

// mulConstant multiplies by a constant
func (cs *CS) mulConstant(v Variable, constant big.Int) Variable {
	expression := &singleTermExpression{
		cs.term(v.id(), constant),
	}
	return cs.addConstraint(expression)
}

// DIV divides two constraints (c1/c2)
func (cs *CS) div(v1, v2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(v2.id(), *bOne)},
		right:     linearExpression{cs.term(v1.id(), *bOne)},
		operation: div,
	}

	return cs.addConstraint(&expression)
}

// divConstantRight c1, c2 -> c1/c2, where the right (c2) is a constant
func (cs *CS) divConstantRight(v1 Variable, v2 big.Int) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(oneWireID, v2)},
		right:     linearExpression{cs.term(v1.id(), *bOne)},
		operation: div,
	}

	return cs.addConstraint(&expression)
}

// divConstantLeft c1, c2 -> c1/c2, where the left (c1) is a constant
func (cs *CS) divConstantLeft(c1 big.Int, c2 Variable) Variable {

	expression := quadraticExpression{
		left:      linearExpression{cs.term(c2.id(), *bOne)},
		right:     linearExpression{cs.term(oneWireID, c1)},
		operation: div,
	}

	return cs.addConstraint(&expression)
}

// inv (e*c1)**-1
func (cs *CS) inverse(c1 Variable, e big.Int) Variable {
	expression := &singleTermExpression{
		cs.term(c1.id(), e, true),
	}
	return cs.addConstraint(expression)
}

// ADD generic version for adding 2 constraints
func (cs *CS) add(c1 Variable, c2 Variable) Variable {

	expression := &linearExpression{
		cs.term(c1.id(), *bOne),
		cs.term(c2.id(), *bOne),
	}

	return cs.addConstraint(expression)
}

// ADDCST adds a constant to a variable
func (cs *CS) addConstant(c Variable, constant big.Int) Variable {

	expression := &linearExpression{
		cs.term(c.id(), *bOne),
		cs.term(oneWireID, constant),
	}

	return cs.addConstraint(expression)
}

// SUB generic version for substracting 2 constraints
func (cs *CS) sub(c1 Variable, c2 Variable) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg(&one)

	expression := &linearExpression{
		cs.term(c1.id(), one),
		cs.term(c2.id(), minusOne),
	}

	return cs.addConstraint(expression)
}

func (cs *CS) subConstant(c Variable, constant big.Int) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg((&constant))

	expression := &linearExpression{
		cs.term(c.id(), one),
		cs.term(oneWireID, minusOne),
	}

	return cs.addConstraint(expression)

}

func (cs *CS) subConstraint(constant big.Int, c Variable) Variable {

	var minusOne big.Int
	one := *bOne
	minusOne.Neg((&one))

	expression := &linearExpression{
		cs.term(oneWireID, constant),
		cs.term(c.id(), minusOne),
	}

	return cs.addConstraint(expression)

}

// divlc divides two linear combination of constraints
func (cs *CS) divlc(num, den LinearCombination) Variable {

	var left, right linearExpression
	for _, t := range den {
		left = append(left, cs.term(t.Variable.id(), t.Coeff))
	}
	for _, t := range num {
		right = append(right, cs.term(t.Variable.id(), t.Coeff))
	}

	expression := &quadraticExpression{
		left:      left,
		right:     right,
		operation: div,
	}

	return cs.addConstraint(expression)
}

// mullc multiplies two linear combination of constraints
func (cs *CS) mullc(l1, l2 LinearCombination) Variable {
	var left, right linearExpression
	for _, t := range l1 {
		left = append(left, cs.term(t.Variable.id(), t.Coeff))
	}
	for _, t := range l2 {
		right = append(right, cs.term(t.Variable.id(), t.Coeff))
	}

	expression := &quadraticExpression{
		left:  left,
		right: right,
	}

	return cs.addConstraint(expression)
}

// mullcinterface multiplies a linear combination with a coeff (represented as an interface)
func (cs *CS) mullcinterface(l LinearCombination, c interface{}) Variable {
	var coeff big.Int
	coeff.SetUint64(1)
	right := LinearCombination{Term{Variable: cs.Allocate(c), Coeff: coeff}}
	return cs.mullc(l, right)
}

// equal equal constraints
func (cs *CS) equal(c1, c2 Variable) {
	idC1, idC2 := c1.id(), c2.id()

	// ensure we're not doing v1.MUST_EQ(v1)
	if idC1 == idC2 {
		fmt.Println("warning: calling MUSTBE_EQ between the same inputs")
		return
	}

	expression := &equalExpression{
		a: idC1,
		b: idC2,
	}

	cs.noExpressions = append(cs.noExpressions, expression)
}

// equalConstant Equal a constraint to a constant
func (cs *CS) equalConstant(c Variable, constant big.Int) {
	// ensure we're not doing x.MUST_EQ(a), x being a user input
	if cs.isUserInput(c.id()) {
		fmt.Println("warning: calling MUSTBE_EQ on a input")
		return
	}

	cs.noExpressions = append(cs.noExpressions, &equalConstantExpression{wire: c.id(), constant: constant})
}

func (cs *CS) mustBeLessOrEqConstant(a Variable, constant big.Int, nbBits int) error {
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
			ci[i*64+j] = int(uint64(words[i]) >> uint64(j) & uint64(1))
		}
	}

	// unpacking the Constraint c
	ai := cs.ToBinary(a, nbBits)

	// building the product (assume bit length is 257 so highest bit is set to 1 for the cst & the variable for consistancy comparison)
	pi := make([]Variable, nbBits+1)
	pi[nbBits] = cs.constVar(1)

	// Setting the product
	for i := nbBits - 1; i >= 0; i-- {
		if ci[i] == 1 {
			pi[i] = cs.Mul(pi[i+1], ai[i])
		} else {
			pi[i] = pi[i+1]
		}
	}

	// constrain the bi
	for i := nbBits - 1; i >= 0; i-- {
		if ci[i] == 0 {
			constraintRes := &implyExpression{b: pi[i+1].id(), a: ai[i].id()}
			cs.noExpressions = append(cs.noExpressions, constraintRes)
		} else {
			cs.MustBeBoolean(ai[i])
		}
	}
	return nil
}

func (cs *CS) mustBeLessOrEq(a Variable, c Variable, nbBits int) error {
	// unpacking the constant bound c and the variable to test a
	ci := cs.ToBinary(c, nbBits)
	ai := cs.ToBinary(a, nbBits)

	// building the product (assume bit length is 257 so highest bit is set to 1 for the cst & the variable for consistancy comparison)
	pi := make([]Variable, nbBits+1)
	pi[nbBits] = cs.Allocate(1)

	// Setting the product
	for i := nbBits - 1; i >= 0; i-- {
		pi[i] = cs.Select(ci[i], cs.Mul(pi[i+1], ai[i]), pi[i+1])
	}

	// constrain the bi
	zero := cs.Allocate(0)
	for i := nbBits - 1; i >= 0; i-- {
		notci := cs.Sub(1, ci[i])
		t1 := cs.Mul(notci, ai[i])
		t2 := cs.Sub(1, pi[i+1])
		res := cs.Mul(t1, cs.Sub(t2, ai[i]))
		cs.MustBeEqual(res, zero)
	}
	return nil
}

func (cs *CS) String() string {
	res := ""
	res += "SO constraints: \n"
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

	return cs.addConstraint(&equalConstantExpression{constant: constant})
}
