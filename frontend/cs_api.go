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
	"fmt"
	"math/big"
	"reflect"

	"github.com/consensys/gnark/backend"
)

// ADD Adds 2+ inputs and returns resulting Constraint
func (cs *CS) ADD(i1, i2 interface{}, in ...interface{}) CircuitVariable {

	// can add constraint and constants
	add := func(_i1, _i2 interface{}) CircuitVariable {
		switch c1 := _i1.(type) {
		case CircuitVariable:
			switch c2 := _i2.(type) {
			case CircuitVariable:
				return cs.add(c1, c2)
			default:
				return cs.addConstant(c1, backend.FromInterface(c2))
			}
		default:
			switch c2 := _i2.(type) {
			case CircuitVariable:
				return cs.addConstant(c2, backend.FromInterface(c1))
			default:
				panic("invalid type")
			}
		}
	}

	res := add(i1, i2)

	for i := 0; i < len(in); i++ {
		res = add(res, in[i])
	}

	return res
}

// SUB Adds two constraints
func (cs *CS) SUB(i1, i2 interface{}) CircuitVariable {
	switch c1 := i1.(type) {
	case CircuitVariable:
		switch c2 := i2.(type) {
		case CircuitVariable:
			return cs.sub(c1, c2)
		case big.Int:
			return cs.subConstant(c1, c2)
		}
	default:
		_c1 := backend.FromInterface(c1)
		switch c2 := i2.(type) {
		case CircuitVariable:
			return cs.subConstraint(_c1, c2)
		}
	}
	panic("invalid type")
}

// MUL Multiplies 2+ constraints together
func (cs *CS) MUL(i1, i2 interface{}, in ...interface{}) CircuitVariable {

	// multiplies 2 terms (constraints, Elements, uint64, int, String)
	mul := func(_i1, _i2 interface{}) CircuitVariable {
		switch c1 := _i1.(type) {
		case LinearCombination:
			switch c2 := _i2.(type) {
			case LinearCombination:
				return cs.mullc(c1, c2)
			default:
				return cs.mullcinterface(c1, c2)
			}
		case CircuitVariable:
			switch c2 := _i2.(type) {
			case CircuitVariable:
				return cs.mul(c1.(CircuitVariable), c2.(CircuitVariable))
			case LinearCombination:
				return cs.mullcinterface(c2, c1)
			default:
				return cs.mulConstant(c1.(CircuitVariable), backend.FromInterface(c2))
			}
		default: // i1 is not a Constraint type, so c2 must be
			switch c2 := _i2.(type) {
			case CircuitVariable:
				return cs.mulConstant(c2.(CircuitVariable), backend.FromInterface(c1))
			default:
				fmt.Println(reflect.TypeOf(_i2))
				panic("invalid type")
			}

		}
	}

	res := mul(i1, i2)

	for i := 0; i < len(in); i++ {
		res = mul(res, in[i])
	}

	return res

}

// DIV divides two constraints (i1/i2)
func (cs *CS) DIV(i1, i2 interface{}) CircuitVariable {

	div := func(_i1, _i2 interface{}) CircuitVariable {
		switch c1 := _i1.(type) {
		case LinearCombination:
			switch c2 := _i2.(type) {
			case LinearCombination:
				return cs.divlc(c1, c2)
			default:
				panic("invalid type; only support linear expression DIV linear expression")
			}
		case CircuitVariable:
			switch c2 := _i2.(type) {
			case CircuitVariable:
				return cs.div(c1, c2)
			default:
				tmp := backend.FromInterface(c2)
				return cs.divConstantRight(c1, tmp)
			}
		default: // i1 is not a Constraint type, so c2 must be
			switch c2 := _i2.(type) {
			case CircuitVariable:
				tmp := backend.FromInterface(c1)
				return cs.divConstantLeft(tmp, c2)
			default:
				panic("invalid type")
			}

		}
	}

	res := div(i1, i2)

	return res

}

// MUSTBE_EQ equalizes two constraints
func (cs *CS) MUSTBE_EQ(i1, i2 interface{}) {

	switch c1 := i1.(type) {
	case CircuitVariable:
		switch c2 := i2.(type) {
		case CircuitVariable:
			if err := cs.equal(c1, c2); err != nil {
				panic(err)
			}
			return
		case big.Int: // TODO handle *big.Int ?
			if err := cs.equalConstant(c1, c2); err != nil {
				panic(err)
			}
			return
		}
	case big.Int: // TODO handle *big.Int ?
		switch c2 := i2.(type) {
		case CircuitVariable:
			if err := cs.equalConstant(c2, c1); err != nil {
				panic(err)
			}
			return
		}
	}

	panic("invalid type")

}

// INV inverse a Constraint
func (cs *CS) INV(c1 CircuitVariable) CircuitVariable {
	return cs.inv(c1, bigOne())
}

// XOR compute the xor between two constraints
func (cs *CS) XOR(c1, c2 CircuitVariable) CircuitVariable {
	// ensure c1 and c2 are already boolean constrained
	cs.MUSTBE_BOOLEAN(c1)
	cs.MUSTBE_BOOLEAN(c2)

	expression := xorExpression{
		a: c1.getOutputWire(),
		b: c2.getOutputWire(),
	}

	return newConstraint(cs, &expression)
}

// MUSTBE_BOOLEAN boolean constrains a variable
func (cs *CS) MUSTBE_BOOLEAN(c CircuitVariable) {
	// check if the variable is already boolean constrained
	for i := 0; i < len(cs.NOConstraints); i++ {
		if bExpression, ok := cs.NOConstraints[i].(*booleanExpression); ok {
			if bExpression.b == c.getOutputWire() {
				// this variable is already boolean constrained
				return
			}
		}
	}
	// check if the variable is the result of a XOR (a xor b == c --> c is automatically boolean constrained)
	for _, val := range cs.Constraints {
		if val == c {
			expresions := val.getExpressions()
			for i := 0; i < len(expresions); i++ {
				if _, ok := expresions[i].(*xorExpression); ok {
					// constraint is the result of a xor expression and is already boolean constrained as such
					return
				}
			}
		}
	}
	cs.NOConstraints = append(cs.NOConstraints, &booleanExpression{b: c.getOutputWire()})
}

// TO_BINARY unpacks a variable in binary, n is the number of bits of the variable
// The result in in little endian (first bit= lsb)
func (cs *CS) TO_BINARY(c CircuitVariable, nbBits int) []CircuitVariable {

	// create the expression ensuring the bit decomposition matches c
	expression := &unpackExpression{
		res: c.getOutputWire(),
	}
	cs.MOConstraints = append(cs.MOConstraints, expression)

	// create our bits constraints
	bits := make([]CircuitVariable, nbBits)
	for i := 0; i < nbBits; i++ {
		bits[i] = newConstraint(cs)
		cs.MUSTBE_BOOLEAN(bits[i]) // (MUSTBE_BOOLEAN check for duplicate constraints)
		expression.bits = append(expression.bits, bits[i].getOutputWire())
	}

	return bits
}

// FROM_BINARY packs b, seen as a fr.Element in little endian
func (cs *CS) FROM_BINARY(b ...CircuitVariable) CircuitVariable {

	expression := packExpression{}

	for _, c := range b {
		cs.MUSTBE_BOOLEAN(c) // ensure input is boolean constrained
		expression.bits = append(expression.bits, c.getOutputWire())
	}

	return newConstraint(cs, &expression)
}

// MUSTBE_LESS_OR_EQ constrains c to be less or equal than e (taken as lifted Integer values from Fr)
// from https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
func (cs *CS) MUSTBE_LESS_OR_EQ(c CircuitVariable, bound interface{}, nbBits int) {

	switch _bound := bound.(type) {
	case CircuitVariable:
		cs.mustBeLessOrEq(c, _bound, nbBits)
	default:
		b := backend.FromInterface(bound)
		cs.mustBeLessOrEqConstant(c, b, nbBits)
	}
}

// SELECT if b is true, yields c1 else yields c2
func (cs *CS) SELECT(b CircuitVariable, i1, i2 interface{}) CircuitVariable {

	// ensure b is boolean constrained
	cs.MUSTBE_BOOLEAN(b)

	switch c1 := i1.(type) {
	case CircuitVariable:
		switch c2 := i2.(type) {
		case CircuitVariable:
			expression := selectExpression{
				b: b.getOutputWire(),
				x: c1.getOutputWire(),
				y: c2.getOutputWire(),
			}
			return newConstraint(cs, &expression)
		default:
			panic("invalid type")
		}
	default:
		c1Bigint := backend.FromInterface(i1)
		c2Bigint := backend.FromInterface(i2)
		c1Bigint.Sub(&c1Bigint, &c2Bigint)
		expression := linearExpression{
			term{Wire: b.getOutputWire(), Coeff: c1Bigint, Operation: mul},
			term{Wire: cs.Constraints[0].getOutputWire(), Coeff: bigOne(), Operation: mul},
		}
		return newConstraint(cs, &expression)
	}
}

// SELECT_LUT select lookuptable[c1*2+c0] where c0 and c1 are boolean constrained
// cf https://z.cash/technology/jubjub/
func (cs *CS) SELECT_LUT(c1, c0 CircuitVariable, lookuptable [4]big.Int) CircuitVariable {

	// ensure c0 and c1 are boolean constrained
	cs.MUSTBE_BOOLEAN(c0)
	cs.MUSTBE_BOOLEAN(c1)

	expression := lutExpression{
		b0:          c0.getOutputWire(),
		b1:          c1.getOutputWire(),
		lookuptable: lookuptable,
	}

	return newConstraint(cs, &expression)

}

// SECRET_INPUT creates a Constraint containing an input
func (cs *CS) SECRET_INPUT(name string) CircuitVariable {
	// checks if the name already exists
	if !cs.registerNamedInput(name) {
		panic("input " + name + " already declared")
	}

	toReturn := &constraint{
		outputWire: &wire{
			Name:         name,
			Tags:         []string{},
			IsPrivate:    true,
			IsConsumed:   true,
			ConstraintID: -1,
			WireID:       -1,
		}}
	cs.addConstraint(toReturn)

	return toReturn

}

// PUBLIC_INPUT creates a Constraint containing an input
func (cs *CS) PUBLIC_INPUT(name string) CircuitVariable {
	toReturn := cs.SECRET_INPUT(name)
	toReturn.getOutputWire().IsPrivate = false
	return toReturn
}

// ALLOCATE will return an allocated cs.Constraint from input {Constraint, element, uint64, int, ...}
func (cs *CS) ALLOCATE(input interface{}) CircuitVariable {
	switch x := input.(type) {
	case CircuitVariable:
		return x
	case constraint:
		return &x
	default:
		return cs.constVar(x)
	}
}
