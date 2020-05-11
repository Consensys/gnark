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

	"github.com/consensys/gnark/backend"
)

// ADD Adds 2+ inputs and returns resulting Constraint
func (cs *CS) ADD(i1, i2 interface{}, in ...interface{}) *Constraint {

	// can add constraint and constants
	add := func(_i1, _i2 interface{}) *Constraint {
		switch c1 := _i1.(type) {
		case *Constraint:
			switch c2 := _i2.(type) {
			case *Constraint:
				return cs.add(c1, c2)
			default:
				return cs.addConstant(c1, backend.FromInterface(c2))
			}
		default:
			switch c2 := _i2.(type) {
			case *Constraint:
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
func (cs *CS) SUB(i1, i2 interface{}) *Constraint {
	switch c1 := i1.(type) {
	case *Constraint:
		switch c2 := i2.(type) {
		case *Constraint:
			return cs.sub(c1, c2)
		case big.Int:
			return cs.subConstant(c1, c2)
		}
	case big.Int:
		switch c2 := i2.(type) {
		case *Constraint:
			return cs.subConstraint(c1, c2)
		}
	}
	panic("invalid type")
}

// MUL Multiplies 2+ constraints together
func (cs *CS) MUL(i1, i2 interface{}, in ...interface{}) *Constraint {

	// multiplies 2 terms (constraints, Elements, uint64, int, String)
	mul := func(_i1, _i2 interface{}) *Constraint {
		switch c1 := _i1.(type) {
		case LinearCombination:
			switch c2 := _i2.(type) {
			case LinearCombination:
				return cs.mullc(c1, c2)
			default:
				panic("invalid type; only support linear expression MUL linear expression")
			}
		case *Constraint:
			switch c2 := _i2.(type) {
			case *Constraint:
				return cs.mul(c1, c2)
			default:
				return cs.mulConstant(c1, backend.FromInterface(c2))
			}
		default: // i1 is not a Constraint type, so c2 must be
			switch c2 := _i2.(type) {
			case *Constraint:
				return cs.mulConstant(c2, backend.FromInterface(c1))
			default:
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
func (cs *CS) DIV(i1, i2 interface{}) *Constraint {

	div := func(_i1, _i2 interface{}) *Constraint {
		switch c1 := _i1.(type) {
		case LinearCombination:
			switch c2 := _i2.(type) {
			case LinearCombination:
				return cs.divlc(c1, c2)
			default:
				panic("invalid type; only support linear expression DIV linear expression")
			}
		case *Constraint:
			switch c2 := _i2.(type) {
			case *Constraint:
				return cs.div(c1, c2)
			default:
				tmp := backend.FromInterface(c2)
				return cs.divConstantRight(c1, tmp)
			}
		default: // i1 is not a Constraint type, so c2 must be
			switch c2 := _i2.(type) {
			case *Constraint:
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
	case *Constraint:
		switch c2 := i2.(type) {
		case *Constraint:
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
		case *Constraint:
			if err := cs.equalConstant(c2, c1); err != nil {
				panic(err)
			}
			return
		}
	}

	panic("invalid type")

}

// INV inverse a Constraint
func (cs *CS) INV(c1 *Constraint) *Constraint {
	return cs.inv(c1, bigOne())
}

// XOR compute the xor between two constraints
func (cs *CS) XOR(c1, c2 *Constraint) *Constraint {
	// ensure c1 and c2 are already boolean constrained
	cs.MUSTBE_BOOLEAN(c1)
	cs.MUSTBE_BOOLEAN(c2)

	expression := xorExpression{
		a: c1.outputWire,
		b: c2.outputWire,
	}

	return newConstraint(cs, &expression)
}

// MUSTBE_BOOLEAN boolean constrains a variable
func (cs *CS) MUSTBE_BOOLEAN(c *Constraint) {
	// check if the variable is already boolean constrained
	for i := 0; i < len(cs.NOConstraints); i++ {
		if bExpression, ok := cs.NOConstraints[i].(*booleanExpression); ok {
			if bExpression.b == c.outputWire {
				// this variable is already boolean constrained
				return
			}
		}
	}
	// check if the variable is the result of a XOR (a xor b == c --> c is automatically boolean constrained)
	for _, constraint := range cs.Constraints {
		if constraint == c {
			for i := 0; i < len(constraint.expressions); i++ {
				if _, ok := constraint.expressions[i].(*xorExpression); ok {
					// constraint is the result of a xor expression and is already boolean constrained as such
					return
				}
			}
		}
	}
	cs.NOConstraints = append(cs.NOConstraints, &booleanExpression{b: c.outputWire})
}

// TO_BINARY unpacks a variable in binary, n is the number of bits of the variable
// The result in in little endian (first bit= lsb)
func (cs *CS) TO_BINARY(c *Constraint, nbBits int) []*Constraint {

	// create the expression ensuring the bit decomposition matches c
	expression := &unpackExpression{
		res: c.outputWire,
	}
	cs.MOConstraints = append(cs.MOConstraints, expression)

	// create our bits constraints
	bits := make([]*Constraint, nbBits)
	for i := 0; i < nbBits; i++ {
		bits[i] = newConstraint(cs)
		cs.MUSTBE_BOOLEAN(bits[i]) // (MUSTBE_BOOLEAN check for duplicate constraints)
		expression.bits = append(expression.bits, bits[i].outputWire)
	}

	return bits
}

// FROM_BINARY c = bi*2^i (first item of b = LSb of c)
func (cs *CS) FROM_BINARY(b ...*Constraint) *Constraint {

	expression := packExpression{}

	for _, c := range b {
		cs.MUSTBE_BOOLEAN(c) // ensure input is boolean constrained
		expression.bits = append(expression.bits, c.outputWire)
	}

	return newConstraint(cs, &expression)
}

// MUSTBE_LESS_OR_EQ constrains c to be less or equal than e (taken as lifted Integer values from Fr)
func (cs *CS) MUSTBE_LESS_OR_EQ(c *Constraint, input interface{}) {
	// parse input
	constant := backend.FromInterface(input)
	// binary decomposition of e
	// var ei []int
	// _e := constant.ToRegular()
	// for i := 0; i < len(_e); i++ {
	// 	for j := 0; j < 64; j++ {
	// 		ei = append(ei, int(_e[i]>>uint64(j)&uint64(1)))
	// 	}
	// }
	var ei []int
	_e := constant
	words := _e.Bits()
	nbWords := len(words)

	for i := 0; i < nbWords; i++ {
		for j := 0; j < 64; j++ {
			// TODO fix me assumes big.Int.Word is 64 bits
			ei = append(ei, int(uint64(words[i])>>uint64(j)&uint64(1)))
		}
	}

	// unpacking the Constraint c
	b := cs.TO_BINARY(c, 256)

	// building the product
	pi := []*Constraint{cs.constVar(1)}

	for i := len(ei) - 1; i >= 0; i-- {
		if ei[i] == 1 {
			pi = append(pi, cs.MUL(pi[len(pi)-1], b[i]))
		} else {
			pi = append(pi, pi[len(pi)-1])
		}
	}

	for i := len(ei) - 1; i >= 0; i-- {
		if ei[i] == 0 {
			constraintRes := &implyExpression{b: pi[len(ei)-i-1].outputWire, a: b[i].outputWire}
			cs.NOConstraints = append(cs.NOConstraints, constraintRes)
		} else {
			cs.MUSTBE_BOOLEAN(b[i])
		}
	}

}

// SELECT if b is true, yields c1 else yields c2
func (cs *CS) SELECT(b *Constraint, i1, i2 interface{}) *Constraint {

	// ensure b is boolean constrained
	cs.MUSTBE_BOOLEAN(b)

	switch c1 := i1.(type) {
	case *Constraint:
		switch c2 := i2.(type) {
		case *Constraint:
			expression := selectExpression{
				b: b.outputWire,
				x: c1.outputWire,
				y: c2.outputWire,
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
			term{Wire: b.outputWire, Coeff: c1Bigint, Operation: mul},
			term{Wire: cs.Constraints[0].outputWire, Coeff: bigOne(), Operation: mul},
		}
		return newConstraint(cs, &expression)
	}
}

// SELECT_LUT select lookuptable[c1*2+c0] where c0 and c1 are boolean constrained
// cf https://z.cash/technology/jubjub/
func (cs *CS) SELECT_LUT(c1, c0 *Constraint, lookuptable [4]big.Int) *Constraint {

	// ensure c0 and c1 are boolean constrained
	cs.MUSTBE_BOOLEAN(c0)
	cs.MUSTBE_BOOLEAN(c1)

	expression := lutExpression{
		b0:          c0.outputWire,
		b1:          c1.outputWire,
		lookuptable: lookuptable,
	}

	return newConstraint(cs, &expression)

}

// SECRET_INPUT creates a Constraint containing an input
func (cs *CS) SECRET_INPUT(name string) *Constraint {
	// checks if the name already exists
	if !cs.registerNamedInput(name) {
		panic("input " + name + " already declared")
	}

	toReturn := &Constraint{
		outputWire: &wire{
			Name:         name,
			Tags:         []string{name},
			IsPrivate:    true,
			IsConsumed:   true,
			ConstraintID: -1,
			WireID:       -1,
		}}
	cs.addConstraint(toReturn)

	return toReturn

}

// PUBLIC_INPUT creates a Constraint containing an input
func (cs *CS) PUBLIC_INPUT(name string) *Constraint {
	toReturn := cs.SECRET_INPUT(name)
	toReturn.outputWire.IsPrivate = false
	return toReturn
}

// ALLOCATE will return an allocated cs.Constraint from input {Constraint, element, uint64, int, ...}
func (cs *CS) ALLOCATE(input interface{}) *Constraint {
	switch x := input.(type) {
	case *Constraint:
		return x
	case Constraint:
		return &x
	default:
		return cs.constVar(x)
	}
}
