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
	"github.com/consensys/gnark/backend/r1cs/r1c"
)

// PublicInput creates a new public input
func (c *CS) PublicInput(name string) Variable {
	idx := len(c.PublicInputs)
	res := Variable{false, Public, idx, nil}

	// checks if the name is not already picked
	for _, v := range c.publicInputsNames {
		if v == name {
			panic("duplicate input name (public)")
		}
	}

	c.publicInputsNames = append(c.publicInputsNames, name)
	c.PublicInputs = append(c.PublicInputs, res)
	return res
}

// SecretInput creates a new public input
func (c *CS) SecretInput(name string) Variable {
	idx := len(c.secretInputs)
	res := Variable{false, Secret, idx, nil}

	// checks if the name is not already picked
	for _, v := range c.publicInputsNames {
		if v == name {
			panic("duplicate input name (secret)")
		}
	}

	c.secretInputsName = append(c.secretInputsName, name)
	c.secretInputs = append(c.secretInputs, res)
	return res
}

// Add adds 2 wires
func (c *CS) Add(i1, i2 interface{}, in ...interface{}) Variable {

	res := c.NewInternalVariable()

	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	lLeft := LinearCombination{}

	add := func(_i interface{}) {
		switch t := _i.(type) {
		case Variable:
			c.checkIsAllocated(t)
			lLeft = append(lLeft, LinearTerm{t, idxOne})
		default:
			n := backend.FromInterface(t)
			idxn := c.GetCoeffID(&n)
			lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn})
		}
	}
	add(i1)
	add(i2)
	for i := 0; i < len(in); i++ {
		add(in[i])
	}

	lRight := LinearCombination{
		LinearTerm{c.PublicInputs[0], idxOne},
	}
	lOoutput := LinearCombination{
		LinearTerm{res, idxOne},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// Sub Adds two wires
func (c *CS) Sub(i1, i2 interface{}) Variable {

	res := c.NewInternalVariable()

	one := big.NewInt(1)
	minusOne := big.NewInt(-1)
	idxOne := c.GetCoeffID(one)
	idxMinusOne := c.GetCoeffID(minusOne)

	lLeft := LinearCombination{}
	switch t := i1.(type) {
	case Variable:
		c.checkIsAllocated(t)
		lLeft = append(lLeft, LinearTerm{t, idxOne})
	default:
		n := backend.FromInterface(t)
		idxn := c.GetCoeffID(&n)
		lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn})
	}

	switch t := i2.(type) {
	case Variable:
		c.checkIsAllocated(t)
		lLeft = append(lLeft, LinearTerm{t, idxMinusOne})
	default:
		n := backend.FromInterface(t)
		n.Mul(&n, minusOne)
		idxn := c.GetCoeffID(&n)
		lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn})
	}

	lRight := LinearCombination{
		LinearTerm{c.PublicInputs[0], idxOne},
	}
	lOoutput := LinearCombination{
		LinearTerm{res, idxOne},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// Mul multiplies 2 wires
func (c *CS) Mul(i1, i2 interface{}, in ...interface{}) Variable {

	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	mul := func(_i1, _i2 interface{}) Variable {

		_res := c.NewInternalVariable()

		lLeft := LinearCombination{}
		lRight := LinearCombination{}

		// left
		switch t1 := _i1.(type) {
		case LinearCombination:
			lLeft = make([]LinearTerm, len(t1))
			copy(lLeft, t1)
		case Variable:
			c.checkIsAllocated(t1)
			lLeft = append(lLeft, LinearTerm{t1, idxOne})
		default:
			n1 := backend.FromInterface(t1)
			idxn1 := c.GetCoeffID(&n1)
			lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn1})
		}

		// right
		switch t2 := _i2.(type) {
		case LinearCombination:
			lRight = make([]LinearTerm, len(t2))
			copy(lRight, t2)
		case Variable:
			c.checkIsAllocated(t2)
			lRight = append(lRight, LinearTerm{t2, idxOne})
		default:
			n2 := backend.FromInterface(t2)
			idxn2 := c.GetCoeffID(&n2)
			lRight = append(lRight, LinearTerm{c.getOneVariable(), idxn2})
		}

		lOoutput := LinearCombination{
			LinearTerm{_res, idxOne},
		}
		g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}
		c.gates = append(c.gates, g)
		return _res
	}

	res := mul(i1, i2)
	for i := 0; i < len(in); i++ {
		res = mul(res, in[i])
	}

	return res
}

// Inverse inverses a variable
func (c *CS) Inverse(v Variable) Variable {

	c.checkIsAllocated(v)

	res := c.NewInternalVariable()

	// find the entry in c.coeffs corresponding to 1
	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	lLeft := LinearCombination{LinearTerm{res, idxOne}}
	lRight := LinearCombination{LinearTerm{v, idxOne}}
	lOoutput := LinearCombination{LinearTerm{c.getOneVariable(), idxOne}}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}
	c.gates = append(c.gates, g)

	return res
}

// Div divides two constraints (i1/i2)
func (c *CS) Div(i1, i2 interface{}) Variable {

	res := c.NewInternalVariable()

	// find the entry in c.coeffs corresponding to 1
	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	// lOoutput
	lOoutput := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lOoutput = make([]LinearTerm, len(t1))
		copy(lOoutput, t1)
	case Variable:
		c.checkIsAllocated(t1)
		lOoutput = append(lOoutput, LinearTerm{t1, idxOne})
	default:
		n1 := backend.FromInterface(t1)
		idxn1 := c.GetCoeffID(&n1)
		lOoutput = append(lOoutput, LinearTerm{c.getOneVariable(), idxn1})
	}

	// left
	lLeft := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		lLeft = make([]LinearTerm, len(t2))
		copy(lLeft, t2)
	case Variable:
		c.checkIsAllocated(t2)
		lLeft = append(lLeft, LinearTerm{t2, idxOne})
	default:
		n2 := backend.FromInterface(t2)
		idxn2 := c.GetCoeffID(&n2)
		lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn2})
	}

	lRight := LinearCombination{LinearTerm{res, idxOne}}

	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// Xor compute the xor between two constraints
func (c *CS) Xor(a, b Variable) Variable {

	c.checkIsAllocated(a)
	c.checkIsAllocated(b)

	c.MustBeBoolean(a)
	c.MustBeBoolean(b)

	two := big.NewInt(2)
	one := big.NewInt(1)
	minusOne := big.NewInt(-1)

	idxtwo := c.GetCoeffID(two)
	idxOne := c.GetCoeffID(one)
	idxMinusOne := c.GetCoeffID(minusOne)

	res := c.NewInternalVariable()
	lLeft := LinearCombination{
		LinearTerm{a, idxtwo},
	}
	lRight := LinearCombination{
		LinearTerm{b, idxOne},
	}
	lOoutput := LinearCombination{
		LinearTerm{a, idxOne},
		LinearTerm{b, idxOne},
		LinearTerm{res, idxMinusOne},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// ToBinary unpacks a variable in binary, n is the number of bits of the variable
// The result in in little endian (first bit= lsb)
func (c *CS) ToBinary(a Variable, nbBits int) []Variable {

	c.checkIsAllocated(a)

	var tmp big.Int

	idx := make([]int, nbBits)
	one := big.NewInt(1)
	two := big.NewInt(2)
	tmp.Set(two)

	idx[0] = c.GetCoeffID(one)
	idx[1] = c.GetCoeffID(two)

	for i := 2; i < nbBits; i++ {
		tmp.Mul(&tmp, two)
		idx[i] = c.GetCoeffID(&tmp)
	}

	res := make([]Variable, nbBits)
	lLeft := make([]LinearTerm, nbBits)
	for i := 0; i < nbBits; i++ {
		res[i] = c.NewInternalVariable()
		c.MustBeBoolean(res[i])
		lLeft[i].Variable = res[i]
		lLeft[i].Coeff = idx[i]
	}
	lRight := LinearCombination{
		LinearTerm{c.getOneVariable(), idx[0]},
	}
	lOoutput := LinearCombination{
		LinearTerm{a, idx[0]},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.BinaryDec}

	c.gates = append(c.gates, g)

	return res

}

// FromBinary packs b, seen as a fr.Element in little endian
func (c *CS) FromBinary(b ...Variable) Variable {

	for _, i := range b {
		c.checkIsAllocated(i)
	}

	res := c.NewInternalVariable()

	l := len(b)

	idx := make([]int, l)
	one := big.NewInt(1)
	two := big.NewInt(2)
	var tmp big.Int
	tmp.Set(two)

	idx[0] = c.GetCoeffID(one)
	idx[1] = c.GetCoeffID(two)

	for i := 2; i < l; i++ {
		tmp.Mul(&tmp, two)
		idx[i] = c.GetCoeffID(&tmp)
	}

	lLeft := make([]LinearTerm, l)
	for i := 0; i < l; i++ {
		lLeft[i].Variable = b[i]
		lLeft[i].Coeff = idx[i]
	}
	lRight := LinearCombination{
		LinearTerm{c.getOneVariable(), idx[0]},
	}
	lOoutput := LinearCombination{
		LinearTerm{res, idx[0]},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// Select if b is true, yields c1 else yields c2
func (c *CS) Select(b Variable, i1, i2 interface{}) Variable {

	c.checkIsAllocated(b)

	res := c.NewInternalVariable()

	one := big.NewInt(1)
	minusOne := big.NewInt(-1)
	idxOne := c.GetCoeffID(one)
	idxMinusOne := c.GetCoeffID(minusOne)

	lLeft := LinearCombination{
		LinearTerm{b, idxOne},
	}

	// lRight, first part
	lRight := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lRight = make([]LinearTerm, len(t1))
		copy(lRight, t1)
	case Variable:
		c.checkIsAllocated(t1)
		lRight = append(lRight, LinearTerm{t1, idxOne})
	default:
		n1 := backend.FromInterface(t1)
		idx1 := c.GetCoeffID(&n1)
		lRight = append(lRight, LinearTerm{c.getOneVariable(), idx1})
	}

	// lRight, second part
	toAppend := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		for _, e := range t2 {
			coef := c.coeffs[e.Coeff]
			coef.Mul(&coef, minusOne)
			idcoef := c.GetCoeffID(&coef)
			toAppend = append(toAppend, LinearTerm{e.Variable, idcoef})
		}
	case Variable:
		c.checkIsAllocated(t2)
		toAppend = append(toAppend, LinearTerm{t2, idxMinusOne})
	default:
		n2 := backend.FromInterface(t2)
		idx2 := c.GetCoeffID(&n2)
		toAppend = append(toAppend, LinearTerm{c.getOneVariable(), idx2})
	}
	lRight = append(lRight, toAppend...)

	lOoutput := LinearCombination{
		LinearTerm{res, idxOne},
	}
	lOoutput = append(lOoutput, toAppend...)

	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res
}

// Constant will return a Variable from input {uint64, int, ...}
func (c *CS) Constant(input interface{}) Variable {

	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	//lLeft
	lLeft := LinearCombination{}

	switch t := input.(type) {
	case Variable:
		c.checkIsAllocated(t)
		return t
	default:
		n := backend.FromInterface(t)
		if n.Cmp(one) == 0 {
			return c.getOneVariable()
		}
		idxn := c.GetCoeffID(&n)
		lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn})
	}

	res := c.NewInternalVariable()
	lRight := LinearCombination{LinearTerm{c.getOneVariable(), idxOne}}
	lOoutput := LinearCombination{LinearTerm{res, idxOne}}

	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.gates = append(c.gates, g)

	return res

}

// MustBeEqual equalizes two variables
func (c *CS) MustBeEqual(i1, i2 interface{}) {

	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)

	//left
	lLeft := LinearCombination{}
	switch t1 := i1.(type) {
	case LinearCombination:
		lLeft = make([]LinearTerm, len(t1))
		copy(lLeft, t1)
	case Variable:
		c.checkIsAllocated(t1)
		lLeft = append(lLeft, LinearTerm{t1, idxOne})
	default:
		n1 := backend.FromInterface(t1)
		idxn1 := c.GetCoeffID(&n1)
		lLeft = append(lLeft, LinearTerm{c.getOneVariable(), idxn1})
	}

	// lOoutput
	lOoutput := LinearCombination{}
	switch t2 := i2.(type) {
	case LinearCombination:
		lOoutput = make([]LinearTerm, len(t2))
		copy(lOoutput, t2)
	case Variable:
		c.checkIsAllocated(t2)
		lOoutput = append(lOoutput, LinearTerm{t2, idxOne})
	default:
		n2 := backend.FromInterface(t2)
		idxn2 := c.GetCoeffID(&n2)
		lOoutput = append(lOoutput, LinearTerm{c.getOneVariable(), idxn2})
	}

	// right
	lRight := LinearCombination{LinearTerm{c.getOneVariable(), idxOne}}

	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}

	c.constraints = append(c.constraints, g)
}

// MustBeBoolean boolean constrains a variable
func (c *CS) MustBeBoolean(a Variable) {

	c.checkIsAllocated(a)

	if a.isBoolean {
		return
	}

	zero := big.NewInt(0)
	one := big.NewInt(1)
	minusOne := big.NewInt(-1)
	idxOne := c.GetCoeffID(one)
	idxMinusOne := c.GetCoeffID(minusOne)
	idxZero := c.GetCoeffID(zero)

	lLeft := LinearCombination{
		LinearTerm{a, idxOne},
	}
	lRight := LinearCombination{
		LinearTerm{c.getOneVariable(), idxOne},
		LinearTerm{a, idxMinusOne},
	}
	lOoutput := LinearCombination{
		LinearTerm{c.getOneVariable(), idxZero},
	}
	g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}
	c.constraints = append(c.constraints, g)
	a.isBoolean = true
}

// MustBeLessOrEqual constrains w to be less or equal than e (taken as lifted Integer values from Fr)
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
func (c *CS) MustBeLessOrEqual(w Variable, bound interface{}) {

	c.checkIsAllocated(w)

	switch b := bound.(type) {
	case Variable:
		c.checkIsAllocated(b)
		c.mustBeLessOrEqVar(w, b)
	default:
		_bound := backend.FromInterface(b)
		c.mustBeLessOrEqCst(w, _bound)
	}

}

func (c *CS) mustBeLessOrEqVar(w, bound Variable) {

	nbBits := 256

	binw := c.ToBinary(w, nbBits)
	binbound := c.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = c.Constant(1)

	zero := big.NewInt(0)
	one := big.NewInt(1)
	minusOne := big.NewInt(-1)
	idxZero := c.GetCoeffID(zero)
	idxOne := c.GetCoeffID(one)
	idxMinusOne := c.GetCoeffID(minusOne)

	for i := nbBits - 1; i >= 0; i-- {
		p1 := c.Mul(p[i+1], binw[i])
		p[i] = c.Select(binbound[i], p1, p[i+1])

		zero := c.Constant(0)
		t := c.Select(binbound[i], zero, p[i+1])
		lLeft := LinearCombination{
			LinearTerm{c.getOneVariable(), idxOne},
			LinearTerm{t, idxMinusOne},
			LinearTerm{binw[i], idxMinusOne},
		}
		lRight := LinearCombination{
			LinearTerm{binw[i], idxOne},
		}
		lOoutput := LinearCombination{
			LinearTerm{c.getOneVariable(), idxZero},
		}
		g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}
		c.constraints = append(c.constraints, g)
	}

}

func (c *CS) mustBeLessOrEqCst(w Variable, bound big.Int) {

	nbBits := 256
	nbWords := 4
	wordSize := 64

	binw := c.ToBinary(w, nbBits)
	binbound := bound.Bits()
	l := len(binbound)
	if len(binbound) < nbWords {
		for i := 0; i < nbWords-l; i++ {
			binbound = append(binbound, big.Word(0))
		}
	}
	p := make([]Variable, nbBits+1)

	var zero big.Int
	idxZero := c.GetCoeffID(&zero)
	one := big.NewInt(1)
	idxOne := c.GetCoeffID(one)
	minusOne := big.NewInt(-1)
	idxMinusOne := c.GetCoeffID(minusOne)
	p[nbBits] = c.Constant(1)
	for i := nbWords - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			b := (binbound[i] >> (wordSize - 1 - j)) & 1
			if b == 0 {
				p[(i+1)*wordSize-1-j] = p[(i+1)*wordSize-j]
				lLeft := LinearCombination{
					LinearTerm{c.getOneVariable(), idxOne},
					LinearTerm{p[(i+1)*wordSize-j], idxMinusOne},
					LinearTerm{binw[(i+1)*wordSize-1-j], idxMinusOne},
				}
				lRight := LinearCombination{LinearTerm{binw[(i+1)*wordSize-1-j], idxOne}}
				lOoutput := LinearCombination{LinearTerm{c.getOneVariable(), idxZero}}
				g := gate{lLeft, lRight, lOoutput, r1c.SingleOutput}
				c.constraints = append(c.constraints, g)

			} else {
				p[(i+1)*wordSize-1-j] = c.Mul(p[(i+1)*wordSize-j], binw[(i+1)*wordSize-1-j])
			}
		}
	}
}
