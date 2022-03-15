/*
Copyright © 2021 ConsenSys Software Inc.

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

package r1cs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (system *r1cs) AssertIsEqual(i1, i2 frontend.Variable) {
	// encoded 1 * i1 == i2
	r := system.toVariable(i1).(compiled.LinearExpression)
	o := system.toVariable(i2).(compiled.LinearExpression)

	debug := system.AddDebugInfo("assertIsEqual", r, " == ", o)

	system.addConstraint(newR1C(system.one(), r, o), debug)
}

// AssertIsDifferent constrain i1 and i2 to be different
func (system *r1cs) AssertIsDifferent(i1, i2 frontend.Variable) {
	system.Inverse(system.Sub(i1, i2))
}

// AssertIsBoolean adds an assertion in the constraint system (v == 0 ∥ v == 1)
func (system *r1cs) AssertIsBoolean(i1 frontend.Variable) {

	vars, _ := system.toVariables(i1)
	v := vars[0]

	if c, ok := system.ConstantValue(v); ok {
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}

	if system.IsBoolean(v) {
		return // compiled.LinearExpression is already constrained
	}
	system.MarkBoolean(v)

	debug := system.AddDebugInfo("assertIsBoolean", v, " == (0|1)")

	o := system.toVariable(0)

	// ensure v * (1 - v) == 0
	_v := system.Sub(1, v)
	system.addConstraint(newR1C(v, _v, o), debug)
}

// AssertIsLessOrEqual adds assertion in constraint system  (v ⩽ bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blob/main/protocol/protocol.pdf
func (system *r1cs) AssertIsLessOrEqual(_v frontend.Variable, bound frontend.Variable) {
	v, _ := system.toVariables(_v)

	switch b := bound.(type) {
	case compiled.LinearExpression:
		assertIsSet(b)
		system.mustBeLessOrEqVar(v[0], b)
	default:
		system.mustBeLessOrEqCst(v[0], utils.FromInterface(b))
	}

}

func (system *r1cs) mustBeLessOrEqVar(a, bound compiled.LinearExpression) {
	debug := system.AddDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := system.BitLen()

	aBits := bits.ToBinary(system, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
	boundBits := system.ToBinary(bound, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = system.toVariable(1)

	zero := system.toVariable(0)

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := system.Mul(p[i+1], aBits[i])
		p[i] = system.Select(boundBits[i], v, p[i+1])

		t := system.Select(boundBits[i], zero, p[i+1])

		// (1 - t - ai) * ai == 0
		var l frontend.Variable
		l = system.one()
		l = system.Sub(l, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		system.MarkBoolean(aBits[i].(compiled.LinearExpression)) // this does not create a constraint

		system.addConstraint(newR1C(l, aBits[i], zero), debug)
	}

}

func (system *r1cs) mustBeLessOrEqCst(a compiled.LinearExpression, bound big.Int) {

	nbBits := system.BitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := system.AddDebugInfo("mustBeLessOrEq", a, " <= ", system.toVariable(bound))

	// note that at this stage, we didn't boolean-constraint these new variables yet
	// (as opposed to ToBinary)
	aBits := bits.ToBinary(system, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())

	// t trailing bits in the bound
	t := 0
	for i := 0; i < nbBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	p := make([]frontend.Variable, nbBits+1)
	// p[i] == 1 → a[j] == c[j] for all j ⩾ i
	p[nbBits] = system.toVariable(1)

	for i := nbBits - 1; i >= t; i-- {
		if bound.Bit(i) == 0 {
			p[i] = p[i+1]
		} else {
			p[i] = system.Mul(p[i+1], aBits[i])
		}
	}

	for i := nbBits - 1; i >= 0; i-- {
		if bound.Bit(i) == 0 {
			// (1 - p(i+1) - ai) * ai == 0
			l := system.Sub(1, p[i+1])
			l = system.Sub(l, aBits[i])

			system.addConstraint(newR1C(l, aBits[i], system.toVariable(0)), debug)
			system.MarkBoolean(aBits[i].(compiled.LinearExpression))
		} else {
			system.AssertIsBoolean(aBits[i])
		}
	}

}
