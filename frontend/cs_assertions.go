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

package frontend

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (cs *constraintSystem) AssertIsEqual(i1, i2 interface{}) {
	// encoded 1 * i1 == i2
	r := cs.constant(i1).(compiled.Variable)
	o := cs.constant(i2).(compiled.Variable)

	debug := cs.addDebugInfo("assertIsEqual", r, " == ", o)

	cs.addConstraint(newR1C(cs.one(), r, o), debug)
}

// AssertIsDifferent constrain i1 and i2 to be different
func (cs *constraintSystem) AssertIsDifferent(i1, i2 interface{}) {
	cs.Inverse(cs.Sub(i1, i2))
}

// AssertIsBoolean adds an assertion in the constraint system (v == 0 || v == 1)
func (cs *constraintSystem) AssertIsBoolean(i1 interface{}) {

	vars, _ := cs.toVariables(i1)
	v := vars[0]

	if *v.IsBoolean {
		return // compiled.Variable is already constrained
	}
	*v.IsBoolean = true

	if v.IsConstant() {
		c := cs.constantValue(v)
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}

	debug := cs.addDebugInfo("assertIsBoolean", v, " == (0|1)")

	o := cs.constant(0)

	// We always have len(v.LinExp) == 1 when the backend is plonk, so it simplifies the conversion
	// to sparse r1cs.
	if cs.backendID == backend.PLONK {
		one := cs.one()
		_v := cs.Neg(v).(compiled.Variable)
		r := compiled.Variable{LinExp: []compiled.Term{one.LinExp[0], _v.LinExp[0]}}

		cs.addConstraint(newR1C(v, r, o), debug)
		return
	}

	// ensure v * (1 - v) == 0
	_v := cs.Sub(1, v)
	cs.addConstraint(newR1C(v, _v, o), debug)
}

// AssertIsLessOrEqual adds assertion in constraint system  (v <= bound)
//
// bound can be a constant or a compiled.Variable
//
// derived from:
// https://github.com/zcash/zips/blob/main/protocol/protocol.pdf
func (cs *constraintSystem) AssertIsLessOrEqual(_v Variable, bound interface{}) {
	v, _ := cs.toVariables(_v)

	switch b := bound.(type) {
	case compiled.Variable:
		b.AssertIsSet()
		cs.mustBeLessOrEqVar(v[0], b)
	default:
		cs.mustBeLessOrEqCst(v[0], FromInterface(b))
	}

}

func (cs *constraintSystem) mustBeLessOrEqVar(a, bound compiled.Variable) {
	debug := cs.addDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := cs.bitLen()

	aBits := cs.toBinary(a, nbBits, true)
	boundBits := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.constant(1)

	zero := cs.constant(0)

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := cs.Mul(p[i+1], aBits[i])
		p[i] = cs.Select(boundBits[i], v, p[i+1])

		t := cs.Select(boundBits[i], zero, p[i+1])

		// (1 - t - ai) * ai == 0
		var l Variable
		l = cs.one()
		l = cs.Sub(l, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// --> this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		cs.markBoolean(aBits[i].(compiled.Variable)) // this does not create a constraint

		cs.addConstraint(newR1C(l, aBits[i], zero), debug)
	}

}

func (cs *constraintSystem) mustBeLessOrEqCst(a compiled.Variable, bound big.Int) {
	nbBits := cs.bitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := cs.addDebugInfo("mustBeLessOrEq", a, " <= ", cs.constant(bound))

	// note that at this stage, we didn't boolean-constraint these new compiled.Variables yet
	// (as opposed to ToBinary)
	aBits := cs.toBinary(a, nbBits, true)

	// t trailing bits in the bound
	t := 0
	for i := 0; i < nbBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	p := make([]Variable, nbBits+1)
	// p[i] == 1 --> a[j] == c[j] for all j >= i
	p[nbBits] = cs.constant(1)

	for i := nbBits - 1; i >= t; i-- {
		if bound.Bit(i) == 0 {
			p[i] = p[i+1]
		} else {
			p[i] = cs.Mul(p[i+1], aBits[i])
		}
	}

	for i := nbBits - 1; i >= 0; i-- {
		if bound.Bit(i) == 0 {
			// (1 - p(i+1) - ai) * ai == 0
			var l Variable
			l = cs.one()
			l = cs.Sub(l, p[i+1], aBits[i])

			cs.addConstraint(newR1C(l, aBits[i], cs.constant(0)), debug)
			cs.markBoolean(aBits[i].(compiled.Variable))
		} else {
			cs.AssertIsBoolean(aBits[i])
		}
	}

}
