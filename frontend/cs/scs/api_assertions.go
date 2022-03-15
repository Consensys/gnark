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

package scs

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual fails if i1 != i2
func (system *scs) AssertIsEqual(i1, i2 frontend.Variable) {

	c1, i1Constant := system.ConstantValue(i1)
	c2, i2Constant := system.ConstantValue(i2)

	if i1Constant && i2Constant {
		if c1.Cmp(c2) != 0 {
			panic("i1, i2 should be equal")
		}
		return
	}
	if i1Constant {
		i1, i2 = i2, i1
		i2Constant = i1Constant
		c2 = c1
	}
	if i2Constant {
		l := i1.(compiled.Term)
		lc, _, _ := l.Unpack()
		k := c2
		debug := system.AddDebugInfo("assertIsEqual", l, "+", i2, " == 0")
		k.Neg(k)
		_k := system.st.CoeffID(k)
		system.addPlonkConstraint(l, system.zero(), system.zero(), lc, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, _k, debug)
		return
	}
	l := i1.(compiled.Term)
	r := system.Neg(i2).(compiled.Term)
	lc, _, _ := l.Unpack()
	rc, _, _ := r.Unpack()

	debug := system.AddDebugInfo("assertIsEqual", l, " + ", r, " == 0")
	system.addPlonkConstraint(l, r, system.zero(), lc, rc, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
}

// AssertIsDifferent fails if i1 == i2
func (system *scs) AssertIsDifferent(i1, i2 frontend.Variable) {
	system.Inverse(system.Sub(i1, i2))
}

// AssertIsBoolean fails if v != 0 ∥ v != 1
func (system *scs) AssertIsBoolean(i1 frontend.Variable) {
	if c, ok := system.ConstantValue(i1); ok {
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}
	t := i1.(compiled.Term)
	if system.IsBoolean(t) {
		return
	}
	system.MarkBoolean(t)
	system.mtBooleans[int(t)] = struct{}{}
	debug := system.AddDebugInfo("assertIsBoolean", t, " == (0|1)")
	cID, _, _ := t.Unpack()
	var mCoef big.Int
	mCoef.Neg(&system.st.Coeffs[cID])
	mcID := system.st.CoeffID(&mCoef)
	system.addPlonkConstraint(t, t, system.zero(), cID, compiled.CoeffIdZero, mcID, cID, compiled.CoeffIdZero, compiled.CoeffIdZero, debug)
}

// AssertIsLessOrEqual fails if  v > bound
func (system *scs) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	switch b := bound.(type) {
	case compiled.Term:
		system.mustBeLessOrEqVar(v.(compiled.Term), b)
	default:
		system.mustBeLessOrEqCst(v.(compiled.Term), utils.FromInterface(b))
	}
}

func (system *scs) mustBeLessOrEqVar(a compiled.Term, bound compiled.Term) {

	debug := system.AddDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := system.BitLen()

	aBits := bits.ToBinary(system, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
	boundBits := system.ToBinary(bound, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = 1

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := system.Mul(p[i+1], aBits[i])
		p[i] = system.Select(boundBits[i], v, p[i+1])

		t := system.Select(boundBits[i], 0, p[i+1])

		// (1 - t - ai) * ai == 0
		l := system.Sub(1, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		system.MarkBoolean(aBits[i].(compiled.Term)) // this does not create a constraint

		system.addPlonkConstraint(
			l.(compiled.Term),
			aBits[i].(compiled.Term),
			system.zero(),
			compiled.CoeffIdZero,
			compiled.CoeffIdZero,
			compiled.CoeffIdOne,
			compiled.CoeffIdOne,
			compiled.CoeffIdZero,
			compiled.CoeffIdZero, debug)
	}

}

func (system *scs) mustBeLessOrEqCst(a compiled.Term, bound big.Int) {

	nbBits := system.BitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := system.AddDebugInfo("mustBeLessOrEq", a, " <= ", bound)

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
	p[nbBits] = 1

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
			l := system.Sub(1, p[i+1], aBits[i]).(compiled.Term)
			//l = system.Sub(l, ).(compiled.Term)

			system.addPlonkConstraint(
				l,
				aBits[i].(compiled.Term),
				system.zero(),
				compiled.CoeffIdZero,
				compiled.CoeffIdZero,
				compiled.CoeffIdOne,
				compiled.CoeffIdOne,
				compiled.CoeffIdZero,
				compiled.CoeffIdZero,
				debug)
			// system.markBoolean(aBits[i].(compiled.Term))
		} else {
			system.AssertIsBoolean(aBits[i])
		}
	}

}
