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

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual fails if i1 != i2
func (builder *scs) AssertIsEqual(i1, i2 frontend.Variable) {

	c1, i1Constant := builder.ConstantValue(i1)
	c2, i2Constant := builder.ConstantValue(i2)

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
		l := i1.(expr.TermToRefactor)
		lc, _ := l.Unpack()
		k := c2
		debug := builder.newDebugInfo("assertIsEqual", l, "+", i2, " == 0")
		k.Neg(k)
		_k := builder.st.CoeffID(k)
		builder.addPlonkConstraint(l, builder.zero(), builder.zero(), lc, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, _k, debug)
		return
	}
	l := i1.(expr.TermToRefactor)
	r := builder.Neg(i2).(expr.TermToRefactor)
	lc, _ := l.Unpack()
	rc, _ := r.Unpack()

	debug := builder.newDebugInfo("assertIsEqual", l, " + ", r, " == 0")
	builder.addPlonkConstraint(l, r, builder.zero(), lc, rc, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdZero, debug)
}

// AssertIsDifferent fails if i1 == i2
func (builder *scs) AssertIsDifferent(i1, i2 frontend.Variable) {
	builder.Inverse(builder.Sub(i1, i2))
}

// AssertIsBoolean fails if v != 0 ∥ v != 1
func (builder *scs) AssertIsBoolean(i1 frontend.Variable) {
	if c, ok := builder.ConstantValue(i1); ok {
		if !(c.IsUint64() && (c.Uint64() == 0 || c.Uint64() == 1)) {
			panic(fmt.Sprintf("assertIsBoolean failed: constant(%s)", c.String()))
		}
		return
	}
	t := i1.(expr.TermToRefactor)
	if builder.IsBoolean(t) {
		return
	}
	builder.MarkBoolean(t)
	builder.mtBooleans[int(t.CID)|t.VID<<32] = struct{}{} // TODO @gbotrel smelly fix me
	debug := builder.newDebugInfo("assertIsBoolean", t, " == (0|1)")
	cID, _ := t.Unpack()
	var mCoef big.Int
	mCoef.Neg(&builder.st.Coeffs[cID])
	mcID := builder.st.CoeffID(&mCoef)
	builder.addPlonkConstraint(t, t, builder.zero(), cID, constraint.CoeffIdZero, mcID, cID, constraint.CoeffIdZero, constraint.CoeffIdZero, debug)
}

// AssertIsLessOrEqual fails if  v > bound
func (builder *scs) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	switch b := bound.(type) {
	case expr.TermToRefactor:
		builder.mustBeLessOrEqVar(v.(expr.TermToRefactor), b)
	default:
		builder.mustBeLessOrEqCst(v.(expr.TermToRefactor), utils.FromInterface(b))
	}
}

func (builder *scs) mustBeLessOrEqVar(a expr.TermToRefactor, bound expr.TermToRefactor) {

	debug := builder.newDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := builder.cs.FieldBitLen()

	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
	boundBits := builder.ToBinary(bound, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = 1

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := builder.Mul(p[i+1], aBits[i])
		p[i] = builder.Select(boundBits[i], v, p[i+1])

		t := builder.Select(boundBits[i], 0, p[i+1])

		// (1 - t - ai) * ai == 0
		l := builder.Sub(1, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		builder.MarkBoolean(aBits[i].(expr.TermToRefactor)) // this does not create a constraint

		builder.addPlonkConstraint(l.(expr.TermToRefactor), aBits[i].(expr.TermToRefactor), builder.zero(), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero, constraint.CoeffIdZero, debug)
	}

}

func (builder *scs) mustBeLessOrEqCst(a expr.TermToRefactor, bound big.Int) {

	nbBits := builder.cs.FieldBitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := builder.newDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	// note that at this stage, we didn't boolean-constraint these new variables yet
	// (as opposed to ToBinary)
	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())

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
			p[i] = builder.Mul(p[i+1], aBits[i])
		}
	}

	for i := nbBits - 1; i >= 0; i-- {

		if bound.Bit(i) == 0 {
			// (1 - p(i+1) - ai) * ai == 0
			l := builder.Sub(1, p[i+1], aBits[i]).(expr.TermToRefactor)
			//l = builder.Sub(l, ).(term)

			builder.addPlonkConstraint(l, aBits[i].(expr.TermToRefactor), builder.zero(), constraint.CoeffIdZero, constraint.CoeffIdZero, constraint.CoeffIdOne, constraint.CoeffIdOne, constraint.CoeffIdZero, constraint.CoeffIdZero, debug)
			// builder.markBoolean(aBits[i].(term))
		} else {
			builder.AssertIsBoolean(aBits[i])
		}
	}

}
