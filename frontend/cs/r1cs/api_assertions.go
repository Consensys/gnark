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
	"math/big"

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual adds an assertion in the constraint builder (i1 == i2)
func (builder *builder) AssertIsEqual(i1, i2 frontend.Variable) {
	// encoded 1 * i1 == i2
	r := builder.getLinearExpression(builder.toVariable(i1))
	o := builder.getLinearExpression(builder.toVariable(i2))

	debug := builder.newDebugInfo("assertIsEqual", r, " == ", o)

	builder.cs.AddConstraint(builder.newR1C(builder.cstOne(), r, o), debug)
}

// AssertIsDifferent constrain i1 and i2 to be different
func (builder *builder) AssertIsDifferent(i1, i2 frontend.Variable) {
	builder.Inverse(builder.Sub(i1, i2))
}

// AssertIsBoolean adds an assertion in the constraint builder (v == 0 ∥ v == 1)
func (builder *builder) AssertIsBoolean(i1 frontend.Variable) {

	v := builder.toVariable(i1)

	if b, ok := builder.constantValue(v); ok {
		if !(builder.isCstZero(&b) || builder.isCstOne(&b)) {
			panic("assertIsBoolean failed: constant is not 0 or 1") // TODO @gbotrel print
		}
		return
	}

	if builder.IsBoolean(v) {
		return // linearExpression is already constrained
	}
	builder.MarkBoolean(v)

	// ensure v * (1 - v) == 0
	_v := builder.Sub(builder.cstOne(), v)

	o := builder.cstZero()

	V := builder.getLinearExpression(v)

	if debug.Debug {
		debug := builder.newDebugInfo("assertIsBoolean", V, " == (0|1)")
		builder.cs.AddConstraint(builder.newR1C(V, _v, o), debug)
	} else {
		builder.cs.AddConstraint(builder.newR1C(V, _v, o))
	}
}

// AssertIsLessOrEqual adds assertion in constraint builder  (v ⩽ bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blob/main/protocol/protocol.pdf
func (builder *builder) AssertIsLessOrEqual(_v frontend.Variable, bound frontend.Variable) {
	v := builder.toVariable(_v)

	if b, ok := bound.(expr.LinearExpression); ok {
		assertIsSet(b)
		builder.mustBeLessOrEqVar(v, b)
	} else {
		builder.mustBeLessOrEqCst(v, utils.FromInterface(bound))
	}
}

func (builder *builder) mustBeLessOrEqVar(a, bound expr.LinearExpression) {
	debug := builder.newDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	nbBits := builder.cs.FieldBitLen()

	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
	boundBits := builder.ToBinary(bound, nbBits)

	// constraint added
	added := make([]int, 0, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	p[nbBits] = builder.cstOne()

	zero := builder.cstZero()

	for i := nbBits - 1; i >= 0; i-- {

		// if bound[i] == 0
		// 		p[i] = p[i+1]
		//		t = p[i+1]
		// else
		// 		p[i] = p[i+1] * a[i]
		//		t = 0
		v := builder.Mul(p[i+1], aBits[i])
		p[i] = builder.Select(boundBits[i], v, p[i+1])

		t := builder.Select(boundBits[i], zero, p[i+1])

		// (1 - t - ai) * ai == 0
		var l frontend.Variable
		l = builder.cstOne()
		l = builder.Sub(l, t, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too
		builder.MarkBoolean(aBits[i].(expr.LinearExpression)) // this does not create a constraint

		added = append(added, builder.cs.AddConstraint(builder.newR1C(l, aBits[i], zero)))
	}

	builder.cs.AttachDebugInfo(debug, added)

}

func (builder *builder) mustBeLessOrEqCst(a expr.LinearExpression, bound big.Int) {

	nbBits := builder.cs.FieldBitLen()

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := builder.newDebugInfo("mustBeLessOrEq", a, " <= ", builder.toVariable(bound))

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

	// constraint added
	added := make([]int, 0, nbBits)

	p := make([]frontend.Variable, nbBits+1)
	// p[i] == 1 → a[j] == c[j] for all j ⩾ i
	p[nbBits] = builder.cstOne()

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
			l := builder.Sub(1, p[i+1])
			l = builder.Sub(l, aBits[i])

			added = append(added, builder.cs.AddConstraint(builder.newR1C(l, aBits[i], builder.cstZero())))
			builder.MarkBoolean(aBits[i].(expr.LinearExpression))
		} else {
			builder.AssertIsBoolean(aBits[i])
		}
	}

	if len(added) != 0 {
		builder.cs.AttachDebugInfo(debug, added)
	}
}
