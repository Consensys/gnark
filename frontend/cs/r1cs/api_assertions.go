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

	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/internal/expr"
	"github.com/consensys/gnark/std/math/bits"
)

// AssertIsEqual adds an assertion in the constraint builder (i1 == i2)
func (builder *builder) AssertIsEqual(i1, i2 frontend.Variable) {
	c1, i1Constant := builder.constantValue(i1)
	c2, i2Constant := builder.constantValue(i2)

	if i1Constant && i2Constant {
		if c1 != c2 {
			panic("non-equal constant values")
		}
		return
	}
	// encoded 1 * i1 == i2
	r := builder.getLinearExpression(builder.toVariable(i1))
	o := builder.getLinearExpression(builder.toVariable(i2))

	cID := builder.cs.AddR1C(builder.newR1C(builder.cstOne(), r, o), builder.genericGate)

	if debug.Debug {
		debug := builder.newDebugInfo("assertIsEqual", r, " == ", o)
		builder.cs.AttachDebugInfo(debug, []int{cID})
	}
}

// AssertIsDifferent constrain i1 and i2 to be different
func (builder *builder) AssertIsDifferent(i1, i2 frontend.Variable) {
	s := builder.Sub(i1, i2).(expr.LinearExpression)
	if len(s) == 1 && s[0].Coeff.IsZero() {
		panic("AssertIsDifferent(x,x) will never be satisfied")
	}

	builder.Inverse(s)
}

// AssertIsBoolean adds an assertion in the constraint builder (v == 0 ∥ v == 1)
func (builder *builder) AssertIsBoolean(i1 frontend.Variable) {

	v := builder.toVariable(i1)

	if b, ok := builder.constantValue(v); ok {
		if !(b.IsZero() || builder.isCstOne(b)) {
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

	cID := builder.cs.AddR1C(builder.newR1C(V, _v, o), builder.genericGate)
	if debug.Debug {
		debug := builder.newDebugInfo("assertIsBoolean", V, " == (0|1)")
		builder.cs.AttachDebugInfo(debug, []int{cID})
	}
}

func (builder *builder) AssertIsCrumb(i1 frontend.Variable) {
	i1 = builder.MulAcc(builder.Mul(-3, i1), i1, i1)
	i1 = builder.MulAcc(builder.Mul(2, i1), i1, i1)
	builder.AssertIsEqual(i1, 0)
}

// AssertIsLessOrEqual adds assertion in constraint builder  (v ⩽ bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blob/main/protocol/protocol.pdf
func (builder *builder) AssertIsLessOrEqual(v frontend.Variable, bound frontend.Variable) {
	cv, vConst := builder.constantValue(v)
	cb, bConst := builder.constantValue(bound)

	// both inputs are constants
	if vConst && bConst {
		bv, bb := builder.cs.ToBigInt(cv), builder.cs.ToBigInt(cb)
		if bv.Cmp(bb) == 1 {
			panic(fmt.Sprintf("AssertIsLessOrEqual: %s > %s", bv.String(), bb.String()))
		}
	}

	// bound is constant
	if bConst {
		nbBits := builder.cs.FieldBitLen()
		vBits := bits.ToBinary(builder, v, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs())
		builder.MustBeLessOrEqCst(vBits, builder.cs.ToBigInt(cb), v)
		return
	}

	builder.mustBeLessOrEqVar(v, bound)
}

func (builder *builder) mustBeLessOrEqVar(a, bound frontend.Variable) {
	// here bound is NOT a constant,
	// but a can be either constant or a wire.

	nbBits := builder.cs.FieldBitLen()

	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(nbBits), bits.WithUnconstrainedOutputs(), bits.OmitModulusCheck())
	boundBits := bits.ToBinary(builder, bound, bits.WithNbDigits(nbBits))

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
		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// → this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too

		// (1 - t - ai) * ai == 0
		l := builder.Sub(builder.cstOne(), t, aBits[i])
		added = append(added, builder.cs.AddR1C(builder.newR1C(l, builder.Mul(aBits[i], builder.cstOne()), zero), builder.genericGate))
	}

	if debug.Debug {
		debug := builder.newDebugInfo("mustBeLessOrEq", a, " <= ", bound)
		builder.cs.AttachDebugInfo(debug, added)
	}

}

// MustBeLessOrEqCst asserts that value represented using its bit decomposition
// aBits is less or equal than constant bound. The method boolean constraints
// the bits in aBits, so the caller can provide unconstrained bits.
func (builder *builder) MustBeLessOrEqCst(aBits []frontend.Variable, bound *big.Int, aForDebug frontend.Variable) {

	nbBits := builder.cs.FieldBitLen()
	if len(aBits) > nbBits {
		panic("more input bits than field bit length")
	}
	for i := len(aBits); i < nbBits; i++ {
		aBits = append(aBits, 0)
	}

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

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

			added = append(added, builder.cs.AddR1C(builder.newR1C(l, aBits[i], builder.cstZero()), builder.genericGate))
		} else {
			builder.AssertIsBoolean(aBits[i])
		}
	}

	if debug.Debug && len(added) != 0 {
		debug := builder.newDebugInfo("mustBeLessOrEq", aForDebug, " <= ", builder.toVariable(bound))
		builder.cs.AttachDebugInfo(debug, added)
	}
}

func (builder *builder) AssertIsLessOrEqualNOp(_v frontend.Variable, bound frontend.Variable, maxBits int, omitRangeCheck ...bool) {
	cv, vConst := builder.constantValue(_v)
	cb, bConst := builder.constantValue(bound)

	// both inputs are constants
	if vConst && bConst {
		bv, bb := builder.cs.ToBigInt(cv), builder.cs.ToBigInt(cb)
		if bv.Cmp(bb) == 1 {
			panic(fmt.Sprintf("AssertIsLessOrEqual: %s > %s", bv.String(), bb.String()))
		}
	}
	omitRangeCheckFlag := false
	if len(omitRangeCheck) > 0 {
		omitRangeCheckFlag = omitRangeCheck[0]
	}

	// bound is constant
	if bConst {
		builder.MustBeLessOrEqCstNOp(_v, builder.cs.ToBigInt(cb), _v, maxBits, omitRangeCheckFlag)
		return
	}
	builder.mustBeLessOrEqVarNOp(_v, bound, maxBits, omitRangeCheckFlag)
}

func (builder *builder) mustBeLessOrEqVarNOp(v, bound frontend.Variable, maxBits int, omitRangeCheck bool) {
	c := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(maxBits)), nil)
	if !omitRangeCheck {
		// make sure v and bound are less than 2^maxBits
		bits.ToBinary(builder, v, bits.WithNbDigits(maxBits))
		bits.ToBinary(builder, bound, bits.WithNbDigits(maxBits))
	}
	
	// res := v + 2^maxBits - (bound + 1)
	// if v <= bound, res <= 2^maxBits - 1, then the max bit of res is 0
	// if v > bound, 2^maxBits <= res < 2^(maxBits + 1), then the max bit of res is 1
	res := builder.Add(v, c)
	res = builder.Sub(res, bound)
	res = builder.Sub(res, 1)
	resBits := bits.ToBinary(builder, res, bits.WithNbDigits(maxBits+1))
	builder.AssertIsEqual(resBits[maxBits], 0)
}

func (builder *builder) MustBeLessOrEqCstNOp(a frontend.Variable, bound *big.Int, aForDebug frontend.Variable, maxBits int, omitRangeCheck bool) {
	nbBits := builder.cs.FieldBitLen()
	if maxBits > nbBits {
		panic("maxBits is larger than field bit length")
	}

	aBits := bits.ToBinary(builder, a, bits.WithNbDigits(maxBits), bits.WithUnconstrainedOutputs())
	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > maxBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will always be satisfied, please check the bound is correct")
	}

	// t trailing bits in the bound
	t := 0
	for i := 0; i < maxBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	p := make([]frontend.Variable, maxBits+1)
	// p[i] == 1 → a[j] == c[j] for all j ⩾ i
	p[maxBits] = builder.cstOne()

	for i := maxBits - 1; i >= t; i-- {
		if bound.Bit(i) == 0 {
			p[i] = p[i+1]
		} else {
			p[i] = builder.Mul(p[i+1], aBits[i])
		}
	}

	for i := maxBits - 1; i >= 0; i-- {
		if bound.Bit(i) == 0 {
			// (1 - p(i+1) - ai) * ai == 0
			l := builder.Sub(1, p[i+1])
			l = builder.Sub(l, aBits[i])
			builder.cs.AddR1C(builder.newR1C(l, aBits[i], builder.cstZero()), builder.genericGate)
		} else {
			builder.AssertIsBoolean(aBits[i])
		}
	}
}