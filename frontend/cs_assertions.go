package frontend

import (
	"math/big"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (cs *ConstraintSystem) AssertIsEqual(i1, i2 interface{}) {
	// encoded i1 * 1 == i2
	// TODO do cs.Sub(i1,i2) == 0 ?

	l := cs.Constant(i1)
	o := cs.Constant(i2)

	if len(l.linExp) > len(o.linExp) {
		l, o = o, l // maximize number of zeroes in r1cs.A
	}

	debug := cs.addDebugInfo("assertIsEqual", l, " == ", o)

	cs.addConstraint(newR1C(l, cs.one(), o), debug)
}

// AssertIsDifferent constrain i1 and i2 to be different
func (cs *ConstraintSystem) AssertIsDifferent(i1, i2 interface{}) {
	cs.Inverse(cs.Sub(i1, i2))
}

// AssertIsBoolean adds an assertion in the constraint system (v == 0 || v == 1)
func (cs *ConstraintSystem) AssertIsBoolean(v Variable) {
	v.assertIsSet()
	if v.visibility == compiled.Unset {
		// we need to create a new wire here.
		vv := cs.newVirtualVariable()
		vv.linExp = v.linExp
		v = vv
	}

	if !cs.markBoolean(v) {
		return // variable is already constrained
	}
	debug := cs.addDebugInfo("assertIsBoolean", v, " == (0|1)")

	// ensure v * (1 - v) == 0
	_v := cs.Sub(1, v)
	o := cs.Constant(0)
	cs.addConstraint(newR1C(v, _v, o), debug)
}

// AssertIsLessOrEqual adds assertion in constraint system  (v <= bound)
//
// bound can be a constant or a Variable
//
// derived from:
// https://github.com/zcash/zips/blob/main/protocol/protocol.pdf
func (cs *ConstraintSystem) AssertIsLessOrEqual(v Variable, bound interface{}) {

	v.assertIsSet()

	switch b := bound.(type) {
	case Variable:
		b.assertIsSet()
		cs.mustBeLessOrEqVar(v, b)
	default:
		cs.mustBeLessOrEqCst(v, FromInterface(b))
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqVar(a, bound Variable) {
	debug := cs.addDebugInfo("mustBeLessOrEq", a, " <= ", bound)

	const nbBits = 256

	aBits := cs.toBinaryUnsafe(a, nbBits)
	boundBits := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.Constant(1)

	zero := cs.Constant(0)

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
		l := cs.one()
		l = cs.Sub(l, t)
		l = cs.Sub(l, aBits[i])

		// note if bound[i] == 1, this constraint is (1 - ai) * ai == 0
		// --> this is a boolean constraint
		// if bound[i] == 0, t must be 0 or 1, thus ai must be 0 or 1 too

		cs.addConstraint(newR1C(l, aBits[i], zero), debug)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(a Variable, bound big.Int) {
	const nbBits = 256

	// ensure the bound is positive, it's bit-len doesn't matter
	if bound.Sign() == -1 {
		panic("AssertIsLessOrEqual: bound must be positive")
	}
	if bound.BitLen() > nbBits {
		panic("AssertIsLessOrEqual: bound is too large, constraint will never be satisfied")
	}

	// debug info
	debug := cs.addDebugInfo("mustBeLessOrEq", a, " <= ", cs.Constant(bound))

	// note that at this stage, we didn't boolean-constraint these new variables yet
	// (as opposed to ToBinary)
	aBits := cs.toBinaryUnsafe(a, nbBits)

	// t trailing bits in the bound
	t := 0
	for i := 0; i < nbBits; i++ {
		if bound.Bit(i) == 0 {
			break
		}
		t++
	}

	var p [nbBits + 1]Variable
	p[nbBits] = cs.Constant(1)

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
			l := cs.one()
			l = cs.Sub(l, p[i+1])
			l = cs.Sub(l, aBits[i])

			cs.addConstraint(newR1C(l, aBits[i], cs.Constant(0)), debug)
			cs.markBoolean(aBits[i])
		} else {
			cs.AssertIsBoolean(aBits[i])
		}
	}

}
