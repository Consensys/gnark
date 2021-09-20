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
// https://github.com/zcash/zips/blOoutputb/master/protocol/protocol.pdf
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

func (cs *ConstraintSystem) mustBeLessOrEqVar(v, bound Variable) {
	debug := cs.addDebugInfo("mustBeLessOrEq", v, " <= ", bound)

	// TODO nbBits shouldn't be here.
	const nbBits = 256

	wBits := cs.ToBinary(v, nbBits)
	boundBits := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.Constant(1)

	zero := cs.Constant(0)

	for i := nbBits - 1; i >= 0; i-- {

		p1 := cs.Mul(p[i+1], wBits[i])
		p[i] = cs.Select(boundBits[i], p1, p[i+1])
		t := cs.Select(boundBits[i], zero, p[i+1])

		l := cs.one()
		l = cs.Sub(l, t)        // no constraint is recorded
		l = cs.Sub(l, wBits[i]) // no constraint is recorded

		r := wBits[i]

		o := cs.Constant(0) // no constraint is recorded

		cs.addConstraint(newR1C(l, r, o), debug)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(v Variable, bound big.Int) {
	debug := cs.addDebugInfo("mustBeLessOrEq", v, " <= ", cs.Constant(bound))

	// TODO store those constant elsewhere (for the moment they don't depend on the base curve, but that might change)
	const nbBits = 256
	const nbWords = 4
	const wordSize = 64

	vBits := cs.ToBinary(v, nbBits)
	boundBits := bound.Bits()
	l := len(boundBits)
	if len(boundBits) < nbWords {
		for i := 0; i < nbWords-l; i++ {
			boundBits = append(boundBits, big.Word(0))
		}
	}

	p := make([]Variable, nbBits+1)

	p[nbBits] = cs.Constant(1)
	for i := nbWords - 1; i >= 0; i-- {
		for j := 0; j < wordSize; j++ {
			b := (boundBits[i] >> (wordSize - 1 - j)) & 1
			if b == 0 {
				p[(i+1)*wordSize-1-j] = p[(i+1)*wordSize-j]

				l := cs.one()
				l = cs.Sub(l, p[(i+1)*wordSize-j])       // no constraint is recorded
				l = cs.Sub(l, vBits[(i+1)*wordSize-1-j]) // no constraint is recorded

				r := vBits[(i+1)*wordSize-1-j]
				o := cs.Constant(0)

				cs.addConstraint(newR1C(l, r, o), debug)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}
