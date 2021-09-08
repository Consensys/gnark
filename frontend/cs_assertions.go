package frontend

import (
	"math/big"
	"strings"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// AssertIsEqual adds an assertion in the constraint system (i1 == i2)
func (cs *ConstraintSystem) AssertIsEqual(i1, i2 interface{}) {

	// encoded as L * R == O
	// set L = i1
	// set R = 1
	// set O = i2

	// we don't do just "cs.Sub(i1,i2)" to allow proper logging
	debugInfo := logEntry{}

	l := cs.Constant(i1) // no constraint is recorded
	r := cs.Constant(1)  // no constraint is recorded
	o := cs.Constant(i2) // no constraint is recorded

	// build log
	var sbb strings.Builder
	sbb.WriteString("[")
	lhs := cs.buildLogEntryFromVariable(l)
	sbb.WriteString(lhs.format)
	debugInfo.toResolve = lhs.toResolve
	sbb.WriteString(" != ")
	rhs := cs.buildLogEntryFromVariable(o)
	sbb.WriteString(rhs.format)
	debugInfo.toResolve = append(debugInfo.toResolve, rhs.toResolve...)
	sbb.WriteString("]")

	// get call stack
	sbb.WriteString("error AssertIsEqual")
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	cs.addAssertion(newR1C(l, r, o), debugInfo)
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

	// ensure v * (1 - v) == 0

	_v := cs.Sub(1, v)  // no variable is recorded in the cs
	o := cs.Constant(0) // no variable is recorded in the cs

	// prepare debug info to be displayed in case the constraint is not solved
	debugInfo := logEntry{
		toResolve: nil,
	}
	var sbb strings.Builder
	sbb.WriteString("error AssertIsBoolean")
	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	cs.addAssertion(newR1C(v, _v, o), debugInfo)
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

func (cs *ConstraintSystem) mustBeLessOrEqVar(w, bound Variable) {

	// prepare debug info to be displayed in case the constraint is not solved
	dbgInfoW := cs.buildLogEntryFromVariable(w)
	dbgInfoBound := cs.buildLogEntryFromVariable(bound)
	var sbb strings.Builder
	var debugInfo logEntry
	sbb.WriteString(dbgInfoW.format)
	sbb.WriteString(" <= ")
	sbb.WriteString(dbgInfoBound.format)
	debugInfo.toResolve = make([]compiled.Term, len(dbgInfoW.toResolve)+len(dbgInfoBound.toResolve))
	copy(debugInfo.toResolve[:], dbgInfoW.toResolve)
	copy(debugInfo.toResolve[len(dbgInfoW.toResolve):], dbgInfoBound.toResolve)

	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

	const nbBits = 256

	binw := cs.ToBinary(w, nbBits)
	binbound := cs.ToBinary(bound, nbBits)

	p := make([]Variable, nbBits+1)
	p[nbBits] = cs.Constant(1)

	zero := cs.Constant(0)

	for i := nbBits - 1; i >= 0; i-- {

		p1 := cs.Mul(p[i+1], binw[i])
		p[i] = cs.Select(binbound[i], p1, p[i+1])
		t := cs.Select(binbound[i], zero, p[i+1])

		l := cs.one()
		l = cs.Sub(l, t)       // no constraint is recorded
		l = cs.Sub(l, binw[i]) // no constraint is recorded

		r := binw[i]

		o := cs.Constant(0) // no constraint is recorded

		cs.addAssertion(newR1C(l, r, o), debugInfo)
	}

}

func (cs *ConstraintSystem) mustBeLessOrEqCst(v Variable, bound big.Int) {

	// prepare debug info to be displayed in case the constraint is not solved
	dbgInfoW := cs.buildLogEntryFromVariable(v)
	var sbb strings.Builder
	var debugInfo logEntry
	sbb.WriteString(dbgInfoW.format)
	sbb.WriteString(" <= ")
	sbb.WriteString(bound.String())

	debugInfo.toResolve = dbgInfoW.toResolve

	stack := getCallStack()
	for i := 0; i < len(stack); i++ {
		sbb.WriteByte('\n')
		sbb.WriteString(stack[i])
	}
	debugInfo.format = sbb.String()

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
				cs.addAssertion(newR1C(l, r, o), debugInfo)

			} else {
				p[(i+1)*wordSize-1-j] = cs.Mul(p[(i+1)*wordSize-j], vBits[(i+1)*wordSize-1-j])
			}
		}
	}
}
