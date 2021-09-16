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
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

// sparseR1CS extends the ConstraintSystem
// alongside with some intermediate data structures needed to convert from
// ConstraintSystem representataion to SparseR1CS
type sparseR1CS struct {
	*ConstraintSystem

	ccs compiled.SparseR1CS

	// we start our internal variables counting after the ConstraintSystem index
	// when we process R1C linear expressions
	// this will create new internal wires in the SparseR1CS
	// we add these new wires starting at position len(previousInternalWires)
	scsInternalVariables int

	// keep track of solved variables to split the R1C in a sensible manner
	// and guarantee that the solver will encounter at most one unsolved wire
	// per SparseR1C
	solvedVariables []bool

	currentR1CDebugID int // mark the current R1C debugID
}

func (cs *ConstraintSystem) toSparseR1CS(curveID ecc.ID) (CompiledConstraintSystem, error) {

	res := sparseR1CS{
		ConstraintSystem: cs,
		ccs: compiled.SparseR1CS{
			NbPublicVariables:   len(cs.public.variables) - 1, // the ONE_WIRE is discarded as it is not used in PLONK
			NbSecretVariables:   len(cs.secret.variables),
			NbInternalVariables: len(cs.internal.variables),
			Constraints:         make([]compiled.SparseR1C, 0, len(cs.constraints)),
			Logs:                make([]compiled.LogEntry, len(cs.logs)),
			DebugInfo:           make([]compiled.LogEntry, len(cs.debugInfo)),
			Hints:               make([]compiled.Hint, len(cs.hints)),
			MDebug:              make(map[int]int),
		},
		solvedVariables:      make([]bool, len(cs.internal.variables), len(cs.internal.variables)*2),
		scsInternalVariables: len(cs.internal.variables),
		currentR1CDebugID:    -1,
	}

	// note: verbose, but we offset the IDs of the wires where they appear, that is,
	// in the logs, debug info, constraints and hints
	// since we don't use pointers but Terms (uint64), we need to potentially offset
	// the same wireID multiple times.
	copy(res.ccs.Hints, cs.hints)

	copy(res.ccs.Logs, cs.logs)
	copy(res.ccs.DebugInfo, cs.debugInfo)

	// TODO @gbotrel we may not want to do that as it may hide some bugs
	// if there is a R1C with several unsolved wires, wether they are hint wires or not
	// will be problematic at solving time
	for i := 0; i < len(cs.hints); i++ {
		res.solvedVariables[cs.hints[i].WireID] = true
	}

	// convert the R1C to SparseR1C
	// in particular, all linear expressions that appear in the R1C
	// will be split in multiple constraints in the SparseR1C
	for i := 0; i < len(cs.constraints); i++ {
		if dID, ok := cs.mDebug[i]; ok {
			res.currentR1CDebugID = dID
		} else {
			res.currentR1CDebugID = -1
		}
		res.r1cToSparseR1C(cs.constraints[i])
	}

	// shift variable ID
	// we want publicWires | privateWires | internalWires
	shiftVID := func(oldID int, visibility compiled.Visibility) int {
		switch visibility {
		case compiled.Internal:
			return oldID + res.ccs.NbPublicVariables + res.ccs.NbSecretVariables
		case compiled.Public:
			return oldID - 1
		case compiled.Secret:
			return oldID + res.ccs.NbPublicVariables
		default:
			return oldID
		}
	}

	offsetTermID := func(t *compiled.Term) {
		if *t == 0 {
			// in a PLONK constraint, not all terms are necessarily set,
			// the terms which are not set are equal to zero. We just
			// need to skip them.
			return
		}
		_, vID, visibility := t.Unpack()
		if vID == 0 && visibility == compiled.Public {
			// this would not happen in a plonk constraint as the constant term has been popped out
			// however it may happen in the logs or the hints that contains
			// terms associated with the ONE wire
			// workaround; we set the visibility to Virtual so that the solver recognizes that as a constant
			t.SetVariableVisibility(compiled.Virtual)
			return
		}
		t.SetVariableID(shiftVID(vID, visibility))
	}

	// offset the IDs of all constraints so that the variables are
	// numbered like this: [publicVariables | secretVariables | internalVariables ]
	for i := 0; i < len(res.ccs.Constraints); i++ {
		r1c := &res.ccs.Constraints[i]
		// offset each term in the constraint
		offsetTermID(&r1c.L)
		offsetTermID(&r1c.R)
		offsetTermID(&r1c.O)
		offsetTermID(&r1c.M[0])
		offsetTermID(&r1c.M[1])
	}

	// offset IDs in the logs
	// we need to offset the ids in logs & debugInfo
	for i := 0; i < len(res.ccs.Logs); i++ {
		for j := 0; j < len(res.ccs.Logs[i].ToResolve); j++ {
			offsetTermID(&res.ccs.Logs[i].ToResolve[j])
		}
	}
	for i := 0; i < len(res.ccs.DebugInfo); i++ {
		for j := 0; j < len(res.ccs.DebugInfo[i].ToResolve); j++ {
			offsetTermID(&res.ccs.DebugInfo[i].ToResolve[j])
		}
	}

	// we need to offset the ids in the hints
	for i := 0; i < len(res.ccs.Hints); i++ {
		res.ccs.Hints[i].WireID = shiftVID(res.ccs.Hints[i].WireID, compiled.Internal)
		for j := 0; j < len(res.ccs.Hints[i].Inputs); j++ {
			l := res.ccs.Hints[i].Inputs[j]
			for k := 0; k < len(l); k++ {
				offsetTermID(&l[k])
			}
		}
	}

	res.ccs.MHints = make(map[int]int, len(res.ccs.Hints))
	for i := 0; i < len(res.ccs.Hints); i++ {
		res.ccs.MHints[res.ccs.Hints[i].WireID] = i
	}

	// update number of internal variables with new wires created
	// while processing R1C -> SparseR1C
	res.ccs.NbInternalVariables = res.scsInternalVariables

	switch curveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	default:
		panic("unknown curveID")
	}

}

// findUnsolvedVariable returns the variable to solve in the r1c. The variables
// which are not internal are considered solved, otherwise the solvedVariables
// slice hold the record of which variables have been solved.
func findUnsolvedVariable(r1c compiled.R1C, solvedVariables []bool) (int, int) {
	// find the variable to solve among L,R,O. pos=0,1,2 corresponds to left,right,o.
	for i := 0; i < len(r1c.L); i++ {
		_, vID, visibility := r1c.L[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[vID] {
			return 0, vID
		}
	}
	for i := 0; i < len(r1c.R); i++ {
		_, vID, visibility := r1c.R[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[vID] {
			return 1, vID
		}
	}
	for i := 0; i < len(r1c.O); i++ {
		_, vID, visibility := r1c.O[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[vID] {
			return 2, vID
		}
	}
	return -1, -1
}

// returns l with the term (id+coef) holding the id-th variable removed
// No side effects on l.
func popInternalVariable(l compiled.LinearExpression, id int) (compiled.LinearExpression, compiled.Term) {
	var t compiled.Term
	_l := make([]compiled.Term, len(l)-1)
	c := 0
	for i := 0; i < len(l); i++ {
		v := l[i]
		if v.VariableVisibility() == compiled.Internal && v.VariableID() == id {
			t = v
			continue
		}
		_l[c] = v
		c++
	}
	return _l, t
}

// pops the constant associated to the one_wire in the cs, which will become
// a constant in a PLONK constraint.
//
// Returns the reduced linear expression and the ID of the coeff corresponding to the constant term (in cs.coeffs).
// If there is no constant term, the id is 0 (the 0-th entry is reserved for this purpose).
//
// ex: if l = <expr> + k1*ONE_WIRE the function returns <expr>, k1.
func (scs *sparseR1CS) popConstantTerm(l compiled.LinearExpression) (compiled.LinearExpression, big.Int) {

	const idOneWire = 0

	for i := 0; i < len(l); i++ {
		if l[i].VariableID() == idOneWire && l[i].VariableVisibility() == compiled.Public {
			lCopy := make(compiled.LinearExpression, len(l)-1)
			copy(lCopy, l[:i])
			copy(lCopy[i:], l[i+1:])
			return lCopy, scs.coeffs[l[i].CoeffID()]
		}
	}

	return l, big.Int{}
}

// newTerm creates a new term =1*new_variable and records it in the scs
// if idCS is set, uses it as variable id and does not increment the number
// of new internal variables created
func (scs *sparseR1CS) newTerm(coeff *big.Int, idCS ...int) compiled.Term {
	var vID int
	if len(idCS) > 0 {
		vID = idCS[0]
	} else {
		vID = scs.scsInternalVariables
		scs.scsInternalVariables++
	}
	// each time we create a new term, we created and added a constraint
	// and as we allow only one unsolved wire per constraint
	// we can mark it as solved such that if it appears in following constraints
	// we don't consider it "unsolved"
	if vID >= len(scs.solvedVariables) {
		if vID < cap(scs.solvedVariables) {
			scs.solvedVariables = scs.solvedVariables[:vID+1]
		} else {
			newSlice := make([]bool, vID+1)
			copy(newSlice, scs.solvedVariables)
			scs.solvedVariables = newSlice
		}
	}
	scs.solvedVariables[vID] = true

	return compiled.Pack(vID, scs.coeffID(coeff), compiled.Internal)
}

// addConstraint records a plonk constraint in the ccs
// The function ensures that all variables ID are set, even
// if the corresponding coefficients are 0.
// A plonk constraint will always look like this:
// L+R+L.R+O+K = 0
func (scs *sparseR1CS) addConstraint(c compiled.SparseR1C) {
	// ensure wire(L) == wire(M[0]) && wire(R) == wire(M[1])
	if c.L == 0 {
		c.L.SetVariableID(c.M[0].VariableID())
	}
	if c.R == 0 {
		c.R.SetVariableID(c.M[1].VariableID())
	}
	if c.M[0] == 0 {
		c.M[0].SetVariableID(c.L.VariableID())
	}
	if c.M[1] == 0 {
		c.M[1].SetVariableID(c.R.VariableID())
	}
	if scs.currentR1CDebugID != -1 {
		scs.ccs.MDebug[len(scs.ccs.Constraints)] = scs.currentR1CDebugID
	}
	scs.ccs.Constraints = append(scs.ccs.Constraints, c)
}

// if t=a*variable, it returns -a*variable
func (scs *sparseR1CS) negate(t compiled.Term) compiled.Term {
	// non existing term are zero, if we negate it it's no
	// longer zero and checks to see if a variable exist will
	// fail (ex: in r1cToPlonkConstraint we might call negate
	// on non existing variables, when split is called with
	// le = nil)
	if t == 0 {
		return t
	}
	cID := t.CoeffID()
	switch cID {
	case compiled.CoeffIdMinusOne:
		t.SetCoeffID(compiled.CoeffIdOne)
	case compiled.CoeffIdZero:
		// do nothing.
	case compiled.CoeffIdOne:
		t.SetCoeffID(compiled.CoeffIdMinusOne)
	default:
		coeff := bigIntPool.Get().(*big.Int)
		defer bigIntPool.Put(coeff)

		coeff.Neg(&scs.coeffs[t.CoeffID()])
		t.SetCoeffID(scs.coeffID(coeff))
	}

	return t
}

// multiplies t by the provided coefficient
func (scs *sparseR1CS) multiply(t compiled.Term, c *big.Int) compiled.Term {
	// fast path
	if c.IsInt64() {
		v := c.Int64()
		switch v {
		case 0:
			t.SetCoeffID(compiled.CoeffIdZero)
			return t
		case 1:
			return t
		case -1:

			switch t.CoeffID() {
			case compiled.CoeffIdZero:
				return t
			case compiled.CoeffIdOne:
				t.SetCoeffID(compiled.CoeffIdMinusOne)
				return t
			case compiled.CoeffIdMinusOne:
				t.SetCoeffID(compiled.CoeffIdOne)
				return t
			}
		}
	}
	coeff := bigIntPool.Get().(*big.Int)
	coeff.Mul(&scs.coeffs[t.CoeffID()], c)
	t.SetCoeffID(scs.coeffID(coeff))
	bigIntPool.Put(coeff)
	return t
}

// split splits a linear expression to plonk constraints
// ex: le = aiwi is split into PLONK constraints (using sums)
// of 3 terms) like this:
// w0' = a0w0+a1w1
// w1' = w0' + a2w2
// ..
// wn' = wn-1'+an-2wn-2
// split returns a term that is equal to aiwi (it's 1xaiwi)
// no side effects on le
func (scs *sparseR1CS) split(a compiled.Term, l compiled.LinearExpression) compiled.Term {

	// floor case
	if len(l) == 0 {
		return a
	}

	// first call
	if a == 0 {
		return scs.split(l[0], l[1:])
	}

	// recursive case
	r := l[0]
	o := scs.newTerm(bOne)
	scs.addConstraint(compiled.SparseR1C{L: a, R: r, O: o})
	o = scs.negate(o)
	return scs.split(o, l[1:])

}

// r1cToSparseR1C splits a r1c constraint
func (scs *sparseR1CS) r1cToSparseR1C(r1c compiled.R1C) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, idCS := findUnsolvedVariable(r1c, scs.solvedVariables)
	if lro == -1 {
		// this may happen if a constraint contained hint wires, that are marked as solved.
		// or if we r1c is an assertion (ie it does not yield any output)
		scs.splitR1C(r1c)
		return // no variable to solve here.
	}

	l := r1c.L
	r := r1c.R
	o := r1c.O

	// if the unsolved variable in not in o,
	// ensure that it is in r1c.L
	if lro == 1 {
		l, r = r, l
		lro = 0
	}

	var (
		cK big.Int // constant K
		cS big.Int // constant S (associated with toSolve)
	)
	var toSolve compiled.Term

	l, cL := scs.popConstantTerm(l)
	r, cR := scs.popConstantTerm(r)
	o, cO := scs.popConstantTerm(o)

	// pop the unsolved wire from the linearexpression
	if lro == 0 { // unsolved is in L
		l, toSolve = popInternalVariable(l, idCS)
	} else { // unsolved is in O
		o, toSolve = popInternalVariable(o, idCS)
	}

	// set cS to toSolve coeff
	cS.Set(&scs.coeffs[toSolve.CoeffID()])

	// cL*cR = toSolve + cO
	f1 := func() {
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		})
	}

	// cL*(r + cR) = toSolve + cO
	f2 := func() {
		rt := scs.split(0, r)

		cRT := scs.multiply(rt, &cL)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			R: cRT,
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		},
		)
	}

	// (l + cL)*cR = toSolve + cO
	f3 := func() {
		lt := scs.split(0, l)

		cRLT := scs.multiply(lt, &cR)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: cRLT,
			O: scs.newTerm(cS.Neg(&cS), idCS),
			K: scs.coeffID(&cK),
		})
	}

	// (l + cL)*(r + cR) = toSolve + cO
	f4 := func() {
		lt := scs.split(0, l)
		rt := scs.split(0, r)

		cRLT := scs.multiply(lt, &cR)
		cRT := scs.multiply(rt, &cL)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: cRLT,
			R: cRT,
			M: [2]compiled.Term{lt, rt},
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		})
	}

	// cL*cR = toSolve + o + cO
	f5 := func() {
		ot := scs.split(0, o)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)
		cK.Neg(&cK)

		scs.addConstraint(compiled.SparseR1C{
			L: ot,
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		})
	}

	// cL*(r + cR) = toSolve + o + cO
	f6 := func() {
		rt := scs.split(0, r)
		ot := scs.split(0, o)

		cRT := scs.multiply(rt, &cL)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)
		cK.Neg(&cK)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.negate(ot),
			R: cRT,
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		})
	}

	// (l + cL)*cR = toSolve + o + cO
	f7 := func() {
		lt := scs.split(0, l)
		ot := scs.split(0, o)

		cRLT := scs.multiply(lt, &cR)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)
		cK.Neg(&cK)

		scs.addConstraint(compiled.SparseR1C{
			R: scs.negate(ot),
			L: cRLT,
			K: scs.coeffID(&cK),
			O: scs.newTerm(cS.Neg(&cS), idCS),
		})
	}

	// (l + cL)*(r + cR) = toSolve + o + cO
	f8 := func() {
		lt := scs.split(0, l)
		rt := scs.split(0, r)
		ot := scs.split(0, o)

		cRLT := scs.multiply(lt, &cR)
		cRT := scs.multiply(rt, &cL)
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)
		cK.Neg(&cK)

		u := scs.newTerm(bOne)
		scs.addConstraint(compiled.SparseR1C{
			L: cRLT,
			R: cRT,
			M: [2]compiled.Term{lt, rt},
			K: scs.coeffID(&cK),
			O: u,
		})

		scs.addConstraint(compiled.SparseR1C{
			L: u,
			R: ot,
			O: scs.newTerm(&cS, idCS),
		})
	}

	// (toSolve + cL)*cR = cO
	f9 := func() {
		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		cS.Mul(&cS, &cR)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.newTerm(&cS, idCS),
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + cL)*(r + cR) = cO
	f10 := func() {
		res := scs.newTerm(&cS, idCS)

		rt := scs.split(0, r)
		cRT := scs.multiply(rt, &cL)
		cRes := scs.multiply(res, &cR)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: cRes,
			R: cRT,
			M: [2]compiled.Term{res, rt},
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + l + cL)*cR = cO
	f11 := func() {
		lt := scs.split(0, l)
		lt = scs.multiply(lt, &cR)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		cS.Mul(&cS, &cR)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.newTerm(&cS, idCS),
			R: lt,
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + l + cL)*(r + cR) = cO
	// => toSolve*r + toSolve*cR + [ l*r + l*cR +cL*r+cL*cR-cO ]=0
	f12 := func() {
		u := scs.newTerm(bOne)
		lt := scs.split(0, l)
		rt := scs.split(0, r)
		cRLT := scs.multiply(lt, &cR)
		cRT := scs.multiply(rt, &cL)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: cRLT,
			R: cRT,
			M: [2]compiled.Term{lt, rt},
			O: u,
			K: scs.coeffID(&cK),
		})

		res := scs.newTerm(&cS, idCS)
		cRes := scs.multiply(res, &cR)

		scs.addConstraint(compiled.SparseR1C{
			R: cRes,
			M: [2]compiled.Term{res, rt},
			O: scs.negate(u),
		})
	}

	// (toSolve + cL)*cR = o + cO
	f13 := func() {
		ot := scs.split(0, o)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		cS.Mul(&cS, &cR)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.newTerm(&cS, idCS),
			O: scs.negate(ot),
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + cL)*(r + cR) = o + cO
	// toSolve*r + toSolve*cR+cL*r+cL*cR-cO-o=0
	f14 := func() {
		ot := scs.split(0, o)
		res := scs.newTerm(&cS, idCS)

		rt := scs.split(0, r)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.multiply(res, &cR),
			R: scs.multiply(rt, &cL),
			M: [2]compiled.Term{res, rt},
			O: scs.negate(ot),
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + l + cL)*cR = o + cO
	// toSolve*cR + l*cR + cL*cR-cO-o=0
	f15 := func() {
		ot := scs.split(0, o)
		lt := scs.split(0, l)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		cS.Mul(&cS, &cR)

		scs.addConstraint(compiled.SparseR1C{
			L: scs.newTerm(&cS, idCS),
			R: scs.multiply(lt, &cR),
			O: scs.negate(ot),
			K: scs.coeffID(&cK),
		})
	}

	// (toSolve + l + cL)*(r + cR) = o + cO
	// => toSolve*r + toSolve*cR + [ [l*r + l*cR +cL*r+cL*cR-cO]- o ]=0
	f16 := func() {
		// [l*r + l*cR +cL*r+cL*cR-cO] + u = 0
		u := scs.newTerm(bOne)
		lt := scs.split(0, l)
		rt := scs.split(0, r)
		cRLT := scs.multiply(lt, &cR)
		cRT := scs.multiply(rt, &cL)

		cK.Mul(&cL, &cR)
		cK.Sub(&cK, &cO)

		scs.addConstraint(compiled.SparseR1C{
			L: cRLT,
			R: cRT,
			M: [2]compiled.Term{lt, rt},
			O: u,
			K: scs.coeffID(&cK),
		})

		// u+o+v = 0 (v = -u - o = [l*r + l*cR +cL*r+cL*cR-cO] -  o)
		v := scs.newTerm(bOne)
		ot := scs.split(0, o)
		scs.addConstraint(compiled.SparseR1C{
			L: u,
			R: ot,
			O: v,
		})

		// toSolve*r + toSolve*cR + v = 0
		res := scs.newTerm(&cS, idCS)
		cRes := scs.multiply(res, &cR)

		scs.addConstraint(compiled.SparseR1C{
			R: cRes,
			M: [2]compiled.Term{res, rt},
			O: v,
		})
	}

	// we have 16 different cases
	var s uint8
	if lro != 0 {
		s |= 0b1000
	}
	if len(o) != 0 {
		s |= 0b0100
	}
	if len(l) != 0 {
		s |= 0b0010
	}
	if len(r) != 0 {
		s |= 0b0001
	}

	switch s {
	case 0b0000:
		// (toSolve + cL)*cR = cO
		f9()
	case 0b0001:
		// (toSolve + cL)*(r + cR) = cO
		f10()
	case 0b0010:
		// (toSolve + l + cL)*cR = cO
		f11()
	case 0b0011:
		// (toSolve + l + cL)*(r + cR) = cO
		// => toSolve*r + toSolve*cR + [ l*r + l*cR +cL*r+cL*cR-cO ]=0
		f12()
	case 0b0100:
		// (toSolve + cL)*cR = o + cO
		f13()
	case 0b0101:
		// (toSolve + cL)*(r + cR) = o + cO
		// toSolve*r + toSolve*cR+cL*r+cL*cR-cO-o=0
		f14()
	case 0b0110:
		// (toSolve + l + cL)*cR = o + cO
		// toSolve*cR + l*cR + cL*cR-cO-o=0
		f15()
	case 0b0111:
		// (toSolve + l + cL)*(r + cR) = o + cO
		// => toSolve*r + toSolve*cR + [ [l*r + l*cR +cL*r+cL*cR-cO]- o ]=0
		f16()
	case 0b1000:
		// cL*cR = toSolve + cO
		f1()
	case 0b1001:
		// cL*(r + cR) = toSolve + cO
		f2()
	case 0b1010:
		// (l + cL)*cR = toSolve + cO
		f3()
	case 0b1011:
		// (l + cL)*(r + cR) = toSolve + cO
		f4()
	case 0b1100:
		// cL*cR = toSolve + o + cO
		f5()
	case 0b1101:
		// cL*(r + cR) = toSolve + o + cO
		f6()
	case 0b1110:
		// (l + cL)*cR = toSolve + o + cO
		f7()
	case 0b1111:
		// (l + cL)*(r + cR) = toSolve + o + cO
		f8()
	}

}

// splitR1C splits a r1c assertion (meaning that
// it's a r1c constraint that is not used to solve a variable,
// like a boolean constraint).
// (l + cL)*(r + cR) = o + cO
func (scs *sparseR1CS) splitR1C(r1c compiled.R1C) {

	l := r1c.L
	r := r1c.R
	o := r1c.O

	l, cL := scs.popConstantTerm(l)
	r, cR := scs.popConstantTerm(r)
	o, cO := scs.popConstantTerm(o)

	var cK big.Int

	if len(o) == 0 {

		if len(l) == 0 {

			if len(r) == 0 { // cL*cR = cO (should never happen...)

				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{K: scs.coeffID(&cK)})

			} else { // cL*(r + cR) = cO

				rt := scs.split(0, r)

				cRLT := scs.multiply(rt, &cL)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{R: cRLT, K: scs.coeffID(&cK)})
			}

		} else {

			if len(r) == 0 { // (l + cL)*cR = cO
				lt := scs.split(0, l)

				cRLT := scs.multiply(lt, &cR)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{L: cRLT, K: scs.coeffID(&cK)})

			} else { // (l + cL)*(r + cR) = cO

				lt := scs.split(0, l)
				rt := scs.split(0, r)

				cRLT := scs.multiply(lt, &cR)
				cRT := scs.multiply(rt, &cL)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{
					L: cRLT,
					R: cRT,
					M: [2]compiled.Term{lt, rt},
					K: scs.coeffID(&cK),
				})
			}
		}

	} else {
		if len(l) == 0 {

			if len(r) == 0 { // cL*cR = o + cO

				ot := scs.split(0, o)

				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{K: scs.coeffID(&cK), O: scs.negate(ot)})

			} else { // cL * (r + cR) = o + cO

				rt := scs.split(0, r)
				ot := scs.split(0, o)

				cRT := scs.multiply(rt, &cL)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{
					R: cRT,
					K: scs.coeffID(&cK),
					O: scs.negate(ot),
				})
			}

		} else {
			if len(r) == 0 { // (l + cL) * cR = o + cO

				lt := scs.split(0, l)
				ot := scs.split(0, o)

				cRLT := scs.multiply(lt, &cR)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{
					L: cRLT,
					K: scs.coeffID(&cK),
					O: scs.negate(ot),
				})

			} else { // (l + cL)*(r + cR) = o + cO
				lt := scs.split(0, l)
				rt := scs.split(0, r)
				ot := scs.split(0, o)

				cRT := scs.multiply(rt, &cL)
				cRLT := scs.multiply(lt, &cR)
				cK.Mul(&cR, &cL)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{
					L: cRLT,
					R: cRT,
					M: [2]compiled.Term{lt, rt},
					K: scs.coeffID(&cK),
					O: scs.negate(ot),
				})
			}
		}
	}
}

var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}
