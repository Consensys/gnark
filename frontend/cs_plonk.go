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

	"github.com/consensys/gnark/backend"
)

// PlonkCS represents a Plonk like circuit
// WIP does not contain logs for the moment
type PlonkCS struct {

	// Variables
	nbInternalVariables int
	nbPublicVariables   int
	nbSecretVariables   int

	// Constraints
	constraints []backend.PlonkConstraint // list of Plonk constraints that yield an output (for example v3 == v1 * v2, return v3)
	assertions  []backend.PlonkConstraint // list of Plonk constraints that yield no output (for example ensuring v1 == v2)

	// Coefficients in the constraints
	coeffs    []big.Int      // list of unique coefficients.
	coeffsIDs map[string]int // map to fast check existence of a coefficient (key = coeff.Text(16))
}

func newPlonkCS() PlonkCS {

	var pcs PlonkCS
	pcs.constraints = make([]backend.PlonkConstraint, 0)
	pcs.assertions = make([]backend.PlonkConstraint, 0)
	pcs.coeffs = make([]big.Int, 0)
	pcs.coeffsIDs = make(map[string]int)
	return pcs
}

type idCS = int
type idPCS = int

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (pcs *PlonkCS) coeffID(b *big.Int) int {

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	key := b.Text(16)
	if idx, ok := pcs.coeffsIDs[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(pcs.coeffs)
	pcs.coeffs = append(pcs.coeffs, bCopy)
	pcs.coeffsIDs[key] = resID
	return resID
}

// findUnsolvedVariable returns the variable to solve in the r1c. The variables
// which are not internal are considered solve, otherwise the solvedVariables
// slice hold the record of which variables have been solved.
func findUnsolvedVariable(r1c backend.R1C, solvedVariables []bool) (pos int, id int) {
	// find the variable to solve among L,R,O. pos=0,1,2 corresponds to left,right,o.
	pos = -1
	id = -1
	for i := 0; i < len(r1c.L); i++ {
		v := r1c.L[i].VariableVisibility()
		if v != backend.Internal {
			continue
		}
		id = r1c.L[i].VariableID()
		if !solvedVariables[id] {
			pos = 0
			break
		}
	}
	if pos == -1 {
		for i := 0; i < len(r1c.R); i++ {
			v := r1c.R[i].VariableVisibility()
			if v != backend.Internal {
				continue
			}
			id = r1c.R[i].VariableID()
			if !solvedVariables[id] {
				pos = 1
				break
			}
		}
	}
	if pos == -1 {
		for i := 0; i < len(r1c.O); i++ {
			v := r1c.O[i].VariableVisibility()
			if v != backend.Internal {
				continue
			}
			id = r1c.O[i].VariableID()
			if !solvedVariables[id] {
				pos = 2
				break
			}
		}
	}
	return pos, id
}

// returns l with the term hanlding the id-th variable removed
// No side effects on l.
func popInternalVariable(l backend.LinearExpression, id int) (backend.LinearExpression, backend.Term) {
	var t backend.Term
	_l := make([]backend.Term, len(l)-1)
	c := 0
	for i := 0; i < len(l); i++ {
		v := l[i]
		if v.VariableVisibility() == backend.Internal && v.VariableID() == id {
			t = v
			continue
		}
		_l[c] = v
		c++
	}
	return _l, t
}

// change t's ID to csPcsMapping[t.ID] to get the corresponding variable in the pcs,
// the coeff ID is changed as well so that it corresponds to a coeff in the pcs.
func (pcs *PlonkCS) getCorrespondingTerm(t backend.Term, csCoeffs []big.Int, csPcsMapping map[idCS]idPCS) backend.Term {

	// if the variable is internal, we need the variable
	// that corresponds in the pcs
	if t.VariableVisibility() == backend.Internal {
		t.SetVariableID(csPcsMapping[t.VariableID()])
		coef := csCoeffs[t.CoeffID()]
		cID := pcs.coeffID(&coef)
		t.SetCoeffID(cID)
		return t
	}
	// if the variable is an input, only the coeff ID needs to
	// be updated so it corresponds to an ID in the pcs coeffs slice.
	// Otherwise, the variable's ID and visibility is the same
	coef := csCoeffs[t.CoeffID()]
	cID := pcs.coeffID(&coef)
	t.SetCoeffID(cID)
	return t
}

// newInternalVariable creates a new term =1*new_variable and
// records it in the pcs. If t is provided, the newly created
// variable has the same coeff Id than t.
func (pcs *PlonkCS) newInternalVariable(t ...backend.Term) backend.Term {

	if len(t) == 0 {
		cID := pcs.coeffID(bOne)
		vID := pcs.nbInternalVariables
		res := backend.Pack(vID, cID, backend.Internal)
		pcs.nbInternalVariables++
		return res
	}
	res := t[0]
	cID := pcs.coeffID(&pcs.coeffs[res.CoeffID()])
	vID := pcs.nbInternalVariables
	res.SetCoeffID(cID)
	res.SetVariableID(vID)
	pcs.nbInternalVariables++
	return res

}

// recordConstraint records a plonk constraint in the pcs
func (pcs *PlonkCS) recordConstraint(c backend.PlonkConstraint) {
	pcs.constraints = append(pcs.constraints, c)
}

// recordAssertion records a plonk constraint (assertion) in the pcs
func (pcs *PlonkCS) recordAssertion(c backend.PlonkConstraint) {
	pcs.assertions = append(pcs.assertions, c)
}

// if t=a*variable, it returns -a*variable
func (pcs *PlonkCS) negate(t backend.Term) backend.Term {
	// non existing term are zero, if we negate it it's no
	// longer zero and checks to see if a variable exist will
	// fail (ex: in r1cToPlonkConstraint we might call negate
	// on non existing variables, when split is called with
	// le = nil)
	if t == 0 {
		return t
	}
	coeff := pcs.coeffs[t.CoeffID()]
	coeff.Neg(&coeff)
	cID := pcs.coeffID(&coeff)
	t.SetCoeffID(cID)
	return t
}

// split splits a linear expression to plonk constraints
// ex: le = aiwi is split into PLONK constraints (using sums)
// of 3 terms).
// split returns a term that is equal to aiwi
func (pcs *PlonkCS) split(l backend.Term, csCoeffs []big.Int, le backend.LinearExpression, csPcsMapping map[idCS]idPCS) backend.Term {

	// floor case
	if len(le) == 0 {
		return l
	}

	// first call
	if l == 0 {
		t := pcs.getCorrespondingTerm(le[0], csCoeffs, csPcsMapping)
		return pcs.split(t, csCoeffs, le[1:], csPcsMapping)
	}

	// recursive case
	r := pcs.getCorrespondingTerm(le[0], csCoeffs, csPcsMapping)
	o := pcs.newInternalVariable()
	pcs.recordConstraint(backend.PlonkConstraint{L: l, R: r, O: o})
	o = pcs.negate(o)
	return pcs.split(o, csCoeffs, le[1:], csPcsMapping)

}

// r1cToPlonkConstraint splits a r1c constraint.
// r1c: l*r=o, if the variable v to solve is in o,
// we pop it from o, we write o=lin+v, we reduce l, r, lin
// to l',r',lin' and we write l'*r'-lin-v=0.
// Similarly if v is in l, we pop it from l, we write l=lin+v,
// we reduce lin,r,o to lin',r',o' and we write
// (lin'+v)*r'=o' -> lin'*r'+v*r'=o'
// we split it in 2: n + lin'*r'=0
// -n+v*r'=0
func (pcs *PlonkCS) r1cToPlonkConstraint(cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, id := findUnsolvedVariable(r1c, solvedVariables)
	solvedVariables[id] = true

	// ensure that the unsolved wire is in the left lineexp
	l := r1c.L
	r := r1c.R
	o := r1c.O
	if lro == 1 {
		r = r1c.L
		l = r1c.R
		o = r1c.O
		lro = 0
	}

	// pop the unsolved wire from the linearexpression
	if lro == 0 {

		l, toSolve := popInternalVariable(l, id)

		lt := pcs.split(0, cs.coeffs, l, csPcsMapping)
		rt := pcs.split(0, cs.coeffs, r, csPcsMapping)
		ot := pcs.split(0, cs.coeffs, o, csPcsMapping)

		// if lt==0, it means that the r1c is of the form toSolve*(linear_combination)=linear_combination
		if lt == 0 {
			res := pcs.newInternalVariable()
			csPcsMapping[id] = res.VariableID()
			coef := cs.coeffs[toSolve.CoeffID()]
			res.SetCoeffID(pcs.coeffID(&coef))

			pcs.recordConstraint(backend.PlonkConstraint{M: [2]backend.Term{res, rt}, O: pcs.negate(ot)})
		} else {
			ltTimesRt := pcs.newInternalVariable()
			ltTimesRt = pcs.negate(ltTimesRt)
			pcs.recordConstraint(backend.PlonkConstraint{M: [2]backend.Term{lt, rt}, O: ltTimesRt})

			res := pcs.newInternalVariable()
			csPcsMapping[id] = res.VariableID()
			coef := cs.coeffs[toSolve.CoeffID()]
			res.SetCoeffID(pcs.coeffID(&coef))

			// res *rt + lt*rt - ot = 0
			pcs.recordConstraint(backend.PlonkConstraint{L: ltTimesRt, M: [2]backend.Term{res, rt}, O: pcs.negate(ot)})
		}
	} else {
		lt := pcs.split(0, cs.coeffs, l, csPcsMapping)
		rt := pcs.split(0, cs.coeffs, r, csPcsMapping)
		o, toSolve := popInternalVariable(o, id)
		ot := pcs.split(0, cs.coeffs, o, csPcsMapping)
		res := pcs.newInternalVariable()
		coef := cs.coeffs[toSolve.CoeffID()]
		coef.Neg(&coef)
		res.SetCoeffID(pcs.coeffID(&coef))
		// lr*rt-ot-coef.res = 0, so solving res is the same as solving toSolve in the cs
		pcs.recordConstraint(backend.PlonkConstraint{L: pcs.negate(ot), M: [2]backend.Term{lt, rt}, O: res})
		csPcsMapping[id] = res.VariableID()
	}

}

// r1cToPlonkAssertion splits a r1c assertion (meaning that
// it's a r1c constraint that is not used to solve a variable,
// like a boolean constraint).
// l*r = o -> reduce l, r to l',r', then reduce o[:2] to o',
// the PLONK constraint is l'*r'-o[0]-o[1]-o'=0
func (pcs *PlonkCS) r1cToPlonkAssertion(cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS) {

	oCopy := make([]backend.Term, len(r1c.O))
	copy(oCopy, r1c.O)
	lt := pcs.split(0, cs.coeffs, r1c.L, csPcsMapping)
	rt := pcs.split(0, cs.coeffs, r1c.R, csPcsMapping)
	var o [3]backend.Term
	o[0] = pcs.getCorrespondingTerm(oCopy[0], cs.coeffs, csPcsMapping)
	oCopy = oCopy[1:]
	if len(oCopy) > 0 {
		o[1] = pcs.getCorrespondingTerm(oCopy[0], cs.coeffs, csPcsMapping)
		oCopy = oCopy[1:]
	}
	o[2] = pcs.split(0, cs.coeffs, oCopy, csPcsMapping)

	// we can record the constraint, which is
	// lt*rt-o[0]-o[1]-o[2]=0
	pcs.recordAssertion(backend.PlonkConstraint{L: pcs.negate(o[0]), R: pcs.negate(o[1]), O: pcs.negate(o[2]), M: [2]backend.Term{lt, rt}})

}

func csToPlonk(cs *ConstraintSystem, pcs *PlonkCS) {

	// build the coeffs slice
	pcs.coeffs = make([]big.Int, len(cs.coeffs))
	pcs.coeffsIDs = make(map[string]int)

	pcs.nbPublicVariables = len(cs.public.variables)
	pcs.nbSecretVariables = len(cs.secret.variables)

	// cs_variable_id -> plonk_cs_variable_id, neg
	// need for reasonning on variables in the pcs (the
	// boolean tells if pcs's id corresponds to +-cs's id
	// false: +, true -)
	varPcsToVarCs := make(map[idCS]idPCS)
	solvedVariables := make([]bool, len(cs.internal.variables))

	// convert the constraints invidually
	for i := 0; i < len(cs.constraints); i++ {
		pcs.r1cToPlonkConstraint(cs, cs.constraints[i], varPcsToVarCs, solvedVariables)
	}
	for i := 0; i < len(cs.assertions); i++ {
		pcs.r1cToPlonkAssertion(cs, cs.assertions[i], varPcsToVarCs)
	}

}
