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
type PlonkCS struct {

	// Variables
	nbInternalVariables int

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

// change t's ID to varCsToVaPcs[t.ID] to get the corresponding variable in the pcs
// the coef is negated as well, since constraints are of the form m+l=0, so solving
// the constraint yields -variable.
func (pcs *PlonkCS) getCorrespondingTerm(t backend.Term, csCoeffs []big.Int, varCsToVaPcs map[int]int) backend.Term {
	id := varCsToVaPcs[t.VariableID()]
	coef := csCoeffs[t.CoeffID()]
	coef.Neg(&coef)
	cID := pcs.coeffID(&coef)
	t.SetCoeffID(cID)
	t.SetVariableID(id)
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

// if t=a*variable, it returns -a*variable
func (pcs *PlonkCS) negate(t backend.Term) backend.Term {
	coeff := pcs.coeffs[t.CoeffID()]
	coeff.Neg(&coeff)
	cID := pcs.coeffID(&coeff)
	t.SetCoeffID(cID)
	return t
}

// split splits a linear expression to plonk constraints
// ex: le = aiwi is split into
// u1=a1w1+a2w2,
// u2=a3w3+u1
// ...
// u_n-1=a_n-1w_n-1+u_n-2
// split is called like this (reduce(le[0]))
// split must be called when all variables in le are registered in pcs
func (pcs *PlonkCS) split(l backend.Term, csCoeffs []big.Int, le backend.LinearExpression, varCsToVaPcs map[int]int) backend.Term {

	// first call
	if l == 0 {
		t := pcs.getCorrespondingTerm(le[0], csCoeffs, varCsToVaPcs)
		return pcs.split(t, csCoeffs, le[1:], varCsToVaPcs)
	}

	// floor case
	if len(le) == 0 {
		return l
	}

	// recursive case
	r := pcs.getCorrespondingTerm(le[0], csCoeffs, varCsToVaPcs)
	o := pcs.newInternalVariable()
	pcs.recordConstraint(backend.PlonkConstraint{L: l, R: r, O: o})
	o = pcs.negate(o)
	return pcs.split(o, csCoeffs, le[1:], varCsToVaPcs)

}

// r1cToplonkConstraint splits a r1c constraint.
// r1c: l*r=o, if the variable v to solve is in o,
// we pop it from o, we write o=lin+v, we reduce l, r, lin
// to l',r',lin' and we write l'*r'-lin-v=0.
// Similarly if v is in l, we pop it from l, we write l=lin+v,
// we reduce lin,r,o to lin',r',o' and we write
// (lin'+v)*r'=o' -> lin'*r'+v*r'=o'
// we split it in 2: n + lin'*r'=0
// -n+v*r'=0
func (pcs *PlonkCS) r1cToplonkConstraint(cs *ConstraintSystem, r1c backend.R1C, varCsToVaPcs map[int]int, solvedVariables []bool) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, id := findUnsolvedVariable(r1c, solvedVariables)

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
	var toSolve backend.Term
	if lro == 0 {
		l, toSolve = popInternalVariable(l, id)
		lt := pcs.split(0, cs.coeffs, l, varCsToVaPcs)
		rt := pcs.split(0, cs.coeffs, r, varCsToVaPcs)
		ot := pcs.split(0, cs.coeffs, o, varCsToVaPcs)
		n := pcs.newInternalVariable()
		// (lt+toSolve)*rt=ot (lt*rt+toSolve*rt = ot)
		// lt*rt+n=0, so -n=lt*rt
		pcs.recordConstraint(backend.PlonkConstraint{M: [2]backend.Term{lt, rt}, O: n})
		// toSolve*rt-n-ot=0 => res+lt*rt+ot=0
		ot = pcs.negate(ot)
		n = pcs.negate(n)
		res := pcs.newInternalVariable()
		pcs.recordConstraint(backend.PlonkConstraint{L: n, R: n, M: [2]backend.Term{res, rt}})
		varCsToVaPcs[toSolve.VariableID()] = res.VariableID()
	} else {
		o, toSolve = popInternalVariable(o, id)
		lt := pcs.split(0, cs.coeffs, l, varCsToVaPcs)
		rt := pcs.split(0, cs.coeffs, r, varCsToVaPcs)
		ot := pcs.split(0, cs.coeffs, o, varCsToVaPcs)
		ot = pcs.negate(ot)
		res := pcs.newInternalVariable()
		// lr*rt-ot+res = 0
		pcs.recordConstraint(backend.PlonkConstraint{L: ot, M: [2]backend.Term{lt, rt}, O: res})
		varCsToVaPcs[toSolve.VariableID()] = res.VariableID()
	}

}

func csToPlonk(cs *ConstraintSystem, pcs *PlonkCS) {

	// build the coeffs slice
	pcs.coeffs = make([]big.Int, len(cs.coeffs))

	// copy public/secret inputs
	pcs.nbInternalVariables = 0

	// cs_variable_id -> plonk_cs_variable_id
	// if a variable is solved, it is recorded in varPcsToVarCs
	varPcsToVarCs := make(map[int]int)
	solvedVariables := make([]bool, len(cs.internal.variables))

	// convert the constraints invidually
	for i := 0; i < len(cs.constraints); i++ {
		pcs.r1cToplonkConstraint(cs, cs.constraints[i], varPcsToVarCs, solvedVariables)
	}
	// for i := 0; i < len(cs.assertions); i++ {

	// }

}
