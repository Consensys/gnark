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
	"fmt"
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/pcs"
	"github.com/consensys/gurvy"
)

type idCS = int
type idPCS = int

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of Coeffs and returns the corresponding entry
func coeffID(pcs *pcs.UntypedPlonkCS, b *big.Int) int {

	// if the coeff is already stored, fetch its ID from the cs.CoeffsIDs map
	key := b.Text(16)
	if idx, ok := pcs.CoeffsIDs[key]; ok {
		return idx
	}

	// else add it in the cs.Coeffs map and update the cs.CoeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(pcs.Coeffs)
	pcs.Coeffs = append(pcs.Coeffs, bCopy)
	pcs.CoeffsIDs[key] = resID
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

// returns l with the term (id+coef) holding the id-th variable removed
// No side effects on l.
func popInternalVariable(l backend.LinearExpression, id int) (backend.LinearExpression, backend.Term) {
	fmt.Printf("need to pop %d-th variable\n", id)
	fmt.Printf("len l: %d\n", len(l))
	var t backend.Term
	_l := make([]backend.Term, len(l)-1)
	c := 0
	for i := 0; i < len(l); i++ {
		v := l[i]
		if v.VariableVisibility() == backend.Internal && v.VariableID() == id {
			fmt.Println("going there")
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
// returns the reduced linear expression and the ID of the coeff corresponding to the constant term (in pcs.Coeffs).
// If there is no constant term, the id is 0
func popConstantTerm(l backend.LinearExpression, cs *ConstraintSystem, pcs *pcs.UntypedPlonkCS) (backend.LinearExpression, int) {

	idOneWire := 0
	resConstantID := 0 // the zero index contains the zero coef, it is reserved

	lCopy := make(backend.LinearExpression, len(l))
	copy(lCopy, l)
	for i := 0; i < len(l); i++ {
		t := lCopy[i]
		id := t.VariableID()
		vis := t.VariableVisibility()
		if vis == backend.Public && id == idOneWire {
			coefID := t.CoeffID()
			coef := cs.coeffs[coefID]
			resConstantID = coeffID(pcs, &coef)
			lCopy = append(lCopy[:i], lCopy[i+1:]...)
			break
		}
	}
	return lCopy, resConstantID
}

// change t's ID to csPcsMapping[t.ID] to get the corresponding variable in the pcs,
// the coeff ID is changed as well so that it corresponds to a coeff in the pcs.
func getCorrespondingTerm(pcs *pcs.UntypedPlonkCS, t backend.Term, csCoeffs []big.Int, csPcsMapping map[idCS]idPCS) backend.Term {

	// if the variable is internal, we need the variable
	// that corresponds in the pcs
	if t.VariableVisibility() == backend.Internal {
		t.SetVariableID(csPcsMapping[t.VariableID()])
		coef := csCoeffs[t.CoeffID()]
		cID := coeffID(pcs, &coef)
		t.SetCoeffID(cID)
		return t
	}
	// if the variable is an input, only the coeff ID needs to
	// be updated so it corresponds to an ID in the pcs Coeffs slice.
	// Otherwise, the variable's ID and visibility is the same
	coef := csCoeffs[t.CoeffID()]
	cID := coeffID(pcs, &coef)
	t.SetCoeffID(cID)
	return t
}

// newInternalVariable creates a new term =1*new_variable and
// records it in the pcs. If t is provided, the newly created
// variable has the same coeff Id than t.
func newInternalVariable(pcs *pcs.UntypedPlonkCS, t ...backend.Term) backend.Term {

	if len(t) == 0 {
		cID := coeffID(pcs, bOne)
		vID := pcs.NbInternalVariables
		res := backend.Pack(vID, cID, backend.Internal)
		pcs.NbInternalVariables++
		return res
	}
	res := t[0]
	cID := coeffID(pcs, &pcs.Coeffs[res.CoeffID()])
	vID := pcs.NbInternalVariables
	res.SetCoeffID(cID)
	res.SetVariableID(vID)
	pcs.NbInternalVariables++
	return res

}

// recordConstraint records a plonk constraint in the pcs
// The function ensures that all variables ID are set, even
// if the corresponding coefficients are 0.
// A plonk constraint will always look like this:
// L+R+L.R+O+K = 0
func recordConstraint(pcs *pcs.UntypedPlonkCS, c backend.PlonkConstraint) {
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
	pcs.Constraints = append(pcs.Constraints, c)
}

// recordAssertion records a plonk constraint (assertion) in the pcs
func recordAssertion(pcs *pcs.UntypedPlonkCS, c backend.PlonkConstraint) {
	pcs.Assertions = append(pcs.Assertions, c)
}

// if t=a*variable, it returns -a*variable
func negate(pcs *pcs.UntypedPlonkCS, t backend.Term) backend.Term {
	// non existing term are zero, if we negate it it's no
	// longer zero and checks to see if a variable exist will
	// fail (ex: in r1cToPlonkConstraint we might call negate
	// on non existing variables, when split is called with
	// le = nil)
	if t == 0 {
		return t
	}
	coeff := pcs.Coeffs[t.CoeffID()]
	coeff.Neg(&coeff)
	cID := coeffID(pcs, &coeff)
	t.SetCoeffID(cID)
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
func split(pcs *pcs.UntypedPlonkCS, acc backend.Term, csCoeffs []big.Int, le backend.LinearExpression, csPcsMapping map[idCS]idPCS) backend.Term {

	// floor case
	if len(le) == 0 {
		return acc
	}

	// first call
	if acc == 0 {
		t := getCorrespondingTerm(pcs, le[0], csCoeffs, csPcsMapping)
		return split(pcs, t, csCoeffs, le[1:], csPcsMapping)
	}

	// recursive case
	r := getCorrespondingTerm(pcs, le[0], csCoeffs, csPcsMapping)
	o := newInternalVariable(pcs)
	recordConstraint(pcs, backend.PlonkConstraint{L: acc, R: r, O: o})
	o = negate(pcs, o)
	return split(pcs, o, csCoeffs, le[1:], csPcsMapping)

}

func r1cToPlonkConstraint(pcs *pcs.UntypedPlonkCS, cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {
	if r1c.Solver == backend.SingleOutput {
		r1cToPlonkConstraintSingleOutput(pcs, cs, r1c, csPcsMapping, solvedVariables)
	} else {
		r1cToPlonkConstraintBinary(pcs, cs, r1c, csPcsMapping, solvedVariables)
	}
}

// r1cToPlonkConstraintSingleOutput splits a r1c constraint.
// r1c: l*r=o, if the variable v to solve is in o,
// we pop it from o, we write o=lin+v, we reduce l, r, lin
// to l',r',lin' and we write l'*r'-lin-v=0.
// Similarly if v is in l, we pop it from l, we write l=lin+v,
// we reduce lin,r,o to lin',r',o' and we write
// (lin'+v)*r'=o' -> lin'*r'+v*r'=o'
// we split it in 2: n + lin'*r'=0
// -n+v*r'=0
func r1cToPlonkConstraintSingleOutput(pcs *pcs.UntypedPlonkCS, cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, id := findUnsolvedVariable(r1c, solvedVariables)

	// ensure that the unsolved wire is in the left lineexp
	var l, r, o backend.LinearExpression
	o = make(backend.LinearExpression, len(r1c.O))
	copy(o, r1c.O)
	if lro == 1 {
		l = make(backend.LinearExpression, len(r1c.R))
		copy(l, r1c.R)
		r = make(backend.LinearExpression, len(r1c.L))
		copy(r, r1c.L)
		lro = 0
	} else {
		l = make(backend.LinearExpression, len(r1c.L))
		copy(l, r1c.L)
		r = make(backend.LinearExpression, len(r1c.R))
		copy(r, r1c.R)
	}

	// the unsolved wire is in the quadratic expression
	if lro == 0 {

		// pop the unsolved wire from the linearexpression
		l, toSolve := popInternalVariable(l, id)

		lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
		rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
		ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

		// if lt==0, it means that the r1c is of the form (toSolve)*(linear_combination)=linear_combination
		if lt == 0 {

			res := newInternalVariable(pcs)
			csPcsMapping[id] = res.VariableID()

			coef := cs.coeffs[toSolve.CoeffID()]
			res.SetCoeffID(coeffID(pcs, &coef))

			toRecord := backend.PlonkConstraint{M: [2]backend.Term{res, rt}, O: negate(pcs, ot)}
			recordConstraint(pcs, toRecord)

		} else {
			// (x+lt)rt=ot =>
			// lt.rt+u = 0
			// v -u-ot = 0
			// x.rt - v = 0 (=x.rt-u-ot=x.rt+lt.rt-ot)
			u := newInternalVariable(pcs)
			recordConstraint(pcs, backend.PlonkConstraint{M: [2]backend.Term{lt, rt}, O: u})

			v := newInternalVariable(pcs)
			recordConstraint(pcs, backend.PlonkConstraint{L: v, R: negate(pcs, u), O: negate(pcs, ot)})

			res := newInternalVariable(pcs)
			csPcsMapping[id] = res.VariableID()
			coef := cs.coeffs[toSolve.CoeffID()]
			res.SetCoeffID(coeffID(pcs, &coef))

			recordConstraint(pcs, backend.PlonkConstraint{M: [2]backend.Term{res, rt}, R: negate(pcs, v)})
		}
	} else { // the unsolved wire is in the linear term (r1c.O)

		lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
		rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
		o, toSolve := popInternalVariable(o, id)
		ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

		// lt*rt-ot-coef.res = 0

		// lt*rt + u = 0
		u := newInternalVariable(pcs)
		recordConstraint(pcs, backend.PlonkConstraint{M: [2]backend.Term{lt, rt}, O: u})

		// u+ot+res = 0
		res := newInternalVariable(pcs)
		csPcsMapping[id] = res.VariableID()
		coef := cs.coeffs[toSolve.CoeffID()]
		res.SetCoeffID(coeffID(pcs, &coef))

		recordConstraint(pcs, backend.PlonkConstraint{R: u, L: ot, O: res})
	}
	solvedVariables[id] = true
}

// r1cToPlonkConstraintBinary splits a r1c constraint corresponding
// to a binary decomposition.
// if bi2^i=a (double indices=summation) then
// a = 2*a1+b0
// a2 = 2*a1+b1
// ...
// an = 2*an-1+bn-1
// b0,..,bn-1 is the binary decomposition
func r1cToPlonkConstraintBinary(pcs *pcs.UntypedPlonkCS, cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {

	// find which part is aibi
	var binDec backend.LinearExpression
	if len(r1c.L) > 1 {
		binDec = make(backend.LinearExpression, len(r1c.L))
		copy(binDec, r1c.L)
	} else { // normally this case should never occur, since from the api ToBinary fills the left linear exp...
		binDec = make(backend.LinearExpression, len(r1c.R))
		copy(binDec, r1c.R)
	}

	// reduce r1c.O (in case it's a linear combination)
	ot := split(pcs, 0, cs.coeffs, r1c.O, csPcsMapping)

	// split the linear expression
	nbBits := len(binDec)
	two := big.NewInt(2)
	one := big.NewInt(1)
	acc := big.NewInt(1)
	pcsTwoIdx := coeffID(pcs, two)
	pcsOneIdx := coeffID(pcs, one)

	// stores the id of the variables ai created
	accAi := make([]backend.Term, nbBits)
	accAi[0] = ot

	for i := 0; i < nbBits-1; i++ {

		// 2*ai+bi=ai-1
		bi := newInternalVariable(pcs)
		bi.SetCoeffID(coeffID(pcs, one))

		ai := newInternalVariable(pcs)
		ai.SetCoeffID(pcsTwoIdx)

		// find the variable corresponding to the i-th bit (it's not ordered since getLinExpCopy is not deterministic)
		// so we can update csPcsMapping
		for k := 0; k < len(binDec)-1; k++ {
			t := binDec[k]
			cID := t.CoeffID()
			coef := cs.coeffs[cID]
			if coef.Cmp(acc) == 0 {
				csID := t.VariableID()
				csPcsMapping[csID] = bi.VariableID()
				binDec = append(binDec[:k], binDec[k+1:]...)
				break
			}
		}
		acc.Mul(acc, two)

		o := accAi[i]
		// 2*ai + bi - a_i-1 = 0
		recordConstraint(pcs, backend.PlonkConstraint{L: ai, R: bi, O: negate(pcs, o), Solver: backend.BinaryDec})
		ai.SetCoeffID(pcsOneIdx)
		accAi[i+1] = ai
	}
	lastTerm := accAi[nbBits-1]
	csPcsMapping[binDec[0].VariableID()] = lastTerm.VariableID()

}

// r1cToPlonkAssertion splits a r1c assertion (meaning that
// it's a r1c constraint that is not used to solve a variable,
// like a boolean constraint).
// l*r = o -> reduce l,r,o to l',r',o', isolating the constants c0,c1,c2
// (l'+c0)(r'+c1) = o' + c2
// so l'r'+c0r'+c1l'+c0c1-c2-o'=0
func r1cToPlonkAssertion(pcs *pcs.UntypedPlonkCS, cs *ConstraintSystem, r1c backend.R1C, csPcsMapping map[idCS]idPCS) {

	var cID [4]int
	var pcsCoeffs [4]big.Int

	lCopy := make([]backend.Term, len(r1c.L))
	copy(lCopy, r1c.L)
	lCopy, cID[0] = popConstantTerm(lCopy, cs, pcs)
	rCopy := make([]backend.Term, len(r1c.R))
	copy(rCopy, r1c.R)
	rCopy, cID[1] = popConstantTerm(rCopy, cs, pcs)
	oCopy := make([]backend.Term, len(r1c.O))
	copy(oCopy, r1c.O)
	oCopy, cID[2] = popConstantTerm(oCopy, cs, pcs)

	pcsCoeffs[0] = pcs.Coeffs[cID[0]]
	pcsCoeffs[1] = pcs.Coeffs[cID[1]]
	pcsCoeffs[2] = pcs.Coeffs[cID[2]]

	lt := split(pcs, 0, cs.coeffs, lCopy, csPcsMapping)
	rt := split(pcs, 0, cs.coeffs, rCopy, csPcsMapping)
	ot := split(pcs, 0, cs.coeffs, oCopy, csPcsMapping)

	reducedCoef := pcs.Coeffs[rt.CoeffID()]
	reducedCoef.Mul(&pcsCoeffs[0], &reducedCoef)
	cID[0] = coeffID(pcs, &reducedCoef)

	reducedCoef = cs.coeffs[lt.CoeffID()]
	reducedCoef.Mul(&pcsCoeffs[1], &reducedCoef)
	cID[1] = coeffID(pcs, &reducedCoef)

	reducedCoef.Mul(&pcsCoeffs[0], &pcsCoeffs[1]).Sub(&reducedCoef, &pcsCoeffs[2])
	cID[2] = coeffID(pcs, &pcsCoeffs[3])

	var t [2]backend.Term
	t[0] = rt
	t[0].SetCoeffID(cID[0])

	t[1] = lt
	t[1].SetCoeffID(cID[1])

	toRecord := backend.PlonkConstraint{L: t[0], R: t[1], M: [2]backend.Term{lt, rt}, O: negate(pcs, ot), K: cID[2]}
	recordAssertion(pcs, toRecord)

}

func (cs *ConstraintSystem) toPlonk(curveID gurvy.ID) (pcs.CS, error) {

	// build the Coeffs slice
	var res pcs.UntypedPlonkCS

	res.NbPublicVariables = len(cs.public.variables)
	res.NbSecretVariables = len(cs.secret.variables)

	res.Constraints = make([]backend.PlonkConstraint, 0)
	res.Assertions = make([]backend.PlonkConstraint, 0)
	res.Coeffs = make([]big.Int, 1) // this slice is append only, so starting at 1 ensure that the zero ID is reserved to store 0
	res.CoeffsIDs = make(map[string]int)
	// reserve the zeroth entry to store 0
	zero := big.NewInt(0)
	coeffID(&res, zero)

	// cs_variable_id -> plonk_cs_variable_id
	varPcsToVarCs := make(map[idCS]idPCS)
	solvedVariables := make([]bool, len(cs.internal.variables))

	// convert the constraints invidually
	for i := 0; i < len(cs.constraints); i++ {
		r1cToPlonkConstraint(&res, cs, cs.constraints[i], varPcsToVarCs, solvedVariables)
	}
	for i := 0; i < len(cs.assertions); i++ {
		r1cToPlonkAssertion(&res, cs, cs.assertions[i], varPcsToVarCs)
	}

	// offset the ID in a term
	offsetIDTerm := func(t *backend.Term) error {

		// in a PLONK constraint, not all terms are necessarily set,
		// the terms which are not set are equal to zero. We just
		// need to skip them.
		if *t != 0 {
			_, _, cID, cVisibility := t.Unpack()
			switch cVisibility {
			case backend.Public:
				t.SetVariableID(cID + res.NbInternalVariables + res.NbSecretVariables)
			case backend.Secret:
				t.SetVariableID(cID + res.NbInternalVariables)
			case backend.Unset:
				//return fmt.Errorf("%w: %s", backend.ErrInputNotSet, cs.unsetVariables[0].format)
				return fmt.Errorf("%w", backend.ErrInputNotSet)
			}
		}

		return nil
	}

	offsetIDs := func(exp *backend.PlonkConstraint) error {
		err := offsetIDTerm(&exp.L)
		if err != nil {
			return err
		}
		err = offsetIDTerm(&exp.R)
		if err != nil {
			return err
		}
		err = offsetIDTerm(&exp.O)
		if err != nil {
			return err
		}
		err = offsetIDTerm(&exp.M[0])
		if err != nil {
			return err
		}
		err = offsetIDTerm(&exp.M[1])
		if err != nil {
			return err
		}
		return nil
	}

	// offset the IDs of all constraints to that the variables are
	// numbered like this: [internalVariables | secretVariables | publicVariables]
	// TODO WIP handle assertions
	for i := 0; i < len(res.Constraints); i++ {
		offsetIDs(&res.Constraints[i])
	}

	return &res, nil
}
