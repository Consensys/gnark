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

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

type idCS = int
type idPCS = int

func (cs *ConstraintSystem) toSparseR1CS(curveID ecc.ID) (CompiledConstraintSystem, error) {

	// build the Coeffs slice
	var res compiled.SparseR1CS

	res.NbPublicVariables = len(cs.public.variables) - 1 // the ONE_WIRE is discarded as it is not used in PLONK
	res.NbSecretVariables = len(cs.secret.variables)

	res.Constraints = make([]compiled.SparseR1C, 0, len(cs.constraints))
	res.Assertions = make([]compiled.SparseR1C, 0, len(cs.assertions))

	res.Logs = make([]compiled.LogEntry, len(cs.logs))

	// reserve first 3 coeffs for special values (0, 1 and -1)
	res.Coeffs = make([]big.Int, 3)
	res.Coeffs[0].SetInt64(0)
	res.Coeffs[1].SetInt64(1)
	res.Coeffs[2].SetInt64(-1)

	// coeffs ids
	res.CoeffsIDs = make(map[string]int)

	// cs_variable_id -> plonk_cs_variable_id (internal variables only)
	varPcsToVarCs := make(map[idCS]idPCS)
	solvedVariables := make([]bool, len(cs.internal.variables))

	// convert the constraints invidually
	for i := 0; i < len(cs.constraints); i++ {
		r1cToSparseR1C(&res, cs, cs.constraints[i], varPcsToVarCs, solvedVariables)
	}
	for i := 0; i < len(cs.assertions); i++ {
		splitR1C(&res, cs, cs.assertions[i], varPcsToVarCs)
	}

	// offset the ID in a term
	offsetIDTerm := func(t *compiled.Term) error {

		// in a PLONK constraint, not all terms are necessarily set,
		// the terms which are not set are equal to zero. We just
		// need to skip them.
		if *t != 0 {
			_, _, cID, cVisibility := t.Unpack()
			switch cVisibility {
			case compiled.Public:
				t.SetVariableID(cID - 1) // -1 because the ONE_WIRE's is not counted
			case compiled.Secret:
				t.SetVariableID(cID + res.NbPublicVariables)
			case compiled.Internal:
				t.SetVariableID(cID + res.NbPublicVariables + res.NbSecretVariables)
			case compiled.Unset:
				//return fmt.Errorf("%w: %s", ErrInputNotSet, cs.unsetVariables[0].format)
				return fmt.Errorf("%w", ErrInputNotSet)
			}
		}

		return nil
	}

	offsetIDs := func(exp *compiled.SparseR1C) error {

		// ensure that L=M[0] and R=M[1] (up to scalar mul)
		if exp.L.CoeffID() == 0 {
			if exp.M[0] != 0 {
				exp.L = exp.M[0]
				exp.L.SetCoeffID(0)
			}
		} else {
			if exp.M[0].CoeffID() == 0 {
				exp.M[0] = exp.L
				exp.M[0].SetCoeffID(0)
			}
		}

		if exp.R.CoeffID() == 0 {
			if exp.M[1] != 0 {
				exp.R = exp.M[1]
				exp.R.SetCoeffID(0)
			}
		} else {
			if exp.M[1].CoeffID() == 0 {
				exp.M[1] = exp.R
				exp.M[1].SetCoeffID(0)
			}
		}

		// offset each term in the constraint
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

	// offset the IDs of all constraints so that the variables are
	// numbered like this: [publicVariables| secretVariables | internalVariables ]
	for i := 0; i < len(res.Constraints); i++ {
		offsetIDs(&res.Constraints[i])
	}
	for i := 0; i < len(res.Assertions); i++ {
		offsetIDs(&res.Assertions[i])
	}

	// offset IDs in the logs
	for i := 0; i < len(cs.logs); i++ {
		entry := compiled.LogEntry{
			Format:    cs.logs[i].format,
			ToResolve: make([]int, len(cs.logs[i].toResolve)),
		}
		for j := 0; j < len(cs.logs[i].toResolve); j++ {
			_, _, cID, cVisibility := cs.logs[i].toResolve[j].Unpack()
			switch cVisibility {
			case compiled.Public:
				entry.ToResolve[j] += cID - 1 //+ res.NbInternalVariables + res.NbSecretVariables // -1 because the ONE_WIRE's is not counted
			case compiled.Secret:
				entry.ToResolve[j] += cID + res.NbPublicVariables
			case compiled.Internal:
				entry.ToResolve[j] = varPcsToVarCs[cID] + res.NbSecretVariables + res.NbPublicVariables
			case compiled.Unset:
				panic("encountered unset visibility on a variable in logs id offset routine")
			}
		}
		res.Logs[i] = entry
	}

	switch curveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewSparseR1CS(res, res.Coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewSparseR1CS(res, res.Coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewSparseR1CS(res, res.Coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewSparseR1CS(res, res.Coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewSparseR1CS(res, res.Coeffs), nil
	case ecc.UNKNOWN:
		return &res, nil
	default:
		panic("not implemtented")
	}

}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of Coeffs and returns the corresponding entry
func coeffID(pcs *compiled.SparseR1CS, b *big.Int) int {
	// if the coeff is a int64, and has value -1, 0 or 1, we have a fast path.
	if b.IsInt64() {
		v := b.Int64()
		switch v {
		case 0:
			return 0
		case 1:
			return 1
		case -1:
			return 2
		}
	}

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
func findUnsolvedVariable(r1c compiled.R1C, solvedVariables []bool) (pos int, id int) {
	// find the variable to solve among L,R,O. pos=0,1,2 corresponds to left,right,o.
	pos = -1
	id = -1
	for i := 0; i < len(r1c.L); i++ {
		v := r1c.L[i].VariableVisibility()
		if v != compiled.Internal {
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
			if v != compiled.Internal {
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
			if v != compiled.Internal {
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
// returns the reduced linear expression and the ID of the coeff corresponding to the constant term (in pcs.Coeffs).
// If there is no constant term, the id is 0 (the 0-th entry is reserved for this purpose).
func popConstantTerm(l compiled.LinearExpression, cs *ConstraintSystem, pcs *compiled.SparseR1CS) (compiled.LinearExpression, int) {

	idOneWire := 0
	resConstantID := 0 // the zero index contains the zero coef, it is reserved
	var coef big.Int

	lCopy := make(compiled.LinearExpression, len(l))
	copy(lCopy, l)
	for i := 0; i < len(l); i++ {
		t := lCopy[i]
		id := t.VariableID()
		vis := t.VariableVisibility()
		if vis == compiled.Public && id == idOneWire {
			coefID := t.CoeffID()
			coef.Set(&cs.coeffs[coefID])
			resConstantID = coeffID(pcs, &coef)
			lCopy = append(lCopy[:i], lCopy[i+1:]...)
			break
		}
	}
	return lCopy, resConstantID
}

// change t's ID to csPcsMapping[t.ID] to get the corresponding variable in the pcs,
// the coeff ID is changed as well so that it corresponds to a coeff in the pcs.
func getCorrespondingTerm(pcs *compiled.SparseR1CS, t compiled.Term, csCoeffs []big.Int, csPcsMapping map[idCS]idPCS) compiled.Term {

	// if the variable is internal, we need the variable
	// that corresponds in the pcs
	if t.VariableVisibility() == compiled.Internal {
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
func newInternalVariable(pcs *compiled.SparseR1CS, t ...compiled.Term) compiled.Term {

	if len(t) == 0 {
		cID := coeffID(pcs, bOne)
		vID := pcs.NbInternalVariables
		res := compiled.Pack(vID, cID, compiled.Internal)
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
func recordConstraint(pcs *compiled.SparseR1CS, c compiled.SparseR1C) {
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
func recordAssertion(pcs *compiled.SparseR1CS, c compiled.SparseR1C) {
	pcs.Assertions = append(pcs.Assertions, c)
}

// if t=a*variable, it returns -a*variable
func negate(pcs *compiled.SparseR1CS, t compiled.Term) compiled.Term {
	// non existing term are zero, if we negate it it's no
	// longer zero and checks to see if a variable exist will
	// fail (ex: in r1cToPlonkConstraint we might call negate
	// on non existing variables, when split is called with
	// le = nil)
	if t == 0 {
		return t
	}
	var coeff big.Int
	coeff.Set(&pcs.Coeffs[t.CoeffID()])
	coeff.Neg(&coeff)
	cID := coeffID(pcs, &coeff)
	t.SetCoeffID(cID)
	return t
}

// multiplies t by the coeff corresponding to idCoeff.
func multiply(pcs *compiled.SparseR1CS, t compiled.Term, idCoeff int) compiled.Term {
	var c big.Int
	c.Set(&pcs.Coeffs[t.CoeffID()])
	c.Mul(&c, &pcs.Coeffs[idCoeff])
	newID := coeffID(pcs, &c)
	t.SetCoeffID(newID)
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
func split(pcs *compiled.SparseR1CS, acc compiled.Term, csCoeffs []big.Int, le compiled.LinearExpression, csPcsMapping map[idCS]idPCS) compiled.Term {

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
	recordConstraint(pcs, compiled.SparseR1C{L: acc, R: r, O: o})
	o = negate(pcs, o)
	return split(pcs, o, csCoeffs, le[1:], csPcsMapping)

}

func r1cToSparseR1C(pcs *compiled.SparseR1CS, cs *ConstraintSystem, r1c compiled.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {
	if r1c.Solver == compiled.SingleOutput {
		r1cToPlonkConstraintSingleOutput(pcs, cs, r1c, csPcsMapping, solvedVariables)
	} else {
		r1cToPlonkConstraintBinary(pcs, cs, r1c, csPcsMapping, solvedVariables)
	}
}

// r1cToPlonkConstraintSingleOutput splits a r1c constraint
func r1cToPlonkConstraintSingleOutput(pcs *compiled.SparseR1CS, cs *ConstraintSystem, r1c compiled.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, idCS := findUnsolvedVariable(r1c, solvedVariables)

	o := r1c.O
	l := r1c.L
	r := r1c.R

	// if the unsolved variable in not in o,
	// ensure that it is in r1c.L
	if lro == 1 {
		l, r = r, l
		lro = 0
	}

	// // the unsolved wire is in r1c.L
	if lro == 0 {

		// pop the unsolved wire from the linearexpression
		l, toSolve := popInternalVariable(l, idCS)
		l, constantl := popConstantTerm(l, cs, pcs)
		r, constantr := popConstantTerm(r, cs, pcs)
		o, constanto := popConstantTerm(o, cs, pcs)

		if len(o) == 0 {
			if len(l) == 0 {
				if len(r) == 0 { // (toSolve + constantl)*constantr = constanto

					var constk, c big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					c.Set(&cs.coeffs[toSolve.CoeffID()])
					c.Mul(&c, &pcs.Coeffs[constantr])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)

					recordConstraint(pcs, compiled.SparseR1C{L: res, K: kID})

				} else { // (toSolve + constantl)*(r + constantr) = constanto

					var constk, c big.Int

					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					c.Set(&cs.coeffs[toSolve.CoeffID()])
					id := coeffID(pcs, &c)
					res.SetCoeffID(id)

					rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
					constlrt := multiply(pcs, rt, constantl)
					constrres := multiply(pcs, res, constantr)

					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					recordConstraint(pcs, compiled.SparseR1C{
						L: constrres,
						R: constlrt,
						M: [2]compiled.Term{res, rt},
						K: kID,
					})

				}
			} else {
				if len(r) == 0 { // (toSolve + l + constantl)*constantr = constanto

					lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
					lt = multiply(pcs, lt, constantr)

					var constk, c big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					c.Set(&cs.coeffs[toSolve.CoeffID()])
					c.Mul(&c, &pcs.Coeffs[constantr])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)

					recordConstraint(pcs, compiled.SparseR1C{
						L: res,
						R: lt,
						K: kID,
					})

				} else { // (toSolve + l + constantl)*(r + constantr) = constanto
					// => toSolve*r + toSolve*constantr + [ l*r + l*constantr +constantl*r+constantl*constantr-constanto ]=0

					u := newInternalVariable(pcs)
					lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
					rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
					constrlt := multiply(pcs, lt, constantr)
					constlrt := multiply(pcs, rt, constantl)

					var constk big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					recordConstraint(pcs, compiled.SparseR1C{
						L: constrlt,
						R: constlrt,
						M: [2]compiled.Term{lt, rt},
						O: u,
						K: kID,
					})

					var c big.Int
					c.Set(&cs.coeffs[toSolve.CoeffID()])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)
					constrres := multiply(pcs, res, constantr)

					recordConstraint(pcs, compiled.SparseR1C{
						R: constrres,
						M: [2]compiled.Term{res, rt},
						O: negate(pcs, u),
					})
				}
			}
		} else {
			if len(l) == 0 {
				if len(r) == 0 { // (toSolve + constantl)*constantr = o + constanto

					ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

					var constk, c big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					c.Set(&cs.coeffs[toSolve.CoeffID()])
					c.Mul(&c, &pcs.Coeffs[constantr])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)

					recordConstraint(pcs, compiled.SparseR1C{L: res, O: negate(pcs, ot), K: kID})

				} else { // (toSolve + constantl)*(r + constantr) = o + constanto
					// toSolve*r + toSolve*constantr+constantl*r+constantl*constantr-constanto-o=0

					ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

					var constk, c big.Int

					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					c.Set(&cs.coeffs[toSolve.CoeffID()])
					id := coeffID(pcs, &c)
					res.SetCoeffID(id)

					rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
					constlrt := multiply(pcs, rt, constantl)
					constrres := multiply(pcs, res, constantr)

					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					recordConstraint(pcs, compiled.SparseR1C{
						L: constrres,
						R: constlrt,
						M: [2]compiled.Term{res, rt},
						O: negate(pcs, ot),
						K: kID,
					})

				}
			} else {
				if len(r) == 0 { // (toSolve + l + constantl)*constantr = o + constanto
					// toSolve*constantr + l*constantr + constantl*constantr-constanto-o=0

					ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

					lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
					lt = multiply(pcs, lt, constantr)

					var constk, c big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					c.Set(&cs.coeffs[toSolve.CoeffID()])
					c.Mul(&c, &pcs.Coeffs[constantr])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)

					recordConstraint(pcs, compiled.SparseR1C{
						L: res,
						R: lt,
						O: negate(pcs, ot),
						K: kID,
					})

				} else { // (toSolve + l + constantl)*(r + constantr) = o + constanto

					// => toSolve*r + toSolve*constantr + [ [l*r + l*constantr +constantl*r+constantl*constantr-constanto]- o ]=0

					// [l*r + l*constantr +constantl*r+constantl*constantr-constanto] + u = 0
					u := newInternalVariable(pcs)
					lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
					rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
					constrlt := multiply(pcs, lt, constantr)
					constlrt := multiply(pcs, rt, constantl)

					var constk big.Int
					constk.Set(&pcs.Coeffs[constantl])
					constk.Mul(&constk, &pcs.Coeffs[constantr])
					constk.Sub(&constk, &pcs.Coeffs[constanto])
					kID := coeffID(pcs, &constk)

					recordConstraint(pcs, compiled.SparseR1C{
						L: constrlt,
						R: constlrt,
						M: [2]compiled.Term{lt, rt},
						O: u,
						K: kID,
					})

					// u+o+v = 0 (v = -u - o = [l*r + l*constantr +constantl*r+constantl*constantr-constanto] -  o)
					v := newInternalVariable(pcs)
					ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)
					recordConstraint(pcs, compiled.SparseR1C{
						L: u,
						R: ot,
						O: v,
					})

					// toSolve*r + toSolve*constantr + v = 0
					var c big.Int
					c.Set(&cs.coeffs[toSolve.CoeffID()])
					id := coeffID(pcs, &c)
					res := newInternalVariable(pcs)
					csPcsMapping[idCS] = res.VariableID()
					res.SetCoeffID(id)
					constrres := multiply(pcs, res, constantr)

					recordConstraint(pcs, compiled.SparseR1C{
						R: constrres,
						M: [2]compiled.Term{res, rt},
						O: v,
					})
				}
			}
		}
		solvedVariables[idCS] = true
		return
	}

	// the unsolved wire is in r1c.O
	l, constantl := popConstantTerm(l, cs, pcs)
	r, constantr := popConstantTerm(r, cs, pcs)
	o, toSolve := popInternalVariable(o, idCS)
	o, constanto := popConstantTerm(o, cs, pcs)

	if len(o) == 0 {

		if len(l) == 0 {

			if len(r) == 0 { // constantl*constantr = toSolve + constanto

				var constk, c big.Int
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{K: kID, O: res})

			} else { // constantl*(r + constantr) = toSolve + constanto
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)

				var constk, c big.Int
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{R: constlrt, K: kID, O: res})

			}

		} else {
			if len(r) == 0 { // (l + constantl)*constantr = toSolve + constanto

				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)

				var constk big.Int
				constrlt := multiply(pcs, lt, constantr)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				var c big.Int
				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{L: constrlt, O: res, K: kID})

			} else { // (l + constantl)*(r + constantr) = toSolve + constanto

				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)

				var constk big.Int
				constrlt := multiply(pcs, lt, constantr)
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				var c big.Int
				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{
					L: constrlt,
					R: constlrt,
					M: [2]compiled.Term{lt, rt},
					K: kID,
					O: res,
				})
			}
		}

	} else {
		if len(l) == 0 {
			if len(r) == 0 { // constantl*constantr = toSolve + o + constanto

				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk, c big.Int
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				constk.Neg(&constk)
				kID := coeffID(pcs, &constk)

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{L: ot, K: kID, O: res})

			} else { // constantl*(r + constantr) = toSolve + o + constanto
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk, c big.Int
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				constk.Neg(&constk)
				kID := coeffID(pcs, &constk)

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{L: negate(pcs, ot), R: constlrt, K: kID, O: res})

			}
		} else {
			if len(r) == 0 { // (l + constantl)*constantr = toSolve + o + constanto

				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk, c big.Int
				constrlt := multiply(pcs, lt, constantr)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				constk.Neg(&constk)
				kID := coeffID(pcs, &constk)

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				c.Neg(&c)
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()

				recordConstraint(pcs, compiled.SparseR1C{R: negate(pcs, ot), L: constrlt, K: kID, O: res})

			} else { // (l + constantl)*(r + constantr) = toSolve + o + constanto
				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk, c big.Int
				constrlt := multiply(pcs, lt, constantr)
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				constk.Neg(&constk)
				kID := coeffID(pcs, &constk)

				u := newInternalVariable(pcs)
				recordConstraint(pcs, compiled.SparseR1C{
					L: constrlt,
					R: constlrt,
					M: [2]compiled.Term{lt, rt},
					K: kID,
					O: u,
				})

				c.Set(&cs.coeffs[toSolve.CoeffID()])
				id := coeffID(pcs, &c)
				res := newInternalVariable(pcs)
				res.SetCoeffID(id)
				csPcsMapping[idCS] = res.VariableID()
				recordConstraint(pcs, compiled.SparseR1C{
					L: u,
					R: ot,
					O: res,
				})
			}
		}
	}
	solvedVariables[idCS] = true
}

// r1cToPlonkConstraintBinary splits a r1c constraint corresponding
// to a binary decomposition.
func r1cToPlonkConstraintBinary(pcs *compiled.SparseR1CS, cs *ConstraintSystem, r1c compiled.R1C, csPcsMapping map[idCS]idPCS, solvedVariables []bool) {

	// from cs_api, le binary decomposition is r1c.L
	binDec := make(compiled.LinearExpression, len(r1c.L))
	copy(binDec, r1c.L)

	// reduce r1c.O (in case it's a linear combination)
	var ot compiled.Term
	o, constanto := popConstantTerm(r1c.O, cs, pcs)
	if len(o) == 0 { // o is a constant term
		ot = newInternalVariable(pcs)
		recordConstraint(pcs, compiled.SparseR1C{L: negate(pcs, ot), K: constanto})
	} else {
		ot = split(pcs, 0, cs.coeffs, o, csPcsMapping)
		if constanto != 0 {
			_ot := newInternalVariable(pcs)
			recordConstraint(pcs, compiled.SparseR1C{L: ot, O: negate(pcs, _ot), K: constanto}) // _ot+ot+K = 0
			ot = _ot
		}
	}

	// split the linear expression
	nbBits := len(binDec)
	two := big.NewInt(2)
	acc := big.NewInt(1)
	pcsTwoIdx := coeffID(pcs, two)

	// accumulators for the quotients and remainders when dividing by 2
	accRi := make([]compiled.Term, nbBits) // accRi[0] -> LSB
	accQi := make([]compiled.Term, nbBits+1)
	accQi[0] = ot

	for i := 0; i < nbBits; i++ {

		accRi[i] = newInternalVariable(pcs)
		accQi[i+1] = newInternalVariable(pcs)

		// find the variable corresponding to the i-th bit (it's not ordered since getLinExpCopy is not deterministic)
		// so we can update csPcsMapping
		for k := 0; k < len(binDec); k++ {
			t := binDec[k]
			coef := cs.coeffs[t.CoeffID()]
			if coef.Cmp(acc) == 0 {
				csPcsMapping[t.VariableID()] = accRi[i].VariableID()
				solvedVariables[t.VariableID()] = true
				binDec = append(binDec[:k], binDec[k+1:]...)
				break
			}
		}
		acc.Mul(acc, two)

		// 2*q[i+1] + ri - q[i] = 0
		recordConstraint(pcs, compiled.SparseR1C{
			L:      multiply(pcs, accQi[i+1], pcsTwoIdx),
			R:      accRi[i],
			O:      negate(pcs, accQi[i]),
			Solver: compiled.BinaryDec,
		})
	}
}

// splitR1C splits a r1c assertion (meaning that
// it's a r1c constraint that is not used to solve a variable,
// like a boolean constraint).
// (l + constantl)*(r + constantr) = o + constanto
func splitR1C(pcs *compiled.SparseR1CS, cs *ConstraintSystem, r1c compiled.R1C, csPcsMapping map[idCS]idPCS) {

	l := make(compiled.LinearExpression, len(r1c.L))
	r := make(compiled.LinearExpression, len(r1c.R))
	o := make(compiled.LinearExpression, len(r1c.O))
	copy(l, r1c.L)
	copy(r, r1c.R)
	copy(o, r1c.O)

	l, constantl := popConstantTerm(l, cs, pcs)
	r, constantr := popConstantTerm(r, cs, pcs)
	o, constanto := popConstantTerm(o, cs, pcs)

	if len(o) == 0 {

		if len(l) == 0 {

			if len(r) == 0 { // constantl*constantr = constanto (should never happen...)

				var constk big.Int
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{K: kID})

			} else { // constantl*(r + constantr) = constanto

				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)

				var constk big.Int
				cosntlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{R: cosntlrt, K: kID})
			}

		} else {

			if len(r) == 0 { // (l + constantl)*constantr = constanto
				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)

				var constk big.Int
				constrlt := multiply(pcs, lt, constantr)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{L: constrlt, K: kID})

			} else { // (l + constantl)*(r + constantr) = constanto

				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)

				var constk big.Int
				constrlt := multiply(pcs, lt, constantr)
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{
					L: constrlt,
					R: constlrt,
					M: [2]compiled.Term{lt, rt},
					K: kID,
				})
			}
		}

	} else {
		if len(l) == 0 {

			if len(r) == 0 { // constantl*constantr = o + constanto

				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk big.Int
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{K: kID, O: negate(pcs, ot)})

			} else { // constantl * (r + constantr) = o + constanto

				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk big.Int
				constlrt := multiply(pcs, rt, constantl)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{
					R: constlrt,
					K: kID,
					O: negate(pcs, ot),
				})
			}

		} else {
			if len(r) == 0 { // (l + constantl) * constantr = o + constanto

				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk big.Int
				constrlt := multiply(pcs, lt, constantr)
				constk.Set(&pcs.Coeffs[constantl])
				constk.Mul(&constk, &pcs.Coeffs[constantr])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordAssertion(pcs, compiled.SparseR1C{
					L: constrlt,
					K: kID,
					O: negate(pcs, ot),
				})

			} else { // (l + constantl)*(r + constantr) = o + constanto
				lt := split(pcs, 0, cs.coeffs, l, csPcsMapping)
				rt := split(pcs, 0, cs.coeffs, r, csPcsMapping)
				ot := split(pcs, 0, cs.coeffs, o, csPcsMapping)

				var constk big.Int

				constlrt := multiply(pcs, rt, constantl)
				constrlt := multiply(pcs, lt, constantr)
				constk.Set(&pcs.Coeffs[constantr])
				constk.Mul(&constk, &pcs.Coeffs[constantl])
				constk.Sub(&constk, &pcs.Coeffs[constanto])
				kID := coeffID(pcs, &constk)

				recordConstraint(pcs, compiled.SparseR1C{
					L: constrlt,
					R: constlrt,
					M: [2]compiled.Term{lt, rt},
					K: kID,
					O: negate(pcs, ot),
				})
			}
		}
	}
}
