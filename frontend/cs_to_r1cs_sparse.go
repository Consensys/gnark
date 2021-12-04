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
	"sort"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

// sparseR1CS extends the ConstraintSystem
// alongside with some intermediate data structures needed to convert from
// ConstraintSystem representataion to SparseR1CS
type sparseR1CS struct {
	*R1CS

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

var bOne = new(big.Int).SetInt64(1)

func (cs *R1CS) toSparseR1CS(curveID ecc.ID) (CompiledConstraintSystem, error) {

	res := sparseR1CS{
		R1CS: cs,
		ccs: compiled.SparseR1CS{
			CS: compiled.CS{
				NbInternalVariables: cs.internal,
				NbPublicVariables:   len(cs.public) - 1, // the ONE_WIRE is discarded in PlonK
				NbSecretVariables:   len(cs.secret),
				DebugInfo:           make([]compiled.LogEntry, len(cs.debugInfo)),
				Logs:                make([]compiled.LogEntry, len(cs.logs)),
				MDebug:              make(map[int]int),
				MHints:              make(map[int]compiled.Hint, len(cs.mHints)),
				Counters:            make([]compiled.Counter, len(cs.counters)),
			},
			Constraints: make([]compiled.SparseR1C, 0, len(cs.constraints)),
		},
		solvedVariables:      make([]bool, cs.internal, cs.internal*2),
		scsInternalVariables: cs.internal,
		currentR1CDebugID:    -1,
	}

	// logs, debugInfo and hints are copied, the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// we mark hint wires are solved
	// each R1C from the frontend.ConstraintSystem is allowed to have at most one unsolved wire
	// excluding hints. We mark hint wires as "solved" to ensure spliting R1C to SparseR1C
	// won't create invalid SparseR1C constraint with more than one wire to solve for the solver
	for VID := range cs.mHints {
		res.solvedVariables[VID] = true
	}

	// clone the counters
	res.counters = cs.counters
	// counters := make([]Counter, len(cs.counters))
	// copy(counters, cs.counters)

	// convert the R1C to SparseR1C
	// in particular, all linear expressions that appear in the R1C
	// will be split in multiple constraints in the SparseR1C
	var i int
	for i = 0; i < len(cs.constraints); i++ {
		// we set currentR1CDebugID to the debugInfo ID corresponding to the R1C we're processing
		// if present. All constraints created throuh addConstraint will add a new mapping
		if dID, ok := cs.mDebug[i]; ok {
			res.currentR1CDebugID = dID
		} else {
			res.currentR1CDebugID = -1
		}
		// mesure delta in what the convertion adds as new contraints and new variables
		Δc := len(res.ccs.Constraints)
		Δv := res.scsInternalVariables

		// res.r1cToSparseR1C(cs.constraints[i])
		res.r1cToSparseR1C(cs.constraints[i])

		Δc = len(res.ccs.Constraints) - Δc - 1 // interested in newly added constraints only
		Δv = res.scsInternalVariables - Δv

		// shift the counters. should maybe be done only when -debug is set?
		// res.shiftCounters(counters, i, Δc, Δv)
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
		_, VID, visibility := t.Unpack()
		if VID == 0 && visibility == compiled.Public {
			// this would not happen in a plonk constraint as the constant term has been popped out
			// however it may happen in the logs or the hints that contains
			// terms associated with the ONE wire
			// workaround; we set the visibility to Virtual so that the solver recognizes that as a constant
			t.SetVariableVisibility(compiled.Virtual)
			return
		}
		t.SetWireID(shiftVID(VID, visibility))
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

	// we need to offset the ids in logs & debugInfo
	for i := 0; i < len(cs.logs); i++ {
		res.ccs.Logs[i] = compiled.LogEntry{
			Format:    cs.logs[i].Format,
			ToResolve: make([]compiled.Term, len(cs.logs[i].ToResolve)),
		}
		copy(res.ccs.Logs[i].ToResolve, cs.logs[i].ToResolve)

		for j := 0; j < len(res.ccs.Logs[i].ToResolve); j++ {
			offsetTermID(&res.ccs.Logs[i].ToResolve[j])
		}
	}
	for i := 0; i < len(cs.debugInfo); i++ {
		res.ccs.DebugInfo[i] = compiled.LogEntry{
			Format:    cs.debugInfo[i].Format,
			ToResolve: make([]compiled.Term, len(cs.debugInfo[i].ToResolve)),
		}
		copy(res.ccs.DebugInfo[i].ToResolve, cs.debugInfo[i].ToResolve)

		for j := 0; j < len(res.ccs.DebugInfo[i].ToResolve); j++ {
			offsetTermID(&res.ccs.DebugInfo[i].ToResolve[j])
		}
	}

	// we need to offset the ids in the hints
	for VID, hint := range cs.mHints {
		k := shiftVID(VID, compiled.Internal)
		inputs := make([]compiled.LinearExpression, len(hint.Inputs))
		copy(inputs, hint.Inputs)
		for j := 0; j < len(inputs); j++ {
			for k := 0; k < len(inputs[j]); k++ {
				offsetTermID(&inputs[j][k])
			}
		}
		res.ccs.MHints[k] = compiled.Hint{ID: hint.ID, Inputs: inputs}
	}

	// update number of internal variables with new wires created
	// while processing R1C -> SparseR1C
	res.ccs.NbInternalVariables = res.scsInternalVariables

	// set the counters
	// for i, c := range counters {
	// 	res.ccs.Counters[i] = compiled.Counter{
	// 		From:          c.From.Name,
	// 		To:            c.To.Name,
	// 		NbVariables:   c.NbVariables,
	// 		NbConstraints: c.NbConstraints,
	// 		CurveID:       curveID,
	// 		BackendID:     backend.PLONK,
	// 	}
	// }

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
	case ecc.BW6_633:
		return bw6633r1cs.NewSparseR1CS(res.ccs, cs.coeffs), nil
	default:
		panic("unknown curveID")
	}

}

// findUnsolvedVariable returns the variable to solve in the r1c. The variables
// which are not internal are considered solved, otherwise the solvedVariables
// slice hold the record of which variables have been solved.
func findUnsolvedVariable(r1c compiled.R1C, solvedVariables []bool) (int, int) {
	// find the variable to solve among L,R,O. pos=0,1,2 corresponds to left,right,o.
	for i := 0; i < len(r1c.L.LinExp); i++ {
		_, VID, visibility := r1c.L.LinExp[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[VID] {
			return 0, VID
		}
	}
	for i := 0; i < len(r1c.R.LinExp); i++ {
		_, VID, visibility := r1c.R.LinExp[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[VID] {
			return 1, VID
		}
	}
	for i := 0; i < len(r1c.O.LinExp); i++ {
		_, VID, visibility := r1c.O.LinExp[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[VID] {
			return 2, VID
		}
	}
	return -1, -1
}

// newTerm creates a new term =coeff*new_variable and records it in the scs
// if idCS is set, uses it as variable id and does not increment the number
// of new internal variables created
func (scs *sparseR1CS) newTerm(coeff *big.Int, idCS ...int) compiled.Term {
	var VID int
	if len(idCS) > 0 {
		VID = idCS[0]
		scs.solvedVariables[VID] = true
	} else {
		VID = scs.scsInternalVariables
		scs.scsInternalVariables++
		scs.solvedVariables = append(scs.solvedVariables, true)
	}

	return compiled.Pack(VID, scs.coeffID(coeff), compiled.Internal)
}

// addConstraint records a plonk constraint in the ccs
// The function ensures that all variables ID are set, even
// if the corresponding coefficients are 0.
// A plonk constraint will always look like this:
// L+R+L.R+O+K = 0
func (scs *sparseR1CS) addConstraint(c compiled.SparseR1C) {
	// ensure wire(L) == wire(M[0]) && wire(R) == wire(M[1])
	if c.L == 0 {
		c.L.SetWireID(c.M[0].WireID())
	}
	if c.R == 0 {
		c.R.SetWireID(c.M[1].WireID())
	}
	if c.M[0] == 0 {
		c.M[0].SetWireID(c.L.WireID())
	}
	if c.M[1] == 0 {
		c.M[1].SetWireID(c.R.WireID())
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
	CID := t.CoeffID()
	switch CID {
	case compiled.CoeffIdMinusOne:
		t.SetCoeffID(compiled.CoeffIdOne)
	case compiled.CoeffIdZero:
		// do nothing.
	case compiled.CoeffIdOne:
		t.SetCoeffID(compiled.CoeffIdMinusOne)
	default:
		coeff := bigIntPool.Get().(*big.Int)
		coeff.Neg(&scs.coeffs[t.CoeffID()])
		t.SetCoeffID(scs.coeffID(coeff))
		bigIntPool.Put(coeff)
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

// split decomposes the linear expression into a single term
// for example 2a + 3b + c will be decomposed in
// v0 := 2a + 3b
// v1 := v0 + c
// return v1
func (scs *sparseR1CS) split(acc compiled.Term, l compiled.LinearExpression) compiled.Term {

	// floor case
	if len(l) == 0 {
		return acc
	}

	var a big.Int
	o := scs.newTerm(a.Neg(bOne))
	m1, m2 := acc, l[0]
	m1.SetCoeffID(compiled.CoeffIdZero)
	m2.SetCoeffID(compiled.CoeffIdZero)
	scs.addConstraint(compiled.SparseR1C{
		L: acc,
		R: l[0],
		M: [2]compiled.Term{m1, m2},
		O: o,
		K: compiled.CoeffIdZero,
	})
	return scs.split(scs.negate(o), l[1:])
}

func (scs *sparseR1CS) shiftCounters(counters []Counter, CID, Δc, Δv int) {
	// what we do here is see what's our resulting current constraintID vs the processID
	// for all counters, if the

	for i := 0; i < len(counters); i++ {
		if (counters[i].From.CID <= CID) && (counters[i].To.CID > CID) {
			// we are processing a constraint in the range of this counter.
			// so we should increment the counter new constraints and nw variables
			counters[i].NbConstraints += Δc
			counters[i].NbVariables += Δv
		}
	}
}

func (scs *sparseR1CS) r1cToSparseR1C(r1c compiled.R1C) {

	// find if the variable to solve is in the left, right, or o linear expression
	lro, idCS := findUnsolvedVariable(r1c, scs.solvedVariables)

	// sets the variable as solved if the constraint is not an assertion
	if lro != -1 {
		scs.solvedVariables[idCS] = true
	}

	s := len(r1c.R.LinExp)

	// special case: boolean constraint
	if *r1c.L.IsBoolean && lro == -1 { //} && len(r1c.L.LinExp) == 1 && scs.IsConstant(r1c.L) {
		lz := r1c.L.LinExp[0]
		lz.SetCoeffID(compiled.CoeffIdZero)
		var oz compiled.Term
		oz.SetCoeffID(compiled.CoeffIdZero)
		scs.addConstraint(compiled.SparseR1C{
			L: r1c.L.LinExp[0],
			R: lz,
			M: [2]compiled.Term{r1c.L.LinExp[0], scs.negate(r1c.L.LinExp[0])},
			O: oz,
			K: compiled.CoeffIdZero,
		})
		*r1c.L.IsBoolean = false //-> so next time there's a constraint with the same pattern (L*(a+b)=c), we don't go there
		return
	}

	// special cases: OR (XY=X+Y-res) and XOR (2XY = X+Y-res)
	if len(r1c.O.LinExp) == 3 {

		cl, _, _ := r1c.L.LinExp[0].Unpack()
		cr, _, _ := r1c.R.LinExp[0].Unpack()

		// OR
		if cl == cr {
			coeffID := compiled.CoeffIdZero
			scs.addConstraint(compiled.SparseR1C{
				L: scs.negate(r1c.L.LinExp[0]),
				R: scs.negate(r1c.R.LinExp[0]),
				M: [2]compiled.Term{r1c.L.LinExp[0], r1c.R.LinExp[0]},
				O: scs.negate(r1c.O.LinExp[0]),
				K: coeffID,
			})
		} else { //XOR (the only remaining possible case)
			coeffID := compiled.CoeffIdZero
			_l := r1c.L.LinExp[0]
			_l.SetCoeffID(cr)
			_l = scs.negate(_l)
			scs.addConstraint(compiled.SparseR1C{
				L: _l,
				R: scs.negate(r1c.R.LinExp[0]),
				M: [2]compiled.Term{r1c.L.LinExp[0], r1c.R.LinExp[0]},
				O: scs.negate(r1c.O.LinExp[0]),
				K: coeffID,
			})
		}
		return
	}

	// a*b=c case, where a, b, o are of length 1. It's either an assertion
	// or a operation of type Mul, Div, Inv.
	if lro == -1 || s == 1 {

		// l, r, o := r1c.L.LinExp[0], r1c.R.LinExp[0], r1c.O.LinExp[0]
		l := r1c.L.LinExp[0]
		r := r1c.R.LinExp[0]
		o := r1c.O.LinExp[0]

		// if the unsolved variable in not in o,
		// ensure that it is in r1c.L
		if lro != -1 {
			if lro == 1 {
				l, r = r, l
				lro = 0
			}
		}

		lCoeffID, lID, lVis := l.Unpack()
		rCoeffID, rID, rVis := r.Unpack()
		oCoeffID, oID, oVis := o.Unpack()

		lConst := (lVis == compiled.Public && lID == 0)
		rConst := (rVis == compiled.Public && rID == 0)
		oConst := (oVis == compiled.Public && oID == 0)

		if lConst && rConst && oConst {
			var c big.Int
			c.Mul(&scs.coeffs[lCoeffID], &scs.coeffs[rCoeffID]).
				Sub(&c, &scs.coeffs[oCoeffID])
			coeffID := scs.coeffID(&c)
			var lz, rz, oz compiled.Term
			lz.SetCoeffID(compiled.CoeffIdZero)
			rz.SetCoeffID(compiled.CoeffIdZero)
			oz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: rz,
				M: [2]compiled.Term{lz, rz},
				O: oz,
				K: coeffID,
			})
		} else if !lConst && rConst && oConst {
			l := scs.multiply(l, &scs.coeffs[rCoeffID])
			o = scs.negate(o)
			oCoeffID, _, _ = o.Unpack()
			o.SetCoeffID(compiled.CoeffIdZero)
			var rz, oz compiled.Term
			rz.SetCoeffID(compiled.CoeffIdZero)
			oz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: l,
				R: rz,
				M: [2]compiled.Term{l, rz},
				O: o,
				K: oCoeffID,
			})
		} else if lConst && !rConst && oConst {
			r := scs.multiply(r, &scs.coeffs[lCoeffID])
			o = scs.negate(o)
			oCoeffID, _, _ = o.Unpack()
			o.SetCoeffID(compiled.CoeffIdZero)
			var lz, oz compiled.Term
			lz.SetCoeffID(compiled.CoeffIdZero)
			oz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: r,
				M: [2]compiled.Term{lz, r},
				O: o,
				K: oCoeffID,
			})
		} else if !lConst && !rConst && oConst {
			r := scs.multiply(r, &scs.coeffs[lCoeffID])
			o = scs.negate(o)
			oCoeffID, _, _ = o.Unpack()
			o.SetCoeffID(compiled.CoeffIdZero)
			var rz, lz, oz compiled.Term
			lz = l
			rz = r
			rz.SetCoeffID(compiled.CoeffIdZero)
			lz.SetCoeffID(compiled.CoeffIdZero)
			oz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: rz,
				M: [2]compiled.Term{l, r},
				O: o,
				K: oCoeffID,
			})
		} else if lConst && rConst && !oConst {
			var c big.Int
			c.Mul(&scs.coeffs[lCoeffID], &scs.coeffs[rCoeffID])
			var lz, rz compiled.Term
			lz.SetCoeffID(compiled.CoeffIdZero)
			rz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: rz,
				M: [2]compiled.Term{lz, rz},
				O: scs.negate(o),
				K: scs.coeffID(&c),
			})
		} else if !lConst && rConst && !oConst {
			l = scs.multiply(l, &scs.coeffs[rCoeffID])
			var rz compiled.Term
			rz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: l,
				R: rz,
				M: [2]compiled.Term{l, rz},
				O: scs.negate(o),
				K: compiled.CoeffIdZero,
			})
		} else if lConst && !rConst && !oConst {
			r = scs.multiply(r, &scs.coeffs[lCoeffID])
			var lz compiled.Term
			lz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: r,
				M: [2]compiled.Term{lz, r},
				O: scs.negate(o),
				K: compiled.CoeffIdZero,
			})
		} else {
			lz, rz := l, r
			lz.SetCoeffID(compiled.CoeffIdZero)
			rz.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: lz,
				R: rz,
				M: [2]compiled.Term{l, r},
				O: scs.negate(o),
				K: compiled.CoeffIdZero,
			})
		}

		return
	}

	// Add, Sub cases, used in PLONK to factorize the linear expressions.
	scs.solvedVariables[idCS] = true

	var t compiled.Term

	sort.Sort(r1c.R.LinExp)

	// pop the constant term if it exists
	coeffID, VID, visID := r1c.R.LinExp[0].Unpack()

	firstTermIsPublic := (visID == compiled.Public) && VID == 0
	if !firstTermIsPublic {
		coeffID = compiled.CoeffIdZero
		t = scs.split(r1c.R.LinExp[0], r1c.R.LinExp[1:s-1])
	} else {
		if s == 2 {
			t.SetCoeffID(compiled.CoeffIdZero)
			scs.addConstraint(compiled.SparseR1C{
				L: t,
				R: r1c.R.LinExp[s-1],
				M: [2]compiled.Term{t, r1c.R.LinExp[s-1]},
				O: scs.negate(r1c.O.LinExp[0]),
				K: coeffID,
			})
			return
		}
		t = scs.split(r1c.R.LinExp[1], r1c.R.LinExp[2:s-1])
	}

	m1, m2 := t, r1c.R.LinExp[s-1]
	m1.SetCoeffID(compiled.CoeffIdZero)
	m2.SetCoeffID(compiled.CoeffIdZero)
	scs.addConstraint(compiled.SparseR1C{
		L: t,
		R: r1c.R.LinExp[s-1],
		M: [2]compiled.Term{m1, m2},
		O: scs.negate(r1c.O.LinExp[0]),
		K: coeffID,
	})

}

var bigIntPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}
