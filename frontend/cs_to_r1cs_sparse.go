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
	"github.com/consensys/gnark/backend"
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
	*constraintSystem

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

	// map LinearExpression -> Term. The goal is to not reduce
	// the same linear expression twice.
	// key == hashCode(linearExpression) (with collisions)
	// value == list of tuples {LinearExpression; reduced resulting Term}
	reducedLE map[uint64][]innerRecord

	// similarly to reducedLE, excepts, the key is the hashCodeNC() which doesn't take
	// into account the coefficient value of the terms
	// this is used to detect if a "similar" linear expression was already recorded when splitting
	reducedLE_ map[uint64]struct{}
}

type innerRecord struct {
	t compiled.Term
	l compiled.LinearExpression
}

var bOne = new(big.Int).SetInt64(1)

func (cs *constraintSystem) toSparseR1CS(curveID ecc.ID) (CompiledConstraintSystem, error) {

	res := sparseR1CS{
		constraintSystem: cs,
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
		reducedLE:            make(map[uint64][]innerRecord, cs.internal),
		reducedLE_:           make(map[uint64]struct{}, cs.internal),
	}

	// logs, debugInfo and hints are copied, the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// we mark hint wires are solved
	// each R1C from the frontend.ConstraintSystem is allowed to have at most one unsolved wire
	// excluding hints. We mark hint wires as "solved" to ensure spliting R1C to SparseR1C
	// won't create invalid SparseR1C constraint with more than one wire to solve for the solver
	for vID := range cs.mHints {
		res.solvedVariables[vID] = true
	}

	// clone the counters
	counters := make([]Counter, len(cs.counters))
	copy(counters, cs.counters)

	// convert the R1C to SparseR1C
	// in particular, all linear expressions that appear in the R1C
	// will be split in multiple constraints in the SparseR1C
	for i := 0; i < len(cs.constraints); i++ {
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

		res.r1cToSparseR1C(cs.constraints[i])

		Δc = len(res.ccs.Constraints) - Δc - 1 // interested in newly added constraints only
		Δv = res.scsInternalVariables - Δv

		// shift the counters. should maybe be done only when -debug is set?
		res.shiftCounters(counters, i, Δc, Δv)
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
	for vID, hint := range cs.mHints {
		k := shiftVID(vID, compiled.Internal)
		inputs := make([]compiled.Variable, len(hint.Inputs))
		copy(inputs, hint.Inputs)
		for j := 0; j < len(inputs); j++ {
			for k := 0; k < len(inputs[j].LinExp); k++ {
				offsetTermID(&inputs[j].LinExp[k])
			}
		}
		res.ccs.MHints[k] = compiled.Hint{ID: hint.ID, Inputs: inputs}
	}

	// update number of internal variables with new wires created
	// while processing R1C -> SparseR1C
	res.ccs.NbInternalVariables = res.scsInternalVariables

	// set the counters
	for i, c := range counters {
		res.ccs.Counters[i] = compiled.Counter{
			From:          c.From.Name,
			To:            c.To.Name,
			NbVariables:   c.NbVariables,
			NbConstraints: c.NbConstraints,
			CurveID:       curveID,
			BackendID:     backend.PLONK,
		}
	}

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
	for i := 0; i < len(r1c.L.LinExp); i++ {
		_, vID, visibility := r1c.L.LinExp[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[vID] {
			return 0, vID
		}
	}
	for i := 0; i < len(r1c.R.LinExp); i++ {
		_, vID, visibility := r1c.R.LinExp[i].Unpack()
		if visibility == compiled.Internal && !solvedVariables[vID] {
			return 1, vID
		}
	}
	for i := 0; i < len(r1c.O.LinExp); i++ {
		_, vID, visibility := r1c.O.LinExp[i].Unpack()
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

// as computeGCD, except, it fills the intermediate values such that gcds[i] == gcd(l[:i])
func (scs *sparseR1CS) computeGCDs(l compiled.LinearExpression, gcds []*big.Int) {
	mustNeg := scs.coeffs[l[0].CoeffID()].Sign() == -1

	gcds[0].Set(&scs.coeffs[l[0].CoeffID()])
	if mustNeg {
		gcds[0].Neg(gcds[0])
	}

	for i := 1; i < len(l); i++ {
		cID := l[i].CoeffID()

		if gcds[i-1].IsUint64() {
			// can be 0 or 1
			prev := gcds[i-1].Uint64()
			if prev == 0 {
				gcds[i].Abs(&scs.coeffs[cID])
				continue
			} else if prev == 1 {
				// set the rest to 1.
				for ; i < len(l); i++ {
					gcds[i].SetUint64(1)
				}
				continue
			}
		}

		// we  check coeffID here for 1 or minus 1
		if cID == compiled.CoeffIdMinusOne || cID == compiled.CoeffIdOne {
			gcds[i].SetUint64(1)
			continue
		}

		if cID == compiled.CoeffIdZero {
			gcds[i].Set(gcds[i-1])
			continue
		}

		// we compute the gcd.
		gcds[i].GCD(nil, nil, gcds[i-1], &scs.coeffs[cID])
	}
	if mustNeg {
		for i := 1; i < len(l); i++ {
			gcds[i].Neg(gcds[i])
		}
	}

}

// returns ( b/computeGCD(b...), computeGCD(b...) )
// if gcd is != 0 and gcd != 1, returns true
func (scs *sparseR1CS) computeGCD(l compiled.LinearExpression, gcd *big.Int) {
	mustNeg := scs.coeffs[l[0].CoeffID()].Sign() == -1

	// fast path: if any of the coeffs is 1 or -1, no need to compute the GCD
	if hasOnes(l) {
		if mustNeg {
			gcd.SetInt64(-1)
			return
		}
		gcd.SetUint64(1)
		return
	}

	gcd.SetUint64(0)
	var i int
	for i = 0; i < len(l); i++ {
		cID := l[i].CoeffID()
		if cID == compiled.CoeffIdZero {
			continue
		}
		gcd.Set(&scs.coeffs[cID])
		break
	}

	for ; i < len(l); i++ {
		cID := l[i].CoeffID()
		if cID == compiled.CoeffIdZero {
			continue
		}
		other := &scs.coeffs[cID]

		gcd.GCD(nil, nil, gcd, other)
		if gcd.IsUint64() && gcd.Uint64() == 1 {
			break
		}
	}

	if mustNeg {
		// ensure the gcd doesn't depend on the sign
		gcd.Neg(gcd)
	}

}

// return true if linear expression contains one or minusOne coefficients
func hasOnes(l compiled.LinearExpression) bool {
	for i := 0; i < len(l); i++ {
		cID := l[i].CoeffID()
		if cID == compiled.CoeffIdMinusOne || cID == compiled.CoeffIdOne {
			return true
		}
	}
	return false
}

// divides all coefficients in l by divisor
// if divisor == 0 or divisor == 1, returns l
func (scs *sparseR1CS) divideLinearExpression(l, r compiled.LinearExpression, divisor *big.Int) compiled.LinearExpression {
	if divisor.IsUint64() && (divisor.Uint64() == 0 || divisor.Uint64() == 1) {
		return l
	}

	// copy linear expression
	if r == nil {
		r = make(compiled.LinearExpression, len(l))
	}
	copy(r, l)

	// new coeff
	lambda := bigIntPool.Get().(*big.Int)

	if divisor.IsInt64() && divisor.Int64() == -1 {
		for i := 0; i < len(r); i++ {
			cID := r[i].CoeffID()
			if cID == compiled.CoeffIdZero {
				continue
			}
			lambda.Neg(&scs.coeffs[cID])
			r[i].SetCoeffID(scs.coeffID(lambda))
		}
		bigIntPool.Put(lambda)
		return r
	}

	for i := 0; i < len(r); i++ {
		cID := r[i].CoeffID()
		if cID == compiled.CoeffIdZero {
			continue
		}
		// we use Quo here instead of Div, as we know there is no remainder
		lambda.Quo(&scs.coeffs[cID], divisor)
		r[i].SetCoeffID(scs.coeffID(lambda))
	}

	bigIntPool.Put(lambda)
	return r
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

// newTerm creates a new term =coeff*new_variable and records it in the scs
// if idCS is set, uses it as variable id and does not increment the number
// of new internal variables created
func (scs *sparseR1CS) newTerm(coeff *big.Int, idCS ...int) compiled.Term {
	var vID int
	if len(idCS) > 0 {
		vID = idCS[0]
		scs.solvedVariables[vID] = true
	} else {
		vID = scs.scsInternalVariables
		scs.scsInternalVariables++
		scs.solvedVariables = append(scs.solvedVariables, true)
	}

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

// l is primitive
// that is, it has been factorized and we can't divide the coefficients further
func (scs *sparseR1CS) wasReduced(l compiled.LinearExpression) (compiled.Term, bool) {
	list, ok := scs.reducedLE[hashCode(l)]
	if !ok {
		return 0, false
	}

	for i := 0; i < len(list); i++ {
		if list[i].l.Equal(l) {
			return list[i].t, true
		}
	}

	return 0, false
}

// l is primitive
// that is, it has been factorized and we can't divide the coefficients further
func (scs *sparseR1CS) markReduced(l compiled.LinearExpression, t compiled.Term, ncHashCode uint64) {
	id := hashCode(l)
	list := scs.reducedLE[id]
	// here we know l is not already in the list, since the call to wasReduced returned false
	list = append(list, innerRecord{t: t, l: l})
	scs.reducedLE[id] = list
	scs.reducedLE_[ncHashCode] = struct{}{}
}

// split decomposes the linear expression into a single term
// for example 2a + 3b + c will be decomposed in
// v0 := 2a + 3b
// v1 := v0 + c
// return v1
//
// for optimal output, one need to check if we can't reuse previous decompositions to avoid duplicate constraints
func (scs *sparseR1CS) split(l compiled.LinearExpression) compiled.Term {
	// floor case
	if len(l) == 1 {
		return l[0]
	}

	gcd := bigIntPool.Get().(*big.Int)

	// lf = gcd * l
	// compute the GCD
	scs.computeGCD(l, gcd)

	// divide if needed l by gcd
	lf := scs.divideLinearExpression(l, nil, gcd)
	// if we already recorded lf, the resulting term is gcd * t
	if t, ok := scs.wasReduced(lf); ok {
		t.SetCoeffID(scs.coeffID(gcd))
		bigIntPool.Put(gcd)
		return t
	}

	// we create a new resulting term for this linear expression
	// o correspond to the factorized linear expression lf =  l / gcd
	// r correspond to the initial linear expression l
	// we record the factorized linear expression for potential later use
	o := scs.newTerm(bOne)
	r := scs.multiply(o, gcd)
	scs.markReduced(lf, o, hashCodeNC(lf))
	bigIntPool.Put(gcd)

	var gcds []*big.Int
	var scratch compiled.LinearExpression

	// idea: find an existing reduction that partially matches l

	// we compute a hash code of the sub expression that takes into account variables id and visibility
	// but not the coeffID. Since this is computed recursively, we store the result up for each lf[:i]
	hcs := hashCodeNC_(lf)

	for i := len(lf) - 1; i > 0; i-- {

		// first, we probabilistically check if it's worth it to factorize the sub expression
		if _, ok := scs.reducedLE_[hcs[i-1]]; !ok {
			// no need to factorize, no linear expression with same variables exist.
			continue
		}

		// we need to factorize, so since gcd (a,b,c) == gcd ( gcd (a,b), c)
		// we compute all gcds up to lf[:i] to use in future iterations
		if gcds == nil {
			gcds = make([]*big.Int, i)
			for i := 0; i < len(gcds); i++ {
				gcds[i] = bigIntPool.Get().(*big.Int)
			}
			scs.computeGCDs(lf[:i], gcds)
			scratch = make(compiled.LinearExpression, i)
		}

		// we divide the linear expression by the gcd, same idea as above
		// note that lff here reuses scratch space, but we never store it, we just compute
		// a hash code on it so we're fine
		lff := scs.divideLinearExpression(lf[:i], scratch[:i], gcds[i-1])

		if t, ok := scs.wasReduced(lff); ok {
			// the lff was already reduced
			// so we return r such that
			// r = (gcd * lff) + reduce(lf[i:])
			scs.addConstraint(compiled.SparseR1C{
				L: scs.multiply(t, gcds[i-1]),
				R: scs.split(lf[i:]),
				O: scs.negate(o),
			})

			for i := 0; i < len(gcds); i++ {
				bigIntPool.Put(gcds[i])
			}

			return r
		}
	}

	for i := 0; i < len(gcds); i++ {
		bigIntPool.Put(gcds[i])
	}

	// else we build the reduction starting from l[0]
	// that is we return a term r such that
	// r = l[0] + reduced(lf[1:])
	scs.addConstraint(compiled.SparseR1C{
		L: lf[0],
		R: scs.split(lf[1:]),
		O: scs.negate(o)},
	)

	return r
}

func (scs *sparseR1CS) shiftCounters(counters []Counter, cID, Δc, Δv int) {
	// what we do here is see what's our resulting current constraintID vs the processID
	// for all counters, if the

	for i := 0; i < len(counters); i++ {
		if (counters[i].From.cID <= cID) && (counters[i].To.cID > cID) {
			// we are processing a constraint in the range of this counter.
			// so we should increment the counter new constraints and nw variables
			counters[i].NbConstraints += Δc
			counters[i].NbVariables += Δv
		}
	}
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
	sort.Sort(l.LinExp)
	sort.Sort(r.LinExp)
	sort.Sort(o.LinExp)

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

	var cL, cR, cO big.Int
	l.LinExp, cL = scs.popConstantTerm(l.LinExp)
	r.LinExp, cR = scs.popConstantTerm(r.LinExp)
	o.LinExp, cO = scs.popConstantTerm(o.LinExp)

	// pop the unsolved wire from the linearexpression
	if lro == 0 { // unsolved is in L
		l.LinExp, toSolve = popInternalVariable(l.LinExp, idCS)
	} else { // unsolved is in O
		o.LinExp, toSolve = popInternalVariable(o.LinExp, idCS)
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
		rt := scs.split(r.LinExp)

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
		lt := scs.split(l.LinExp)

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
		lt := scs.split(l.LinExp)
		rt := scs.split(r.LinExp)

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
		ot := scs.split(o.LinExp)

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
		rt := scs.split(r.LinExp)
		ot := scs.split(o.LinExp)

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
		lt := scs.split(l.LinExp)
		ot := scs.split(o.LinExp)

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

		lt := scs.split(l.LinExp)
		rt := scs.split(r.LinExp)
		ot := scs.split(o.LinExp)

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

		rt := scs.split(r.LinExp)
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

		lt := scs.split(l.LinExp)
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

		lt := scs.split(l.LinExp)
		rt := scs.split(r.LinExp)
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
		ot := scs.split(o.LinExp)

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
		ot := scs.split(o.LinExp)
		res := scs.newTerm(&cS, idCS)

		rt := scs.split(r.LinExp)

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

		ot := scs.split(o.LinExp)
		lt := scs.split(l.LinExp)

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

		lt := scs.split(l.LinExp)
		rt := scs.split(r.LinExp)
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
		ot := scs.split(o.LinExp)
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
	if len(o.LinExp) != 0 {
		s |= 0b0100
	}
	if len(l.LinExp) != 0 {
		s |= 0b0010
	}
	if len(r.LinExp) != 0 {
		s |= 0b0001
	}

	switch s {
	case 0b0000:
		f9()
	case 0b0001:
		f10()
	case 0b0010:
		f11()
	case 0b0011:
		f12()
	case 0b0100:
		f13()
	case 0b0101:
		f14()
	case 0b0110:
		f15()
	case 0b0111:
		f16()
	case 0b1000:
		f1()
	case 0b1001:
		f2()
	case 0b1010:
		f3()
	case 0b1011:
		f4()
	case 0b1100:
		f5()
	case 0b1101:
		f6()
	case 0b1110:
		f7()
	case 0b1111:
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

	sort.Sort(l.LinExp)
	sort.Sort(r.LinExp)
	sort.Sort(o.LinExp)

	var cL, cR, cO big.Int
	l.LinExp, cL = scs.popConstantTerm(l.LinExp)
	r.LinExp, cR = scs.popConstantTerm(r.LinExp)
	o.LinExp, cO = scs.popConstantTerm(o.LinExp)

	var cK big.Int

	if len(o.LinExp) == 0 {

		if len(l.LinExp) == 0 {

			if len(r.LinExp) == 0 { // cL*cR = cO (should never happen...)

				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{K: scs.coeffID(&cK)})

			} else { // cL*(r + cR) = cO

				//rt := scs.split(0, r)
				rt := scs.split(r.LinExp)

				cRLT := scs.multiply(rt, &cL)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{R: cRLT, K: scs.coeffID(&cK)})
			}

		} else {

			if len(r.LinExp) == 0 { // (l + cL)*cR = cO
				//lt := scs.split(0, l)
				lt := scs.split(l.LinExp)

				cRLT := scs.multiply(lt, &cR)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{L: cRLT, K: scs.coeffID(&cK)})

			} else { // (l + cL)*(r + cR) = cO

				// lt := scs.split(0, l)
				// rt := scs.split(0, r)
				lt := scs.split(l.LinExp)
				rt := scs.split(r.LinExp)

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
		if len(l.LinExp) == 0 {

			if len(r.LinExp) == 0 { // cL*cR = o + cO

				//ot := scs.split(0, o)
				ot := scs.split(o.LinExp)

				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{K: scs.coeffID(&cK), O: scs.negate(ot)})

			} else { // cL * (r + cR) = o + cO

				// rt := scs.split(0, r)
				// ot := scs.split(0, o)
				rt := scs.split(r.LinExp)
				ot := scs.split(o.LinExp)

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
			if len(r.LinExp) == 0 { // (l + cL) * cR = o + cO

				// lt := scs.split(0, l)
				// ot := scs.split(0, o)
				lt := scs.split(l.LinExp)
				ot := scs.split(o.LinExp)

				cRLT := scs.multiply(lt, &cR)
				cK.Mul(&cL, &cR)
				cK.Sub(&cK, &cO)

				scs.addConstraint(compiled.SparseR1C{
					L: cRLT,
					K: scs.coeffID(&cK),
					O: scs.negate(ot),
				})

			} else { // (l + cL)*(r + cR) = o + cO
				// lt := scs.split(0, l)
				// rt := scs.split(0, r)
				// ot := scs.split(0, o)
				lt := scs.split(l.LinExp)
				rt := scs.split(r.LinExp)
				ot := scs.split(o.LinExp)

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

// hashCode returns a fast hash of the linear expression; this is not collision resistant
// but two SORTED equal linear expressions will have equal hashes.
//
// pre conditions: l is sorted
func hashCode(l compiled.LinearExpression) uint64 {
	hashcode := uint64(1)
	for i := 0; i < len(l); i++ {
		hashcode = hashcode*31 + uint64(l[i])
	}
	return hashcode
}

// same as hashCode but ignore the coeffID
func hashCodeNC(l compiled.LinearExpression) uint64 {
	hashcode := uint64(1)
	for i := 0; i < len(l); i++ {
		t := l[i]
		t.SetCoeffID(0)
		hashcode = hashcode*31 + uint64(t)
	}
	return hashcode
}

// same as hashCodeNC but return all the intermediate hash codes
func hashCodeNC_(l compiled.LinearExpression) []uint64 {
	r := make([]uint64, len(l))
	hashcode := uint64(1)
	for i := 0; i < len(l); i++ {
		t := l[i]
		t.SetCoeffID(0)
		hashcode = hashcode*31 + uint64(t)
		r[i] = hashcode
	}
	return r
}
