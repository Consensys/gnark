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
	"errors"
	"io"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// constraintSystem represents a Groth16 like circuit
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type constraintSystem struct {
	// Variables (aka wires)
	// virtual variables do not result in a new circuit wire
	// they may only contain a linear expression
	public, secret    inputs
	internal, virtual variables

	// list of constraints in the form a * b == c
	// a,b and c being linear expressions
	constraints []compiled.R1C

	// Coefficients in the constraints
	coeffs         []big.Int      // list of unique coefficients.
	coeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	coeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)

	// Hints
	mHints            map[int]compiled.Hint // solver hints
	mHintsConstrained map[int]bool          // marks hints variables constrained status

	logs      []compiled.LogEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo []compiled.LogEntry // list of logs storing information about R1C

	mDebug map[int]int // maps constraint ID to debugInfo id

	curveID ecc.ID
}

type variables struct {
	variables []variable
	booleans  map[int]struct{} // keep track of boolean variables (we constrain them once)
}

type inputs struct {
	variables
	names []string
}

func (v *inputs) new(cs *constraintSystem, visibility compiled.Visibility, name string) variable {
	v.names = append(v.names, name)
	return v.variables.new(cs, visibility)
}

func (v *variables) new(cs *constraintSystem, visibility compiled.Visibility) variable {
	idx := len(v.variables)
	variable := variable{visibility: visibility, id: idx, linExp: cs.LinearExpression(compiled.Pack(idx, compiled.CoeffIdOne, visibility))}

	v.variables = append(v.variables, variable)
	return variable
}

// CompiledConstraintSystem ...
type CompiledConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() ecc.ID
	FrSize() int

	// ToHTML generates a human readable representation of the constraint system
	ToHTML(w io.Writer) error
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newConstraintSystem(curveID ecc.ID, initialCapacity ...int) constraintSystem {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	cs := constraintSystem{
		coeffs:            make([]big.Int, 4),
		coeffsIDsLarge:    make(map[string]int),
		coeffsIDsInt64:    make(map[int64]int, 4),
		constraints:       make([]compiled.R1C, 0, capacity),
		mDebug:            make(map[int]int),
		mHints:            make(map[int]compiled.Hint),
		mHintsConstrained: make(map[int]bool),
	}

	cs.coeffs[compiled.CoeffIdZero].SetInt64(0)
	cs.coeffs[compiled.CoeffIdOne].SetInt64(1)
	cs.coeffs[compiled.CoeffIdTwo].SetInt64(2)
	cs.coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	cs.coeffsIDsInt64[0] = compiled.CoeffIdZero
	cs.coeffsIDsInt64[1] = compiled.CoeffIdOne
	cs.coeffsIDsInt64[2] = compiled.CoeffIdTwo
	cs.coeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	cs.public.variables.variables = make([]variable, 0)
	cs.public.booleans = make(map[int]struct{})

	cs.secret.variables.variables = make([]variable, 0)
	cs.secret.booleans = make(map[int]struct{})

	cs.internal.variables = make([]variable, 0, capacity)
	cs.internal.booleans = make(map[int]struct{})

	cs.virtual.variables = make([]variable, 0)
	cs.virtual.booleans = make(map[int]struct{})

	// by default the circuit is given on public wire equal to 1
	cs.public.variables.variables[0] = cs.newPublicVariable("one")

	cs.curveID = curveID

	return cs
}

// NewHint initialize a variable whose value will be evaluated in the Prover by the constraint
// solver using the provided hint function
// hint function is provided at proof creation time and must match the hintID
// inputs must be either variables or convertible to big int
// /!\ warning /!\
// this doesn't add any constraint to the newly created wire
// from the backend point of view, it's equivalent to a user-supplied witness
// except, the solver is going to assign it a value, not the caller
func (cs *constraintSystem) NewHint(f hint.Function, inputs ...interface{}) Variable {
	// create resulting wire
	r := cs.newInternalVariable()

	// mark hint as unconstrained, for now
	cs.mHintsConstrained[r.id] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		t := cs.Constant(in).(variable)
		hintInputs[i] = t.linExp.Clone() // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	cs.mHints[r.id] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

// bitLen returns the number of bits needed to represent a fr.Element
func (cs *constraintSystem) bitLen() int {
	return cs.curveID.Info().Fr.Bits
}

func (cs *constraintSystem) one() variable {
	return cs.public.variables.variables[0]
}

// Term packs a variable and a coeff in a compiled.Term and returns it.
func (cs *constraintSystem) makeTerm(v variable, coeff *big.Int) compiled.Term {
	return compiled.Pack(v.id, cs.coeffID(coeff), v.visibility)
}

// newR1C clones the linear expression associated with the variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(_l, _r, _o Variable) compiled.R1C {
	l := _l.(variable)
	r := _r.(variable)
	o := _o.(variable)

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l.linExp) > len(r.linExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.linExp.Clone(), R: r.linExp.Clone(), O: o.linExp.Clone()}
}

// NbConstraints enables circuit profiling and helps debugging
// It returns the number of constraints created at the current stage of the circuit construction.
func (cs *constraintSystem) NbConstraints() int {
	return len(cs.constraints)
}

// LinearExpression packs a list of compiled.Term in a compiled.LinearExpression and returns it.
func (cs *constraintSystem) LinearExpression(terms ...compiled.Term) compiled.LinearExpression {
	res := make(compiled.LinearExpression, len(terms))
	for i, args := range terms {
		res[i] = args
	}
	return res
}

// reduces redundancy in linear expression
// It factorizes variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, variables are stored as public||secret||internal||unset
// for each visibility, the variables are sorted from lowest ID to highest ID
func (cs *constraintSystem) reduce(l compiled.LinearExpression) compiled.LinearExpression {
	// ensure our linear expression is sorted, by visibility and by variable ID
	if !sort.IsSorted(l) { // may not help
		sort.Sort(l)
	}

	var c big.Int
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&cs.coeffs[pcID], &cs.coeffs[ccID])
			l[i-1].SetCoeffID(cs.coeffID(&c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

func (cs *constraintSystem) coeffID64(v int64) int {
	if resID, ok := cs.coeffsIDsInt64[v]; ok {
		return resID
	} else {
		var bCopy big.Int
		bCopy.SetInt64(v)
		resID := len(cs.coeffs)
		cs.coeffs = append(cs.coeffs, bCopy)
		cs.coeffsIDsInt64[v] = resID
		return resID
	}
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (cs *constraintSystem) coeffID(b *big.Int) int {

	// if the coeff is a int64 we have a fast path.
	if b.IsInt64() {
		return cs.coeffID64(b.Int64())
	}

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	bKey, _ := b.GobEncode()
	key := string(bKey)

	// if the coeff is already stored, fetch its ID from the cs.coeffsIDs map
	if idx, ok := cs.coeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the cs.coeffs map and update the cs.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(cs.coeffs)
	cs.coeffs = append(cs.coeffs, bCopy)
	cs.coeffsIDsLarge[key] = resID
	return resID
}

func (cs *constraintSystem) addConstraint(r1c compiled.R1C, debugID ...int) {
	cs.constraints = append(cs.constraints, r1c)
	if len(debugID) > 0 {
		cs.mDebug[len(cs.constraints)-1] = debugID[0]
	}
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (cs *constraintSystem) newInternalVariable() variable {
	return cs.internal.new(cs, compiled.Internal)
}

// newPublicVariable creates a new public variable
func (cs *constraintSystem) newPublicVariable(name string) variable {
	return cs.public.new(cs, compiled.Public, name)
}

// newSecretVariable creates a new secret variable
func (cs *constraintSystem) newSecretVariable(name string) variable {
	return cs.secret.new(cs, compiled.Secret, name)
}

// newVirtualVariable creates a new virtual variable
// this will not result in a new wire in the constraint system
// and just represents a linear expression
func (cs *constraintSystem) newVirtualVariable() variable {
	return cs.virtual.new(cs, compiled.Virtual)
}

// markBoolean marks the variable as boolean and return true
// if a constraint was added, false if the variable was already
// constrained as a boolean
func (cs *constraintSystem) markBoolean(v variable) bool {
	switch v.visibility {
	case compiled.Internal:
		if _, ok := cs.internal.booleans[v.id]; ok {
			return false
		}
		cs.internal.booleans[v.id] = struct{}{}
	case compiled.Secret:
		if _, ok := cs.secret.booleans[v.id]; ok {
			return false
		}
		cs.secret.booleans[v.id] = struct{}{}
	case compiled.Public:
		if _, ok := cs.public.booleans[v.id]; ok {
			return false
		}
		cs.public.booleans[v.id] = struct{}{}
	case compiled.Virtual:
		if _, ok := cs.virtual.booleans[v.id]; ok {
			return false
		}
		cs.virtual.booleans[v.id] = struct{}{}
	default:
		panic("not implemented")
	}
	return true
}

// checkVariables perform post compilation checks on the variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (cs *constraintSystem) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(cs.secret.variables.variables)
	cptPublic := len(cs.public.variables.variables) - 1
	cptHints := len(cs.mHintsConstrained)

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic+1)
	publicConstrained[0] = true

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l compiled.LinearExpression) {
		for _, t := range l {
			if t.CoeffID() == compiled.CoeffIdZero {
				// ignore zero coefficient, as it does not constraint the variable
				// though, we may want to flag that IF the variable doesn't appear else where
				continue
			}
			visibility := t.VariableVisibility()
			vID := t.VariableID()

			switch visibility {
			case compiled.Public:
				if vID != 0 && !publicConstrained[vID] {
					publicConstrained[vID] = true
					cptPublic--
				}
			case compiled.Secret:
				if !secretConstrained[vID] {
					secretConstrained[vID] = true
					cptSecret--
				}
			case compiled.Internal:
				if b, ok := cs.mHintsConstrained[vID]; ok && !b {
					cs.mHintsConstrained[vID] = true
					cptHints--
				}
			}
		}
	}
	for _, r1c := range cs.constraints {
		processLinearExpression(r1c.L)
		processLinearExpression(r1c.R)
		processLinearExpression(r1c.O)

		if cptHints|cptSecret|cptPublic == 0 {
			return nil // we can stop.
		}

	}

	// something is a miss, we build the error string
	var sbb strings.Builder
	if cptSecret != 0 {
		sbb.WriteString(strconv.Itoa(cptSecret))
		sbb.WriteString(" unconstrained secret input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(secretConstrained) && cptSecret != 0; i++ {
			if !secretConstrained[i] {
				sbb.WriteString(cs.secret.names[i])
				sbb.WriteByte('\n')
				cptSecret--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptPublic != 0 {
		sbb.WriteString(strconv.Itoa(cptPublic))
		sbb.WriteString(" unconstrained public input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(publicConstrained) && cptPublic != 0; i++ {
			if !publicConstrained[i] {
				sbb.WriteString(cs.public.names[i])
				sbb.WriteByte('\n')
				cptPublic--
			}
		}
		sbb.WriteByte('\n')
	}

	if cptHints != 0 {
		sbb.WriteString(strconv.Itoa(cptHints))
		sbb.WriteString(" unconstrained hints")
		sbb.WriteByte('\n')
		// TODO we may add more debug info here --> idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())

}
