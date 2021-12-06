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
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
)

// R1CS represents a Groth16 like circuit
//
// All the APIs to define a circuit (see Circuit.Define) like Add, Sub, Mul, ...
// may take as input interface{}
//
// these interfaces are either cs.Variables (/LinearExpressions) or constants (big.Int, strings, uint, fr.Element)
type R1CS struct {

	// input wires
	public, secret []string

	// internal wires
	internal int

	// list of constraints in the form a * b == c
	// a,b and c being linear expressions
	constraints []compiled.R1C

	// Coefficients in the constraints
	coeffs         []big.Int      // list of unique coefficients.
	coeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	coeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)

	// Hints
	mHints            map[int]compiled.Hint // solver hints
	mHintsConstrained map[int]bool          // marks hints compiled.Variables constrained status

	logs      []compiled.LogEntry // list of logs to be printed when solving a circuit. The logs are called with the method Println
	debugInfo []compiled.LogEntry // list of logs storing information about R1C

	mDebug map[int]int // maps constraint ID to debugInfo id

	// counters []Counter // statistic counters
	counters []compiled.Counter // statistic counters

	curveID   ecc.ID
	backendID backend.ID
}

// // CompiledConstraintSystem ...
// type CompiledConstraintSystem interface {
// 	io.WriterTo
// 	io.ReaderFrom

// 	// GetNbVariables return number of internal, secret and public cs.Variables
// 	GetNbVariables() (internal, secret, public int)
// 	GetNbConstraints() int
// 	GetNbCoefficients() int

// 	CurveID() ecc.ID
// 	FrSize() int

// 	// ToHTML generates a human readable representation of the constraint system
// 	ToHTML(w io.Writer) error

// 	// GetCounters return the collected constraint counters, if any
// 	GetCounters() []compiled.Counter
// }

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newConstraintSystem(curveID ecc.ID, backendID backend.ID, initialCapacity ...int) R1CS {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	system := R1CS{
		coeffs:            make([]big.Int, 4),
		coeffsIDsLarge:    make(map[string]int),
		coeffsIDsInt64:    make(map[int64]int, 4),
		constraints:       make([]compiled.R1C, 0, capacity),
		mDebug:            make(map[int]int),
		mHints:            make(map[int]compiled.Hint),
		mHintsConstrained: make(map[int]bool),
		counters:          make([]compiled.Counter, 0),
	}

	system.coeffs[compiled.CoeffIdZero].SetInt64(0)
	system.coeffs[compiled.CoeffIdOne].SetInt64(1)
	system.coeffs[compiled.CoeffIdTwo].SetInt64(2)
	system.coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	system.coeffsIDsInt64[0] = compiled.CoeffIdZero
	system.coeffsIDsInt64[1] = compiled.CoeffIdOne
	system.coeffsIDsInt64[2] = compiled.CoeffIdTwo
	system.coeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	// system.public.variables = make([]Variable, 0)
	// system.secret.variables = make([]Variable, 0)
	// system.internal = make([]Variable, 0, capacity)
	system.public = make([]string, 1)
	system.secret = make([]string, 0)

	// by default the circuit is given a public wire equal to 1
	// system.public.variables[0] = system.newPublicVariable("one")
	system.public[0] = "one"

	system.curveID = curveID
	system.backendID = backendID

	return system
}

// NewHint initializes an internal variable whose value will be evaluated using
// the provided hint function at run time from the inputs. Inputs must be either
// variables or convertible to *big.Int.
//
// The hint function is provided at the proof creation time and is not embedded
// into the circuit. From the backend point of view, the variable returned by
// the hint function is equivalent to the user-supplied witness, but its actual
// value is assigned by the solver, not the caller.
//
// No new constraints are added to the newly created wire and must be added
// manually in the circuit. Failing to do so leads to solver failure.
func (system *R1CS) NewHint(f hint.Function, inputs ...cs.Variable) cs.Variable {
	// create resulting wire
	r := system.newInternalVariable()
	_, vID, _ := r.LinExp[0].Unpack()

	// mark hint as unconstrained, for now
	system.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]interface{}, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.Variable:
			tmp := t.Clone()
			hintInputs[i] = tmp.LinExp
		default:
			hintInputs[i] = t
		}
		// t := system.constant(in).(compiled.Variable)
		// tmp := t.Clone()
		// hintInputs[i] = tmp.LinExp // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	system.mHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

func (system *R1CS) Compile(curveID ecc.ID) (compiled.CompiledConstraintSystem, error) {
	return nil, nil
}

// bitLen returns the number of bits needed to represent a fr.Element
func (system *R1CS) bitLen() int {
	return system.curveID.Info().Fr.Bits
}

func (system *R1CS) one() compiled.Variable {
	t := false
	return compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(0, compiled.CoeffIdOne, compiled.Public)},
		IsBoolean: &t,
	}
}

// Term packs a cs.Variable and a coeff in a Term and returns it.
// func (system *R1CS) setCoeff(v cs.Variable, coeff *big.Int) Term {
func (system *R1CS) setCoeff(v compiled.Term, coeff *big.Int) compiled.Term {
	_, vID, vVis := v.Unpack()
	return compiled.Pack(vID, system.coeffID(coeff), vVis)
}

// newR1C clones the linear expression associated with the cs.Variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(_l, _r, _o cs.Variable) compiled.R1C {
	l := _l.(compiled.Variable)
	r := _r.(compiled.Variable)
	o := _o.(compiled.Variable)

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less cs.Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l.LinExp) > len(r.LinExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.Clone(), R: r.Clone(), O: o.Clone()}
}

// NbConstraints enables circuit profiling and helps debugging
// It returns the number of constraints created at the current stage of the circuit construction.
func (system *R1CS) NbConstraints() int {
	return len(system.constraints)
}

// LinearExpression packs a list of Term in a LinearExpression and returns it.
func (system *R1CS) LinearExpression(terms ...compiled.Term) compiled.Variable {
	var res compiled.Variable
	res.LinExp = make([]compiled.Term, len(terms))
	for i, args := range terms {
		res.LinExp[i] = args
	}
	return res
}

// reduces redundancy in linear expression
// It factorizes cs.Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, cs.Variables are stored as public||secret||internal||unset
// for each visibility, the cs.Variables are sorted from lowest ID to highest ID
func (system *R1CS) reduce(l compiled.Variable) compiled.Variable {
	// ensure our linear expression is sorted, by visibility and by cs.Variable ID
	if !sort.IsSorted(l.LinExp) { // may not help
		sort.Sort(l.LinExp)
	}

	mod := system.curveID.Info().Fr.Modulus()
	c := new(big.Int)
	for i := 1; i < len(l.LinExp); i++ {
		pcID, pvID, pVis := l.LinExp[i-1].Unpack()
		ccID, cvID, cVis := l.LinExp[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.coeffs[pcID], &system.coeffs[ccID])
			c.Mod(c, mod)
			l.LinExp[i-1].SetCoeffID(system.coeffID(c))
			l.LinExp = append(l.LinExp[:i], l.LinExp[i+1:]...)
			i--
		}
	}
	return l
}

func (system *R1CS) coeffID64(v int64) int {
	if resID, ok := system.coeffsIDsInt64[v]; ok {
		return resID
	} else {
		var bCopy big.Int
		bCopy.SetInt64(v)
		resID := len(system.coeffs)
		system.coeffs = append(system.coeffs, bCopy)
		system.coeffsIDsInt64[v] = resID
		return resID
	}
}

// coeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of coeffs and returns the corresponding entry
func (system *R1CS) coeffID(b *big.Int) int {

	// if the coeff is a int64 we have a fast path.
	if b.IsInt64() {
		return system.coeffID64(b.Int64())
	}

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	bKey, _ := b.GobEncode()
	key := string(bKey)

	// if the coeff is already stored, fetch its ID from the system.coeffsIDs map
	if idx, ok := system.coeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the system.coeffs map and update the system.coeffsIDs map
	var bCopy big.Int
	bCopy.Set(b)
	resID := len(system.coeffs)
	system.coeffs = append(system.coeffs, bCopy)
	system.coeffsIDsLarge[key] = resID
	return resID
}

func (system *R1CS) addConstraint(r1c compiled.R1C, debugID ...int) {
	system.constraints = append(system.constraints, r1c)
	if len(debugID) > 0 {
		system.mDebug[len(system.constraints)-1] = debugID[0]
	}
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *R1CS) newInternalVariable() compiled.Variable {
	t := false
	idx := system.internal
	system.internal++
	return compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)},
		IsBoolean: &t,
	}
}

// newPublicVariable creates a new public cs.Variable
func (system *R1CS) newPublicVariable(name string) compiled.Variable {
	t := false
	idx := len(system.public)
	system.public = append(system.public, name)
	res := compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)},
		IsBoolean: &t,
	}
	return res
}

// newSecretVariable creates a new secret cs.Variable
func (system *R1CS) newSecretVariable(name string) compiled.Variable {
	t := false
	idx := len(system.secret)
	system.secret = append(system.secret, name)
	res := compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)},
		IsBoolean: &t,
	}
	return res
}

// markBoolean marks the cs.Variable as boolean and return true
// if a constraint was added, false if the cs.Variable was already
// constrained as a boolean
func (system *R1CS) markBoolean(v compiled.Variable) bool {
	if *v.IsBoolean {
		return false
	}
	*v.IsBoolean = true
	return true
}

// checkVariables perform post compilation checks on the cs.Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *R1CS) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(system.secret)
	cptPublic := len(system.public) - 1
	cptHints := len(system.mHintsConstrained)

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic+1)
	publicConstrained[0] = true

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l compiled.Variable) {
		for _, t := range l.LinExp {
			if t.CoeffID() == compiled.CoeffIdZero {
				// ignore zero coefficient, as it does not constraint the cs.Variable
				// though, we may want to flag that IF the cs.Variable doesn't appear else where
				continue
			}
			visibility := t.VariableVisibility()
			vID := t.WireID()

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
				if b, ok := system.mHintsConstrained[vID]; ok && !b {
					system.mHintsConstrained[vID] = true
					cptHints--
				}
			}
		}
	}
	for _, r1c := range system.constraints {
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
				sbb.WriteString(system.secret[i])
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
				sbb.WriteString(system.public[i])
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

func (system *R1CS) Curve() ecc.ID {
	return system.curveID
}

func (system *R1CS) Backend() backend.ID {
	return system.backendID
}
