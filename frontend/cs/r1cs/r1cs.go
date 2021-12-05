/*
Copyright © 2021 ConsenSys Software Inc.

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

package r1cs

import (
	"math/big"
	"reflect"
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
)

type R1CSRefactor struct {
	cs.ConstraintSystem

	Constraints []compiled.R1C
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func NewR1CSRefactor(curveID ecc.ID, initialCapacity ...int) *R1CSRefactor {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	system := R1CSRefactor{
		ConstraintSystem: cs.ConstraintSystem{

			CS: compiled.CS{
				MDebug: make(map[int]int),
				MHints: make(map[int]compiled.Hint),
			},

			Coeffs:         make([]big.Int, 4),
			CoeffsIDsLarge: make(map[string]int),
			CoeffsIDsInt64: make(map[int64]int, 4),
		},
		Constraints: make([]compiled.R1C, 0, capacity),

		// Counters:          make([]Counter, 0),
	}

	system.Coeffs[compiled.CoeffIdZero].SetInt64(0)
	system.Coeffs[compiled.CoeffIdOne].SetInt64(1)
	system.Coeffs[compiled.CoeffIdTwo].SetInt64(2)
	system.Coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	system.CoeffsIDsInt64[0] = compiled.CoeffIdZero
	system.CoeffsIDsInt64[1] = compiled.CoeffIdOne
	system.CoeffsIDsInt64[2] = compiled.CoeffIdTwo
	system.CoeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	// system.public.variables = make([]Variable, 0)
	// system.secret.variables = make([]Variable, 0)
	// system.internal = make([]Variable, 0, capacity)
	system.Public = make([]string, 1)
	system.Secret = make([]string, 0)

	// by default the circuit is given a public wire equal to 1
	// system.public.variables[0] = system.newPublicVariable("one")
	system.Public[0] = "one"

	system.CurveID = curveID
	// system.BackendID = backendID

	return &system
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *R1CSRefactor) newInternalVariable() compiled.Variable {
	t := false
	idx := system.NbInternalVariables
	system.NbInternalVariables++
	return compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)},
		IsBoolean: &t,
	}
}

// NewPublicVariable creates a new public Variable
func (system *R1CSRefactor) NewPublicVariable(name string) cs.Variable {
	t := false
	idx := len(system.Public)
	system.Public = append(system.Public, name)
	res := compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)},
		IsBoolean: &t,
	}
	return res
}

// NewSecretVariable creates a new secret Variable
func (system *R1CSRefactor) NewSecretVariable(name string) cs.Variable {
	t := false
	idx := len(system.Secret)
	system.Secret = append(system.Secret, name)
	res := compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)},
		IsBoolean: &t,
	}
	return res
}

// func (v *variable) constantValue(system *R1CS) *big.Int {
func (system *R1CSRefactor) constantValue(v compiled.Variable) *big.Int {
	// TODO this might be a good place to start hunting useless allocations.
	// maybe through a big.Int pool.
	if !v.IsConstant() {
		panic("can't get big.Int value on a non-constant variable")
	}
	return new(big.Int).Set(&system.Coeffs[v.LinExp[0].CoeffID()])
}

func (system *R1CSRefactor) one() compiled.Variable {
	t := false
	return compiled.Variable{
		LinExp:    compiled.LinearExpression{compiled.Pack(0, compiled.CoeffIdOne, compiled.Public)},
		IsBoolean: &t,
	}
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public||secret||internal||unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *R1CSRefactor) reduce(l compiled.Variable) compiled.Variable {
	// ensure our linear expression is sorted, by visibility and by Variable ID
	if !sort.IsSorted(l.LinExp) { // may not help
		sort.Sort(l.LinExp)
	}

	var c big.Int
	for i := 1; i < len(l.LinExp); i++ {
		pcID, pvID, pVis := l.LinExp[i-1].Unpack()
		ccID, cvID, cVis := l.LinExp[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.Coeffs[pcID], &system.Coeffs[ccID])
			l.LinExp[i-1].SetCoeffID(system.CoeffID(&c))
			l.LinExp = append(l.LinExp[:i], l.LinExp[i+1:]...)
			i--
		}
	}
	return l
}

// newR1C clones the linear expression associated with the Variables (to avoid offseting the ID multiple time)
// and return a R1C
func newR1C(_l, _r, _o cs.Variable) compiled.R1C {
	l := _l.(compiled.Variable)
	r := _r.(compiled.Variable)
	o := _o.(compiled.Variable)

	// interestingly, this is key to groth16 performance.
	// l * r == r * l == o
	// but the "l" linear expression is going to end up in the A matrix
	// the "r" linear expression is going to end up in the B matrix
	// the less Variable we have appearing in the B matrix, the more likely groth16.Setup
	// is going to produce infinity points in pk.G1.B and pk.G2.B, which will speed up proving time
	if len(l.LinExp) > len(r.LinExp) {
		l, r = r, l
	}

	return compiled.R1C{L: l.Clone(), R: r.Clone(), O: o.Clone()}
}

func (system *R1CSRefactor) addConstraint(r1c compiled.R1C, debugID ...int) {
	system.Constraints = append(system.Constraints, r1c)
	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)-1] = debugID[0]
	}
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
func (system *R1CSRefactor) NewHint(f hint.Function, inputs ...interface{}) cs.Variable {
	// create resulting wire
	r := system.newInternalVariable()
	_, vID, _ := r.LinExp[0].Unpack()

	// mark hint as unconstrained, for now
	//system.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		t := system.constant(in).(compiled.Variable)
		tmp := t.Clone()
		hintInputs[i] = tmp.LinExp // TODO @gbotrel check that we need to clone here ?
	}

	// add the hint to the constraint system
	system.MHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

// Term packs a Variable and a coeff in a Term and returns it.
// func (system *R1CSRefactor) setCoeff(v Variable, coeff *big.Int) Term {
func (system *R1CSRefactor) setCoeff(v compiled.Term, coeff *big.Int) compiled.Term {
	_, vID, vVis := v.Unpack()
	return compiled.Pack(vID, system.CoeffID(coeff), vVis)
}

// markBoolean marks the Variable as boolean and return true
// if a constraint was added, false if the Variable was already
// constrained as a boolean
func (system *R1CSRefactor) markBoolean(v compiled.Variable) bool {
	if *v.IsBoolean {
		return false
	}
	*v.IsBoolean = true
	return true
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A cs.Variable }{}).FieldByName("A").Type()
}
