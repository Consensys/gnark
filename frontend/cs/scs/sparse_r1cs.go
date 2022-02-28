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

package scs

import (
	"errors"
	"math/big"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/schema"
)

func NewCompiler(curve ecc.ID) (frontend.Builder, error) {
	return newSparseR1CS(curve), nil
}

type sparseR1CS struct {
	compiled.ConstraintSystem
	Constraints []compiled.SparseR1C

	st cs.CoeffTable

	// map for recording boolean constrained variables (to not constrain them twice)
	mtBooleans map[int]struct{}
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newSparseR1CS(curveID ecc.ID, initialCapacity ...int) *sparseR1CS {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	system := sparseR1CS{
		ConstraintSystem: compiled.ConstraintSystem{

			MDebug: make(map[int]int),
			MHints: make(map[int]*compiled.Hint),
		},
		mtBooleans:  make(map[int]struct{}),
		Constraints: make([]compiled.SparseR1C, 0, capacity),
		st:          cs.NewCoeffTable(),
	}

	system.st.Coeffs[compiled.CoeffIdZero].SetInt64(0)
	system.st.Coeffs[compiled.CoeffIdOne].SetInt64(1)
	system.st.Coeffs[compiled.CoeffIdTwo].SetInt64(2)
	system.st.Coeffs[compiled.CoeffIdMinusOne].SetInt64(-1)

	system.st.CoeffsIDsInt64[0] = compiled.CoeffIdZero
	system.st.CoeffsIDsInt64[1] = compiled.CoeffIdOne
	system.st.CoeffsIDsInt64[2] = compiled.CoeffIdTwo
	system.st.CoeffsIDsInt64[-1] = compiled.CoeffIdMinusOne

	// system.public.variables = make([]Variable, 0)
	// system.secret.variables = make([]Variable, 0)
	// system.internal = make([]Variable, 0, capacity)
	system.Public = make([]string, 0)
	system.Secret = make([]string, 0)

	system.CurveID = curveID

	return &system
}

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
//func (system *SparseR1CS) addPlonkConstraint(l, r, o frontend.Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {
func (system *sparseR1CS) addPlonkConstraint(l, r, o compiled.Term, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)] = debugID[0]
	}

	l.SetCoeffID(cidl)
	r.SetCoeffID(cidr)
	o.SetCoeffID(cido)

	u := l
	v := r
	u.SetCoeffID(cidm1)
	v.SetCoeffID(cidm2)

	//system.Constraints = append(system.Constraints, compiled.SparseR1C{L: _l, R: _r, O: _o, M: [2]compiled.Term{u, v}, K: k})
	system.Constraints = append(system.Constraints, compiled.SparseR1C{L: l, R: r, O: o, M: [2]compiled.Term{u, v}, K: k})
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *sparseR1CS) newInternalVariable() compiled.Term {
	idx := system.NbInternalVariables
	system.NbInternalVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Internal)
}

// AddPublicVariable creates a new Public Variable
func (system *sparseR1CS) AddPublicVariable(name string) frontend.Variable {
	if system.Schema != nil {
		panic("do not call AddPublicVariable in circuit.Define()")
	}
	idx := len(system.Public)
	system.Public = append(system.Public, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Public)
}

// AddSecretVariable creates a new Secret Variable
func (system *sparseR1CS) AddSecretVariable(name string) frontend.Variable {
	if system.Schema != nil {
		panic("do not call AddSecretVariable in circuit.Define()")
	}
	idx := len(system.Secret)
	system.Secret = append(system.Secret, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, schema.Secret)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public∥secret∥internal∥unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *sparseR1CS) reduce(l compiled.LinearExpression) compiled.LinearExpression {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	mod := system.CurveID.Info().Fr.Modulus()
	c := new(big.Int)
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.st.Coeffs[pcID], &system.st.Coeffs[ccID])
			c.Mod(c, mod)
			l[i-1].SetCoeffID(system.st.CoeffID(c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// to handle wires that don't exist (=coef 0) in a sparse constraint
func (system *sparseR1CS) zero() compiled.Term {
	var a compiled.Term
	return a
}

// IsBoolean returns true if given variable was marked as boolean in the compiler (see MarkBoolean)
// Use with care; variable may not have been **constrained** to be boolean
// This returns true if the v is a constant and v == 0 || v == 1.
func (system *sparseR1CS) IsBoolean(v frontend.Variable) bool {
	if b, ok := system.ConstantValue(v); ok {
		return b.IsUint64() && b.Uint64() <= 1
	}
	_, ok := system.mtBooleans[int(v.(compiled.Term))]
	return ok
}

// MarkBoolean sets (but do not constraint!) v to be boolean
// This is useful in scenarios where a variable is known to be boolean through a constraint
// that is not api.AssertIsBoolean. If v is a constant, this is a no-op.
func (system *sparseR1CS) MarkBoolean(v frontend.Variable) {
	if system.IsConstant(v) {
		return
	}
	system.mtBooleans[int(v.(compiled.Term))] = struct{}{}
}

// checkVariables perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *sparseR1CS) checkVariables() error {

	// TODO @gbotrel add unit test for that.

	cptSecret := len(system.Secret)
	cptPublic := len(system.Public)
	cptHints := len(system.MHints)

	// compared to R1CS, we may have a circuit which does not have any inputs
	// (R1CS always has a constant ONE wire). Check the edge case and omit any
	// processing if so.
	if cptSecret+cptPublic+cptHints == 0 {
		return nil
	}

	secretConstrained := make([]bool, cptSecret)
	publicConstrained := make([]bool, cptPublic)

	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the terms and mark our inputs / hints as constrained
	processTerm := func(t compiled.Term) {

		// L and M[0] handles the same wire but with a different coeff
		visibility := t.VariableVisibility()
		vID := t.WireID()
		if t.CoeffID() != compiled.CoeffIdZero {
			switch visibility {
			case schema.Public:
				if !publicConstrained[vID] {
					publicConstrained[vID] = true
					cptPublic--
				}
			case schema.Secret:
				if !secretConstrained[vID] {
					secretConstrained[vID] = true
					cptSecret--
				}
			case schema.Internal:
				if _, ok := system.MHints[vID]; !mHintsConstrained[vID] && ok {
					mHintsConstrained[vID] = true
					cptHints--
				}
			}
		}

	}
	for _, c := range system.Constraints {
		processTerm(c.L)
		processTerm(c.R)
		processTerm(c.M[0])
		processTerm(c.M[1])
		processTerm(c.O)
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
				sbb.WriteString(system.Secret[i])
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
				sbb.WriteString(system.Public[i])
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
		// TODO we may add more debug info here → idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
