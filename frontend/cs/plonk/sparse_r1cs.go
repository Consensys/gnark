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

package plonk

import (
	"math/big"
	"reflect"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/hint"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/utils"
	"github.com/consensys/gnark/internal/backend/compiled"
)

type SparseR1CS struct {
	cs.ConstraintSystem

	Constraints []compiled.SparseR1C
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func NewSparseR1CS(curveID ecc.ID, backendID backend.ID, initialCapacity ...int) *SparseR1CS {
	capacity := 0
	if len(initialCapacity) > 0 {
		capacity = initialCapacity[0]
	}
	system := SparseR1CS{
		ConstraintSystem: cs.ConstraintSystem{

			CS: compiled.CS{
				MDebug: make(map[int]int),
				MHints: make(map[int]compiled.Hint),
			},

			Coeffs:         make([]big.Int, 4),
			CoeffsIDsLarge: make(map[string]int),
			CoeffsIDsInt64: make(map[int64]int, 4),
		},
		Constraints: make([]compiled.SparseR1C, 0, capacity),

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
	system.Public = make([]string, 0)
	system.Secret = make([]string, 0)

	system.CurveID = curveID

	return &system
}

// addPlonkConstraint creates a constraint of the for al+br+clr+k=0
func (system *SparseR1CS) addPlonkConstraint(l, r, o cs.Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)-1] = debugID[0]
	}

	_l := l.(compiled.Term)
	_r := r.(compiled.Term)
	_o := o.(compiled.Term)
	_l.SetCoeffID(cidl)
	_r.SetCoeffID(cidr)
	_o.SetCoeffID(cido)

	u := _l
	v := _r
	u.SetCoeffID(cidm1)
	v.SetCoeffID(cidm2)

	system.Constraints = append(system.Constraints, compiled.SparseR1C{L: _l, R: _r, O: _o, M: [2]compiled.Term{u, v}, K: k})
}

// newInternalVariable creates a new wire, appends it on the list of wires of the circuit, sets
// the wire's id to the number of wires, and returns it
func (system *SparseR1CS) newInternalVariable() compiled.Term {
	idx := system.NbInternalVariables
	system.NbInternalVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)
}

// NewPublicVariable creates a new Public Variable
func (system *SparseR1CS) NewPublicVariable(name string) cs.Variable {
	idx := system.NbPublicVariables
	system.Public = append(system.Public, name)
	system.NbPublicVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)
}

// NewPublicVariable creates a new Secret Variable
func (system *SparseR1CS) NewSecretVariable(name string) cs.Variable {
	idx := len(system.Secret)
	system.Public = append(system.Secret, name)
	system.NbSecretVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)
}

func (system *SparseR1CS) NewHint(f hint.Function, inputs ...interface{}) cs.Variable {
	// create resulting wire
	r := system.newInternalVariable()
	_, vID, _ := r.Unpack()

	// mark hint as unconstrained, for now
	//system.mHintsConstrained[vID] = false

	// now we need to store the linear expressions of the expected input
	// that will be resolved in the solver
	hintInputs := make([]compiled.LinearExpression, len(inputs))

	// ensure inputs are set and pack them in a []uint64
	for i, in := range inputs {
		switch t := in.(type) {
		case compiled.Term:
			hintInputs[i] = []compiled.Term{t}
		default:
			n := utils.FromInterface(in)
			id := system.CoeffID(&n)
			var u compiled.Term
			u.SetCoeffID(id)
			u.SetWireID(-1) // -1 so it is recognized as a constant
		}
	}

	// add the hint to the constraint system
	system.MHints[vID] = compiled.Hint{ID: hint.UUID(f), Inputs: hintInputs}

	return r
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A cs.Variable }{}).FieldByName("A").Type()
}
