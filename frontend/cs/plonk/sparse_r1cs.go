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
	"sort"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
)

func NewBuilder(curve ecc.ID) (frontend.Builder, error) {
	return newSparseR1CS(curve), nil
}

type SparseR1CS struct {
	cs.ConstraintSystem

	Constraints []compiled.SparseR1C
}

// initialCapacity has quite some impact on frontend performance, especially on large circuits size
// we may want to add build tags to tune that
func newSparseR1CS(curveID ecc.ID, initialCapacity ...int) *SparseR1CS {
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
			MTBooleans:     make(map[int]struct{}),
		},
		Constraints: make([]compiled.SparseR1C, 0, capacity),
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
//func (system *SparseR1CS) addPlonkConstraint(l, r, o frontend.Variable, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {
func (system *SparseR1CS) addPlonkConstraint(l, r, o compiled.Term, cidl, cidr, cidm1, cidm2, cido, k int, debugID ...int) {

	if len(debugID) > 0 {
		system.MDebug[len(system.Constraints)-1] = debugID[0]
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
func (system *SparseR1CS) newInternalVariable() compiled.Term {
	idx := system.NbInternalVariables
	system.NbInternalVariables++
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Internal)
}

// NewPublicVariable creates a new Public Variable
func (system *SparseR1CS) NewPublicVariable(name string) frontend.Variable {
	idx := len(system.Public)
	system.Public = append(system.Public, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Public)
}

// NewPublicVariable creates a new Secret Variable
func (system *SparseR1CS) NewSecretVariable(name string) frontend.Variable {
	idx := len(system.Secret)
	system.Secret = append(system.Secret, name)
	return compiled.Pack(idx, compiled.CoeffIdOne, compiled.Secret)
}

// reduces redundancy in linear expression
// It factorizes Variable that appears multiple times with != coeff Ids
// To ensure the determinism in the compile process, Variables are stored as public||secret||internal||unset
// for each visibility, the Variables are sorted from lowest ID to highest ID
func (system *SparseR1CS) reduce(l compiled.LinearExpression) compiled.LinearExpression {

	// ensure our linear expression is sorted, by visibility and by Variable ID
	sort.Sort(l)

	var c big.Int
	for i := 1; i < len(l); i++ {
		pcID, pvID, pVis := l[i-1].Unpack()
		ccID, cvID, cVis := l[i].Unpack()
		if pVis == cVis && pvID == cvID {
			// we have redundancy
			c.Add(&system.Coeffs[pcID], &system.Coeffs[ccID])
			l[i-1].SetCoeffID(system.CoeffID(&c))
			l = append(l[:i], l[i+1:]...)
			i--
		}
	}
	return l
}

// to handle wires that don't exist (=coef 0) in a sparse constraint
func (system *SparseR1CS) zero() compiled.Term {
	var a compiled.Term
	return a
}

// returns true if a variable is already boolean
func (system *SparseR1CS) isBoolean(t compiled.Term) bool {
	_, ok := system.MTBooleans[int(t)]
	return ok
}

// markBoolean records t in the map to not boolean constrain it twice
func (system *SparseR1CS) markBoolean(t compiled.Term) {
	system.MTBooleans[int(t)] = struct{}{}
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.ValueOf(struct{ A frontend.Variable }{}).FieldByName("A").Type()
}
