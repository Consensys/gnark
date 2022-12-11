// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package constraint

import (
	"errors"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend/schema"
)

type SparseR1CS interface {
	ConstraintSystem
	AddConstraint(c SparseR1C, debugInfo ...DebugInfo) error
	// GetConstraints() []R1C
	BuildLevelTOREMOVE()
}

// R1CS decsribes a set of SparseR1C constraint
// TODO @gbotrel maybe SparseR1CSCore and R1CSCore should go in code generation directly to avoid confusing this package.
type SparseR1CSCore struct {
	System
	Constraints []SparseR1C
}

// GetNbConstraints returns the number of constraints
func (cs *SparseR1CSCore) GetNbConstraints() int {
	return len(cs.Constraints)
}

func (cs *SparseR1CSCore) BuildLevelTOREMOVE() {
	cs.Levels = buildSCSLevels(*cs)
}

// SparseR1C used to compute the wires
// L+R+M[0]M[1]+O+k=0
// if a Term is zero, it means the field doesn't exist (ex M=[0,0] means there is no multiplicative term)
type SparseR1C struct {
	L, R, O Term
	M       [2]Term
	K       int // stores only the ID of the constant term that is used
}

func (r1c *SparseR1C) String(getCoeff func(cID int) string, getVisibility func(vID int) schema.Visibility) string {
	var sbb strings.Builder
	sbb.WriteString("L[")
	r1c.L.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] * R[")
	r1c.R.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] + M0[")
	r1c.M[0].String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] + M1[")
	r1c.M[1].String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] + O[")
	r1c.O.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] + K[")
	sbb.WriteString(getCoeff(r1c.K))
	sbb.WriteString("]")

	return sbb.String()
}

func (system *SparseR1CSCore) IsValid() error {
	// TODO @gbotrel add unit test for that.

	inputConstrained := make([]bool, system.GetNbSecretVariables()+system.GetNbPublicVariables())
	cptInputs := len(inputConstrained)
	if cptInputs == 0 {
		return errors.New("invalid constraint system: no input defined")
	}

	cptHints := len(system.MHints)
	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the terms and mark our inputs / hints as constrained
	processTerm := func(t Term) {

		// L and M[0] handles the same wire but with a different coeff
		vID := t.WireID()
		if t.CoeffID() != CoeffIdZero {
			if vID < len(inputConstrained) {
				if !inputConstrained[vID] {
					inputConstrained[vID] = true
					cptInputs--
				}
			} else {
				// internal variable, let's check if it's a hint
				if _, ok := system.MHints[vID]; ok {
					vID -= (system.GetNbPublicVariables() + system.GetNbSecretVariables())
					if !mHintsConstrained[vID] {
						mHintsConstrained[vID] = true
						cptHints--
					}
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
		if cptHints|cptInputs == 0 {
			return nil // we can stop.
		}

	}

	// something is a miss, we build the error string
	var sbb strings.Builder
	if cptInputs != 0 {
		sbb.WriteString(strconv.Itoa(cptInputs))
		sbb.WriteString(" unconstrained input(s):")
		sbb.WriteByte('\n')
		for i := 0; i < len(inputConstrained) && cptInputs != 0; i++ {
			if !inputConstrained[i] {
				if i < len(system.Public) {
					sbb.WriteString(system.Public[i])
				} else {
					sbb.WriteString(system.Secret[i-len(system.Public)])
				}
				sbb.WriteByte('\n')
				cptInputs--
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
