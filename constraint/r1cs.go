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
	"github.com/consensys/gnark/logger"
)

type R1CS interface {
	ConstraintSystem

	// AddConstraint adds a constraint to the sytem and returns its id
	// This does not check for validity of the constraint.
	// If a debugInfo parameter is provided, it will be appended to the debug info structure
	// and will grow the memory usage of the constraint system.
	AddConstraint(r1c R1C, debugInfo ...DebugInfo) int

	// GetConstraints() []R1C
	BuildLevelTOREMOVE()
	// TODO maybe add sort of a constraint iterator / so that build level and isValid
	// can be factorized between CS and R1CS.
}

// R1C used to compute the wires
type R1C struct {
	L, R, O LinearExpression
}

// R1CS describes a set of R1C constraint
type R1CSCore struct {
	System
	Constraints []R1C
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CSCore) GetNbConstraints() int {
	return len(r1cs.Constraints)
}

func (r1cs *R1CSCore) BuildLevelTOREMOVE() {
	buildR1CSLevels(r1cs)
}

// IsValid perform post compilation checks on the Variables
//
// 1. checks that all user inputs are referenced in at least one constraint
// 2. checks that all hints are constrained
func (system *R1CSCore) IsValid() error {

	// TODO @gbotrel add unit test for that.

	inputConstrained := make([]bool, system.GetNbSecretVariables()+system.GetNbPublicVariables())
	// one wire does not need to be constrained
	inputConstrained[0] = true
	cptInputs := len(inputConstrained) - 1 // marking 1 wire as already constrained // TODO @gbotrel check that
	if cptInputs == 0 {
		return errors.New("invalid constraint system: no input defined")
	}

	cptHints := len(system.MHints)
	mHintsConstrained := make(map[int]bool)

	// for each constraint, we check the linear expressions and mark our inputs / hints as constrained
	processLinearExpression := func(l LinearExpression) {
		for _, t := range l {
			if t.CoeffID() == CoeffIdZero {
				// ignore zero coefficient, as it does not constraint the Variable
				// though, we may want to flag that IF the Variable doesn't appear else where
				continue
			}
			vID := t.WireID()
			if vID < len(inputConstrained) {
				if !inputConstrained[vID] {
					inputConstrained[vID] = true
					cptInputs--
				}
			} else {
				// internal variable, let's check if it's a hint
				if _, ok := system.MHints[vID]; ok {
					if !mHintsConstrained[vID] {
						mHintsConstrained[vID] = true
						cptHints--
					}
				}
			}

		}
	}
	for _, r1c := range system.Constraints {
		processLinearExpression(r1c.L)
		processLinearExpression(r1c.R)
		processLinearExpression(r1c.O)

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
		return errors.New(sbb.String())
	}

	if cptHints != 0 {
		// TODO @gbotrel @ivokub investigate --> emulated hints seems to go in this path a lot.
		sbb.WriteString(strconv.Itoa(cptHints))
		sbb.WriteString(" unconstrained hints; i.e. wire created through NewHint() but doesn't not appear in the constraint system")
		sbb.WriteByte('\n')
		log := logger.Logger()
		log.Warn().Err(errors.New(sbb.String())).Send()
		return nil
		// TODO we may add more debug info here → idea, in NewHint, take the debug stack, and store in the hint map some
		// debugInfo to find where a hint was declared (and not constrained)
	}
	return errors.New(sbb.String())
}

func (r1c *R1C) String(getCoeff func(cID int) string, getVisibility func(vID int) schema.Visibility) string {
	var sbb strings.Builder
	sbb.WriteString("L[")
	r1c.L.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] * R[")
	r1c.R.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("] = O[")
	r1c.O.String(&sbb, getCoeff, getVisibility)
	sbb.WriteString("]")

	return sbb.String()
}
