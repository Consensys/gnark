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

package compiled

import (
	"strings"

	"github.com/consensys/gnark/frontend/field"
)

// R1CS decsribes a set of R1C constraint
type R1CS[E field.El, ptE field.PtEl[E]] struct {
	ConstraintSystem[E, ptE]
	Constraints []R1C[E, ptE]
}

// GetNbConstraints returns the number of constraints
func (r1cs *R1CS[E, ptE]) GetNbConstraints() int {
	return len(r1cs.Constraints)
}

// R1C used to compute the wires
type R1C[E field.El, ptE field.PtEl[E]] struct {
	L, R, O LinearExpression[E, ptE]
}

func (r1c *R1C[E, ptE]) String() string {
	var sbb strings.Builder
	sbb.WriteString("L[")
	r1c.L.string(&sbb)
	sbb.WriteString("] * R[")
	r1c.R.string(&sbb)
	sbb.WriteString("] = O[")
	r1c.O.string(&sbb)
	sbb.WriteString("]")

	return sbb.String()
}
