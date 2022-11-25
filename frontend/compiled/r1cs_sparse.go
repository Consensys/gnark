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

// R1CS decsribes a set of SparseR1C constraint
type SparseR1CS[E field.El, ptE field.PtEl[E]] struct {
	ConstraintSystem[E, ptE]
	Constraints []SparseR1C[E, ptE]
}

// GetNbConstraints returns the number of constraints
func (cs *SparseR1CS[E, ptE]) GetNbConstraints() int {
	return len(cs.Constraints)
}

// SparseR1C used to compute the wires
// L+R+M[0]M[1]+O+k=0
// if a Term is zero, it means the field doesn't exist (ex M=[0,0] means there is no multiplicative term)
type SparseR1C[E field.El, ptE field.PtEl[E]] struct {
	L, R, O Term[E, ptE]    // left, right, output terms. Left and right are addition terms
	M       [2]Term[E, ptE] // multiplication terms
	K       E               // constant term
}

func (r1c *SparseR1C[E, ptE]) String() string {
	var sbb strings.Builder
	sbb.WriteString("L[")
	r1c.L.string(&sbb)
	sbb.WriteString("] * R[")
	r1c.R.string(&sbb)
	sbb.WriteString("] + M0[")
	r1c.M[0].string(&sbb)
	sbb.WriteString("] + M1[")
	r1c.M[1].string(&sbb)
	sbb.WriteString("] + O[")
	r1c.O.string(&sbb)
	sbb.WriteString("] + K[")
	sbb.WriteString(ptE(&r1c.K).String())
	sbb.WriteString("]")

	return sbb.String()
}
