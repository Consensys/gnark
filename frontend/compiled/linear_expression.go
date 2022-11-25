// Copyright 2021 ConsenSys AG
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

// A linear expression is a linear combination of Term
type LinearExpression[E field.El, ptE field.PtEl[E]] []Term[E, ptE]

// Clone returns a copy of the underlying slice
func (l LinearExpression[E, ptE]) Clone() LinearExpression[E, ptE] {
	res := make(LinearExpression[E, ptE], len(l))
	copy(res, l)
	return res
}

func (l LinearExpression[E, ptE]) string(sbb *strings.Builder) {
	for i := 0; i < len(l); i++ {
		l[i].string(sbb)
		if i+1 < len(l) {
			sbb.WriteString(" + ")
		}
	}
}

// Len return the lenght of the Variable (implements Sort interface)
func (l LinearExpression[E, ptE]) Len() int {
	return len(l)
}

// Equals returns true if both SORTED expressions are the same
//
// pre conditions: l and o are sorted
func (l LinearExpression[E, ptE]) Equal(o LinearExpression[E, ptE]) bool {
	if len(l) != len(o) {
		return false
	}
	if (l == nil) != (o == nil) {
		return false
	}
	for i := 0; i < len(l); i++ {
		if !(l[i].Var == o[i].Var && ptE(&l[i].Coeff).Equal(&o[i].Coeff)) {
			return false
		}
	}
	return true
}

// Swap swaps terms in the Variable (implements Sort interface)
func (l LinearExpression[E, ptE]) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// Less returns true if variableID for term at i is less than variableID for term at j (implements Sort interface)
func (l LinearExpression[E, ptE]) Less(i, j int) bool {
	_, iID, iVis := l[i].Unpack()
	_, jID, jVis := l[j].Unpack()
	if iVis == jVis {
		return iID < jID
	}
	return iVis > jVis
}

// HashCode returns a fast-to-compute but NOT collision resistant hash code identifier for the linear
// expression
func (l LinearExpression[E, ptE]) HashCode() uint64 {
	h := uint64(17)
	for _, val := range l {
		h = h*23 + val.HashCode()
	}
	return h
}
