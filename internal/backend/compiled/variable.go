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
	"math/big"
	"strings"
)

// Variable represent a linear expression of wires
type Variable []Term

// Clone returns a copy of the underlying slice
func (l Variable) Clone() Variable {
	res := make(Variable, len(l))
	copy(res, l)
	return res
}

// Len return the lenght of the Variable (implements Sort interface)
func (l Variable) Len() int {
	return len(l)
}

// Equals returns true if both SORTED expressions are the same
//
// pre conditions: l and o are sorted
func (l Variable) Equal(o Variable) bool {
	if len(l) != len(o) {
		return false
	}
	if (l == nil) != (o == nil) {
		return false
	}
	for i := 0; i < len(l); i++ {
		if l[i] != o[i] {
			return false
		}
	}
	return true
}

// Swap swaps terms in the Variable (implements Sort interface)
func (l Variable) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// Less returns true if variableID for term at i is less than variableID for term at j (implements Sort interface)
func (l Variable) Less(i, j int) bool {
	_, iID, iVis := l[i].Unpack()
	_, jID, jVis := l[j].Unpack()
	if iVis == jVis {
		return iID < jID
	}
	return iVis > jVis
}

func (l Variable) string(sbb *strings.Builder, coeffs []big.Int) {
	for i := 0; i < len(l); i++ {
		l[i].string(sbb, coeffs)
		if i+1 < len(l) {
			sbb.WriteString(" + ")
		}
	}
}
