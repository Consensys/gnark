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
	"errors"
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend/schema"
)

// errNoValue triggered when trying to access a variable that was not allocated
var errNoValue = errors.New("can't determine API input value")

// Variable represent a linear expression of wires
type Variable struct {
	LinExp LinearExpression
}

// Clone returns a copy of the underlying slice
func (v Variable) Clone() Variable {
	var res Variable
	res.LinExp = make([]Term, len(v.LinExp))
	copy(res.LinExp, v.LinExp)
	return res
}

func (v Variable) string(sbb *strings.Builder, coeffs []big.Int) {
	for i := 0; i < len(v.LinExp); i++ {
		v.LinExp[i].string(sbb, coeffs)
		if i+1 < len(v.LinExp) {
			sbb.WriteString(" + ")
		}
	}
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func (v Variable) AssertIsSet() {

	if len(v.LinExp) == 0 {
		panic(errNoValue)
	}

}

// isConstant returns true if the variable is ONE_WIRE * coeff
func (v Variable) IsConstant() bool {
	if len(v.LinExp) != 1 {
		return false
	}
	_, vID, visibility := v.LinExp[0].Unpack()
	return vID == 0 && visibility == schema.Public
}
