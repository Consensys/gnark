/*
Copyright © 2020 ConsenSys
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

package frontend

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// errNoValue triggered when trying to access a variable that was not allocated
var errNoValue = errors.New("can't determine API input value")

type Variable interface{}

// variable of a circuit
// represents a variable to a circuit, plus the  linear combination leading to it.
// the linExp is always non empty, the PartialVariabl can be unset. It is set and allocated in the
// circuit when there is no other choice (to avoid wasting wires doing only linear expressions)
type variable struct {
	visibility compiled.Visibility
	id         int // index of the wire in the corresponding list of wires (private, public or intermediate)
	linExp     compiled.LinearExpression
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func (v *variable) assertIsSet(cs *constraintSystem) {

	if len(v.linExp) == 0 {
		panic(errNoValue)
	}

}

// isConstant returns true if the variable is ONE_WIRE * coeff
func (v *variable) isConstant() bool {
	if len(v.linExp) != 1 {
		return false
	}
	_, vID, visibility := v.linExp[0].Unpack()
	return vID == 0 && visibility == compiled.Public
}

func (v *variable) constantValue(cs *constraintSystem) *big.Int {
	// TODO this might be a good place to start hunting useless allocations.
	// maybe through a big.Int pool.
	if !v.isConstant() {
		panic("can't get big.Int value on a non-constant variable")
	}
	return new(big.Int).Set(&cs.coeffs[v.linExp[0].CoeffID()])
}
