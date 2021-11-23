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
	"math/big"

	"github.com/consensys/gnark/internal/backend/compiled"
)

// Variable represents a variable in the circuit. Any integer type (e.g. int, *big.Int, fr.Element)
// can be assigned to it. It is also allowed to set a base-10 encoded string representing an integer value.
type Variable interface{}

// variable of a circuit
// represents a variable to a circuit, plus the  linear combination leading to it.
// the linExp is always non empty, the PartialVariabl can be unset. It is set and allocated in the
// circuit when there is no other choice (to avoid wasting wires doing only linear expressions)
// type variable struct {
// 	visibility compiled.Visibility
// 	id         int // index of the wire in the corresponding list of wires (private, public or intermediate)
// 	linExp     compiled.LinearExpression
// }

// func (v *variable) constantValue(cs *constraintSystem) *big.Int {
func (cs *constraintSystem) constantValue(v compiled.Variable) *big.Int {
	// TODO this might be a good place to start hunting useless allocations.
	// maybe through a big.Int pool.
	if !v.IsConstant() {
		panic("can't get big.Int value on a non-constant variable")
	}
	return new(big.Int).Set(&cs.coeffs[v.V[0].CoeffID()])
}
