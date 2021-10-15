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
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	fr_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
)

// // Wire of a circuit
// // They represent secret or public inputs in a circuit struct{} / definition (see circuit.Define(), type Tag)
// type Wire struct {

// }

// Variable of a circuit
// represents a Variable to a circuit, plus the  linear combination leading to it.
// the linExp is always non empty, the PartialVariabl can be unset. It is set and allocated in the
// circuit when there is no other choice (to avoid wasting wires doing only linear expressions)
type Variable struct {
	WitnessValue interface{} // witness usage only
	visibility   compiled.Visibility
	id           int // index of the wire in the corresponding list of wires (private, public or intermediate)
	linExp       compiled.LinearExpression
}

// assertIsSet panics if the variable is unset
// this may happen if inside a Define we have
// var a Variable
// cs.Mul(a, 1)
// since a was not in the circuit struct it is not a secret variable
func (v *Variable) assertIsSet(cs *constraintSystem) {
	if v.WitnessValue != nil {
		var l compiled.LogEntry
		var sbb strings.Builder
		l.WriteStack(&sbb)
		panic(fmt.Errorf("variable.WitnessValue is set. this is illegal in Define.\n%s", sbb.String()))
	}
	if len(v.linExp) == 0 {
		var l compiled.LogEntry
		var sbb strings.Builder
		l.WriteStack(&sbb)
		panic(fmt.Errorf("%w\n%s", ErrInputNotSet, sbb.String()))
	}

}

// GetWitnessValue returns the assigned value to the variable
// the value is converted to a field element (mod curveID base field modulus)
// then converted to a big.Int
// if it is not set this panics
func (v *Variable) GetWitnessValue(curveID ecc.ID) big.Int {
	if v.WitnessValue == nil {
		var l compiled.LogEntry
		var sbb strings.Builder
		l.WriteStack(&sbb)
		panic(fmt.Errorf("%w\n%s", ErrInputNotSet, sbb.String()))
	}

	b := FromInterface(v.WitnessValue)
	switch curveID {
	case ecc.BLS12_377:
		var e fr_bls12377.Element
		e.SetBigInt(&b)
		e.ToBigIntRegular(&b)
	case ecc.BLS12_381:
		var e fr_bls12381.Element
		e.SetBigInt(&b)
		e.ToBigIntRegular(&b)
	case ecc.BN254:
		var e fr_bn254.Element
		e.SetBigInt(&b)
		e.ToBigIntRegular(&b)
	case ecc.BLS24_315:
		var e fr_bls24315.Element
		e.SetBigInt(&b)
		e.ToBigIntRegular(&b)
	case ecc.BW6_761:
		var e fr_bw6761.Element
		e.SetBigInt(&b)
		e.ToBigIntRegular(&b)
	default:
		panic("curve not implemented")
	}
	return b
}

// Assign v = value . This must called when using a Circuit as a witness data structure
//
// Prefer the use of variable.WitnessValue = value
func (v *Variable) Assign(value interface{}) {
	if v.WitnessValue != nil {
		panic("variable already assigned")
	}
	v.WitnessValue = value
}
