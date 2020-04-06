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

package mimc

import "github.com/consensys/gnark/frontend"

// execution of a mimc run expressed as r1cs
func (h MiMC) encrypt(circuit *frontend.CS, message *frontend.Constraint, key *frontend.Constraint) *frontend.Constraint {

	res := message

	for i := 0; i < len(h.Params); i++ {
		//for i := 0; i < 1; i++ {
		tmp := circuit.ADD(res, key, h.Params[i])
		// res = (res+k+c)^7
		res = circuit.MUL(tmp, tmp)
		res = circuit.MUL(res, tmp)
		res = circuit.MUL(res, res)
		res = circuit.MUL(res, tmp)
	}
	res = circuit.ADD(res, key)
	return res

}
