// +build bn256

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

import "github.com/consensys/gnark/curve/fr"

const mimcNbRounds = 91

// plain execution of a mimc run
// m: message
// k: encryption key
func (h MiMC) encrypt(m, k fr.Element) fr.Element {

	for _, cons := range h.Params {
		// m = (m+k+c)^7
		var tmp fr.Element
		tmp.Add(&m, &k).Add(&tmp, &cons)
		m.Square(&tmp).
			Mul(&m, &tmp).
			Square(&m).
			Mul(&m, &tmp)
	}
	m.Add(&m, &k)
	return m

}
