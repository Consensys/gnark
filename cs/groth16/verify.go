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

package groth16

import (
	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/internal/curve"
)

// Verify verifies a proof
func Verify(proof *Proof, vk *VerifyingKey, publicInputs map[string]cs.Assignment) (bool, error) {

	c := curve.GetCurve()

	var kSum curve.G1Jac
	var eKrsδ, eArBs, eKvkγ curve.PairingResult
	chan1 := make(chan bool, 1)
	chan2 := make(chan bool, 1)

	// e([Krs]1, -[δ]2)
	go func() {
		c.MillerLoop(proof.Krs, vk.G2Aff.DeltaNeg, &eKrsδ)
		chan1 <- true
	}()

	// e([Ar]1, [Bs]2)
	go func() {
		c.MillerLoop(proof.Ar, proof.Bs, &eArBs)
		chan2 <- true
	}()

	inputs, err := ParsePublicInput(vk.PublicInputsTracker, publicInputs)
	if err != nil {
		return false, err
	}
	kSum.WindowedMultiExp(c, vk.G1Jac.K, inputs)

	// e(Σx.[Kvk(t)]1, -[γ]2)
	var kSumAff curve.G1Affine
	kSum.ToAffineFromJac(&kSumAff)

	c.MillerLoop(kSumAff, vk.G2Aff.GammaNeg, &eKvkγ)

	<-chan1
	<-chan2
	right := c.FinalExponentiation(&eKrsδ, &eArBs, &eKvkγ)
	return vk.E.Equal(&right), nil
}

// ParsePublicInput return the input values, not in Montgomery form
func ParsePublicInput(expectedNames []string, publicInput map[string]cs.Assignment) ([]curve.Element, error) {

	toReturn := make([]curve.Element, len(expectedNames))

	for i := 0; i < len(expectedNames); i++ {

		// ONE_WIRE is a reserved name, it should not be set by the user
		if _, ok := publicInput[cs.OneWire]; ok {
			return nil, ErrGotOneWire
		}

		if expectedNames[i] == cs.OneWire {
			toReturn[i].SetOne()
			toReturn[i].FromMont()
		} else {

			if val, ok := publicInput[expectedNames[i]]; ok {
				if !val.IsPublic {
					return nil, ErrGotPrivateInput
				}
				toReturn[i] = val.Value.ToRegular()
			} else {
				return nil, ErrMissingAssigment
			}

		}

	}
	return toReturn, nil
}
