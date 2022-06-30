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

// Package kzg_bls24315 provides a ZKP-circuit function to verify BLS24_315 KZG inside a BW6_633 circuit.
package kzg_bls24315

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls24315"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
)

// Digest commitment of a polynomial.
type Digest = sw_bls24315.G1Affine

// VK verification key (G2 part of SRS)
type VK struct {
	G1 sw_bls24315.G1Affine    // G₁
	G2 [2]sw_bls24315.G2Affine // [G₂, [α]G₂]
}

// OpeningProof KZG proof for opening at a single point.
type OpeningProof struct {
	// H quotient polynomial (f - f(z))/(x-z)
	H sw_bls24315.G1Affine

	// ClaimedValue purported value
	ClaimedValue frontend.Variable
}

// Verify verifies a KZG opening proof at a single point
func Verify(api frontend.API, commitment Digest, proof OpeningProof, point frontend.Variable, srs VK) {

	// [f(a)]G₁
	var claimedValueG1Aff sw_bls24315.G1Affine
	claimedValueG1Aff.ScalarMul(api, srs.G1, proof.ClaimedValue)

	// [f(α) - f(a)]G₁
	var fminusfaG1 sw_bls24315.G1Affine
	fminusfaG1.Neg(api, claimedValueG1Aff)
	fminusfaG1.AddAssign(api, commitment)

	// [-H(α)]G₁
	var negH sw_bls24315.G1Affine
	negH.Neg(api, proof.H)

	// [α-a]G₂
	var alphaMinusaG2 sw_bls24315.G2Affine
	alphaMinusaG2.ScalarMul(api, srs.G2[0], point).
		Neg(api, alphaMinusaG2).
		AddAssign(api, srs.G2[1])

	// e([f(α) - f(a)]G₁, G₂).e([-H(α)]G₁, [α-a]G₂) ==? 1
	resPairing, _ := sw_bls24315.Pair(
		api,
		[]sw_bls24315.G1Affine{fminusfaG1, negH},
		[]sw_bls24315.G2Affine{srs.G2[0], alphaMinusaG2},
	)

	var one fields_bls24315.E24
	one.SetOne()
	resPairing.AssertIsEqual(api, one)

}
