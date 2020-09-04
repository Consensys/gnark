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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields"
	"github.com/consensys/gnark/std/algebra/sw"
)

// Proof represents a groth16 proof in a r1cs
type Proof struct {
	Ar, Krs sw.G1Affine // πA, πC in https://eprint.iacr.org/2020/278.pdf
	Bs      sw.G2Affine // πB in https://eprint.iacr.org/2020/278.pdf
}

// VerifyingKey represents the groth16 verifying key in a r1cs
type VerifyingKey struct {

	// e(α, β)
	E fields.E12

	// -[γ]2, -[δ]2
	G2 struct {
		GammaNeg, DeltaNeg sw.G2Affine
	}

	// [Kvk]1 (part of the verifying key yielding psi0, cf https://eprint.iacr.org/2020/278.pdf)
	G1 []sw.G1Affine // The indexes correspond to the public wires
}

// Verify implements the verification function of groth16.
// pubInputNames should what r1cs.PublicInputs() outputs for the inner r1cs.
// It creates public circuits input, corresponding to the pubInputNames slice.
// Notations and naming are from https://eprint.iacr.org/2020/278.
func Verify(cs *frontend.CS, pairingInfo sw.PairingContext, innerVk VerifyingKey, innerProof Proof, innerPubInputs []frontend.Variable) {

	var eπCdelta, eπAπB, epsigamma fields.E12

	// e(-πC, -δ)
	sw.MillerLoopAffine(cs, innerProof.Krs, innerVk.G2.DeltaNeg, &eπCdelta, pairingInfo)

	// e(πA, πB)
	sw.MillerLoopAffine(cs, innerProof.Ar, innerProof.Bs, &eπAπB, pairingInfo)

	// compute psi0 using a sequence of multiexponentiations
	// TODO maybe implement the bucket method with c=1 when there's a large input set
	var psi0, tmp sw.G1Affine

	// assign the initial psi0 to the part of the public key corresponding to one_wire
	// TODO this assumes ONE_WIRE is at position 0
	psi0.X = innerVk.G1[0].X
	psi0.Y = innerVk.G1[0].Y

	for k, v := range innerPubInputs {
		tmp.ScalarMul(cs, &innerVk.G1[k+1], v, 377)
		psi0.AddAssign(cs, &tmp)
	}

	// e(psi0, -gamma)
	sw.MillerLoopAffine(cs, psi0, innerVk.G2.GammaNeg, &epsigamma, pairingInfo)

	// combine the results before performing the final expo
	var preFinalExpo fields.E12
	preFinalExpo.Mul(cs, &eπCdelta, &eπAπB, pairingInfo.Extension).
		Mul(cs, &preFinalExpo, &epsigamma, pairingInfo.Extension)

	// performs the final expo
	var resPairing fields.E12
	resPairing.FinalExpoBLS(cs, &preFinalExpo, pairingInfo.AteLoop, pairingInfo.Extension)

	// vk.E must be equal to resPairing
	innerVk.E.MustBeEqual(cs, resPairing)

}
