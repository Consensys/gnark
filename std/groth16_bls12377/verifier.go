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

// Package groth16_bls12377 provides a ZKP-circuit function to verify BLS12_377 Groth16 inside a BW6_761 circuit.
package groth16_bls12377

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
)

// Proof represents a groth16 proof in a r1cs
type Proof struct {
	Ar, Krs sw_bls12377.G1Affine // πA, πC in https://eprint.iacr.org/2020/278.pdf
	Bs      sw_bls12377.G2Affine // πB in https://eprint.iacr.org/2020/278.pdf
}

// VerifyingKey represents the groth16 verifying key in a r1cs
type VerifyingKey struct {

	// e(α, β)
	E fields_bls12377.E12

	// -[γ]2, -[δ]2
	G2 struct {
		GammaNeg, DeltaNeg sw_bls12377.G2Affine
	}

	// [Kvk]1 (part of the verifying key yielding psi0, cf https://eprint.iacr.org/2020/278.pdf)
	G1 []sw_bls12377.G1Affine // The indexes correspond to the public wires
}

// Verify implements the verification function of groth16.
// pubInputNames should what r1cs.PublicInputs() outputs for the inner r1cs.
// It creates public circuits input, corresponding to the pubInputNames slice.
// Notations and naming are from https://eprint.iacr.org/2020/278.
func Verify(api frontend.API, innerVk VerifyingKey, innerProof Proof, innerPubInputs []frontend.Variable) {

	// compute psi0 using a sequence of multiexponentiations
	// TODO maybe implement the bucket method with c=1 when there's a large input set
	var psi0, tmp sw_bls12377.G1Affine

	if len(innerVk.G1) == 0 {
		panic("innver verifying key needs at least one point; VerifyingKey.G1 must be initialized before compiling circuit")
	}

	// assign the initial psi0 to the part of the public key corresponding to one_wire
	// note this assumes ONE_WIRE is at position 0
	psi0.X = innerVk.G1[0].X
	psi0.Y = innerVk.G1[0].Y

	for k, v := range innerPubInputs {
		tmp.ScalarMul(api, innerVk.G1[k+1], v)
		psi0.AddAssign(api, tmp)
	}

	var resMillerLoop fields_bls12377.E12
	// e(psi0, -gamma)*e(-πC, -δ)*e(πA, πB)
	sw_bls12377.TripleMillerLoop(api, [3]sw_bls12377.G1Affine{psi0, innerProof.Krs, innerProof.Ar}, [3]sw_bls12377.G2Affine{innerVk.G2.GammaNeg, innerVk.G2.DeltaNeg, innerProof.Bs}, &resMillerLoop)

	// performs the final expo
	var resPairing fields_bls12377.E12
	resPairing.FinalExponentiation(api, resMillerLoop)

	// vk.E must be equal to resPairing
	innerVk.E.MustBeEqual(api, resPairing)

}
