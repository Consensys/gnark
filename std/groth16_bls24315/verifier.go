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

// Package groth16_bls24315 provides a ZKP-circuit function to verify BLS24-315 Groth16 inside a BW6-633 circuit.
package groth16_bls24315

import (
	"reflect"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	groth16_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/groth16"
	"github.com/consensys/gnark/std/algebra/fields_bls24315"
	"github.com/consensys/gnark/std/algebra/sw_bls24315"
	bls24315 "github.com/nume-crypto/gnark-crypto/ecc/bls24-315"
)

// Proof represents a Groth16 proof
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type Proof struct {
	Ar, Krs sw_bls24315.G1Affine
	Bs      sw_bls24315.G2Affine
}

// VerifyingKey represents a Groth16 verifying key
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type VerifyingKey struct {
	// e(α, β)
	E fields_bls24315.E24

	// -[γ]2, -[δ]2
	G2 struct {
		GammaNeg, DeltaNeg sw_bls24315.G2Affine
	}

	// [Kvk]1
	G1 struct {
		K []sw_bls24315.G1Affine // The indexes correspond to the public wires
	}
}

// Verify implements the verification function of Groth16.
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
// publicInputs do NOT contain the ONE_WIRE
func Verify(api frontend.API, vk VerifyingKey, proof Proof, publicInputs []frontend.Variable) {
	if len(vk.G1.K) == 0 {
		panic("innver verifying key needs at least one point; VerifyingKey.G1 must be initialized before compiling circuit")
	}

	// compute kSum = Σx.[Kvk(t)]1
	var kSum sw_bls24315.G1Affine

	// kSum = Kvk[0] (assumes ONE_WIRE is at position 0)
	kSum.X = vk.G1.K[0].X
	kSum.Y = vk.G1.K[0].Y

	for k, v := range publicInputs {
		var ki sw_bls24315.G1Affine
		ki.ScalarMultiplication(api, vk.G1.K[k+1], v)
		kSum.AddAssign(api, ki)
	}

	// compute e(Σx.[Kvk(t)]1, -[γ]2) * e(Krs,δ) * e(Ar,Bs)
	ml, _ := sw_bls24315.MillerLoop(api, []sw_bls24315.G1Affine{kSum, proof.Krs, proof.Ar}, []sw_bls24315.G2Affine{vk.G2.GammaNeg, vk.G2.DeltaNeg, proof.Bs})
	pairing := sw_bls24315.FinalExponentiation(api, ml)

	// vk.E must be equal to pairing
	vk.E.AssertIsEqual(api, pairing)

}

// Assign values to the "in-circuit" VerifyingKey from a "out-of-circuit" VerifyingKey
func (vk *VerifyingKey) Assign(_ovk groth16.VerifyingKey) {
	ovk, ok := _ovk.(*groth16_bls24315.VerifyingKey)
	if !ok {
		panic("expected *groth16_bls24315.VerifyingKey, got " + reflect.TypeOf(_ovk).String())
	}

	e, err := bls24315.Pair([]bls24315.G1Affine{ovk.G1.Alpha}, []bls24315.G2Affine{ovk.G2.Beta})
	if err != nil {
		panic(err)
	}
	vk.E.Assign(&e)

	vk.G1.K = make([]sw_bls24315.G1Affine, len(ovk.G1.K))
	for i := 0; i < len(ovk.G1.K); i++ {
		vk.G1.K[i].Assign(&ovk.G1.K[i])
	}
	var deltaNeg, gammaNeg bls24315.G2Affine
	deltaNeg.Neg(&ovk.G2.Delta)
	gammaNeg.Neg(&ovk.G2.Gamma)
	vk.G2.DeltaNeg.Assign(&deltaNeg)
	vk.G2.GammaNeg.Assign(&gammaNeg)
}
