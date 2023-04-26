/*
Copyright 2020 ConsenSys

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
	"reflect"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bls12377 "github.com/consensys/gnark/backend/groth16/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
)

// Proof represents a Groth16 proof
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type Proof struct {
	Ar, Krs sw_bls12377.G1Affine
	Bs      sw_bls12377.G2Affine
}

// VerifyingKey represents a Groth16 verifying key
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type VerifyingKey struct {
	// e(α, β)
	E fields_bls12377.E12

	// -[γ]2, -[δ]2
	G2 struct {
		GammaNeg, DeltaNeg sw_bls12377.G2Affine
	}

	// [Kvk]1
	G1 struct {
		K []sw_bls12377.G1Affine // The indexes correspond to the public wires

	}
}

// Verify implements the verification function of Groth16.
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
// publicInputs do NOT contain the ONE_WIRE
func Verify(api frontend.API, vk VerifyingKey, proof Proof, publicInputs []frontend.Variable) {
	if len(vk.G1.K) == 0 {
		panic("inner verifying key needs at least one point; VerifyingKey.G1 must be initialized before compiling circuit")

	}

	// compute kSum = Σx.[Kvk(t)]1
	var kSum sw_bls12377.G1Affine

	// kSum = Kvk[0] (assumes ONE_WIRE is at position 0)
	kSum.X = vk.G1.K[0].X
	kSum.Y = vk.G1.K[0].Y

	for k, v := range publicInputs {
		var ki sw_bls12377.G1Affine
		ki.ScalarMul(api, vk.G1.K[k+1], v)
		kSum.AddAssign(api, ki)

	}

	// compute e(Σx.[Kvk(t)]1, -[γ]2) * e(Krs,δ) * e(Ar,Bs)
	pairing, _ := sw_bls12377.Pair(api, []sw_bls12377.G1Affine{kSum, proof.Krs, proof.Ar}, []sw_bls12377.G2Affine{vk.G2.GammaNeg, vk.G2.DeltaNeg, proof.Bs})

	// vk.E must be equal to pairing
	vk.E.AssertIsEqual(api, pairing)

}

// Assign values to the "in-circuit" VerifyingKey from a "out-of-circuit" VerifyingKey
func (vk *VerifyingKey) Assign(_ovk groth16.VerifyingKey) {
	ovk, ok := _ovk.(*groth16_bls12377.VerifyingKey)
	if !ok {
		panic("expected *groth16_bls12377.VerifyingKey, got " + reflect.TypeOf(_ovk).String())

	}

	e, err := bls12377.Pair([]bls12377.G1Affine{ovk.G1.Alpha}, []bls12377.G2Affine{ovk.G2.Beta})
	if err != nil {
		panic(err)

	}
	vk.E.Assign(&e)

	vk.G1.K = make([]sw_bls12377.G1Affine, len(ovk.G1.K))
	for i := 0; i < len(ovk.G1.K); i++ {
		vk.G1.K[i].Assign(&ovk.G1.K[i])

	}
	var deltaNeg, gammaNeg bls12377.G2Affine
	deltaNeg.Neg(&ovk.G2.Delta)
	gammaNeg.Neg(&ovk.G2.Gamma)
	vk.G2.DeltaNeg.Assign(&deltaNeg)
	vk.G2.GammaNeg.Assign(&gammaNeg)

}

// Fill one point for inner verifying key
func (vk *VerifyingKey) FillG1K(_ovk groth16.VerifyingKey) {
	ovk, ok := _ovk.(*groth16_bls12377.VerifyingKey)
	if !ok {
		panic("expected *groth16_bls12377.VerifyingKey, got " + reflect.TypeOf(_ovk).String())

	}
	vk.G1.K = make([]sw_bls12377.G1Affine, len(ovk.G1.K))

}

// Assign the proof values of Groth16
func (proof *Proof) Assign(_oproof groth16.Proof) {
	oproof, ok := _oproof.(*groth16_bls12377.Proof)
	if !ok {
		panic("expected *groth16_bls12377.Proof, got " + reflect.TypeOf(oproof).String())

	}
	proof.Ar.Assign(&oproof.Ar)
	proof.Krs.Assign(&oproof.Krs)
	proof.Bs.Assign(&oproof.Bs)

}
