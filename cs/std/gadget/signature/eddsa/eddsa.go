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

package eddsa

import (
	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/internal/curve"
	twistededwards "github.com/consensys/gnark/cs/std/gadget/algebra/twisted_edwards"
	"github.com/consensys/gnark/cs/std/gadget/hash/mimc"
	"github.com/consensys/gnark/cs/std/reference/signature/eddsa"
)

// PublicKey snark version of the public key
type PublicKey struct {
	A twistededwards.Point
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(circuit *cs.CS, pubKey eddsa.PublicKey, sig eddsa.Signature, message *cs.Constraint) {

	var cofactorMont curve.Element
	cofactorMont.Set(&sig.EdCurve.Cofactor)
	cofactorMont.ToMont()

	var sigSMont curve.Element
	sigSMont.Set(&sig.S)
	sigSMont.ToMont()

	// first put data in the circuit
	RSnark := twistededwards.NewPoint(circuit, sig.R.X, sig.R.Y)
	sAllocated := circuit.ALLOCATE(sigSMont)                                    // s part of the signature (s = r+H(R,A,M)*secret)
	cofactorAllocated := circuit.ALLOCATE(cofactorMont)                         // cofactor of group of the group <base_point>
	pubKeyAllocated := twistededwards.NewPoint(circuit, pubKey.A.X, pubKey.A.Y) // allocate the public key on the circuit

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []*cs.Constraint{
		RSnark.X,
		RSnark.Y,
		pubKeyAllocated.X,
		pubKeyAllocated.Y,
		message,
	}
	hramAllocated := mimc.NewMiMC("seed").Hash(circuit, data...)

	// lhs = cofactor*SB
	lhs := twistededwards.NewPoint(circuit, nil, nil)
	lhs.ScalarMul(&sig.EdCurve.Base, *sig.EdCurve, sAllocated, curve.NbBits).
		ScalarMul(&lhs, *sig.EdCurve, cofactorAllocated, 4)

	// rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.NewPoint(circuit, nil, nil)
	rhs.ScalarMul(pubKeyAllocated, *sig.EdCurve, hramAllocated, curve.NbBits).
		Add(&rhs, &sig.R, *sig.EdCurve).
		ScalarMul(&rhs, *sig.EdCurve, cofactorAllocated, 4)

	circuit.MUSTBE_EQ(lhs.X, rhs.X)
	circuit.MUSTBE_EQ(lhs.Y, rhs.Y)
}
