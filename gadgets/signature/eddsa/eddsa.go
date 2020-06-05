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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets/algebra/twistededwards"
	"github.com/consensys/gnark/gadgets/hash/mimc"
)

// PublicKeyGadget stores an eddsa public key in a r1cs
type PublicKeyGadget struct {
	A     twistededwards.PointGadget
	Curve twistededwards.EdCurveGadget
}

// SignatureGadget stores a signature as a gadget
type SignatureGadget struct {
	R PublicKeyGadget
	S *frontend.Constraint
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(circuit *frontend.CS, sig SignatureGadget, msg *frontend.Constraint, pubKey PublicKeyGadget) error {

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []*frontend.Constraint{
		sig.R.A.X,
		sig.R.A.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}

	mimcGadget, err := mimc.NewMiMCGadget("seed", pubKey.Curve.ID)
	if err != nil {
		return err
	}
	hramAllocated := mimcGadget.Hash(circuit, data...)

	// lhs = cofactor*SB
	cofactorAllocated := circuit.ALLOCATE(pubKey.Curve.Cofactor)
	lhs := twistededwards.NewPointGadget(circuit, nil, nil)

	lhs.ScalarMulFixedBase(circuit, pubKey.Curve.BaseX, pubKey.Curve.BaseY, sig.S, pubKey.Curve).
		ScalarMulNonFixedBase(circuit, &lhs, cofactorAllocated, pubKey.Curve)
	// TODO adding lhs.IsOnCurveGadget(...) makes the r1cs bug

	// rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.NewPointGadget(circuit, nil, nil)
	rhs.ScalarMulNonFixedBase(circuit, &pubKey.A, hramAllocated, pubKey.Curve).
		AddGeneric(circuit, &rhs, &sig.R.A, pubKey.Curve).
		ScalarMulNonFixedBase(circuit, &rhs, cofactorAllocated, pubKey.Curve)
	// TODO adding rhs.IsOnCurveGadget(...) makes the r1cs bug

	circuit.MUSTBE_EQ(lhs.X, rhs.X)
	circuit.MUSTBE_EQ(lhs.Y, rhs.Y)

	return nil
}
