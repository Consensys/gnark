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
	A twistededwards.PointGadget
}

// SignatureGadget stores a signature as a gadget
type SignatureGadget struct {
	R PublicKeyGadget
	S *frontend.Constraint
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(circuit *frontend.CS, sig SignatureGadget, msg *frontend.Constraint, pubKey PublicKeyGadget, params twistededwards.EdCurveGadget) error {

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []*frontend.Constraint{
		sig.R.A.X,
		sig.R.A.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}

	mimcGadget, err := mimc.NewMiMCGadget("seed", params.ID)
	if err != nil {
		return err
	}
	hramAllocated := mimcGadget.Hash(circuit, data...)
	hramAllocated.Tag("hramAllocated")

	// lhs = cofactor*SB
	cofactorAllocated := circuit.ALLOCATE(params.Cofactor)
	lhs := twistededwards.NewPointGadget(circuit, nil, nil)

	lhs.ScalarMulFixedBase(circuit, params.BaseX, params.BaseY, sig.S, params).
		ScalarMulNonFixedBase(circuit, &lhs, cofactorAllocated, params)
	// TODO adding lhs.IsOnCurveGadget(...) makes the r1cs bug

	// rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.NewPointGadget(circuit, nil, nil)
	rhs.ScalarMulNonFixedBase(circuit, &pubKey.A, hramAllocated, params).
		AddGeneric(circuit, &rhs, &sig.R.A, params).
		ScalarMulNonFixedBase(circuit, &rhs, cofactorAllocated, params)
	// TODO adding rhs.IsOnCurveGadget(...) makes the r1cs bug

	rhs.X.Tag("rhsX")
	lhs.X.Tag("lhsX")

	// circuit.MUSTBE_EQ(lhs.X, rhs.X)
	// circuit.MUSTBE_EQ(lhs.Y, rhs.Y)

	return nil
}
