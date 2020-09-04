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
	"github.com/consensys/gnark/std/algebra/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey struct {
	A     twistededwards.Point
	Curve twistededwards.EdCurve
}

// Signature stores a signature  (to be used in gnark circuit)
type Signature struct {
	R PublicKey
	S frontend.Variable
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(cs *frontend.CS, sig Signature, msg frontend.Variable, pubKey PublicKey) error {

	// compute H(R, A, M), all parameters in data are in Montgomery form
	data := []frontend.Variable{
		sig.R.A.X,
		sig.R.A.Y,
		pubKey.A.X,
		pubKey.A.Y,
		msg,
	}

	hash, err := mimc.NewMiMC("seed", pubKey.Curve.ID)
	if err != nil {
		return err
	}
	hramAllocated := hash.Hash(cs, data...)

	// lhs = cofactor*SB
	cofactorAllocated := cs.Allocate(pubKey.Curve.Cofactor)
	lhs := twistededwards.Point{}

	lhs.ScalarMulFixedBase(cs, pubKey.Curve.BaseX, pubKey.Curve.BaseY, sig.S, pubKey.Curve).
		ScalarMulNonFixedBase(cs, &lhs, cofactorAllocated, pubKey.Curve)
	// TODO adding lhs.IsOnCurve(...) makes the r1cs bug

	// rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.Point{}
	rhs.ScalarMulNonFixedBase(cs, &pubKey.A, hramAllocated, pubKey.Curve).
		AddGeneric(cs, &rhs, &sig.R.A, pubKey.Curve).
		ScalarMulNonFixedBase(cs, &rhs, cofactorAllocated, pubKey.Curve)
	// TODO adding rhs.IsOnCurve(...) makes the r1cs bug

	cs.MustBeEqual(lhs.X, rhs.X)
	cs.MustBeEqual(lhs.Y, rhs.Y)

	return nil
}
