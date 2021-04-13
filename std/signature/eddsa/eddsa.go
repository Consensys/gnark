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

// Package eddsa provides a ZKP-circuit function to verify a EdDSA signature.
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
	S frontend.Variable // TODO S must be split in 2, because it can be bigger than r (Hasse bound)
}

// Verify verifies an eddsa signature
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(cs *frontend.ConstraintSystem, sig Signature, msg frontend.Variable, pubKey PublicKey) error {

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
	hramConstant := hash.Hash(cs, data...)

	// lhs = cofactor*SB
	cofactorConstant := cs.Constant(pubKey.Curve.Cofactor)
	lhs := twistededwards.Point{}

	lhs.ScalarMulFixedBase(cs, pubKey.Curve.BaseX, pubKey.Curve.BaseY, sig.S, pubKey.Curve).
		ScalarMulNonFixedBase(cs, &lhs, cofactorConstant, pubKey.Curve)
	lhs.MustBeOnCurve(cs, pubKey.Curve)

	//rhs = cofactor*(R+H(R,A,M)*A)
	rhs := twistededwards.Point{}
	rhs.ScalarMulNonFixedBase(cs, &pubKey.A, hramConstant, pubKey.Curve).
		AddGeneric(cs, &rhs, &sig.R.A, pubKey.Curve).
		ScalarMulNonFixedBase(cs, &rhs, cofactorConstant, pubKey.Curve)
	rhs.MustBeOnCurve(cs, pubKey.Curve)

	cs.AssertIsEqual(lhs.X, rhs.X)
	cs.AssertIsEqual(lhs.Y, rhs.Y)

	return nil
}
