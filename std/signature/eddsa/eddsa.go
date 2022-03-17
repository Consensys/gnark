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
	"errors"

	"github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/hash"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/twistededwards"
)

// PublicKey stores an eddsa public key (to be used in gnark circuit)
type PublicKey struct {
	A twistededwards.Point
}

// Signature stores a signature  (to be used in gnark circuit)
// An EdDSA signature is a tuple (R,S) where R is a point on the twisted Edwards curve
// and S a scalar. Since the base field of the twisted Edwards is Fr, the number of points
// N on the Edwards is < r+1+2sqrt(r)+2 (since the curve has 2 points of multiplicity 2).
// The subgroup l used in eddsa is <1/2N, so the reduction
// mod l ensures S < r, therefore there is no risk of overflow.
type Signature struct {
	R twistededwards.Point
	S frontend.Variable
}

// Verify verifies an eddsa signature using MiMC hash function
// cf https://en.wikipedia.org/wiki/EdDSA
func Verify(curve twistededwards.Curve, sig Signature, msg frontend.Variable, pubKey PublicKey, hash hash.Hash) error {

	// compute H(R, A, M)
	hash.Write(sig.R.X)
	hash.Write(sig.R.Y)
	hash.Write(pubKey.A.X)
	hash.Write(pubKey.A.Y)
	hash.Write(msg)
	hRAM := hash.Sum()

	base := twistededwards.Point{
		X: curve.Params().Base[0],
		Y: curve.Params().Base[1],
	}

	//[S]G-[H(R,A,M)]*A
	_A := curve.Neg(pubKey.A)
	Q := curve.DoubleBaseScalarMul(base, _A, sig.S, hRAM)
	curve.AssertIsOnCurve(Q)

	//[S]G-[H(R,A,M)]*A-R
	Q = curve.Add(curve.Neg(Q), sig.R)

	// [cofactor]*(lhs-rhs)
	log := logger.Logger()
	if !curve.Params().Cofactor.IsUint64() {
		err := errors.New("invalid cofactor")
		log.Err(err).Str("cofactor", curve.Params().Cofactor.String()).Send()
		return err
	}
	cofactor := curve.Params().Cofactor.Uint64()
	switch cofactor {
	case 4:
		Q = curve.Double(curve.Double(Q))
	case 8:
		Q = curve.Double(curve.Double(curve.Double(Q)))
	default:
		log.Warn().Str("cofactor", curve.Params().Cofactor.String()).Msg("curve cofactor is not implemented")
	}

	curve.API().AssertIsEqual(Q.X, 0)
	curve.API().AssertIsEqual(Q.Y, 1)

	return nil
}
