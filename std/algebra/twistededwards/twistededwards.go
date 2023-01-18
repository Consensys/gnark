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

package twistededwards

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	edbls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	edbls12381_bandersnatch "github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	edbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edbls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/twistededwards"
	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
)

// Curve methods implemented by a twisted edwards curve inside a circuit
type Curve interface {
	Params() *CurveParams
	Endo() *EndoParams
	Add(p1, p2 Point) Point
	Double(p1 Point) Point
	Neg(p1 Point) Point
	AssertIsOnCurve(p1 Point)
	ScalarMul(p1 Point, scalar frontend.Variable) Point
	DoubleBaseScalarMul(p1, p2 Point, s1, s2 frontend.Variable) Point
	API() frontend.API
}

// Point represent a pair of X, Y coordinates inside a circuit
type Point struct {
	X, Y frontend.Variable
}

// CurveParams twisted edwards curve parameters ax^2 + y^2 = 1 + d*x^2*y^2
// Matches gnark-crypto curve specific params
type CurveParams struct {
	A, D, Cofactor, Order *big.Int
	Base                  [2]*big.Int // base point coordinates
}

// EndoParams endomorphism parameters for the curve, if they exist
type EndoParams struct {
	Endo   [2]*big.Int
	Lambda *big.Int
}

// NewEdCurve returns a new Edwards curve
func NewEdCurve(api frontend.API, id twistededwards.ID) (Curve, error) {
	snarkField, err := GetSnarkField(id)
	if err != nil {
		return nil, err
	}
	if api.Compiler().Field().Cmp(snarkField) != 0 {
		return nil, errors.New("invalid curve pair; snark field doesn't match twisted edwards field")
	}
	params, err := GetCurveParams(id)
	if err != nil {
		return nil, err
	}
	var endo *EndoParams

	// bandersnatch
	if id == twistededwards.BLS12_381_BANDERSNATCH {
		endo = &EndoParams{
			Endo:   [2]*big.Int{new(big.Int), new(big.Int)},
			Lambda: new(big.Int),
		}
		endo.Endo[0].SetString("37446463827641770816307242315180085052603635617490163568005256780843403514036", 10)
		endo.Endo[1].SetString("49199877423542878313146170939139662862850515542392585932876811575731455068989", 10)
		endo.Lambda.SetString("8913659658109529928382530854484400854125314752504019737736543920008458395397", 10)
	}

	// default
	return &curve{api: api, params: params, endo: endo, id: id}, nil
}

func GetCurveParams(id twistededwards.ID) (*CurveParams, error) {
	var params *CurveParams
	switch id {
	case twistededwards.BN254:
		params = newEdBN254()
	case twistededwards.BLS12_377:
		params = newEdBLS12_377()
	case twistededwards.BLS12_381:
		params = newEdBLS12_381()
	case twistededwards.BLS12_381_BANDERSNATCH:
		params = newEdBLS12_381_BANDERSNATCH()
	case twistededwards.BLS24_317:
		params = newEdBLS24_317()
	case twistededwards.BLS24_315:
		params = newEdBLS24_315()
	case twistededwards.BW6_761:
		params = newEdBW6_761()
	case twistededwards.BW6_633:
		params = newEdBW6_633()
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
	return params, nil
}

// GetSnarkField returns the matching snark curve for a twisted edwards curve
func GetSnarkField(id twistededwards.ID) (*big.Int, error) {
	switch id {
	case twistededwards.BN254:
		return ecc.BN254.ScalarField(), nil
	case twistededwards.BLS12_377:
		return ecc.BLS12_377.ScalarField(), nil
	case twistededwards.BLS12_381, twistededwards.BLS12_381_BANDERSNATCH:
		return ecc.BLS12_381.ScalarField(), nil
	case twistededwards.BLS24_315:
		return ecc.BLS24_315.ScalarField(), nil
	case twistededwards.BLS24_317:
		return ecc.BLS24_317.ScalarField(), nil
	case twistededwards.BW6_761:
		return ecc.BW6_761.ScalarField(), nil
	case twistededwards.BW6_633:
		return ecc.BW6_633.ScalarField(), nil
	default:
		return nil, errors.New("unknown twisted edwards curve id")
	}
}

// -------------------------------------------------------------------------------------------------
// constructors

func newCurveParams() *CurveParams {
	return &CurveParams{
		A:        new(big.Int),
		D:        new(big.Int),
		Cofactor: new(big.Int),
		Order:    new(big.Int),
		Base:     [2]*big.Int{new(big.Int), new(big.Int)},
	}
}

func newEdBN254() *CurveParams {

	edcurve := edbn254.GetEdwardsCurve()
	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_381() *CurveParams {

	edcurve := edbls12381.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_381_BANDERSNATCH() *CurveParams {

	edcurve := edbls12381_bandersnatch.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS12_377() *CurveParams {

	edcurve := edbls12377.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBW6_633() *CurveParams {

	edcurve := edbw6633.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBW6_761() *CurveParams {

	edcurve := edbw6761.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS24_317() *CurveParams {

	edcurve := edbls24317.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}

func newEdBLS24_315() *CurveParams {

	edcurve := edbls24315.GetEdwardsCurve()

	r := newCurveParams()
	edcurve.A.BigInt(r.A)
	edcurve.D.BigInt(r.D)
	edcurve.Cofactor.BigInt(r.Cofactor)
	r.Order.Set(&edcurve.Order)
	edcurve.Base.X.BigInt(r.Base[0])
	edcurve.Base.Y.BigInt(r.Base[1])
	return r

}
