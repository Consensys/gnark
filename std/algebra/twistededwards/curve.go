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
	frbls377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	edbls377 "github.com/consensys/gnark-crypto/ecc/bls12-377/twistededwards"
	frbls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	edbls381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	frbn256 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	edbn256 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	frbw761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	edbw761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark/crypto/utils"
)

// EdCurve stores the info on the chosen edwards curve
type EdCurve struct {
	A, D, Cofactor, Order, BaseX, BaseY, Modulus big.Int
	ID                                           ecc.ID
}

var newTwistedEdwards map[ecc.ID]func() EdCurve

func init() {
	newTwistedEdwards = make(map[ecc.ID]func() EdCurve)
	newTwistedEdwards[ecc.BLS12_381] = newEdBLS381
	newTwistedEdwards[ecc.BN254] = newEdBN256
	newTwistedEdwards[ecc.BLS12_377] = newEdBLS377
	newTwistedEdwards[ecc.BW6_761] = newEdBW761
}

// NewEdCurve returns an Edwards curve parameters
func NewEdCurve(id ecc.ID) (EdCurve, error) {
	if constructor, ok := newTwistedEdwards[id]; ok {
		return constructor(), nil
	}
	return EdCurve{}, errors.New("unknown curve id")
}

// -------------------------------------------------------------------------------------------------
// constructors

func newEdBN256() EdCurve {

	edcurve := edbn256.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(cofactorReg),
		Order:    utils.FromInterface(edcurve.Order),
		BaseX:    utils.FromInterface(edcurve.Base.X),
		BaseY:    utils.FromInterface(edcurve.Base.Y),
		ID:       ecc.BN254,
	}
	res.Modulus.Set(frbn256.Modulus())

	return res

}

func newEdBLS381() EdCurve {

	edcurve := edbls381.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(cofactorReg),
		Order:    utils.FromInterface(edcurve.Order),
		BaseX:    utils.FromInterface(edcurve.Base.X),
		BaseY:    utils.FromInterface(edcurve.Base.Y),
		ID:       ecc.BLS12_381,
	}
	res.Modulus.Set(frbls381.Modulus())

	return res
}

func newEdBLS377() EdCurve {

	edcurve := edbls377.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(cofactorReg),
		Order:    utils.FromInterface(edcurve.Order),
		BaseX:    utils.FromInterface(edcurve.Base.X),
		BaseY:    utils.FromInterface(edcurve.Base.Y),
		ID:       ecc.BLS12_377,
	}
	res.Modulus.Set(frbls377.Modulus())

	return res
}

func newEdBW761() EdCurve {

	edcurve := edbw761.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(cofactorReg),
		Order:    utils.FromInterface(edcurve.Order),
		BaseX:    utils.FromInterface(edcurve.Base.X),
		BaseY:    utils.FromInterface(edcurve.Base.Y),
		ID:       ecc.BW6_761,
	}
	res.Modulus.Set(frbw761.Modulus())

	return res
}
