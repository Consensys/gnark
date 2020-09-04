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

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gurvy"
	edbls381 "github.com/consensys/gurvy/bls381/twistededwards"
	"github.com/consensys/gurvy/bn256/fr"
	edbn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

// EdCurve stores the info on the chosen edwards curve
type EdCurve struct {
	A, D, Cofactor, Order, BaseX, BaseY, Modulus big.Int
	ID                                           gurvy.ID
}

var newTwistedEdwards map[gurvy.ID]func() EdCurve

func init() {
	newTwistedEdwards = make(map[gurvy.ID]func() EdCurve)
	newTwistedEdwards[gurvy.BLS381] = newEdBLS381
	newTwistedEdwards[gurvy.BN256] = newEdBN256
}

// NewEdCurve returns an Edwards curve parameters
func NewEdCurve(id gurvy.ID) (EdCurve, error) {
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
		A:        backend.FromInterface(edcurve.A),
		D:        backend.FromInterface(edcurve.D),
		Cofactor: backend.FromInterface(cofactorReg),
		Order:    backend.FromInterface(edcurve.Order),
		BaseX:    backend.FromInterface(edcurve.Base.X),
		BaseY:    backend.FromInterface(edcurve.Base.Y),
		ID:       gurvy.BN256,
	}
	res.Modulus.Set(fr.Modulus())

	return res

}

func newEdBLS381() EdCurve {

	edcurve := edbls381.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurve{
		A:        backend.FromInterface(edcurve.A),
		D:        backend.FromInterface(edcurve.D),
		Cofactor: backend.FromInterface(cofactorReg),
		Order:    backend.FromInterface(edcurve.Order),
		BaseX:    backend.FromInterface(edcurve.Base.X),
		BaseY:    backend.FromInterface(edcurve.Base.Y),
		ID:       gurvy.BLS381,
	}
	// TODO use the modulus soon-to-be exported by goff
	res.Modulus.SetString("52435875175126190479447740508185965837690552500527637822603658699938581184513", 10)

	return res

}
