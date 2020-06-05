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
	"math/big"

	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/gadgets"
	"github.com/consensys/gurvy"
	edbls381 "github.com/consensys/gurvy/bls381/twistededwards"
	edbn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

// EdCurveGadget stores the info on the chosen edwards curve
type EdCurveGadget struct {
	A, D, Cofactor, Order, BaseX, BaseY, Modulus big.Int
	ID                                           gurvy.ID
}

var newTwistedEdwards map[gurvy.ID]func() EdCurveGadget

func init() {
	newTwistedEdwards = make(map[gurvy.ID]func() EdCurveGadget)
	newTwistedEdwards[gurvy.BLS381] = newEdBLS381
	newTwistedEdwards[gurvy.BN256] = newEdBN256
}

// NewEdCurveGadget returns an Edwards curve parameters
func NewEdCurveGadget(id gurvy.ID) (EdCurveGadget, error) {
	if constructor, ok := newTwistedEdwards[id]; ok {
		return constructor(), nil
	}
	return EdCurveGadget{}, gadgets.ErrUnknownCurve
}

// -------------------------------------------------------------------------------------------------
// constructors

func newEdBN256() EdCurveGadget {

	edcurve := edbn256.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurveGadget{
		A:        backend.FromInterface(edcurve.A),
		D:        backend.FromInterface(edcurve.D),
		Cofactor: backend.FromInterface(cofactorReg),
		Order:    backend.FromInterface(edcurve.Order),
		BaseX:    backend.FromInterface(edcurve.Base.X),
		BaseY:    backend.FromInterface(edcurve.Base.Y),
		ID:       gurvy.BN256,
	}
	// TODO use the modulus soon-to-be exported by goff
	res.Modulus.SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)

	return res

}

func newEdBLS381() EdCurveGadget {

	edcurve := edbls381.GetEdwardsCurve()
	var cofactorReg big.Int
	edcurve.Cofactor.ToBigInt(&cofactorReg)

	res := EdCurveGadget{
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
