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
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/gadgets"
	"github.com/consensys/gurvy"
	edbls381 "github.com/consensys/gurvy/bls381/twistededwards"
	edbn256 "github.com/consensys/gurvy/bn256/twistededwards"
)

// EdCurveGadget stores the info on the chosen edwards curve
type EdCurveGadget struct {
	A, D, Cofactor, Order, BaseX, BaseY big.Int
}

var newTwistedEdwards map[gurvy.ID]func(*frontend.CS) EdCurveGadget

func init() {
	newTwistedEdwards = make(map[gurvy.ID]func(*frontend.CS) EdCurveGadget)
	newTwistedEdwards[gurvy.BLS381] = newEdBLS381
	newTwistedEdwards[gurvy.BN256] = newEdBN256
}

// NewEdCurveGadget returns an Edwards curve parameters
func NewEdCurveGadget(circuit *frontend.CS, id gurvy.ID) (EdCurveGadget, error) {
	if val, ok := newTwistedEdwards[id]; ok {
		return val(circuit), nil
	}
	return EdCurveGadget{}, gadgets.ErrUnknownCurve
}

// -------------------------------------------------------------------------------------------------
// constructors

func newEdBN256(circuit *frontend.CS) EdCurveGadget {

	edcurve := edbn256.GetEdwardsCurve()

	res := EdCurveGadget{
		A:        backend.FromInterface(edcurve.A),
		D:        backend.FromInterface(edcurve.D),
		Cofactor: backend.FromInterface(edcurve.Cofactor),
		Order:    backend.FromInterface(edcurve.Order),
		BaseX:    backend.FromInterface(edcurve.Base.X),
		BaseY:    backend.FromInterface(edcurve.Base.Y),
	}

	return res

}

func newEdBLS381(circuit *frontend.CS) EdCurveGadget {

	edcurve := edbls381.GetEdwardsCurve()

	res := EdCurveGadget{
		A:        backend.FromInterface(edcurve.A),
		D:        backend.FromInterface(edcurve.D),
		Cofactor: backend.FromInterface(edcurve.Cofactor),
		Order:    backend.FromInterface(edcurve.Order),
		BaseX:    backend.FromInterface(edcurve.Base.X),
		BaseY:    backend.FromInterface(edcurve.Base.Y),
	}

	return res

}
