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

package bandersnatch

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/bandersnatch"
	"github.com/consensys/gnark/internal/utils"
)

// Coordinates of a point on a twisted Edwards curve
type Coord struct {
	X, Y big.Int
}

// EdCurve stores the info on the chosen edwards curve
type EdCurve struct {
	A, D, Cofactor, Order, endo0, endo1 big.Int
	Base                                Coord
	ID                                  ecc.ID
	lambda                              big.Int
}

var constructors map[ecc.ID]func() EdCurve

func init() {
	constructors = map[ecc.ID]func() EdCurve{
		ecc.BLS12_381: newBandersnatch,
	}
}

// NewEdCurve returns an Edwards curve parameters
func NewEdCurve(id ecc.ID) (EdCurve, error) {
	if constructor, ok := constructors[id]; ok {
		return constructor(), nil
	}
	return EdCurve{}, errors.New("unknown curve id")
}

// -------------------------------------------------------------------------------------------------
// constructors

func newBandersnatch() EdCurve {

	edcurve := bandersnatch.GetEdwardsCurve()
	edcurve.Cofactor.FromMont()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID:     ecc.BLS12_381,
		lambda: utils.FromInterface("8913659658109529928382530854484400854125314752504019737736543920008458395397"),
		endo0:  utils.FromInterface("37446463827641770816307242315180085052603635617490163568005256780843403514036"),
		endo1:  utils.FromInterface("49199877423542878313146170939139662862850515542392585932876811575731455068989"),
	}
}
