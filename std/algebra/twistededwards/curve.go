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
	edbls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/twistededwards"
	edbls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/twistededwards"
	edbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	edbw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/twistededwards"
	edbw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/twistededwards"
	"github.com/consensys/gnark/internal/utils"
)

// Coordinates of a point on a twisted Edwards curve
type Coord struct {
	X, Y big.Int
}

// EdCurve stores the info on the chosen edwards curve
// note that all curves implemented in gnark-crypto have A = -1
type EdCurve struct {
	A, D, Cofactor, Order big.Int
	Base                  Coord
	ID                    ecc.ID
}

var constructors map[ecc.ID]func() EdCurve

func init() {
	constructors = map[ecc.ID]func() EdCurve{
		ecc.BLS12_381: newEdBLS381,
		ecc.BN254:     newEdBN254,
		ecc.BLS12_377: newEdBLS377,
		ecc.BW6_761:   newEdBW761,
		ecc.BLS24_315: newEdBLS315,
		ecc.BW6_633:   newEdBW633,
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

func newEdBN254() EdCurve {

	edcurve := edbn254.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BN254,
	}

}

func newEdBLS381() EdCurve {

	edcurve := edbls12381.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BLS12_381,
	}

}

func newEdBLS377() EdCurve {

	edcurve := edbls12377.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BLS12_377,
	}

}

func newEdBW633() EdCurve {

	edcurve := edbw6633.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BW6_633,
	}

}

func newEdBW761() EdCurve {

	edcurve := edbw6761.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BW6_761,
	}

}

func newEdBLS315() EdCurve {

	edcurve := edbls24315.GetEdwardsCurve()

	return EdCurve{
		A:        utils.FromInterface(edcurve.A),
		D:        utils.FromInterface(edcurve.D),
		Cofactor: utils.FromInterface(edcurve.Cofactor),
		Order:    utils.FromInterface(edcurve.Order),
		Base: Coord{
			X: utils.FromInterface(edcurve.Base.X),
			Y: utils.FromInterface(edcurve.Base.Y),
		},
		ID: ecc.BLS24_315,
	}

}
