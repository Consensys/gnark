/*
 *
 * Copyright © 2020 ConsenSys
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * /
 */

package sw_bw6761

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bw6761"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
	"testing"
)

const testCurve = ecc.BN254

type pairingBW6761 struct {
	A G1Affine
	B G2Affine
	C GT
}

func (circuit *pairingBW6761) Define(api frontend.API) error {
	// TODO
	Pair(api, []G1Affine{circuit.A}, []G2Affine{circuit.B})

	// pairingRes.Equal(api, circuit.C)

	return nil
}

func TestPairingBW6761(t *testing.T) {
	assert := test.NewAssert(t)
	// witness values
	var (
		a     bw6761.G1Affine
		b     bw6761.G2Affine
		c     bw6761.GT
		r1, _ = rand.Int(rand.Reader, fr.Modulus())
		r2, _ = rand.Int(rand.Reader, fr.Modulus())
	)
	_, _, g1, g2 := bw6761.Generators()

	a.ScalarMultiplication(&g1, r1)
	b.ScalarMultiplication(&g2, r2)
	c, err := bw6761.Pair([]bw6761.G1Affine{a}, []bw6761.G2Affine{b})
	if err != nil {
		panic(err)
	}

	circuit := pairingBW6761{
		A: G1Affine{
			X: emulated.NewElement[emulated.BW6761Fp](nil),
			Y: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		B: G2Affine{
			X: emulated.NewElement[emulated.BW6761Fp](nil),
			Y: emulated.NewElement[emulated.BW6761Fp](nil),
		},
		C: GT{
			B0: fields_bw6761.E3{
				A0: emulated.NewElement[emulated.BW6761Fp](nil),
				A1: emulated.NewElement[emulated.BW6761Fp](nil),
				A2: emulated.NewElement[emulated.BW6761Fp](nil),
			},
			B1: fields_bw6761.E3{
				A0: emulated.NewElement[emulated.BW6761Fp](nil),
				A1: emulated.NewElement[emulated.BW6761Fp](nil),
				A2: emulated.NewElement[emulated.BW6761Fp](nil),
			},
		},
	}

	witness := pairingBW6761{
		A: G1Affine{
			X: emulated.NewElement[emulated.BW6761Fp](a.X),
			Y: emulated.NewElement[emulated.BW6761Fp](a.Y),
		},
		B: G2Affine{
			X: emulated.NewElement[emulated.BW6761Fp](b.X),
			Y: emulated.NewElement[emulated.BW6761Fp](b.Y),
		},
		C: GT{
			B0: fields_bw6761.E3{
				A0: emulated.NewElement[emulated.BW6761Fp](c.B0.A0),
				A1: emulated.NewElement[emulated.BW6761Fp](c.B0.A1),
				A2: emulated.NewElement[emulated.BW6761Fp](c.B0.A2),
			},
			B1: fields_bw6761.E3{
				A0: emulated.NewElement[emulated.BW6761Fp](c.B1.A0),
				A1: emulated.NewElement[emulated.BW6761Fp](c.B1.A1),
				A2: emulated.NewElement[emulated.BW6761Fp](c.B1.A2),
			},
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := emulated.NewField[emulated.BW6761Fp](api)
		assert.NoError(err)
		return napi
	})

	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}
