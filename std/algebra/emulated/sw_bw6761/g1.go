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
	bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
)

type G1Affine = sw_emulated.AffinePoint[emulated.BW6761Fp]

func NewG1Affine(v bw6761.G1Affine) G1Affine {
	return G1Affine{
		X: emulated.ValueOf[emulated.BW6761Fp](v.X),
		Y: emulated.ValueOf[emulated.BW6761Fp](v.Y),
	}
}
