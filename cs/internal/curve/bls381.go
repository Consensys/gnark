// +build bls381

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

package curve

import (
	"github.com/consensys/gnark/ecc/bls381"
	"github.com/consensys/gnark/ecc/bls381/fr"
)

// GetCurve returns bls381 singleton accessor
var GetCurve = bls381.BLS381

// CurveID is used to ensure compatibilities of binaries (each curve has a unique ID)
const CurveID = bls381.ID

type G1Affine = bls381.G1Affine
type G2Affine = bls381.G2Affine

type G1Jac = bls381.G1Jac
type G2Jac = bls381.G2Jac
type PairingResult = bls381.PairingResult

// Fr Curve

type Element = fr.Element

const RootOfUnityStr = "10238227357739495823651030575849232062558860180284477541189508159991286009131"
const MaxOrder = 32
const NbBits = fr.ElementBits
const NbLimbs = fr.ElementLimbs
