// +build bn256

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
	"github.com/consensys/gnark/ecc/bn256"
)

// GetCurve returns bn256 singleton accessor
var GetCurve = bn256.BN256

// ID is used to ensure compatibilities of binaries (each curve has a unique ID)
const ID = bn256.ID

type G1Affine = bn256.G1Affine
type G2Affine = bn256.G2Affine

type G1Jac = bn256.G1Jac
type G2Jac = bn256.G2Jac
type PairingResult = bn256.PairingResult
