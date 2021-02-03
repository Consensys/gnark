// Copyright 2020 ConsenSys AG
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pcs

import (
	bn256backend "github.com/consensys/gnark/internal/backend/bn256/pcs"
	"github.com/consensys/gurvy/bn256/fr"
)

func (plonkcs *UntypedPlonkCS) toBN256() *bn256backend.CS {

	toReturn := bn256backend.CS{
		NbInternalVariables: plonkcs.NbInternalVariables,
		NbPublicVariables:   plonkcs.NbPublicVariables,
		NbSecretVariables:   plonkcs.NbSecretVariables,
		Constraints:         plonkcs.Constraints,
		Assertions:          plonkcs.Assertions,
		Logs:                plonkcs.Logs,
		Coeffs:              make([]fr.Element, len(plonkcs.Coeffs)),
	}

	for i := 0; i < len(plonkcs.Coeffs); i++ {
		toReturn.Coeffs[i].SetBigInt(&plonkcs.Coeffs[i])
	}

	return &toReturn
}
