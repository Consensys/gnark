// Copyright 2020 ConsenSys Software Inc.
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

package bn256

import (
	"github.com/consensys/gurvy/bn256/fr"
)

// Poly polynomial represented by coefficients bn256 fr field.
type Poly struct {
	Data []fr.Element
}

// Degree returns the degree of the polynomial, which is the length of Data.
func (p *Poly) Degree() uint64 {
	res := uint64(len(p.Data) - 1)
	return res
}
