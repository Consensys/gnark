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

package constraint

import (
	"math"
	"strconv"
	"strings"

	"github.com/consensys/gnark/frontend/schema"
)

// Term represents a coeff * variable in a constraint system
type Term struct {
	CID, VID uint32
}

// Coeff represents a term coefficient data. It is instantiated by the concrete
// constraint system implementation.
// Most of the scalar field used in gnark are on 4 uint64, so we have a clear memory overhead here.
// TODO make that generic, but first attempt has no perf gain and contaminates codebase / make
// it less readable.
type Coeff [6]uint64

// IsZero returns true if coeff == 0
func (z *Coeff) IsZero() bool {
	return (z[5] | z[4] | z[3] | z[2] | z[1] | z[0]) == 0
}

// ids of the coefficients with simple values in any cs.coeffs slice.
// TODO @gbotrel let's keep that here for the refactoring -- and move it to concrete cs package after
const (
	CoeffIdZero     = 0
	CoeffIdOne      = 1
	CoeffIdTwo      = 2
	CoeffIdMinusOne = 3
	CoeffIdMinusTwo = 4
)

func (t *Term) MarkConstant() {
	t.VID = math.MaxUint32
}

func (t *Term) IsConstant() bool {
	return t.VID == math.MaxUint32
}

func (t *Term) WireID() int {
	return int(t.VID)
}

func (t *Term) CoeffID() int {
	return int(t.CID)
}

func (t Term) String(sbb *strings.Builder, getCoeff func(cID int) string, getVisibility func(vID int) schema.Visibility) {
	sbb.WriteString(getCoeff(t.CoeffID()))
	sbb.WriteString("*")
	switch getVisibility(t.WireID()) {
	case schema.Internal:
		sbb.WriteString("i")
	case schema.Public:
		sbb.WriteString("p")
	case schema.Secret:
		sbb.WriteString("s")
	case schema.Virtual:
		sbb.WriteString("v")
	case schema.Unset:
		sbb.WriteString("u")
	default:
		panic("not implemented")
	}
	sbb.WriteString(strconv.Itoa(int(t.VID)))
}
