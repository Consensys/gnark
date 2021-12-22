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

package utils

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestFromInterfaceValidFormats(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("valid input should not panic")
		}
	}()

	var a fr.Element
	a.SetRandom()

	_ = FromInterface(a)
	_ = FromInterface(&a)
	_ = FromInterface(12)
	_ = FromInterface(big.NewInt(-42))
	_ = FromInterface(*big.NewInt(42))
	_ = FromInterface("8000")

}
