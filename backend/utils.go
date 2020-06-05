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

package backend

import (
	"math/big"
	"strconv"

	fr_bls377 "github.com/consensys/gurvy/bls377/fr"
	fr_bls381 "github.com/consensys/gurvy/bls381/fr"
	fr_bn256 "github.com/consensys/gurvy/bn256/fr"
)

// FromInterface converts an interface to a big.Int element
func FromInterface(i1 interface{}) big.Int {
	var val big.Int

	switch c1 := i1.(type) {
	case uint64:
		val.SetUint64(c1)
	case int:
		if _, ok := val.SetString(strconv.Itoa(c1), 10); !ok {
			panic("unable to set big.Int from base10 string")
		}
	case string:
		if _, ok := val.SetString(c1, 10); !ok {
			panic("unable to set big.Int from base10 string")
		}
	case big.Int:
		val = c1
	case *big.Int:
		val.Set(c1)
	case fr_bn256.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bn256.Element:
		c1.ToBigIntRegular(&val)
	case fr_bls381.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bls381.Element:
		c1.ToBigIntRegular(&val)
	case fr_bls377.Element:
		c1.ToBigIntRegular(&val)
	case *fr_bls377.Element:
		c1.ToBigIntRegular(&val)
	case []byte:
		val.SetBytes(c1)
	default:
		panic("invalid type")
	}

	return val
}
