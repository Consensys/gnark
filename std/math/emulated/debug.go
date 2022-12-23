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

package emulated

import (
	"fmt"
	"math/big"
)

func (f *Field[T]) String(a *Element[T]) (string, error) {
	// for debug only, if is not test engine then no-op
	var fp T
	blimbs := make([]*big.Int, len(a.Limbs))
	for i, v := range a.Limbs {
		switch vv := v.(type) {
		case *big.Int:
			blimbs[i] = vv
		case big.Int:
			blimbs[i] = &vv
		case int:
			blimbs[i] = new(big.Int)
			blimbs[i].SetInt64(int64(vv))
		case uint:
			blimbs[i] = new(big.Int)
			blimbs[i].SetUint64(uint64(vv))
		default:
			return "", fmt.Errorf("not big int")
		}
	}
	res := new(big.Int)
	err := recompose(blimbs, fp.BitsPerLimb(), res)
	if err != nil {
		return "", fmt.Errorf("recompose: %w", err)
	}
	reduced := new(big.Int).Mod(res, fp.Modulus())
	return reduced.String(), nil
}
