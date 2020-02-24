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

package fft

import (
	"math/bits"

	"github.com/consensys/gnark/cs/internal/curve"
)

// SubGroup with a power of 2 cardinality
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
type SubGroup struct {
	Generator        curve.Element
	GeneratorInv     curve.Element
	GeneratorSqRt    curve.Element // generator of 2 adic subgroup of order 2*nb_constraints
	GeneratorSqRtInv curve.Element
	Cardinality      int
	CardinalityInv   curve.Element
}

// NewSubGroup returns a subgroup with a power of 2 cardinality
// cardinality >= m
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
func NewSubGroup(rootOfUnity curve.Element, maxOrderRoot uint, m int) *SubGroup {
	subGroup := &SubGroup{}
	x := nextPowerOfTwo(uint(m))

	// maxOderRoot is the largest power-of-two order for any element in the field
	// set subGroup.GeneratorSqRt = rootOfUnity^(2^(maxOrderRoot-log(x)-1))
	// to this end, compute expo = 2^(maxOrderRoot-log(x)-1)
	logx := uint(bits.TrailingZeros(x))
	if logx > maxOrderRoot-1 {
		panic("m is too big: the required root of unity does not exist")
	}
	expo := uint64(1 << (maxOrderRoot - logx - 1))
	subGroup.GeneratorSqRt.Exp(rootOfUnity, expo)

	// Generator = GeneratorSqRt^2 has order x
	subGroup.Generator.Mul(&subGroup.GeneratorSqRt, &subGroup.GeneratorSqRt) // order x
	subGroup.Cardinality = int(x)
	subGroup.GeneratorSqRtInv.Inverse(&subGroup.GeneratorSqRt)
	subGroup.GeneratorInv.Inverse(&subGroup.Generator)
	subGroup.CardinalityInv.SetUint64(uint64(x)).Inverse(&subGroup.CardinalityInv)

	return subGroup
}

func nextPowerOfTwo(n uint) uint {
	p := uint(1)
	if (n & (n - 1)) == 0 {
		return n
	}
	for p < n {
		p <<= 1
	}
	return p
}
