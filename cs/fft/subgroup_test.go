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
	"testing"

	. "github.com/consensys/gnark/cs/internal/curve"
)

func TestNewSubGroup(t *testing.T) {

	var rootOfUnity Element
	rootOfUnity.SetString(RootOfUnityStr)

	var one Element
	one.SetOne()

	// TODO fixme : stopping at 2^25 , probably enough?
	for i := uint(0); i < uint(25); i++ {
		m := 1 << i // m = 2^i

		S := NewSubGroup(rootOfUnity, MaxOrder, m)

		// test S.GeneratorSqRt^2 == S.Generator
		var generatorSqRtSq Element
		generatorSqRtSq.Mul(&S.GeneratorSqRt, &S.GeneratorSqRt)
		if generatorSqRtSq != S.Generator {
			t.Error("GeneratorSqRt^2 != Generator")
		}

		// test order of S.Generator
		var generatorPow Element
		generatorPow.Set(&S.Generator)
		for j := uint(0); j < i; j++ {
			if generatorPow.Equal(&one) {
				t.Error("Generator order too small: expected:", m, "received:", 1<<j)
				break
			}
			generatorPow.Mul(&generatorPow, &generatorPow)
		}
		if !generatorPow.Equal(&one) {
			t.Error("Generator power incorrect: expected: 1 received:", generatorPow.FromMont())
			break
		}

		// test S.Generator * S.GeneratorInv == 1
		var inverseTest Element
		inverseTest.Mul(&S.Generator, &S.GeneratorInv)
		if !inverseTest.Equal(&one) {
			t.Error("Generator inverse incorrect: expected: 1 received:", inverseTest.FromMont())
			break
		}

		// test S.GeneratorSqRt * S.GeneratorSqRtInv == 1
		inverseTest.Mul(&S.GeneratorSqRt, &S.GeneratorSqRtInv)
		if !inverseTest.Equal(&one) {
			t.Error("GeneratorSqRt inverse incorrect: expected: 1 received:", inverseTest.FromMont())
			break
		}

		// test S.Cardinality, S.CardinalityInv
		if S.Cardinality != m {
			t.Error("Cardinality incorrect: expected:", m, "received:", S.Cardinality)
			break
		}
		var cardinalityelement Element
		cardinalityelement.SetUint64(uint64(S.Cardinality))
		inverseTest.Mul(&cardinalityelement, &S.CardinalityInv)
		if !inverseTest.Equal(&one) {
			t.Error("CardinalityInv incorrect: expected: 1 received:", inverseTest.FromMont())
			break
		}
	}
}
