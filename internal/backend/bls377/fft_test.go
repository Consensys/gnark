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

package backend

import (
	"testing"

	"github.com/consensys/gurvy/bls377/fr"
)

func TestFFT(t *testing.T) {

	var w, winv fr.Element

	// primitive 4-th root of 1
	w.SetString("880904806456922042258150504921383618666682042621506879489")

	// inverse of primitive 4-th root of 1
	winv.SetString("8444461749428370423367920132324624489117748830232680209268551413295902359552")

	poly := make([]fr.Element, 4)
	poly[0].SetString("12323")
	poly[1].SetString("298923")
	poly[2].SetString("28379")
	poly[3].SetString("98343")
	polyCpy := make([]fr.Element, 4)
	copy(polyCpy[:], poly[:])

	fftExpected := make([]fr.Element, 4)
	fftExpected[0].SetString("437968")
	fftExpected[1].SetString("176691886079129423236139828277131126232163084109021849887887564")
	fftExpected[2].SetString("8444461749428370424248824938781546531375899335154063827935233455917408882477")
	fftExpected[3].SetString("8444461749428193732362745809358310391547622204027831664851124434067521319365")
	FFT(poly, w)

	for i := 0; i < 4; i++ {
		if !poly[i].Equal(&fftExpected[i]) {
			t.Fatal("Error fft")
		}
	}
}

func TestBitReverse(t *testing.T) {

	var got [8]fr.Element // not in Mongomery form
	got[0].SetUint64(1)
	got[1].SetUint64(2)
	got[2].SetUint64(3)
	got[3].SetUint64(4)
	got[4].SetUint64(5)
	got[5].SetUint64(6)
	got[6].SetUint64(7)
	got[7].SetUint64(8)

	bitReverse(got[:])

	var want [8]fr.Element // not in Mongomery form
	want[0].SetUint64(1)
	want[1].SetUint64(5)
	want[2].SetUint64(3)
	want[3].SetUint64(7)
	want[4].SetUint64(2)
	want[5].SetUint64(6)
	want[6].SetUint64(4)
	want[7].SetUint64(8)

	if got != want {
		t.Error("expected:", want, "received:", got)
	}
}

func BenchmarkFFT(b *testing.B) {

	const nbGates = 500000
	subGroup := NewDomain(nbGates)

	a := make([]fr.Element, subGroup.Cardinality)
	for i := 0; i < len(a); i++ {
		a[i].SetRandom()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FFT(a, subGroup.Generator)
	}
}

func TestNewDomain(t *testing.T) {

	var one fr.Element
	one.SetOne()

	// stopping at 2^25 , probably enough?
	for i := uint(0); i < uint(25); i++ {
		m := 1 << i // m = 2^i

		S := NewDomain(m)

		// test S.GeneratorSqRt^2 == S.Generator
		var generatorSqRtSq fr.Element
		generatorSqRtSq.Mul(&S.GeneratorSqRt, &S.GeneratorSqRt)
		if generatorSqRtSq != S.Generator {
			t.Error("GeneratorSqRt^2 != Generator")
		}

		// test order of S.Generator
		var generatorPow fr.Element
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
		var inverseTest fr.Element
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
		var cardinalityelement fr.Element
		cardinalityelement.SetUint64(uint64(S.Cardinality))
		inverseTest.Mul(&cardinalityelement, &S.CardinalityInv)
		if !inverseTest.Equal(&one) {
			t.Error("CardinalityInv incorrect: expected: 1 received:", inverseTest.FromMont())
			break
		}
	}
}
