// +build bls377 !bn256,!bls381

// TODO what about bn256 and bls381?
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

func TestFFT(t *testing.T) {

	var w, winv Element

	// primitive 4-th root of 1
	w.SetString("880904806456922042258150504921383618666682042621506879489")

	// inverse of primitive 4-th root of 1
	winv.SetString("8444461749428370423367920132324624489117748830232680209268551413295902359552")

	poly := make([]Element, 4)
	poly[0].SetString("12323")
	poly[1].SetString("298923")
	poly[2].SetString("28379")
	poly[3].SetString("98343")
	polyCpy := make([]Element, 4)
	copy(polyCpy[:], poly[:])

	fftExpected := make([]Element, 4)
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

	var got [8]Element // not in Mongomery form
	got[0].SetUint64(1)
	got[1].SetUint64(2)
	got[2].SetUint64(3)
	got[3].SetUint64(4)
	got[4].SetUint64(5)
	got[5].SetUint64(6)
	got[6].SetUint64(7)
	got[7].SetUint64(8)

	bitReverse(got[:])

	var want [8]Element // not in Mongomery form
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
	var rootOfUnity Element
	rootOfUnity.SetString(RootOfUnityStr)

	const nbGates = 500000
	subGroup := NewSubGroup(rootOfUnity, MaxOrder, nbGates)

	a := make([]Element, subGroup.Cardinality)
	for i := 0; i < len(a); i++ {
		a[i].SetRandom()
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		FFT(a, subGroup.Generator)
	}
}
