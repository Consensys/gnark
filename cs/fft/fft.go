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
	"sync"

	"github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/internal/pool"
)

// FFT computes the discrete Fourier transform of a and stores the result in a.
// The result is in bit-reversed order.
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
// The algorithm is recursive, decimation-in-frequency. [cite]
func FFT(a []curve.Element, w curve.Element) {
	var wg sync.WaitGroup
	asyncFFT(a, w, &wg)
	wg.Wait()
}

// Coset Evaluation on ker(X^n+1)
func Coset(a []curve.Element, w curve.Element, wSqrt curve.Element) {
	wSqrtCopy := wSqrt
	for i := 1; i < len(a); i++ {
		a[i].MulAssign(&wSqrtCopy)
		wSqrtCopy.MulAssign(&wSqrt)
	}

	FFT(a, w)
	BitReverse(a)
}

// InvCoset Get back polynomial from its values on ker X^n+1
func InvCoset(a []curve.Element, w curve.Element, wSqrt curve.Element) {

	var wInv, wSqrtInv curve.Element
	wInv.Inverse(&w)
	wSqrtInv.Inverse(&wSqrt)
	wsqrtInvCpy := wSqrtInv

	Inv(a, wInv)
	BitReverse(a)

	for i := 1; i < len(a); i++ {
		a[i].MulAssign(&wSqrtInv)
		wSqrtInv.MulAssign(&wsqrtInvCpy)
	}
}

func asyncFFT(a []curve.Element, w curve.Element, wg *sync.WaitGroup) {
	n := len(a)
	if n == 1 {
		return
	}
	m := n / 2

	// wPow == w^1
	wPow := w

	// i == 0
	tmp := a[0]
	a[0].AddAssign(&a[m])
	a[m].Sub(&tmp, &a[m])

	for i := 1; i < m; i++ {
		tmp = a[i]
		a[i].AddAssign(&a[i+m])
		a[i+m].
			Sub(&tmp, &a[i+m]).
			MulAssign(&wPow)

		wPow.MulAssign(&w)

	}

	// note: w is passed by value
	w.Square(&w)

	if m < 20 {
		asyncFFT(a[0:m], w, nil)
		asyncFFT(a[m:n], w, nil)
	} else {
		wg.Add(2)
		pool.Push(func() {
			asyncFFT(a[0:m], w, wg)
			wg.Done()
		}, true)
		pool.Push(func() {
			asyncFFT(a[m:n], w, wg)
			wg.Done()
		}, true)
	}
}

// Inv computes the inverse discrete Fourier transform of a and stores the result in a.
// See FFT for more info.
func Inv(a []curve.Element, wInv curve.Element) {
	var wg sync.WaitGroup
	asyncFFT(a, wInv, &wg)
	wg.Wait()

	// scale by inverse of n
	var nInv curve.Element
	nInv.SetUint64(uint64(len(a)))
	nInv.Inverse(&nInv)

	for i := 0; i < len(a); i++ {
		a[i].MulAssign(&nInv)
	}
}

// BitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2 (as in every single function in this file)
func BitReverse(a []curve.Element) {
	l := uint(len(a))
	n := uint(bits.UintSize - bits.TrailingZeros(l))

	var tmp curve.Element
	for i := uint(0); i < l; i++ {
		irev := bits.Reverse(i) >> n
		if irev > i {
			tmp = a[i]
			a[i] = a[irev]
			a[irev] = tmp
		}
	}
}

func reverse(x, n int) int {
	return int(bits.Reverse(uint(x)) >> (bits.UintSize - uint(n)))
}
