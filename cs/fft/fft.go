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
	"runtime"
	"sync"

	"github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/internal/pool"
)

// FFT computes the discrete Fourier transform of a and stores the result in a.
// The result is in bit-reversed order.
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
// The algorithm is recursive, decimation-in-frequency. [cite]
func FFT(a []curve.Element, w curve.Element, numCPU ...uint) {
	var wg sync.WaitGroup
	asyncFFT(a, w, &wg, 1)
	wg.Wait()
	bitReverse(a)
}

func asyncFFT(a []curve.Element, w curve.Element, wg *sync.WaitGroup, splits uint) {
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1

	// wPow == w^1
	wPow := w

	// i == 0
	t := a[0]
	a[0].AddAssign(&a[m])
	a[m].Sub(&t, &a[m])

	for i := 1; i < m; i++ {
		t = a[i]
		a[i].AddAssign(&a[i+m])

		a[i+m].
			Sub(&t, &a[i+m]).
			MulAssign(&wPow)

		wPow.MulAssign(&w)
	}

	// if m == 1, then next iteration ends, no need to call 2 extra functions for that
	if m == 1 {
		return
	}

	// note: w is passed by value
	w.Square(&w)

	const parallelThreshold = 64
	serial := splits > uint(runtime.NumCPU()) || m <= parallelThreshold

	if serial {
		asyncFFT(a[0:m], w, nil, splits)
		asyncFFT(a[m:n], w, nil, splits)
	} else {
		splits <<= 1
		wg.Add(1)
		pool.Push(func() {
			asyncFFT(a[m:n], w, wg, splits)
			wg.Done()
		}, true)
		// TODO fixme that seems risky behavior and could starve the thread pool
		// we may want to push that as a taks in the pool too?.
		asyncFFT(a[0:m], w, wg, splits)
	}
}

// bitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2 (as in every single function in this file)
func bitReverse(a []curve.Element) {
	n := uint(len(a))
	nn := uint(bits.UintSize - bits.TrailingZeros(n))

	var tReverse curve.Element
	for i := uint(0); i < n; i++ {
		irev := bits.Reverse(i) >> nn
		if irev > i {
			tReverse = a[i]
			a[i] = a[irev]
			a[irev] = tReverse
		}
	}
}
