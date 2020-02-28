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

package groth16

import (
	"runtime"
	"sync"

	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/fft"
	"github.com/consensys/gnark/cs/internal/curve"
	ecc "github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/internal/debug"
	"github.com/consensys/gnark/internal/pool"
)

// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
type Proof struct {
	Ar, Krs ecc.G1Affine
	Bs      ecc.G2Affine
}

var (
	root        ecc.Element
	minusTwoInv ecc.Element
)

func init() {
	root.SetString(ecc.RootOfUnityStr)
	minusTwoInv.SetUint64(2)
	minusTwoInv.Neg(&minusTwoInv).
		Inverse(&minusTwoInv)
}

// Prove creates proof from a circuit
func Prove(r1cs *cs.R1CS, pk *ProvingKey, solution map[string]cs.Assignment) (*Proof, error) {
	proof := &Proof{}
	// sample random r and s
	var r, s, _r, _s ecc.Element
	r.SetRandom()
	s.SetRandom()
	_r = r.ToRegular()
	_s = s.ToRegular()

	// Solve the R1CS and compute the a, b, c vectors
	a, b, c, err := r1cs.Solve(solution)
	if err != nil {
		return nil, err
	}
	// get the wire values in regular form
	wireValues := make([]ecc.Element, len(r1cs.WireTracker))
	work := func(start, end int) {
		for i := start; i < end; i++ {
			wireValues[i] = r1cs.WireTracker[i].Value.ToRegular()
		}
	}
	pool.Execute(0, len(wireValues), work, false)

	// compute proof elements
	// 4 multiexp + 1 FFT
	// G2 multiexp is likely the most compute intensive task here

	// H (witness reduction / FFT part)
	chH := computeH(a, b, c, r1cs.NbConstraints())

	// these tokens ensure multiExp tasks are enqueue in order in the pool
	// so that bs2 doesn't compete with ar1 and bs1 for resources
	// hence delaying Krs compute longer than needed
	chTokenA := make(chan struct{}, 1)
	chTokenB := make(chan struct{}, 1)

	// Ar1 (1 multi exp G1 - size = len(wires))
	chAr1 := computeAr1(pk, _r, wireValues, chTokenA)

	// Bs1 (1 multi exp G1 - size = len(wires))
	chBs1 := computeBs1(pk, _s, wireValues, chTokenA, chTokenB)

	// Bs2 (1 multi exp G2 - size = len(wires))
	chBs2 := computeBs2(pk, _s, wireValues, chTokenB)

	// Krs -- computeKrs go routine will wait for H, Ar1 and Bs1 to be done
	h := <-chH
	proof.Ar = <-chAr1
	bs := <-chBs1
	proof.Krs = <-computeKrs(pk, r, s, _r, _s, wireValues, proof.Ar, bs, h, r1cs.PublicInputsStartIndex, chTokenB)

	proof.Bs = <-chBs2

	return proof, nil
}

func computeKrs(pk *ProvingKey, r, s, _r, _s ecc.Element, wireValues []ecc.Element, ar, bs ecc.G1Affine, h []ecc.Element, kIndex int, chToken chan struct{}) <-chan ecc.G1Affine {
	chResult := make(chan ecc.G1Affine, 1)
	go func() {
		var Krs ecc.G1Jac
		var KrsAffine ecc.G1Affine

		// Krs (H part + priv part)
		r.Mul(&r, &s).Neg(&r)
		points := append(pk.G1.Z, pk.G1.K[:kIndex]...) //, Ar, bs1, pk.G1.Delta)
		scalars := append(h, wireValues[:kIndex]...)   //, _s, _r, r.ToRegular())
		// Krs random part
		points = append(points, pk.G1.Delta, ar, bs)
		scalars = append(scalars, r.ToRegular(), _s, _r)
		<-chToken
		chAsync := Krs.MultiExp(ecc.GetCurve(), points, scalars)
		<-chAsync
		Krs.ToAffineFromJac(&KrsAffine)

		chResult <- KrsAffine
		close(chResult)
	}()
	return chResult
}

func computeBs2(pk *ProvingKey, _s ecc.Element, wireValues []ecc.Element, chToken chan struct{}) <-chan ecc.G2Affine {
	chResult := make(chan ecc.G2Affine, 1)
	go func() {
		var Bs ecc.G2Jac
		var BsAffine ecc.G2Affine
		points2 := append(pk.G2.B, pk.G2.Delta)
		scalars2 := append(wireValues, _s)
		<-chToken
		chAsync := Bs.MultiExp(ecc.GetCurve(), points2, scalars2)
		chToken <- struct{}{}
		<-chAsync
		Bs.AddMixed(&pk.G2.Beta)
		Bs.ToAffineFromJac(&BsAffine)
		chResult <- BsAffine
		close(chResult)
	}()
	return chResult
}

func computeBs1(pk *ProvingKey, _s ecc.Element, wireValues []ecc.Element, chTokenA, chTokenB chan struct{}) <-chan ecc.G1Affine {
	chResult := make(chan ecc.G1Affine, 1)
	go func() {
		var bs1 ecc.G1Jac
		var bs1Affine ecc.G1Affine

		points := append(pk.G1.B, pk.G1.Delta)
		scalars := append(wireValues, _s)
		<-chTokenA
		chAsync := bs1.MultiExp(ecc.GetCurve(), points, scalars)
		chTokenB <- struct{}{}
		<-chAsync
		bs1.AddMixed(&pk.G1.Beta)
		bs1.ToAffineFromJac(&bs1Affine)

		chResult <- bs1Affine
		close(chResult)
	}()
	return chResult
}

func computeAr1(pk *ProvingKey, _r ecc.Element, wireValues []ecc.Element, chToken chan struct{}) <-chan ecc.G1Affine {
	chResult := make(chan ecc.G1Affine, 1)
	go func() {
		var ar ecc.G1Jac
		var arAffine ecc.G1Affine
		points := append(pk.G1.A, pk.G1.Delta)
		scalars := append(wireValues, _r)
		chAsync := ar.MultiExp(ecc.GetCurve(), points, scalars)
		chToken <- struct{}{}
		<-chAsync
		ar.AddMixed(&pk.G1.Alpha)
		ar.ToAffineFromJac(&arAffine)
		chResult <- arAffine
		close(chResult)
	}()
	return chResult
}

func computeH(a, b, c []ecc.Element, nbConstraints int) <-chan []ecc.Element {
	chResult := make(chan []ecc.Element, 1)
	go func() {
		// H part of Krs
		// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
		// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
		// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
		// 	3 - h = ifft_coset(ca o cb - cc)
		fftDomain := fft.NewSubGroup(root, ecc.MaxOrder, nbConstraints)

		n := len(a)
		debug.Assert((n == len(b)) && (n == len(c)))

		// add padding
		padding := make([]ecc.Element, fftDomain.Cardinality-n)
		a = append(a, padding...)
		b = append(b, padding...)
		c = append(c, padding...)
		n = len(a)

		// exptable = scale by inverse of n + coset
		// ifft(a) would normaly do FFT(a, wInv) then scale by CardinalityInv
		// fft_coset(a) would normaly mutliply a with expTable of fftDomain.GeneratorSqRt
		// this pre-computed expTable do both in one pass --> it contains
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqrt^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqrt^2 * fftDomain.CardinalityInv
		// ...
		expTable := make([]curve.Element, n)
		expTable[0] = fftDomain.CardinalityInv

		var wgExpTable sync.WaitGroup

		// to ensure the pool is busy while the FFT splits, we schedule precomputation of the exp table
		// before the FFTs
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRt, expTable, &wgExpTable)

		var wg sync.WaitGroup
		FFT := func(s []curve.Element) {
			// FFT inverse
			fft.FFT(s, fftDomain.GeneratorInv)

			// wait for the expTable to be pre-computed
			// in the nominal case, this is non-blocking as the expTable was scheduled before the FFT
			wgExpTable.Wait()
			pool.Execute(0, n, func(start, end int) {
				for i := start; i < end; i++ {
					s[i].MulAssign(&expTable[i])
				}
			}, true)

			// FFT coset
			fft.FFT(s, fftDomain.Generator)
			wg.Done()
		}
		wg.Add(3)
		go FFT(a)
		go FFT(b)
		FFT(c)

		// wait for first step (ifft + fft_coset) to be done
		wg.Wait()

		// h = ifft_coset(ca o cb - cc)
		// reusing a to avoid unecessary memalloc
		pool.Execute(0, n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &b[i]).
					SubAssign(&c[i]).
					MulAssign(&minusTwoInv)
			}
		}, true)

		// before computing the ifft_coset, we schedule the expTable precompute of the ifft_coset
		// to ensure the pool is busy while the FFT splits
		// similar reasoning as in ifft pass -->
		// expTable[0] = fftDomain.CardinalityInv
		// expTable[1] = fftDomain.GeneratorSqRtInv^1 * fftDomain.CardinalityInv
		// expTable[2] = fftDomain.GeneratorSqRtInv^2 * fftDomain.CardinalityInv
		asyncExpTable(fftDomain.CardinalityInv, fftDomain.GeneratorSqRtInv, expTable, &wgExpTable)

		// ifft_coset
		fft.FFT(a, fftDomain.GeneratorInv)

		wgExpTable.Wait() // wait for pre-computation of exp table to be done
		pool.Execute(0, n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].MulAssign(&expTable[i]).FromMont()
			}
		}, true)

		chResult <- a
		close(chResult)
	}()

	return chResult
}

func asyncExpTable(scale, w curve.Element, table []curve.Element, wg *sync.WaitGroup) {
	n := len(table)

	// see if it makes sense to parallelize exp tables pre-computation
	interval := (n - 1) / runtime.NumCPU()
	// this ratio roughly correspond to the number of multiplication one can do in place of a Exp operation
	const ratioExpMul = 2400 / 26

	if interval < ratioExpMul {
		wg.Add(1)
		pool.Push(func() {
			precomputeExpTableChunk(scale, w, 1, table[1:])
			wg.Done()
		}, true)
	} else {
		// we parallelize
		for i := 1; i < n; i += interval {
			start := i
			end := i + interval
			if end > n {
				end = n
			}
			wg.Add(1)
			pool.Push(func() {
				precomputeExpTableChunk(scale, w, uint64(start), table[start:end])
				wg.Done()
			}, true)
		}
	}
}

func precomputeExpTableChunk(scale, w curve.Element, power uint64, table []curve.Element) {
	table[0].Exp(w, power)
	table[0].MulAssign(&scale)
	for i := 1; i < len(table); i++ {
		table[i].Mul(&table[i-1], &w)
	}
}
