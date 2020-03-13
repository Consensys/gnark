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
	"github.com/consensys/gnark/ecc/bn256/fr"
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
	curve := ecc.GetCurve()
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

	// krs need to add Ar1 and Bs1
	chKrsRandom := make(chan ecc.G1Jac, 2)

	chMAr1, chMBs1, chMBs2 := multiExp(pk.G1.A, pk.G1.B, pk.G2.B, wireValues)

	// Ar1 (1 multi exp G1 - size = len(wires))
	go func() {
		var t ecc.G1Jac
		// chAsync := ar.MultiExp(curve, pk.G1.A, wireValues)
		pk.G1.Delta.ToJacobian(&t)
		t.ScalarMul(curve, &t, _r)
		ar := <-chMAr1
		ar.Add(curve, &t)
		ar.AddMixed(&pk.G1.Alpha)

		ar.ToAffineFromJac(&proof.Ar)
		ar.ScalarMul(curve, &ar, _s)
		chKrsRandom <- ar
	}()

	// Bs1 (1 multi exp G1 - size = len(wires))
	go func() {
		var t ecc.G1Jac

		// chAsync := bs1.MultiExp(curve, pk.G1.B, wireValues)
		pk.G1.Delta.ToJacobian(&t)
		t.ScalarMul(curve, &t, _s)
		bs1 := <-chMBs1
		bs1.Add(curve, &t)
		bs1.AddMixed(&pk.G1.Beta)

		bs1.ScalarMul(curve, &bs1, _r)
		chKrsRandom <- bs1
	}()

	// Bs2 (1 multi exp G2 - size = len(wires))
	chBs2 := make(chan ecc.G2Affine, 1)
	go func() {
		var t ecc.G2Jac
		var BsAffine ecc.G2Affine
		// chAsync := Bs.MultiExp(curve, pk.G2.B, wireValues)
		pk.G2.Delta.ToJacobian(&t)
		t.ScalarMul(curve, &t, _s)
		Bs := <-chMBs2
		Bs.Add(curve, &t)
		Bs.AddMixed(&pk.G2.Beta)
		Bs.ToAffineFromJac(&BsAffine)
		chBs2 <- BsAffine
		close(chBs2)
	}()

	// Krs -- computeKrs go routine will wait for H, Ar1 and Bs1 to be done
	var Krs ecc.G1Jac

	// Krs (H part + priv part)
	r.Mul(&r, &s).Neg(&r)
	points := append(pk.G1.Z, pk.G1.K[:r1cs.PublicInputsStartIndex]...) //, Ar, bs1, pk.G1.Delta)
	h := <-chH
	scalars := append(h, wireValues[:r1cs.PublicInputsStartIndex]...) //, _s, _r, r.ToRegular())
	// Krs random part
	points = append(points, pk.G1.Delta)     //, ar, bs)
	scalars = append(scalars, r.ToRegular()) //, _s, _r)
	<-Krs.MultiExp(curve, points, scalars)

	// wait for Ar1 and Bs1
	rand := <-chKrsRandom
	Krs.Add(curve, &rand)
	rand = <-chKrsRandom
	Krs.Add(curve, &rand)

	Krs.ToAffineFromJac(&proof.Krs)

	// get Bs2
	proof.Bs = <-chBs2

	return proof, nil
}

func multiExp(pointsA, pointsB1 []ecc.G1Affine, pointsB2 []ecc.G2Affine, wireValues []ecc.Element) (chA, chB1 chan ecc.G1Jac, chB2 chan ecc.G2Jac) {
	chA = make(chan ecc.G1Jac, 1)
	chB1 = make(chan ecc.G1Jac, 1)
	chB2 = make(chan ecc.G2Jac, 1)
	nbPoints := len(wireValues)
	curve := ecc.GetCurve()
	if nbPoints < 50 {
		go func() {
			var v ecc.G1Jac
			chA <- <-v.MultiExp(curve, pointsA, wireValues)
		}()

		go func() {
			var v ecc.G1Jac
			chB1 <- <-v.MultiExp(curve, pointsB1, wireValues)
		}()

		go func() {
			var v ecc.G2Jac
			chB2 <- <-v.MultiExp(curve, pointsB2, wireValues)
		}()
		return
	}

	// compute nbCalls and nbPointsPerBucket as a function of available CPUs
	const chunkSize = 64
	const totalSize = chunkSize * fr.ElementLimbs
	var nbBits, nbCalls uint64
	nbPointsPerBucket := 20 // empirical parameter to chose nbBits
	// set nbBbits and nbCalls
	nbBits = 0
	for nbPoints/(1<<nbBits) >= nbPointsPerBucket {
		nbBits++
	}
	nbCalls = totalSize / nbBits
	if totalSize%nbBits > 0 {
		nbCalls++
	}
	const useAllCpus = false
	// if we need to use all CPUs
	if useAllCpus {
		nbCpus := uint64(runtime.NumCPU())
		// goal here is to have at least as many calls as number of go routine we're allowed to spawn
		for nbCalls < nbCpus && nbPointsPerBucket < nbPoints {
			nbBits = 0
			for nbPoints/(1<<nbBits) >= nbPointsPerBucket {
				nbBits++
			}
			nbCalls = totalSize / nbBits
			if totalSize%nbBits > 0 {
				nbCalls++
			}
			nbPointsPerBucket *= 2
		}
	}

	// result (1 per go routine)
	tmpResA := make([]chan ecc.G1Jac, nbCalls)
	tmpResB1 := make([]chan ecc.G1Jac, nbCalls)
	tmpResB2 := make([]chan ecc.G2Jac, nbCalls)
	chIndices := make([]chan struct{}, nbCalls)
	indices := make([][][]int, nbCalls)
	for i := 0; i < int(nbCalls); i++ {
		tmpResA[i] = make(chan ecc.G1Jac, 1)
		tmpResB1[i] = make(chan ecc.G1Jac, 1)
		tmpResB2[i] = make(chan ecc.G2Jac, 1)
		chIndices[i] = make(chan struct{}, 3)
		indices[i] = make([][]int, 0, 1<<nbBits)
		for j := 0; j < len(indices[i]); j++ {
			indices[i][j] = make([]int, 0, nbPointsPerBucket)
		}
	}

	work := func(iStart, iEnd int) {
		chunks := make([]uint64, nbBits)
		offsets := make([]uint64, nbBits)
		for i := uint64(iStart); i < uint64(iEnd); i++ {
			start := i * nbBits
			debug.Assert(start != totalSize)
			var counter uint64
			for j := start; counter < nbBits && (j < totalSize); j++ {
				chunks[counter] = j / chunkSize
				offsets[counter] = j % chunkSize
				counter++
			}
			c := 1 << counter
			indices[i] = make([][]int, c-1)
			var l uint64
			for j := 0; j < nbPoints; j++ {
				var index uint64
				for k := uint64(0); k < counter; k++ {
					l = wireValues[j][chunks[k]] >> offsets[k]
					l &= 1
					l <<= k
					index += l
				}
				if index != 0 {
					indices[i][index-1] = append(indices[i][index-1], j)
				}
			}
			chIndices[i] <- struct{}{}
			chIndices[i] <- struct{}{}
			chIndices[i] <- struct{}{}
			close(chIndices[i])
		}
	}
	pool.ExecuteAsyncReverse(0, int(nbCalls), work, false)

	// indices are being computed, let's launch multiExp work
	g1Worker := func(points, points2 []ecc.G1Affine, tRes, tRes2 []chan ecc.G1Jac) {
		pool.ExecuteAsyncReverse(0, int(nbCalls), func(start, end int) {
			for i := start; i < end; i++ {
				var res, sum ecc.G1Jac
				var res2, sum2 ecc.G1Jac
				sum.X.SetOne()
				sum.Y.SetOne()
				sum2.X.SetOne()
				sum2.Y.SetOne()
				<-chIndices[i]
				for j := len(indices[i]) - 1; j >= 0; j-- {
					for k := 0; k < len(indices[i][j]); k++ {
						sum.AddMixed(&points[indices[i][j][k]])
						sum2.AddMixed(&points2[indices[i][j][k]])
					}
					res.Add(curve, &sum)
					res2.Add(curve, &sum2)
				}
				tRes[i] <- res
				tRes2[i] <- res2
				close(tRes[i])
				close(tRes2[i])
			}
		}, false)
	}

	g1Accumulator := func(chResult chan ecc.G1Jac, tRes []chan ecc.G1Jac) {
		var result ecc.G1Jac
		result.X.SetOne()
		result.Y.SetOne()
		for i := len(tRes) - 1; i >= 0; i-- {
			for j := uint64(0); j < nbBits; j++ {
				result.Double()
			}
			r := <-tRes[i]
			result.Add(curve, &r)
		}
		chResult <- result
	}

	g2Worker := func(points []ecc.G2Affine, tRes []chan ecc.G2Jac) {
		pool.ExecuteAsyncReverse(0, int(nbCalls), func(start, end int) {
			for i := start; i < end; i++ {
				var res, sum ecc.G2Jac
				sum.X.SetOne()
				sum.Y.SetOne()
				<-chIndices[i]
				for j := len(indices[i]) - 1; j >= 0; j-- {
					for k := 0; k < len(indices[i][j]); k++ {
						sum.AddMixed(&points[indices[i][j][k]])
					}
					res.Add(curve, &sum)
				}
				tRes[i] <- res
				close(tRes[i])
			}
		}, false)
	}

	g2Accumulator := func(chResult chan ecc.G2Jac, tRes []chan ecc.G2Jac) {
		var result ecc.G2Jac
		result.X.SetOne()
		result.Y.SetOne()
		for i := len(tRes) - 1; i >= 0; i-- {
			for j := uint64(0); j < nbBits; j++ {
				result.Double()
			}
			r := <-tRes[i]
			result.Add(curve, &r)
		}
		chResult <- result
	}

	go g1Worker(pointsA, pointsB1, tmpResA, tmpResB1)
	// go g1Worker(pointsB1, tmpResB1)
	go g2Worker(pointsB2, tmpResB2)

	go g1Accumulator(chA, tmpResA)
	go g1Accumulator(chB1, tmpResB1)
	go g2Accumulator(chB2, tmpResB2)

	return
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
		go func() {
			precomputeExpTableChunk(scale, w, 1, table[1:])
			wg.Done()
		}()
	} else {
		// we parallelize
		for i := 1; i < n; i += interval {
			start := i
			end := i + interval
			if end > n {
				end = n
			}
			wg.Add(1)
			go func() {
				precomputeExpTableChunk(scale, w, uint64(start), table[start:end])
				wg.Done()
			}()
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
