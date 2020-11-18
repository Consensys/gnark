package fft

// FFT ...
const FFT = `

import (
	"math/bits"
	"runtime"

	"github.com/consensys/gnark/internal/utils"
	{{ template "import_fr" . }}
)

// Decimation is used in the FFT call to select decimation in time or in frequency
type Decimation uint8

const (
	DIT Decimation = iota
	DIF 
)

// parallelize threshold for a single butterfly op, if the fft stage is not parallelized already
const butterflyThreshold = 16

// FFT computes (recursively) the discrete Fourier transform of a and stores the result in a
// if decimation == DIT (decimation in time), the input must be in bit-reversed order
// if decimation == DIF (decimation in frequency), the output will be in bit-reversed order
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
func (domain *Domain) FFT(a []fr.Element, decimation Decimation) {
	
	numCPU := uint64(runtime.NumCPU())

	// find the stage where we should stop spawning go routines in our recursive calls
	// (ie when we have as many go routines running as we have available CPUs)
	maxSplits := bits.TrailingZeros64(nextPowerOfTwo(numCPU))
	if numCPU <= 1 {
		maxSplits = -1
	}

	switch decimation {
	case DIF:
		difFFT(a, domain.Twiddles, 0, maxSplits,nil)
	case DIT:
		ditFFT(a, domain.Twiddles, 0, maxSplits,nil)
	default:
		panic("not implemented")
	}
}

// FFTInverse computes (recursively) the inverse discrete Fourier transform of a and stores the result in a
// if decimation == DIT (decimation in time), the input must be in bit-reversed order
// if decimation == DIF (decimation in frequency), the output will be in bit-reversed order
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
func (domain *Domain) FFTInverse(a []fr.Element, decimation Decimation) {
	
	numCPU := uint64(runtime.NumCPU())

	// find the stage where we should stop spawning go routines in our recursive calls
	// (ie when we have as many go routines running as we have available CPUs)
	maxSplits := bits.TrailingZeros64(nextPowerOfTwo(numCPU))
	if numCPU <= 1 {
		maxSplits = -1
	}
	switch decimation {
	case DIF:
		difFFT(a, domain.TwiddlesInv, 0, maxSplits,nil)
	case DIT:
		ditFFT(a, domain.TwiddlesInv, 0, maxSplits,nil)
	default:
		panic("not implemented")
	}

	// scale by CardinalityInv
	utils.Parallelize(len(a), func(start, end int) {
		for i := start; i < end; i++ {
			a[i].MulAssign(&domain.CardinalityInv)
		}
	})
}


func difFFT(a []fr.Element,twiddles [][]fr.Element, stage, maxSplits int, chDone chan struct{})  {
	if chDone != nil {
		defer func() {
			chDone <- struct{}{}
		}()
	}
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1

	// if stage < maxSplits, we parallelize this butterfly
	// but we have only numCPU / stage cpus available
	if (m > butterflyThreshold) &&(stage < maxSplits) {
		// 1 << stage == estimated used CPUs
		numCPU := runtime.NumCPU()  / (1 << (stage))
		utils.Parallelize(m, func(start, end int) {
			var t fr.Element
			for i := start; i < end; i++ {
				t = a[i]
				a[i].Add(&a[i], &a[i+m])
		
				a[i+m].
					Sub(&t, &a[i+m]).
					Mul(&a[i+m], &twiddles[stage][i])
			}
		}, numCPU)
	} else {
		var t fr.Element

		// i == 0
		t = a[0]
		a[0].Add(&a[0], &a[m])
		a[m].Sub(&t, &a[m])

		for i := 1; i < m; i++ {
			t = a[i]
			a[i].Add(&a[i], &a[i+m])
	
			a[i+m].
				Sub(&t, &a[i+m]).
				Mul(&a[i+m], &twiddles[stage][i])
		}
	}


	if m == 1 {
		return
	}

	nextStage := stage + 1
	if stage < maxSplits {
		chDone := make(chan struct{}, 1)
		go difFFT(a[m:n], twiddles, nextStage, maxSplits ,chDone)
		difFFT(a[0:m], twiddles, nextStage, maxSplits ,nil)
		<-chDone
	} else {
		difFFT(a[0:m], twiddles, nextStage, maxSplits ,nil)
		difFFT(a[m:n], twiddles, nextStage, maxSplits ,nil)
	}
}


func ditFFT(a []fr.Element, twiddles [][]fr.Element, stage, maxSplits int, chDone chan struct{})  {
	if chDone != nil {
		defer func() {
			chDone <- struct{}{}
		}()
	}
	n := len(a)
	if n == 1 {
		return
	}
	m := n >> 1

	nextStage := stage + 1 
	
	if stage < maxSplits {
		// that's the only time we fire go routines
		chDone := make(chan struct{}, 1)
		go ditFFT(a[m:], twiddles,  nextStage, maxSplits, chDone)
		ditFFT(a[0:m], twiddles,  nextStage, maxSplits, nil)
		<-chDone
	} else {
		ditFFT(a[0:m], twiddles, nextStage, maxSplits, nil)
		ditFFT(a[m:n], twiddles,  nextStage, maxSplits, nil)
		
	}

	// if stage < maxSplits, we parallelize this butterfly
	// but we have only numCPU / stage cpus available
	if (m > butterflyThreshold) &&(stage < maxSplits) {
		// 1 << stage == estimated used CPUs
		numCPU := runtime.NumCPU()  / (1 << (stage))
		utils.Parallelize(m, func(start, end int) {
			var t, tm fr.Element
			for k := start; k < end; k++ {
				t = a[k]
				tm.Mul(&a[k+m],&twiddles[stage][k])
				a[k].Add(&a[k], &tm)
				a[k+m].Sub(&t, &tm)
			}
		}, numCPU)
		
	} else {
		var t, tm fr.Element
		// k == 0
		// wPow == 1
		t = a[0]
		a[0].Add(&a[0], &a[m])
		a[m].Sub(&t, &a[m])

		for k := 1; k < m; k++ {
			t = a[k]
			tm.Mul(&a[k+m],&twiddles[stage][k])
			a[k].Add(&a[k], &tm)
			a[k+m].Sub(&t, &tm)
		}
	}
}


// BitReverse applies the bit-reversal permutation to a.
// len(a) must be a power of 2 (as in every single function in this file)
func BitReverse(a []fr.Element) {
	n := uint64(len(a))
	nn := uint64(64 - bits.TrailingZeros64(n))

	for i := uint64(0); i < n; i++ {
		irev := bits.Reverse64(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev],a[i]
		}
	}
}
`

// FFTTests ...
const FFTTests = `

import (
	"math/big"
	"testing"
	"strconv"

	{{ template "import_fr" . }}

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/prop"
	"github.com/leanovate/gopter/gen"

)

func TestFFT(t *testing.T) {
	const maxSize = 1 << 10

	domain := NewDomain(maxSize)

	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 5

	properties := gopter.NewProperties(parameters)

	properties.Property("DIF FFT should be consistent with dual basis", prop.ForAll(

		// checks that a random evaluation of a dual function eval(gen**ithpower) is consistent with the FFT result
		func(ithpower int) bool {

			pol := make([]fr.Element, maxSize)
			backupPol := make([]fr.Element, maxSize)

			for i := 0; i < maxSize; i++ {
				pol[i].SetRandom()
			}
			copy(backupPol, pol)

			domain.FFT(pol, DIF)
			BitReverse(pol)

			sample := domain.Generator
			sample.Exp(sample, big.NewInt(int64(ithpower)))

			eval := evaluatePolynomial(backupPol, sample)

			return eval.Equal(&pol[ithpower])

		},
		gen.IntRange(0, maxSize-1),
	))

	properties.Property("DIT FFT should be consistent with dual basis", prop.ForAll(

		// checks that a random evaluation of a dual function eval(gen**ithpower) is consistent with the FFT result
		func(ithpower int) bool {

			pol := make([]fr.Element, maxSize)
			backupPol := make([]fr.Element, maxSize)

			for i := 0; i < maxSize; i++ {
				pol[i].SetRandom()
			}
			copy(backupPol, pol)

			BitReverse(pol)
			domain.FFT(pol, DIT)

			sample := domain.Generator
			sample.Exp(sample, big.NewInt(int64(ithpower)))

			eval := evaluatePolynomial(backupPol, sample)

			return eval.Equal(&pol[ithpower])

		},
		gen.IntRange(0, maxSize-1),
	))

	properties.Property("bitReverse(DIF FFT(DIT FFT (bitReverse))))==id", prop.ForAll(

		func() bool {

			pol := make([]fr.Element, maxSize)
			backupPol := make([]fr.Element, maxSize)

			for i := 0; i < maxSize; i++ {
				pol[i].SetRandom()
			}
			copy(backupPol, pol)

			BitReverse(pol)
			domain.FFT(pol, DIT)
			domain.FFTInverse(pol, DIF)
			BitReverse(pol)

			check := true
			for i := 0; i < len(pol); i++ {
				check = check && pol[i].Equal(&backupPol[i])
			}
			return check
		},
	))

	properties.Property("DIT FFT(DIF FFT)==id", prop.ForAll(

		func() bool {

			pol := make([]fr.Element, maxSize)
			backupPol := make([]fr.Element, maxSize)

			for i := 0; i < maxSize; i++ {
				pol[i].SetRandom()
			}
				copy(backupPol, pol)

			domain.FFTInverse(pol, DIF)
			domain.FFT(pol, DIT)

			check := true
			for i := 0; i < len(pol); i++ {
				check = check && (pol[i] == backupPol[i])
			}
			return check
		},
	))

	properties.TestingRun(t, gopter.ConsoleReporter(false))

}

// --------------------------------------------------------------------
// benches
func BenchmarkBitReverse(b *testing.B) {

	const maxSize = 1 << 20

	pol := make([]fr.Element, maxSize)
	for i := uint64(0); i < maxSize; i++ {
		pol[i].SetRandom()
	}

	for i := 8; i < 20; i++ {
		b.Run("bit reversing 2**"+strconv.Itoa(i)+"bits", func(b *testing.B) {
			_pol := make([]fr.Element, 1<<i)
			copy(_pol, pol)
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				BitReverse(_pol)
			}
		})
	}

}

func BenchmarkFFT(b *testing.B) {

	const maxSize = 1 << 20

	pol := make([]fr.Element, maxSize)
	for i := uint64(0); i < maxSize; i++ {
		pol[i].SetRandom()
	}

	for i := 8; i < 20; i++ {
		b.Run("fft 2**"+strconv.Itoa(i)+"bits", func(b *testing.B) {
			sizeDomain := 1 << i
			_pol := make([]fr.Element, sizeDomain)
			copy(_pol, pol)
			domain := NewDomain(uint64(sizeDomain))
			b.ResetTimer()
			for j := 0; j < b.N; j++ {
				domain.FFT(_pol, DIT)
			}
		})
	}

}


func evaluatePolynomial(pol []fr.Element, val fr.Element) fr.Element {
	var acc, res, tmp fr.Element
	res.Set(&pol[0])
	acc.Set(&val)
	for i := 1; i < len(pol); i++ {
		tmp.Mul(&acc, &pol[i])
		res.Add(&res, &tmp)
		acc.Mul(&acc, &val)
	}
	return res
}

`
