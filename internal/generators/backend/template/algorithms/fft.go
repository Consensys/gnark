package algorithms

// FFT ...
const FFT = `

import (
	"math/bits"
	"runtime"

	"github.com/consensys/gnark/internal/utils"

	{{ template "import_curve" . }}
)

// FFTType is used in the FFT call to select decimation in time or in frequency
type FFTType uint8

// See FFTType and FFT documentation
const (
	DIT FFTType = iota
	DIF 
)

// parallelize threshold for a single butterfly op, if the fft stage is not parallelized already
const butterflyThreshold = 16

// FFT computes (recursively) the discrete Fourier transform of a and stores the result in a.
// if fType == DIT (decimation in time), the input must be in bit-reversed order
// if fType == DIF (decimation in frequency), the output will be in bit-reversed order
// len(a) must be a power of 2, and w must be a len(a)th root of unity in field F.
func FFT(a []fr.Element, domain *Domain, fType FFTType, inverse bool) {
	
	numCPU := uint(runtime.NumCPU())

	maxSplits := bits.TrailingZeros(nextPowerOfTwo(numCPU))
	if numCPU <= 1 {
		maxSplits = -1
	}
	var twiddles [][]fr.Element
	if inverse {
		twiddles = domain.TwiddlesInv
	} else {
		twiddles = domain.Twiddles
	}

	switch fType {
	case DIF:
		difFFT(a, twiddles, 0, maxSplits,nil)
	case DIT:
		ditFFT(a, twiddles, 0, maxSplits,nil)
	default:
		panic("not implemented")
	}
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
	n := uint(len(a))
	nn := uint(bits.UintSize - bits.TrailingZeros(n))

	for i := uint(0); i < n; i++ {
		irev := bits.Reverse(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev],a[i]
		}
	}
}
`

// Domain ...
const Domain = `

import (
	"math/big"
	"math/bits"
	"runtime"
	"sync"

	{{ template "import_curve" . }}
)

// Domain with a power of 2 cardinality
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
type Domain struct {
	Generator        fr.Element
	GeneratorInv     fr.Element
	GeneratorSqRt    fr.Element // generator of 2 adic subgroup of order 2*nb_constraints
	GeneratorSqRtInv fr.Element
	Cardinality      int
	CardinalityInv   fr.Element


	// TODO -- the following pre-computed slices need not to be serialized, they can be re-computed

	// Twiddles factor for the FFT using Generator for each stage of the recursive FFT
	Twiddles 		 [][]fr.Element

	// Twiddles factor for the FFT using GeneratorInv for each stage of the recursive FFT
	TwiddlesInv 	 [][]fr.Element

	// ExpTable1 = scale by inverse of n + coset
	// ifft(a) would normaly do FFT(a, wInv) then scale by CardinalityInv
	// fft_coset(a) would normaly mutliply a with expTable of fftDomain.GeneratorSqRt
	// this pre-computed ExpTable1 do both in one pass --> it contains
	// ExpTable1[0] = fftDomain.CardinalityInv
	// ExpTable1[1] = fftDomain.GeneratorSqrt^1 * fftDomain.CardinalityInv
	// ExpTable1[2] = fftDomain.GeneratorSqrt^2 * fftDomain.CardinalityInv
	// ...
	// note that the ExpTable1 is in bitReversed order
	ExpTable1 []fr.Element

	// similar reasoning as in ExpTable1 pass -->
	// ExpTable2[0] = fftDomain.CardinalityInv
	// ExpTable2[1] = fftDomain.GeneratorSqRtInv^1 * fftDomain.CardinalityInv
	// ExpTable2[2] = fftDomain.GeneratorSqRtInv^2 * fftDomain.CardinalityInv
	// note that the ExpTable2 is in bitReversed order
	ExpTable2 []fr.Element
}

// NewDomain returns a subgroup with a power of 2 cardinality
// cardinality >= m
// compute a field element of order 2x and store it in GeneratorSqRt
// all other values can be derived from x, GeneratorSqrt
func NewDomain(m int) *Domain {

	// generator of the largest 2-adic subgroup
	var rootOfUnity fr.Element
	{{if eq .Curve "BLS377"}}
		rootOfUnity.SetString("8065159656716812877374967518403273466521432693661810619979959746626482506078")
		const maxOrderRoot uint = 47
	{{else if eq .Curve "BLS381"}}
		rootOfUnity.SetString("10238227357739495823651030575849232062558860180284477541189508159991286009131")
		const maxOrderRoot uint = 32
	{{else if eq .Curve "BN256"}}
		rootOfUnity.SetString("19103219067921713944291392827692070036145651957329286315305642004821462161904")
		const maxOrderRoot uint = 28
	{{else if eq .Curve "BW761"}}
		rootOfUnity.SetString("32863578547254505029601261939868325669770508939375122462904745766352256812585773382134936404344547323199885654433")
		const maxOrderRoot uint = 46
	{{end}}
	

	subGroup := &Domain{}
	x := nextPowerOfTwo(uint(m))

	// maxOderRoot is the largest power-of-two order for any element in the field
	// set subGroup.GeneratorSqRt = rootOfUnity^(2^(maxOrderRoot-log(x)-1))
	// to this end, compute expo = 2^(maxOrderRoot-log(x)-1)
	logx := uint(bits.TrailingZeros(x))
	if logx > maxOrderRoot-1 {
		panic("m is too big: the required root of unity does not exist")
	}
	expo := uint64(1 << (maxOrderRoot - logx - 1))
	bExpo := new(big.Int).SetUint64(expo)
	subGroup.GeneratorSqRt.Exp(rootOfUnity, bExpo)

	// Generator = GeneratorSqRt^2 has order x
	subGroup.Generator.Mul(&subGroup.GeneratorSqRt, &subGroup.GeneratorSqRt) // order x
	subGroup.Cardinality = int(x)
	subGroup.GeneratorSqRtInv.Inverse(&subGroup.GeneratorSqRt)
	subGroup.GeneratorInv.Inverse(&subGroup.Generator)
	subGroup.CardinalityInv.SetUint64(uint64(x)).Inverse(&subGroup.CardinalityInv)

	// twiddle factors
	subGroup.preComputeTwiddles()

	return subGroup
}

func (d *Domain) preComputeTwiddles() {
	// nb fft stages
	nbStages := uint(bits.TrailingZeros(uint(d.Cardinality)))

	d.Twiddles = make([][]fr.Element, nbStages)
	d.TwiddlesInv = make([][]fr.Element, nbStages)
	d.ExpTable1 = make([]fr.Element, d.Cardinality)
	d.ExpTable2 = make([]fr.Element, d.Cardinality)

	var wg sync.WaitGroup

	// for each fft stage, we pre compute the twiddle factors
	twiddles := func(t [][]fr.Element, omega fr.Element) {
		for i := uint(0) ; i < nbStages; i++ {
			t[i] = make([]fr.Element, 1+(1 << (nbStages-i)))
			var w fr.Element
			if i == 0 {
				w = omega
			} else {
				w = t[i-1][2]
			}
			t[i][0] = fr.One()
			t[i][1] = w
			for j:= 2; j < len(t[i]); j++ {
				t[i][j].Mul(&t[i][j-1], &w)
			}
		}
		wg.Done()
	}

	expTable := func(sqrt fr.Element, t []fr.Element) {
		t[0] = d.CardinalityInv
		precomputeExpTable(d.CardinalityInv, sqrt, t)
		BitReverse(t)
		wg.Done()
	}
	
	wg.Add(4)
	go twiddles(d.Twiddles, d.Generator)
	go twiddles(d.TwiddlesInv, d.GeneratorInv)
	go expTable(d.GeneratorSqRt, d.ExpTable1)
	expTable(d.GeneratorSqRtInv, d.ExpTable2)

	wg.Wait()
}

func precomputeExpTable(scale, w fr.Element, table []fr.Element) {
	n := len(table)

	// see if it makes sense to parallelize exp tables pre-computation
	interval := (n - 1) / (runtime.NumCPU() / 4)
	// this ratio roughly correspond to the number of multiplication one can do in place of a Exp operation
	const ratioExpMul = 6000 / 17

	if interval < ratioExpMul {
		precomputeExpTableChunk(scale, w, 1, table[1:])
		return
	} 

	// we parallelize
	var wg sync.WaitGroup
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
	wg.Wait()
}

func precomputeExpTableChunk(scale, w fr.Element, power uint64, table []fr.Element) {
	table[0].Exp(w, new(big.Int).SetUint64(power))
	table[0].Mul(&table[0], &scale)
	for i := 1; i < len(table); i++ {
		table[i].Mul(&table[i-1], &w)
	}
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


`
