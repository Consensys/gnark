package zkpschemes

// Groth16Prove ...
const Groth16Prove = `

import (
	{{ template "import_curve" . }}
	{{ template "import_backend" . }}
	{{ template "import_fft" . }}
	"runtime"
	"sync"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/backend"
)


// Proof represents a Groth16 proof that was encoded with a ProvingKey and can be verified
// with a valid statement and a VerifyingKey
type Proof struct {
	Ar, Krs curve.G1Affine
	Bs      curve.G2Affine
}

// GetCurveID returns the curveID
func (proof *Proof) GetCurveID() gurvy.ID {
	return curve.ID
}

// Prove creates proof from a circuit
func Prove(r1cs *{{toLower .Curve}}backend.R1CS, pk *ProvingKey, solution map[string]interface{}) (*Proof, error) {
	nbPrivateWires := r1cs.NbWires-r1cs.NbPublicWires


	// solve the R1CS and compute the a, b, c vectors
	a := make([]fr.Element, r1cs.NbConstraints, pk.Domain.Cardinality) 
	b := make([]fr.Element, r1cs.NbConstraints, pk.Domain.Cardinality)
	c := make([]fr.Element, r1cs.NbConstraints, pk.Domain.Cardinality)
	wireValues := make([]fr.Element, r1cs.NbWires)
	if err := r1cs.Solve(solution, a, b, c, wireValues); err != nil {
		return nil, err
	}

	// set the wire values in regular form
	utils.Parallelize(len(wireValues), func(start, end int){
		for i := start; i < end; i++ {
			wireValues[i].FromMont()
		}
	})
	

	// H (witness reduction / FFT part)
	var h []fr.Element
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeH(a, b, c, &pk.Domain)
		a = nil
		b = nil 
		c = nil 
		chHDone <- struct{}{}
	}()

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	_r.SetRandom()
	_s.SetRandom()
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.FromMont()
	_s.FromMont()
	_kr.FromMont()
	_r.ToBigInt(&r)
	_s.ToBigInt(&s)

	// computes r[δ], s[δ], kr[δ] 
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r,_s,_kr})


	proof := &Proof{}
	var bs1, ar curve.G1Jac

	// using this ensures that our multiExps running in parallel won't use more than
	// provided CPUs
	opt := curve.NewMultiExpOptions(runtime.NumCPU())


	chBs1Done := make(chan struct{}, 1)
	computeBS1 := func() {
		bs1.MultiExp(pk.G1.B, wireValues, opt)
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- struct{}{}
	}

	chArDone:= make(chan struct{}, 1)
	computeAR1 := func() {
		ar.MultiExp(pk.G1.A, wireValues, opt)
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
		chArDone <- struct{}{}
	}

	chKrsDone := make(chan struct{}, 1)
	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism 

		var krs, krs2, p1 curve.G1Jac
		chKrs2Done := make(chan struct{}, 1)
		go func() {
			krs2.MultiExp( pk.G1.Z, h, opt)
			chKrs2Done <- struct{}{}
		}()
		krs.MultiExp(pk.G1.K[:nbPrivateWires], wireValues[:nbPrivateWires], opt)
		krs.AddMixed(&deltas[2])
		n := 3
		for n!=0 {
			select {
			case <-chKrs2Done:
				krs.AddAssign(&krs2)
			case <-chArDone:
				p1.ScalarMultiplication(&ar, &s)
				krs.AddAssign(&p1)
			case <-chBs1Done:
				p1.ScalarMultiplication(&bs1, &r)
				krs.AddAssign(&p1)
			}
			n--
		}
		
		proof.Krs.FromJacobian(&krs)
		chKrsDone <- struct{}{}
	}

	computeBS2 := func() {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac
	
		// splitting Bs2 in 3 ensures all our go routines in the prover have similar running time
		// and is good for parallelism. However, on a machine with limited CPUs, this may not be
		// a good idea, as the MultiExp scales slightly better than linearly
		bsSplit := len(pk.G2.B) / 3
		if bsSplit > 10 {
			chDone1 := make(chan struct{}, 1)
			chDone2 := make(chan struct{}, 1)
			var bs1,bs2 curve.G2Jac
			go func() {
				bs1.MultiExp(pk.G2.B[:bsSplit], wireValues[:bsSplit], opt)
				chDone1 <- struct{}{}
			}()
			go func() {
				bs2.MultiExp(pk.G2.B[bsSplit:bsSplit*2], wireValues[bsSplit:bsSplit*2], opt)
				chDone2 <- struct{}{}
			}()
			Bs.MultiExp(pk.G2.B[bsSplit*2:], wireValues[bsSplit*2:], opt)
			
			<-chDone1 
			Bs.AddAssign(&bs1)
			<-chDone2
			Bs.AddAssign(&bs2)
		} else {
			Bs.MultiExp(pk.G2.B, wireValues, opt)
		}
	
		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone

	// schedule our proof part computations
	go computeKRS()
	go computeAR1()
	go computeBS1()
	computeBS2()

	// wait for all parts of the proof to be computed.
	<-chKrsDone

	return proof, nil
}


func computeH(a, b, c []fr.Element, fftDomain *fft.Domain) []fr.Element {
		// H part of Krs
		// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
		// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
		// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
		// 	3 - h = ifft_coset(ca o cb - cc)

		n := len(a)

		// add padding to ensure input length is domain cardinality
		padding := make([]fr.Element, fftDomain.Cardinality-n)
		a = append(a, padding...)
		b = append(b, padding...)
		c = append(c, padding...)
		n = len(a)

		
		fft.FFT(a, fftDomain, fft.DIF, true)
		fft.FFT(b, fftDomain, fft.DIF, true)
		fft.FFT(c, fftDomain, fft.DIF, true)
		
		utils.Parallelize(n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &fftDomain.ExpTable1[i])
				b[i].Mul(&b[i], &fftDomain.ExpTable1[i])
				c[i].Mul(&c[i], &fftDomain.ExpTable1[i])
			}
		})
		
		fft.FFT(a, fftDomain, fft.DIT, false)
		fft.FFT(b, fftDomain, fft.DIT, false)
		fft.FFT(c, fftDomain, fft.DIT, false)

		var minusTwoInv fr.Element
		minusTwoInv.SetUint64(2)
		minusTwoInv.Neg(&minusTwoInv).
			Inverse(&minusTwoInv)

		// h = ifft_coset(ca o cb - cc)
		// reusing a to avoid unecessary memalloc
		utils.Parallelize( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &b[i]).
					Sub(&a[i], &c[i]).
					Mul(&a[i], &minusTwoInv)
			}
		})

	

		// ifft_coset
		fft.FFT(a, fftDomain, fft.DIF, true)
		
		
		utils.Parallelize( n, func(start, end int) {
			for i := start; i < end; i++ {
				a[i].Mul(&a[i], &fftDomain.ExpTable2[i]).FromMont()
			}
		})

		return a
}





`
