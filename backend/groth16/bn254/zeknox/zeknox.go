//go:build !zeknox

package zeknox_bn254

import (
	"context"
	"fmt"
	"math/big"
	"runtime"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/okx/cryptography_cuda/wrappers/go/device"
	"github.com/okx/cryptography_cuda/wrappers/go/msm"
	"golang.org/x/sync/errgroup"
)

const HasZeknox = true

// Use single GPU
const deviceId = 0

func (pk *ProvingKey) setupDevicePointers() error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	// TODO: setup FFT

	// MSM G1 & G2 Device Setup
	g, _ := errgroup.WithContext(context.TODO())
	// G1.A
	deviceA := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	g.Go(func() error { return CopyToDevice(pk.G1.A, deviceA) })

	// G1.B
	deviceG1B := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	g.Go(func() error { return CopyToDevice(pk.G1.B, deviceG1B) })

	// G1.K
	var pointsNoInfinity []curve.G1Affine
	for i, gnarkPoint := range pk.G1.K {
		if gnarkPoint.IsInfinity() {
			pk.InfinityPointIndicesK = append(pk.InfinityPointIndicesK, i)
		} else {
			pointsNoInfinity = append(pointsNoInfinity, gnarkPoint)
		}
	}
	deviceK := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	g.Go(func() error { return CopyToDevice(pointsNoInfinity, deviceK) })

	// G1.Z
	deviceZ := make(chan *device.HostOrDeviceSlice[curve.G1Affine], 1)
	g.Go(func() error { return CopyToDevice(pk.G1.Z, deviceZ) })

	// G2.B
	deviceG2B := make(chan *device.HostOrDeviceSlice[curve.G2Affine], 1)
	g.Go(func() error { return CopyToDevice(pk.G2.B, deviceG2B) })

	// wait for all points to be copied to the device
	// if any of the copy failed, return the error
	if err := g.Wait(); err != nil {
		return err
	}
	// if no error, store device pointers in pk
	pk.G1Device.A = <-deviceA
	pk.G1Device.B = <-deviceG1B
	pk.G1Device.K = <-deviceK
	pk.G1Device.Z = <-deviceZ
	pk.G2Device.B = <-deviceG2B

	return nil
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, opts ...backend.ProverOption) (*groth16_bn254.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	if opt.Accelerator != "zeknox" {
		return groth16_bn254.Prove(r1cs, &pk.ProvingKey, fullWitness, opts...)
	}
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "zeknox").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	if pk.deviceInfo == nil {
		start := time.Now()
		if err := pk.setupDevicePointers(); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
		log.Debug().Dur("took", time.Since(start)).Msg("Copy proving key to device")
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &groth16_bn254.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))

	// override hints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	solverOpts = append(solverOpts, solver.OverrideHint(bsb22ID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
		i := int(in[0].Int64())
		in = in[1:]
		privateCommittedValues[i] = make([]fr.Element, len(commitmentInfo[i].PrivateCommitted))
		hashed := in[:len(commitmentInfo[i].PublicAndCommitmentCommitted)]
		committed := in[+len(hashed):]
		for j, inJ := range committed {
			privateCommittedValues[i][j].SetBigInt(inJ)
		}

		var err error
		if proof.Commitments[i], err = pk.CommitmentKeys[i].Commit(privateCommittedValues[i]); err != nil {
			return err
		}

		opt.HashToFieldFn.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1))
		hashBts := opt.HashToFieldFn.Sum(nil)
		opt.HashToFieldFn.Reset()
		nbBuf := fr.Bytes
		if opt.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = opt.HashToFieldFn.Size()
		}
		var res fr.Element
		res.SetBytes(hashBts[:nbBuf])
		res.BigInt(out[0])
		return nil
	}))

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	start := time.Now()
	poks := make([]curve.G1Affine, len(pk.CommitmentKeys))

	for i := range pk.CommitmentKeys {
		var err error
		if poks[i], err = pk.CommitmentKeys[i].ProveKnowledge(privateCommittedValues[i]); err != nil {
			return nil, err
		}
	}
	// compute challenge for folding the PoKs from the commitments
	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}
	challenge, err := fr.Hash(commitmentsSerialized, []byte("G16-BSB22"), 1)
	if err != nil {
		return nil, err
	}
	if _, err = proof.CommitmentPok.Fold(poks, challenge[0], ecc.MultiExpConfig{NbTasks: 1}); err != nil {
		return nil, err
	}

	// quotient poly H (witness reduction / FFT part)
	var h []fr.Element
	chHDone := make(chan struct{}, 1)
	go func() {
		startH := time.Now()
		h = computeH(solution.A, solution.B, solution.C, &pk.Domain)
		log.Debug().Dur("took", time.Since(startH)).Msg("computed H")
		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var deviceWireValuesA, deviceWireValuesB *device.HostOrDeviceSlice[fr.Element]
	// indicate if the wire values have been copied to the device
	chWireValuesA, chWireValuesB := make(chan error, 1), make(chan error, 1)

	go func() {
		wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}
		chDeviceValues := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		if err := CopyToDevice(wireValuesA, chDeviceValues); err != nil {
			chWireValuesA <- err
			return
		}
		deviceWireValuesA = <-chDeviceValues
		close(chWireValuesA)
	}()
	go func() {
		wireValuesB := make([]fr.Element, len(wireValues)-int(pk.NbInfinityB))
		for i, j := 0, 0; j < len(wireValuesB); i++ {
			if pk.InfinityB[i] {
				continue
			}
			wireValuesB[j] = wireValues[i]
			j++
		}
		chDeviceValues := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		if err := CopyToDevice(wireValuesB, chDeviceValues); err != nil {
			chWireValuesB <- err
			return
		}
		deviceWireValuesB = <-chDeviceValues
		close(chWireValuesB)
	}()

	// sample random r and s
	var r, s big.Int
	var _r, _s, _kr fr.Element
	if _, err := _r.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := _s.SetRandom(); err != nil {
		return nil, err
	}
	// -rs
	// Why it is called kr? not rs? -> notation from DIZK paper
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.BigInt(&r)
	_s.BigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var bs1, ar curve.G1Jac

	chBs1Done := make(chan error, 1)

	computeBS1 := func() {
		if err := <-chWireValuesB; err != nil {
			chBs1Done <- err
			return
		}
		startBs1 := time.Now()
		if err := msmG1(&bs1, pk.G1Device.B, deviceWireValuesB); err != nil {
			chBs1Done <- err
			return
		}
		log.Debug().Dur(fmt.Sprintf("MSMG1 %d took", deviceWireValuesB.Len()), time.Since(startBs1)).Msg("bs1 done")
		// + beta + s[δ]
		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])
		chBs1Done <- nil
	}

	chArDone := make(chan error, 1)
	computeAR1 := func() {
		if err := <-chWireValuesA; err != nil {
			chArDone <- err
			return
		}
		startAr := time.Now()
		if err := msmG1(&ar, pk.G1Device.A, deviceWireValuesA); err != nil {
			chArDone <- err
			return
		}
		log.Debug().Dur(fmt.Sprintf("MSMG1 %d took", deviceWireValuesA.Len()), time.Since(startAr)).Msg("ar done")
		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)
		chArDone <- nil
	}

	chKrsDone := make(chan error, 1)
	var deviceH *device.HostOrDeviceSlice[fr.Element]
	computeKRS := func() {
		// we could NOT split the Krs multiExp in 2, and just append pk.G1.K and pk.G1.Z
		// however, having similar lengths for our tasks helps with parallelism

		var krs, krs2, p1 curve.G1Jac
		chKrs2Done := make(chan error, 1)
		go func() {
			startKrs2 := time.Now()
			// Copy h poly to device, since we haven't implemented FFT on device
			chDeviceH := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
			sizeH := int(pk.Domain.Cardinality - 1) // comes from the fact the deg(H)=(n-1)+(n-1)-n=n-2
			if err := CopyToDevice(h[:sizeH], chDeviceH); err != nil {
				chKrs2Done <- err
				return
			}
			deviceH = <-chDeviceH
			if err := msmG1(&krs2, pk.G1Device.Z, deviceH); err != nil {
				chKrs2Done <- err
				return
			}
			log.Debug().Dur(fmt.Sprintf("MSMG1 %d took", sizeH), time.Since(startKrs2)).Msg("krs2 done")
			close(chKrs2Done)
		}()

		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		// original Groth16 witness without pedersen commitment
		wireValuesWithoutCom := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))

		startKrs := time.Now()
		// GPU runtime error
		// var deviceWire *device.HostOrDeviceSlice[fr.Element]
		// defer deviceWire.Free()
		// chDeviceWire := make(chan *device.HostOrDeviceSlice[fr.Element], 1)
		// if err := CopyToDevice(wireValuesWithoutCom, chDeviceWire); err != nil {
		// 	chKrsDone <- err
		// 	return
		// }
		// deviceWire = <-chDeviceWire
		// if err := msmG1(&krs, pk.G1Device.K, deviceWire); err != nil {
		// 	chKrsDone <- err
		// 	return
		// }

		// CPU
		// Compute this MSM on CPU, as it can be done in parallel with other MSM on GPU
		if _, err := krs.MultiExp(pk.G1.K, wireValuesWithoutCom, ecc.MultiExpConfig{NbTasks: runtime.NumCPU() / 2}); err != nil {
			chKrsDone <- err
			return
		}
		log.Debug().Dur(fmt.Sprintf("MSMG1 %d took", len(wireValues)), time.Since(startKrs)).Msg("krs done")
		// -rs[δ]
		krs.AddMixed(&deltas[2])

		n := 3
		for n != 0 {
			select {
			case err := <-chKrs2Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				krs.AddAssign(&krs2)
			case err := <-chArDone:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&ar, &s)
				krs.AddAssign(&p1)
			case err := <-chBs1Done:
				if err != nil {
					chKrsDone <- err
					return
				}
				p1.ScalarMultiplication(&bs1, &r)
				krs.AddAssign(&p1)
			}
			n--
		}

		proof.Krs.FromJacobian(&krs)
		chKrsDone <- nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		if err := <-chWireValuesB; err != nil {
			return err
		}
		startBs := time.Now()
		if err := msmG2(&Bs, pk.G2Device.B, deviceWireValuesB); err != nil {
			return err
		}
		log.Debug().Dur(fmt.Sprintf("MSMG2 %v took", deviceWireValuesB.Len()), time.Since(startBs)).Msg("Bs done")

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end, as it uses all our CPUs
	<-chHDone

	// schedule our proof part computations
	// Sequencial GPU execution
	// TODO: see GPU utilization data
	computeAR1()
	if err := <-chArDone; err != nil {
		return nil, err
	}
	computeBS1()
	if err := <-chBs1Done; err != nil {
		return nil, err
	}
	computeKRS()
	if err := <-chKrsDone; err != nil {
		return nil, err
	}
	if err := computeBS2(); err != nil {
		return nil, err
	}

	// Parallel GPU execution, memory may hit limit
	// go computeKRS()
	// go computeAR1()
	// go computeBS1()
	// go computeBS2()

	// wait for all parts of the proof to be computed.
	// if err := <-chKrsDone; err != nil {
	// 	return nil, err
	// }

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	// Free device memory
	go func() {
		deviceWireValuesA.Free()
		deviceWireValuesB.Free()
		deviceH.Free()
	}()

	return proof, nil
}

// if len(toRemove) == 0, returns slice
//
// else, returns a new slice without the indexes in toRemove. The first value in the slice is taken as indexes as sliceFirstIndex
// this assumes len(slice) > len(toRemove)
// filterHeap modifies toRemove
func filterHeap(slice []fr.Element, sliceFirstIndex int, toRemove []int) (r []fr.Element) {

	if len(toRemove) == 0 {
		return slice
	}

	heap := utils.IntHeap(toRemove)
	heap.Heapify()

	r = make([]fr.Element, 0, len(slice))

	// note: we can optimize that for the likely case where len(slice) >>> len(toRemove)
	for i := 0; i < len(slice); i++ {
		if len(heap) > 0 && i+sliceFirstIndex == heap[0] {
			for len(heap) > 0 && i+sliceFirstIndex == heap[0] {
				heap.Pop()
			}
			continue
		}
		r = append(r, slice[i])
	}

	return
}

func computeH(a, b, c []fr.Element, domain *fft.Domain) []fr.Element {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	// a -> aPoly, b -> bPoly, c -> cPoly
	// point-value form -> coefficient form
	domain.FFTInverse(a, fft.DIF)
	domain.FFTInverse(b, fft.DIF)
	domain.FFTInverse(c, fft.DIF)

	// evaluate aPoly, bPoly, cPoly on coset (roots of unity)
	domain.FFT(a, fft.DIT, fft.OnCoset())
	domain.FFT(b, fft.DIT, fft.OnCoset())
	domain.FFT(c, fft.DIT, fft.OnCoset())

	// vanishing poly t(x) = x^N - 1
	// calcualte 1/t(g), where g is the generator
	var den, one fr.Element
	one.SetOne()
	// g^N
	den.Exp(domain.FrMultiplicativeGen, big.NewInt(int64(domain.Cardinality)))
	// 1/(g^N - 1)
	den.Sub(&den, &one).Inverse(&den)

	// h = (a*b - c)/t
	// h = ifft_coset(ca o cb - cc)
	// reusing a to avoid unnecessary memory allocation
	utils.Parallelize(n, func(start, end int) {
		for i := start; i < end; i++ {
			a[i].Mul(&a[i], &b[i]).
				Sub(&a[i], &c[i]).
				Mul(&a[i], &den)
		}
	})

	// ifft_coset: point-value form -> coefficient form
	domain.FFTInverse(a, fft.DIF, fft.OnCoset())

	return a
}

func msmG1(res *curve.G1Jac, points *device.HostOrDeviceSlice[curve.G1Affine], scalars *device.HostOrDeviceSlice[fr.Element]) error {
	if points.Len() != scalars.Len() {
		return fmt.Errorf("MSM: len(points) != len(scalars)")
	}
	cfg := msm.DefaultMSMConfig()
	cfg.ArePointsInMont = true
	cfg.Npoints = uint32(points.Len())
	cfg.FfiAffineSz = 64
	if err := msm.MSM_G1(unsafe.Pointer(res), points.AsPtr(), scalars.AsPtr(), deviceId, cfg); err != nil {
		return err
	}
	return nil
}

func msmG2(res *curve.G2Jac, points *device.HostOrDeviceSlice[curve.G2Affine], scalars *device.HostOrDeviceSlice[fr.Element]) error {
	if points.Len() != scalars.Len() {
		return fmt.Errorf("MSM: len(points) != len(scalars)")
	}
	cfg := msm.DefaultMSMConfig()
	cfg.AreInputsOnDevice = true
	cfg.ArePointsInMont = true
	cfg.Npoints = uint32(points.Len())
	cfg.LargeBucketFactor = 2
	// TODO: MSM_G2 should return Jacobian
	// https://github.com/okx/cryptography_cuda/issues/90
	resAffine := curve.G2Affine{}
	if err := msm.MSM_G2(unsafe.Pointer(&resAffine), points.AsPtr(), scalars.AsPtr(), deviceId, cfg); err != nil {
		return err
	}
	res.FromAffine(&resAffine)
	return nil
}

func CopyToDevice[T any](hostData []T, chDeviceSlice chan *device.HostOrDeviceSlice[T]) error {
	deviceSlice, err := device.CudaMalloc[T](deviceId, len(hostData))
	if err != nil {
		chDeviceSlice <- nil
		return err
	}
	if err := deviceSlice.CopyFromHost(hostData[:]); err != nil {
		chDeviceSlice <- nil
		return err
	}
	chDeviceSlice <- deviceSlice
	return nil
}
