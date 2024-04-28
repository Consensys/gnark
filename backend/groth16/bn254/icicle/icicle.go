//go:build icicle

package icicle

import (
	"fmt"
	"math/big"
	"math/bits"
	"time"

	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/backend"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/groth16/internal"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"
	"github.com/rs/zerolog"

	icicle_core "github.com/ingonyama-zk/icicle/v2/wrappers/golang/core"
	icicle_cr "github.com/ingonyama-zk/icicle/v2/wrappers/golang/cuda_runtime"
	icicle_bn254 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254"
	icicle_g2 "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/g2"
	icicle_msm "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/ntt"
	icicle_vecops "github.com/ingonyama-zk/icicle/v2/wrappers/golang/curves/bn254/vecOps"

	fcs "github.com/consensys/gnark/frontend/cs"
)

const HasIcicle = true

func (pk *ProvingKey) setupDevicePointers() error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	gen, _ := fft.Generator(2 * pk.Domain.Cardinality)
	/*************************     Den      ***************************/
	n := int(pk.Domain.Cardinality)
	var denI, oneI fr.Element
	oneI.SetOne()
	denI.Exp(gen, big.NewInt(int64(pk.Domain.Cardinality)))
	denI.Sub(&denI, &oneI).Inverse(&denI)
	
	log2SizeFloor := bits.Len(uint(n)) - 1
	denIcicleArr := []fr.Element{denI}
	for i := 0; i < log2SizeFloor; i++ {
		denIcicleArr = append(denIcicleArr, denIcicleArr...)
	}
	pow2Remainder := n - 1<<log2SizeFloor
	for i := 0; i < pow2Remainder; i++ {
		denIcicleArr = append(denIcicleArr, denI)
	}
	
	copyDenDone := make(chan bool, 1)
	go func() {
		denIcicleArrHost := (icicle_core.HostSlice[fr.Element])(denIcicleArr)
		denIcicleArrHost.CopyToDevice(&pk.DenDevice, true)
		icicle_bn254.FromMontgomery(&pk.DenDevice)
		copyDenDone <- true
		}()
		
	/*************************  Init Domain Device  ***************************/
	ctx, err := icicle_cr.GetDefaultDeviceContext()
	if err != icicle_cr.CudaSuccess {
		panic("Couldn't create device context") // TODO
	}

	genBits := gen.Bits()
	limbs := icicle_core.ConvertUint64ArrToUint32Arr(genBits[:])
	copy(pk.CosetGenerator[:], limbs[:fr.Limbs*2])
	var rouIcicle icicle_bn254.ScalarField
	rouIcicle.FromLimbs(limbs)
	e := icicle_ntt.InitDomain(rouIcicle, ctx, true)
	if e.IcicleErrorCode != icicle_core.IcicleSuccess {
		panic("Couldn't initialize domain") // TODO
	}

	/*************************  End Init Domain Device  ***************************/
	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	copyADone := make(chan bool, 1)
	go func() {
		g1AHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.A)
		g1AHost.CopyToDevice(&pk.G1Device.A, true)
		copyADone <- true
	}()
	/*************************     B      ***************************/
	copyBDone := make(chan bool, 1)
	go func() {
		g1BHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.B)
		g1BHost.CopyToDevice(&pk.G1Device.B, true)
		copyBDone <- true
	}()
	/*************************     K      ***************************/
	copyKDone := make(chan bool, 1)
	go func() {
		g1KHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.K)
		g1KHost.CopyToDevice(&pk.G1Device.K, true)
		copyKDone <- true
	}()
	/*************************     Z      ***************************/
	copyZDone := make(chan bool, 1)
	go func() {
		g1ZHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.Z)
		g1ZHost.CopyToDevice(&pk.G1Device.Z, true)
		copyZDone <- true
	}()
	/*************************  End G1 Device Setup  ***************************/
	<-copyDenDone
	<-copyADone
	<-copyBDone
	<-copyKDone
	<-copyZDone
	/*************************  Start G2 Device Setup  ***************************/
	copyG2BDone := make(chan bool, 1)
	go func() {
		g2BHost := (icicle_core.HostSlice[curve.G2Affine])(pk.G2.B)
		g2BHost.CopyToDevice(&pk.G2Device.B, true)
		copyG2BDone <- true
	}()

	<-copyG2BDone
	/*************************  End G2 Device Setup  ***************************/
	return nil
}

func projectiveToGnarkAffine(p icicle_bn254.Projective) *curve.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.X.ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Y.ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Z.ToBytesLittleEndian()))

	var x, y, zInv fp.Element

	zInv.Inverse(&pz)
	x.Mul(&px, &zInv)
	y.Mul(&py, &zInv)

	return &curve.G1Affine{X: x, Y: y}
}

func g1ProjectiveToG1Jac(p icicle_bn254.Projective) curve.G1Jac {
	var p1 curve.G1Jac
	p1.FromAffine(projectiveToGnarkAffine(p))

	return p1
}

func toGnarkE2(f icicle_g2.G2BaseField) curve.E2 {
	bytes := f.ToBytesLittleEndian()
	a0, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[:fp.Bytes]))
	a1, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(bytes[fp.Bytes:]))
	return curve.E2{
		A0: a0,
		A1: a1,
	}
}

func g2ProjectiveToG2Jac(p *icicle_g2.G2Projective) curve.G2Jac {
	x := toGnarkE2(p.X)
	y := toGnarkE2(p.Y)
	z := toGnarkE2(p.Z)
	var zSquared curve.E2
	zSquared.Mul(&z, &z)

	var X curve.E2
	X.Mul(&x, &z)

	var Y curve.E2
	Y.Mul(&y, &zSquared)

	return curve.G2Jac{
		X: X,
		Y: Y,
		Z: z,
	}
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
	if opt.Accelerator != "icicle" {
		return groth16_bn254.Prove(r1cs, &pk.ProvingKey, fullWitness, opts...)
	}
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()
	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key in GPU")
		if err := pk.setupDevicePointers(); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
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

	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}

	if proof.CommitmentPok, err = pedersen.BatchProve(pk.CommitmentKeys, privateCommittedValues, commitmentsSerialized); err != nil {
		return nil, err
	}

	// H (witness reduction / FFT part)
	var h icicle_core.DeviceSlice
	chHDone := make(chan struct{}, 1)
	go func() {
		h = computeH(solution.A, solution.B, solution.C, pk, log)

		solution.A = nil
		solution.B = nil
		solution.C = nil
		chHDone <- struct{}{}
	}()

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesADevice, wireValuesBDevice icicle_core.DeviceSlice
	chWireValuesA, chWireValuesB := make(chan struct{}, 1), make(chan struct{}, 1)

	go func() {
		wireValuesA := make([]fr.Element, len(wireValues)-int(pk.NbInfinityA))
		for i, j := 0, 0; j < len(wireValuesA); i++ {
			if pk.InfinityA[i] {
				continue
			}
			wireValuesA[j] = wireValues[i]
			j++
		}

		// Copy scalars to the device and retain ptr to them
		wireValuesAHost := (icicle_core.HostSlice[fr.Element])(wireValuesA)
		wireValuesAHost.CopyToDevice(&wireValuesADevice, true)

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

		// Copy scalars to the device and retain ptr to them
		wireValuesBHost := (icicle_core.HostSlice[fr.Element])(wireValuesB)
		wireValuesBHost.CopyToDevice(&wireValuesBDevice, true)

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
	_kr.Mul(&_r, &_s).Neg(&_kr)

	_r.BigInt(&r)
	_s.BigInt(&s)

	// computes r[δ], s[δ], kr[δ]
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{_r, _s, _kr})

	var bs1, ar curve.G1Jac

	computeBS1 := func() error {
		<-chWireValuesB

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesBDevice, pk.G1Device.B, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs1")
		bs1 = g1ProjectiveToG1Jac(res[0])

		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])

		return nil
	}

	computeAR1 := func() error {
		<-chWireValuesA

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(wireValuesADevice, pk.G1Device.A, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Ar1")
		ar = g1ProjectiveToG1Jac(res[0])

		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)

		return nil
	}

	computeKRS := func() error {
		var krs, krs2, p1 curve.G1Jac
		sizeH := int(pk.Domain.Cardinality - 1)

		cfg := icicle_msm.GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		resKrs2 := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start := time.Now()
		icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), internal.ConcatAll(toRemove...))
		_wireValuesHost := (icicle_core.HostSlice[fr.Element])(_wireValues)
		resKrs := make(icicle_core.HostSlice[icicle_bn254.Projective], 1)
		start = time.Now()
		icicle_msm.Msm(_wireValuesHost, pk.G1Device.K, &cfg, resKrs)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs")
		krs = g1ProjectiveToG1Jac(resKrs[0])

		krs.AddMixed(&deltas[2])

		krs.AddAssign(&krs2)

		p1.ScalarMultiplication(&ar, &s)
		krs.AddAssign(&p1)

		p1.ScalarMultiplication(&bs1, &r)
		krs.AddAssign(&p1)

		proof.Krs.FromJacobian(&krs)

		return nil
	}

	computeBS2 := func() error {
		// Bs2 (1 multi exp G2 - size = len(wires))
		var Bs, deltaS curve.G2Jac

		<-chWireValuesB

		cfg := icicle_g2.G2GetDefaultMSMConfig()
		cfg.ArePointsMontgomeryForm = true
		cfg.AreScalarsMontgomeryForm = true
		res := make(icicle_core.HostSlice[icicle_g2.G2Projective], 1)
		start := time.Now()
		icicle_g2.G2Msm(wireValuesBDevice, pk.G2Device.B, &cfg, res)
		log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs2 G2")
		Bs = g2ProjectiveToG2Jac(&res[0])

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// wait for FFT to end
	<-chHDone

	// schedule our proof part computations
	if err := computeAR1(); err != nil {
		return nil, err
	}
	if err := computeBS1(); err != nil {
		return nil, err
	}
	if err := computeKRS(); err != nil {
		return nil, err
	}
	if err := computeBS2(); err != nil {
		return nil, err
	}

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	// free device/GPU memory that is not needed for future proofs (scalars/hpoly)
	go func() {
		wireValuesADevice.Free()
		wireValuesBDevice.Free()
		// h.Free()
	}()

	return proof, nil
}

// if len(toRemove) == 0, returns slice
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

func computeH(a, b, c []fr.Element, pk *ProvingKey, log zerolog.Logger) icicle_core.DeviceSlice {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)

	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(pk.Domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	computeADone := make(chan icicle_core.DeviceSlice, 1)
	computeBDone := make(chan icicle_core.DeviceSlice, 1)
	computeCDone := make(chan icicle_core.DeviceSlice, 1)

	computeInttNttOnDevice := func(scalars []fr.Element, channel chan icicle_core.DeviceSlice) {
		cfg := icicle_ntt.GetDefaultNttConfig()
		scalarsStream, _ := icicle_cr.CreateStream()
		cfg.Ctx.Stream = &scalarsStream
		cfg.Ordering = icicle_core.KNM
		cfg.IsAsync = true
		scalarsHost := icicle_core.HostSliceFromElements(scalars)
		var scalarsDevice icicle_core.DeviceSlice
		scalarsHost.CopyToDeviceAsync(&scalarsDevice, scalarsStream, true)
		start := time.Now()
		cfg.NttAlgorithm = icicle_core.Radix2
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KInverse, &cfg, scalarsDevice)
		cfg.Ordering = icicle_core.KMN
		cfg.CosetGen = pk.CosetGenerator
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KForward, &cfg, scalarsDevice)
		icicle_cr.SynchronizeStream(&scalarsStream)
		log.Debug().Dur("took", time.Since(start)).Msg("computeH: NTT + INTT")
		channel <-scalarsDevice
	}

	go computeInttNttOnDevice(a, computeADone)
	go computeInttNttOnDevice(b, computeBDone)
	go computeInttNttOnDevice(c, computeCDone)

	aDevice := <-computeADone
	bDevice := <-computeBDone
	cDevice := <-computeCDone

	vecCfg := icicle_core.DefaultVecOpsConfig()
	start := time.Now()
	icicle_bn254.FromMontgomery(&aDevice)
	icicle_vecops.VecOp(aDevice, bDevice, aDevice, vecCfg, icicle_core.Mul)
	icicle_vecops.VecOp(aDevice, cDevice, aDevice, vecCfg, icicle_core.Sub)
	icicle_vecops.VecOp(aDevice, pk.DenDevice, aDevice, vecCfg, icicle_core.Mul)
	log.Debug().Dur("took", time.Since(start)).Msg("computeH: vecOps")
	defer bDevice.Free()
	defer cDevice.Free()

	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.CosetGen = pk.CosetGenerator
	cfg.Ordering = icicle_core.KNM
	cfg.NttAlgorithm = icicle_core.Radix2
	start = time.Now()
	icicle_ntt.Ntt(aDevice, icicle_core.KInverse, &cfg, aDevice)
	log.Debug().Dur("took", time.Since(start)).Msg("computeH: INTT final")

	return aDevice
}
