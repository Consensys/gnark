//go:build icicle

package bw6761

import (
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"slices"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bw6-761"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fp"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bw6-761/fr/hash_to_field"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	groth16_bw6761 "github.com/consensys/gnark/backend/groth16/bw6-761"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bw6-761"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/logger"

	icicle_core "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/core"
	icicle_bw6761 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761"
	icicle_g2 "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761/g2"
	icicle_msm "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761/msm"
	icicle_ntt "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761/ntt"
	icicle_vecops "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/curves/bw6761/vecOps"
	icicle_runtime "github.com/ingonyama-zk/icicle-gnark/v3/wrappers/golang/runtime"

	fcs "github.com/consensys/gnark/frontend/cs"
)

var isProfileMode bool

func init() {
	_, isProfileMode = os.LookupEnv("ICICLE_STEP_PROFILE")
}

func (pk *ProvingKey) setupDevicePointers(device *icicle_runtime.Device) error {
	if pk.deviceInfo != nil {
		return nil
	}
	pk.deviceInfo = &deviceInfo{}
	gen, err := fft.Generator(2 * pk.Domain.Cardinality)
	if err != nil {
		return fmt.Errorf("get fft generator: %w", err)
	}
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

	copyDenDone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		denIcicleArrHost := (icicle_core.HostSlice[fr.Element])(denIcicleArr)
		denIcicleArrHost.CopyToDevice(&pk.DenDevice, true)
		if err := icicle_bw6761.FromMontgomery(pk.DenDevice); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy den to device: %s", err.AsString()))
		}
		close(copyDenDone)
	})

	/*************************  Init Domain Device  ***************************/
	genBits := gen.Bits()
	limbs := icicle_core.ConvertUint64ArrToUint32Arr(genBits[:])
	copy(pk.CosetGenerator[:], limbs[:fr.Limbs*2])
	var rouIcicle icicle_bw6761.ScalarField
	rouIcicle.FromLimbs(limbs)

	initDomain := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		if e := icicle_ntt.InitDomain(rouIcicle, icicle_core.GetDefaultNTTInitDomainConfig()); e != icicle_runtime.Success {
			panic(fmt.Sprintf("couldn't initialize domain: %s", e.AsString())) // TODO
		}
		close(initDomain)
	})

	/*************************  End Init Domain Device  ***************************/
	/*************************  Start G1 Device Setup  ***************************/
	/*************************     A      ***************************/
	copyADone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		g1AHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.A)
		g1AHost.CopyToDevice(&pk.G1Device.A, true)
		if err := icicle_bw6761.AffineFromMontgomery(pk.G1Device.A); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy A to device: %s", err.AsString()))
		}
		close(copyADone)
	})
	/*************************     B      ***************************/
	copyBDone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		g1BHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.B)
		g1BHost.CopyToDevice(&pk.G1Device.B, true)
		if err := icicle_bw6761.AffineFromMontgomery(pk.G1Device.B); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy B to device: %s", err.AsString()))
		}
		close(copyBDone)
	})
	/*************************     K      ***************************/
	copyKDone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		g1KHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.K)
		g1KHost.CopyToDevice(&pk.G1Device.K, true)
		if err := icicle_bw6761.AffineFromMontgomery(pk.G1Device.K); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy K to device: %s", err.AsString()))
		}
		close(copyKDone)
	})
	/*************************     Z      ***************************/
	copyZDone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		g1ZHost := (icicle_core.HostSlice[curve.G1Affine])(pk.G1.Z)
		g1ZHost.CopyToDevice(&pk.G1Device.Z, true)
		err := icicle_bw6761.AffineFromMontgomery(pk.G1Device.Z)
		if err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy Z to device: %s", err.AsString()))
		}
		close(copyZDone)
	})
	/*************************  End G1 Device Setup  ***************************/
	/*************************  Start G2 Device Setup  ***************************/
	copyG2BDone := make(chan struct{})
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		g2BHost := (icicle_core.HostSlice[curve.G2Affine])(pk.G2.B)
		g2BHost.CopyToDevice(&pk.G2Device.B, true)
		if err := icicle_g2.G2AffineFromMontgomery(pk.G2Device.B); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy G2 B to device: %s", err.AsString()))
		}
		close(copyG2BDone)
	})
	/*************************  End G2 Device Setup  ***************************/

	/*************************  Commitment Keys Device Setup  ***************************/

	commitmentKeysDeviceDone := make(chan struct{})
	pk.CommitmentKeysDevice.Basis = make([]icicle_core.DeviceSlice, len(pk.CommitmentKeys))
	pk.CommitmentKeysDevice.BasisExpSigma = make([]icicle_core.DeviceSlice, len(pk.CommitmentKeys))
	icicle_runtime.RunOnDevice(device, func(args ...any) {
		for i := range pk.CommitmentKeys {
			commitmentKeyBasisHost := icicle_core.HostSliceFromElements(pk.CommitmentKeys[i].Basis)
			commitmentKeyBasisExpSigmaHost := icicle_core.HostSliceFromElements(pk.CommitmentKeys[i].BasisExpSigma)
			commitmentKeyBasisHost.CopyToDevice(&pk.CommitmentKeysDevice.Basis[i], true)
			commitmentKeyBasisExpSigmaHost.CopyToDevice(&pk.CommitmentKeysDevice.BasisExpSigma[i], true)
		}
		close(commitmentKeysDeviceDone)
	})
	/*************************  End Commitment Keys Device Setup  ***************************/

	/*************************  Wait for all data tranfsers  ***************************/
	<-initDomain
	<-copyDenDone
	<-copyADone
	<-copyBDone
	<-copyKDone
	<-copyZDone
	<-copyG2BDone
	<-commitmentKeysDeviceDone

	return nil
}

func projectiveToGnarkAffine(p icicle_bw6761.Projective) *curve.G1Affine {
	px, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.X.ToBytesLittleEndian()))
	py, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Y.ToBytesLittleEndian()))
	pz, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(p.Z.ToBytesLittleEndian()))

	var x, y, zInv fp.Element

	zInv.Inverse(&pz)
	x.Mul(&px, &zInv)
	y.Mul(&py, &zInv)

	return &curve.G1Affine{X: x, Y: y}
}

func g1ProjectiveToG1Jac(p icicle_bw6761.Projective) curve.G1Jac {
	var p1 curve.G1Jac
	p1.FromAffine(projectiveToGnarkAffine(p))

	return p1
}

func g2ProjectiveToG2Jac(p *icicle_g2.G2Projective) curve.G2Jac {
	px := p.X.ToBytesLittleEndian()
	py := p.Y.ToBytesLittleEndian()
	pz := p.Z.ToBytesLittleEndian()
	x, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(px))
	y, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(py))
	z, _ := fp.LittleEndian.Element((*[fp.Bytes]byte)(pz))

	var jZSquared, jX, jY fp.Element
	jZSquared.Mul(&z, &z)
	jX.Mul(&x, &z)
	jY.Mul(&y, &jZSquared)
	return curve.G2Jac{
		X: jX,
		Y: jY,
		Z: z,
	}
}

// Prove generates the proof of knowledge of a r1cs with full witness (secret + public part).
func Prove(r1cs *cs.R1CS, pk *ProvingKey, fullWitness witness.Witness, cfg *icicle.Config) (*groth16_bw6761.Proof, error) {
	opt, err := backend.NewProverConfig(cfg.ProverOpts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}
	log := logger.Logger().With().Str("curve", r1cs.CurveID().String()).Str("acceleration", "icicle").Int("nbConstraints", r1cs.GetNbConstraints()).Str("backend", "groth16").Logger()

	device := icicle_runtime.CreateDevice(cfg.Backend.String(), cfg.DeviceID)

	if pk.deviceInfo == nil {
		log.Debug().Msg("precomputing proving key in GPU")

		if err := pk.setupDevicePointers(&device); err != nil {
			return nil, fmt.Errorf("setup device pointers: %w", err)
		}
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &groth16_bw6761.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))
	privateCommittedValuesDevice := make([]icicle_core.DeviceSlice, len(commitmentInfo))

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

		proofCommitmentIcicle := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		ckBasisMsmDone := make(chan struct{})
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			cfg := icicle_msm.GetDefaultMSMConfig()
			cfg.AreBasesMontgomeryForm = true
			cfg.AreScalarsMontgomeryForm = true
			privateCommittedValuesHost := icicle_core.HostSliceFromElements(privateCommittedValues[i])
			privateCommittedValuesHost.CopyToDevice(&privateCommittedValuesDevice[i], true)
			if err := icicle_msm.Msm(privateCommittedValuesDevice[i], pk.CommitmentKeysDevice.Basis[i], &cfg, proofCommitmentIcicle); err != icicle_runtime.Success {
				panic(fmt.Sprintf("commitment: %s", err.AsString()))
			}
			close(ckBasisMsmDone)
		})
		<-ckBasisMsmDone
		proof.Commitments[i] = *projectiveToGnarkAffine(proofCommitmentIcicle[0])

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
	numCommitmentKeys := len(pk.CommitmentKeys)
	poks := make([]curve.G1Affine, numCommitmentKeys)

	// if there are CommitmentKeys, run a batch MSM for pederson Proof of Knowledge
	if numCommitmentKeys > 0 {
		startPoKBatch := time.Now()
		poksIcicle := make([]icicle_core.HostSlice[icicle_bw6761.Projective], numCommitmentKeys)
		for i := range poksIcicle {
			poksIcicle[i] = make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		}
		ckBasisExpSigmaMsmBatchDone := make(chan struct{})
		icicle_runtime.RunOnDevice(&device, func(args ...any) {
			cfg := icicle_msm.GetDefaultMSMConfig()
			cfg.AreBasesMontgomeryForm = true
			cfg.AreScalarsMontgomeryForm = true
			for i := range pk.CommitmentKeysDevice.BasisExpSigma {
				if err := icicle_msm.Msm(privateCommittedValuesDevice[i], pk.CommitmentKeysDevice.BasisExpSigma[i], &cfg, poksIcicle[i]); err != icicle_runtime.Success {
					panic(fmt.Sprintf("commitment POK: %s", err.AsString()))
				}
			}
			close(ckBasisExpSigmaMsmBatchDone)
		})
		<-ckBasisExpSigmaMsmBatchDone
		for i := range pk.CommitmentKeys {
			poks[i] = *projectiveToGnarkAffine(poksIcicle[i][0])
		}
		if isProfileMode {
			log.Debug().Dur("took", time.Since(startPoKBatch)).Msg("ICICLE Batch Proof of Knowledge")
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
	// H (witness reduction / FFT part)
	var h icicle_core.DeviceSlice
	chHDone := make(chan struct{})
	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		h = computeH(solution.A, solution.B, solution.C, pk, &device)

		solution.A = nil
		solution.B = nil
		solution.C = nil
		close(chHDone)
	})

	// we need to copy and filter the wireValues for each multi exp
	// as pk.G1.A, pk.G1.B and pk.G2.B may have (a significant) number of point at infinity
	var wireValuesADevice, wireValuesBDevice icicle_core.DeviceSlice
	chWireValuesA, chWireValuesB := make(chan struct{}), make(chan struct{})

	icicle_runtime.RunOnDevice(&device, func(args ...any) {
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
		if err := icicle_bw6761.FromMontgomery(wireValuesADevice); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy A to device: %s", err.AsString()))
		}

		close(chWireValuesA)
	})

	icicle_runtime.RunOnDevice(&device, func(args ...any) {
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
		if err := icicle_bw6761.FromMontgomery(wireValuesBDevice); err != icicle_runtime.Success {
			panic(fmt.Sprintf("copy B to device: %s", err.AsString()))
		}

		close(chWireValuesB)
	})

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
	chArDone, chBs1Done := make(chan struct{}), make(chan struct{})

	computeBS1 := func() error {
		<-chWireValuesB

		cfg := icicle_msm.GetDefaultMSMConfig()
		res := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		start := time.Now()
		if err := icicle_msm.Msm(wireValuesBDevice, pk.G1Device.B, &cfg, res); err != icicle_runtime.Success {
			panic(fmt.Sprintf("msm Bs1: %s", err.AsString()))
		}

		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs1")
		}
		bs1 = g1ProjectiveToG1Jac(res[0])

		bs1.AddMixed(&pk.G1.Beta)
		bs1.AddMixed(&deltas[1])

		close(chBs1Done)
		return nil
	}

	computeAR1 := func() error {
		<-chWireValuesA

		cfg := icicle_msm.GetDefaultMSMConfig()
		res := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		start := time.Now()
		if err := icicle_msm.Msm(wireValuesADevice, pk.G1Device.A, &cfg, res); err != icicle_runtime.Success {
			panic(fmt.Sprintf("msm Ar1: %s", err.AsString()))
		}
		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("MSM Ar1")
		}
		ar = g1ProjectiveToG1Jac(res[0])

		ar.AddMixed(&pk.G1.Alpha)
		ar.AddMixed(&deltas[0])
		proof.Ar.FromJacobian(&ar)

		close(chArDone)
		return nil
	}

	computeKRS := func() error {
		var krs, krs2, p1 curve.G1Jac
		sizeH := int(pk.Domain.Cardinality - 1)

		cfg := icicle_msm.GetDefaultMSMConfig()
		resKrs2 := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		start := time.Now()
		if err := icicle_msm.Msm(h.RangeTo(sizeH, false), pk.G1Device.Z, &cfg, resKrs2); err != icicle_runtime.Success {
			panic(fmt.Sprintf("msm Krs2: %s", err.AsString()))
		}
		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs2")
		}
		krs2 = g1ProjectiveToG1Jac(resKrs2[0])

		// filter the wire values if needed
		// TODO Perf @Tabaie worst memory allocation offender
		toRemove := commitmentInfo.GetPrivateCommitted()
		toRemove = append(toRemove, commitmentInfo.CommitmentIndexes())
		_wireValues := filterHeap(wireValues[r1cs.GetNbPublicVariables():], r1cs.GetNbPublicVariables(), slices.Concat(toRemove...))
		_wireValuesHost := (icicle_core.HostSlice[fr.Element])(_wireValues)
		resKrs := make(icicle_core.HostSlice[icicle_bw6761.Projective], 1)
		cfg.AreScalarsMontgomeryForm = true
		start = time.Now()
		if err := icicle_msm.Msm(_wireValuesHost, pk.G1Device.K, &cfg, resKrs); err != icicle_runtime.Success {
			panic(fmt.Sprintf("msm Krs: %s", err.AsString()))
		}
		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("MSM Krs")
		}
		krs = g1ProjectiveToG1Jac(resKrs[0])

		krs.AddMixed(&deltas[2])

		krs.AddAssign(&krs2)

		<-chArDone
		<-chBs1Done

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
		res := make(icicle_core.HostSlice[icicle_g2.G2Projective], 1)
		start := time.Now()
		if err := icicle_g2.G2Msm(wireValuesBDevice, pk.G2Device.B, &cfg, res); err != icicle_runtime.Success {
			panic(fmt.Sprintf("msm Bs2: %s", err.AsString()))
		}
		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("MSM Bs2 G2")
		}
		Bs = g2ProjectiveToG2Jac(&res[0])

		deltaS.FromAffine(&pk.G2.Delta)
		deltaS.ScalarMultiplication(&deltaS, &s)
		Bs.AddAssign(&deltaS)
		Bs.AddMixed(&pk.G2.Beta)

		proof.Bs.FromJacobian(&Bs)
		return nil
	}

	// schedule our proof part computations
	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		if err := computeAR1(); err != nil {
			panic(fmt.Sprintf("compute AR1: %v", err))
		}
	})

	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		if err := computeBS1(); err != nil {
			panic(fmt.Sprintf("compute BS1: %v", err))
		}
	})

	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		if err := computeBS2(); err != nil {
			panic(fmt.Sprintf("compute BS2: %v", err))
		}
	})

	// wait for FFT to end
	<-chHDone

	computeKrsDone := make(chan struct{})
	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		if err := computeKRS(); err != nil {
			panic(fmt.Sprintf("compute KRS: %v", err))
		}
		close(computeKrsDone)
	})
	<-computeKrsDone

	log.Debug().Dur("took", time.Since(start)).Msg("prover done")

	// free device/GPU memory that is not needed for future proofs (scalars/hpoly)
	icicle_runtime.RunOnDevice(&device, func(args ...any) {
		if err := wireValuesADevice.Free(); err != icicle_runtime.Success {
			log.Error().Msgf("free wireValuesADevice failed: %s", err.AsString())
		}
		if err := wireValuesBDevice.Free(); err != icicle_runtime.Success {
			log.Error().Msgf("free wireValuesBDevice failed: %s", err.AsString())
		}
		if err := h.Free(); err != icicle_runtime.Success {
			log.Error().Msgf("free h failed: %s", err.AsString())
		}
	})

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

func computeH(a, b, c []fr.Element, pk *ProvingKey, device *icicle_runtime.Device) icicle_core.DeviceSlice {
	// H part of Krs
	// Compute H (hz=ab-c, where z=-2 on ker X^n+1 (z(x)=x^n-1))
	// 	1 - _a = ifft(a), _b = ifft(b), _c = ifft(c)
	// 	2 - ca = fft_coset(_a), ba = fft_coset(_b), cc = fft_coset(_c)
	// 	3 - h = ifft_coset(ca o cb - cc)
	log := logger.Logger()
	startTotal := time.Now()
	n := len(a)

	// add padding to ensure input length is domain cardinality
	padding := make([]fr.Element, int(pk.Domain.Cardinality)-n)
	a = append(a, padding...)
	b = append(b, padding...)
	c = append(c, padding...)
	n = len(a)

	computeADone := make(chan icicle_core.DeviceSlice)
	computeBDone := make(chan icicle_core.DeviceSlice)
	computeCDone := make(chan icicle_core.DeviceSlice)

	computeInttNttOnDevice := func(args ...any) {
		var scalars []fr.Element = args[0].([]fr.Element)
		var channel chan icicle_core.DeviceSlice = args[1].(chan icicle_core.DeviceSlice)

		cfg := icicle_ntt.GetDefaultNttConfig()
		scalarsStream, _ := icicle_runtime.CreateStream()
		cfg.StreamHandle = scalarsStream
		cfg.Ordering = icicle_core.KNM
		cfg.IsAsync = true
		scalarsHost := icicle_core.HostSliceFromElements(scalars)
		var scalarsDevice icicle_core.DeviceSlice
		scalarsHost.CopyToDeviceAsync(&scalarsDevice, scalarsStream, true)
		start := time.Now()
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KInverse, &cfg, scalarsDevice)
		cfg.Ordering = icicle_core.KMN
		cfg.CosetGen = pk.CosetGenerator
		icicle_ntt.Ntt(scalarsDevice, icicle_core.KForward, &cfg, scalarsDevice)
		icicle_runtime.SynchronizeStream(scalarsStream)
		if isProfileMode {
			log.Debug().Dur("took", time.Since(start)).Msg("computeH: NTT + INTT")
		}
		channel <- scalarsDevice
		close(channel)
	}

	icicle_runtime.RunOnDevice(device, computeInttNttOnDevice, a, computeADone)
	icicle_runtime.RunOnDevice(device, computeInttNttOnDevice, b, computeBDone)
	icicle_runtime.RunOnDevice(device, computeInttNttOnDevice, c, computeCDone)

	aDevice := <-computeADone
	bDevice := <-computeBDone
	cDevice := <-computeCDone

	// The following does not need to be run in a RunOnDevice call because
	// computeH is being run inside a RunOnDevice call and the following is not
	// being run in a different goroutine unlike the calls above to
	// computeInttNttOnDevice which are running in different goroutines
	vecCfg := icicle_core.DefaultVecOpsConfig()
	start := time.Now()
	if err := icicle_bw6761.FromMontgomery(aDevice); err != icicle_runtime.Success {
		panic(fmt.Sprintf("fromMontgomery a in computeH: %s", err.AsString()))
	}
	if err := icicle_vecops.VecOp(aDevice, bDevice, aDevice, vecCfg, icicle_core.Mul); err != icicle_runtime.Success {
		panic(fmt.Sprintf("mul a b in computeH: %s", err.AsString()))
	}
	if err := icicle_vecops.VecOp(aDevice, cDevice, aDevice, vecCfg, icicle_core.Sub); err != icicle_runtime.Success {
		panic(fmt.Sprintf("sub a c in computeH: %s", err.AsString()))
	}
	if err := icicle_vecops.VecOp(aDevice, pk.DenDevice, aDevice, vecCfg, icicle_core.Mul); err != icicle_runtime.Success {
		panic(fmt.Sprintf("mul a den in computeH: %s", err.AsString()))
	}
	if isProfileMode {
		log.Debug().Dur("took", time.Since(start)).Msg("computeH: vecOps")
	}
	defer bDevice.Free()
	defer cDevice.Free()

	cfg := icicle_ntt.GetDefaultNttConfig()
	cfg.CosetGen = pk.CosetGenerator
	cfg.Ordering = icicle_core.KNR
	start = time.Now()
	if err := icicle_ntt.Ntt(aDevice, icicle_core.KInverse, &cfg, aDevice); err != icicle_runtime.Success {
		panic(fmt.Sprintf("ntt a in computeH: %s", err.AsString()))
	}
	if isProfileMode {
		log.Debug().Dur("took", time.Since(start)).Msg("computeH: INTT final")
	}
	if err := icicle_bw6761.FromMontgomery(aDevice); err != icicle_runtime.Success {
		panic(fmt.Sprintf("fromMontgomery a in computeH: %s", err.AsString()))
	}

	if isProfileMode {
		log.Debug().Dur("took", time.Since(startTotal)).Msg("computeH: Total")
	}
	return aDevice
}
