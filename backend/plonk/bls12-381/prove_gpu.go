//go:build cuda

package plonk

import (
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"sync"
	"time"
	"unsafe"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
	p2 "github.com/consensys/gnark/internal/gpu/bls12381/p2"
	"github.com/consensys/gnark/internal/utils"
)

// gpuBuildZ computes the permutation grand-product Z on-device via the resident
// p2.RatioBuildZ pipeline (gpu_ratio_copy_terms -> prefix_scan -> apply_inverse),
// reproducing iop.BuildRatioCopyConstraint. Gated by GNARK_P2_GRANDPRODUCT.
// With GNARK_P2_GRANDPRODUCT_SHADOW set it cross-checks against the CPU result
// and falls back to it on any mismatch (so the proof is always valid).
func (s *instance) gpuBuildZ() ([]fr.Element, bool) {
	if !gpu.Available() || os.Getenv("GNARK_DISABLE_P2") != "" {
		return nil, false
	}
	n := int(s.domain0.Cardinality)
	dev, err := p2.NewDevice()
	if err != nil {
		return nil, false
	}
	t0 := time.Now()

	// twiddles0 = identity support for j=0 = [ω⁰, ω¹, …, ωⁿ⁻¹]
	tw0 := make([]fr.Element, n)
	tw0[0].SetOne()
	for i := 1; i < n; i++ {
		tw0[i].Mul(&tw0[i-1], &s.domain0.Generator)
	}
	u := s.domain0.FrMultiplicativeGen
	var u2 fr.Element
	u2.Mul(&u, &u)
	ch := [4]fr.Element{s.beta, s.gamma, u, u2}

	vecs := make([]*p2.FrVector, 0, 8)
	defer func() {
		for _, v := range vecs {
			if v != nil {
				v.Free()
			}
		}
	}()
	mk := func(h []fr.Element) *p2.FrVector {
		v, e := dev.NewFrVector(n)
		if e != nil {
			return nil
		}
		vecs = append(vecs, v)
		if e := v.CopyFromHost(h); e != nil {
			return nil
		}
		return v
	}
	vl := mk(s.x[id_L].Coefficients())
	vr := mk(s.x[id_R].Coefficients())
	vo := mk(s.x[id_O].Coefficients())
	vs1 := mk(s.trace.S1.Coefficients())
	vs2 := mk(s.trace.S2.Coefficients())
	vs3 := mk(s.trace.S3.Coefficients())
	vtw := mk(tw0)
	z, _ := dev.NewFrVector(n)
	if z != nil {
		vecs = append(vecs, z)
	}
	if vl == nil || vr == nil || vo == nil || vs1 == nil || vs2 == nil || vs3 == nil || vtw == nil || z == nil {
		return nil, false
	}
	if err := dev.RatioBuildZ(z, vl, vr, vo, vs1, vs2, vs3, vtw, ch); err != nil {
		return nil, false
	}
	out := make([]fr.Element, n)
	if err := z.CopyToHost(out); err != nil {
		return nil, false
	}
	traceProvef("[P2 grandproduct] device build %v\n", time.Since(t0))

	if os.Getenv("GNARK_P2_GRANDPRODUCT_SHADOW") != "" {
		ref, e := iop.BuildRatioCopyConstraint(
			[]*iop.Polynomial{s.x[id_L], s.x[id_R], s.x[id_O]},
			s.trace.S, s.beta, s.gamma,
			iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}, s.domain0)
		if e == nil {
			rc := ref.Coefficients()
			mism := 0
			for i := range rc {
				if rc[i] != out[i] {
					mism++
				}
			}
			traceProvef("[P2 GRANDPRODUCT SHADOW] mismatches=%d of %d\n", mism, len(rc))
			if mism > 0 {
				return rc, true
			}
		}
	}
	return out, true
}

// gpuCommitLRO commits the L,R,O wire polynomials resident: it subtracts s0,
// commits each window against the Lagrange SRS via the resident-scalar G1MSM,
// restores, and adds the correction point + blinding — byte-identical to the CPU
// commitToLRO. Gated by GNARK_P2_COMMITLRO; the apk proof verifying is the check
// (a wrong commitment fails Fiat-Shamir downstream). Returns (handled, err).
func (s *instance) gpuCommitLRO() (bool, error) {
	if !gpu.Available() || os.Getenv("GNARK_DISABLE_P2") != "" {
		return false, nil
	}
	n := int(s.domain0.Cardinality)
	nbPublic := len(s.spr.Public)
	offset := nbPublic + s.spr.GetNbConstraints()

	wWitness, ok := s.fullWitness.Vector().(fr.Vector)
	if !ok {
		return false, nil
	}
	s0 := wWitness[0]
	var s0BigInt big.Int
	s0.BigInt(&s0BigInt)
	var correctionPoint curve.G1Affine
	correctionPoint.ScalarMultiplication(&s.pk.Kzg.G1[0], &s0BigInt)

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	lagG1 := s.pk.KzgLagrange.G1
	// pre-warm (convert + cache) the two SRS base ranges so the async MSMs below
	// are cache hits and don't trigger a serializing point conversion mid-stream.
	if err := gpu.PrewarmPoints(unsafe.Pointer(&lagG1[0]), offset); err != nil {
		return false, err
	}
	if err := gpu.PrewarmPoints(unsafe.Pointer(&lagG1[nbPublic]), offset-nbPublic); err != nil {
		return false, err
	}
	gpu.DeviceSync()

	type win struct {
		coeffs []fr.Element
		lo, hi int
		bp     int
		out    *curve.G1Affine
	}
	wins := [3]win{
		{s.x[id_L].Coefficients(), 0, offset, id_Bl, &s.proof.LRO[0]},
		{s.x[id_R].Coefficients(), nbPublic, offset, id_Br, &s.proof.LRO[1]},
		{s.x[id_O].Coefficients(), nbPublic, offset, id_Bo, &s.proof.LRO[2]},
	}
	projBytes := gpu.MSMProjBytes()
	var streams, hProjs, dScalars, dCanons [3]unsafe.Pointer
	defer func() {
		for k := 0; k < 3; k++ {
			if dScalars[k] != nil {
				gpu.Free(dScalars[k])
			}
			if dCanons[k] != nil {
				gpu.Free(dCanons[k])
			}
			if hProjs[k] != nil {
				gpu.FreeHost(hProjs[k])
			}
			if streams[k] != nil {
				gpu.StreamDestroy(streams[k])
			}
		}
	}()

	// issue the 3 MSMs asynchronously, one per stream, so they overlap on the GPU.
	// The s0-subtract / upload / restore is synchronous per window, so the host
	// coeffs are untouched once the MSM is in flight.
	for k := range wins {
		w := wins[k]
		m := w.hi - w.lo
		for i := w.lo; i < w.hi; i++ {
			w.coeffs[i].Sub(&w.coeffs[i], &s0)
		}
		dScalars[k] = gpu.Malloc(m * 32)
		if dScalars[k] == nil {
			return false, fmt.Errorf("gpuCommitLRO: scalar alloc failed")
		}
		if err := gpu.MemcpyH2D(dScalars[k], unsafe.Pointer(&w.coeffs[w.lo]), m*32); err != nil {
			return false, err
		}
		for i := w.lo; i < w.hi; i++ {
			w.coeffs[i].Add(&w.coeffs[i], &s0)
		}
		streams[k] = gpu.StreamCreate()
		hProjs[k] = gpu.MallocHost(projBytes)
		dc, err := gpu.MSMDeviceScalarsAsync(unsafe.Pointer(&lagG1[w.lo]), dScalars[k], m, hProjs[k], streams[k])
		if err != nil {
			return false, err
		}
		dCanons[k] = dc
	}

	for k := range wins {
		gpu.StreamSync(streams[k])
	}
	for k := range wins {
		w := wins[k]
		var jac curve.G1Jac
		gpu.MSMMarshalProj(hProjs[k], unsafe.Pointer(&jac))
		var commit curve.G1Affine
		commit.FromJacobian(&jac)
		commit.Add(&commit, &correctionPoint)
		cb := commitBlindingFactor(n, s.bp[w.bp], s.pk.Kzg)
		w.out.Add(&commit, &cb)
	}
	return true, nil
}

// prewarmGPU pulls the witness-independent GPU prep — SRS point Montgomery→canonical
// conversion and the big-domain NTT twiddle init, both otherwise done lazily inside
// the commit/quotient phases — forward so it overlaps the CPU witness solve (during
// which the GPU is otherwise 100% idle). Best-effort: errors are swallowed so the
// real phases just do the work themselves. The point/NTT caches are mutex-guarded,
// so racing the commit phases is safe.
func (s *instance) prewarmGPU() error {
	if !gpu.Available() || os.Getenv("GNARK_DISABLE_P2") != "" {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	nbPublic := len(s.spr.Public)
	offset := nbPublic + s.spr.GetNbConstraints()
	if len(s.pk.KzgLagrange.G1) >= offset && offset > 0 {
		_ = gpu.PrewarmPoints(unsafe.Pointer(&s.pk.KzgLagrange.G1[0]), offset)
		if offset-nbPublic > 0 {
			_ = gpu.PrewarmPoints(unsafe.Pointer(&s.pk.KzgLagrange.G1[nbPublic]), offset-nbPublic)
		}
	}
	if n2 := int(s.domain0.Cardinality) + 2; len(s.pk.Kzg.G1) >= n2 {
		_ = gpu.PrewarmPoints(unsafe.Pointer(&s.pk.Kzg.G1[0]), n2)
	}
	if bigN := int(s.domain1.Cardinality); bigN > 1 {
		_ = gpu.NTTInit(uint32(bits.TrailingZeros(uint(bigN))))
	}
	return nil
}

type proverGPUContext struct {
	mu         sync.Mutex
	n          int
	polyPtrs   []unsafe.Pointer
	dL         unsafe.Pointer
	dR         unsafe.Pointer
	dO         unsafe.Pointer
	dS1        unsafe.Pointer
	dS2        unsafe.Pointer
	dS3        unsafe.Pointer
	dTwiddles0 unsafe.Pointer
	dNumerator unsafe.Pointer
	dInvRho    unsafe.Pointer
	invRhoLen  int
}

func (ctx *proverGPUContext) free() {
	if ctx == nil {
		return
	}
	for _, ptr := range []unsafe.Pointer{
		ctx.dL, ctx.dR, ctx.dO, ctx.dS1, ctx.dS2, ctx.dS3, ctx.dTwiddles0,
		ctx.dNumerator, ctx.dInvRho,
	} {
		if ptr != nil {
			gpu.Free(ptr)
		}
	}
	ctx.dL, ctx.dR, ctx.dO = nil, nil, nil
	ctx.dS1, ctx.dS2, ctx.dS3 = nil, nil, nil
	ctx.dTwiddles0 = nil
	ctx.dNumerator = nil
	ctx.dInvRho = nil
	ctx.invRhoLen = 0
	for i, ptr := range ctx.polyPtrs {
		if ptr != nil {
			gpu.Free(ptr)
			ctx.polyPtrs[i] = nil
		}
	}
	ctx.polyPtrs = nil
	ctx.n = 0
}

func uploadResidentSlice(dst *unsafe.Pointer, dstLen *int, src []fr.Element) error {
	if len(src) == 0 {
		return nil
	}
	size := len(src) * 32
	if *dst != nil && *dstLen != len(src) {
		gpu.Free(*dst)
		*dst = nil
		*dstLen = 0
	}
	if *dst == nil {
		*dst = gpu.Malloc(size)
		if *dst == nil {
			return fmt.Errorf("GPU malloc failed for resident slice")
		}
	}
	if err := gpu.MemcpyH2D(*dst, unsafe.Pointer(&src[0]), size); err != nil {
		return err
	}
	*dstLen = len(src)
	return nil
}

func (ctx *proverGPUContext) ensurePolySlot(size int) {
	if len(ctx.polyPtrs) < size {
		old := ctx.polyPtrs
		ctx.polyPtrs = make([]unsafe.Pointer, size)
		copy(ctx.polyPtrs, old)
	}
}

func (ctx *proverGPUContext) getPoly(id int) unsafe.Pointer {
	if id < 0 || id >= len(ctx.polyPtrs) {
		return nil
	}
	return ctx.polyPtrs[id]
}

// gpuComputeNumeratorRhoLoop runs the rho-loop of computeNumerator on GPU.
// Uploads all polynomials once, runs fused IFFT→scale→FFT + constraint evaluation
// per iteration, downloads only the result buffer each iteration.
func (s *instance) gpuComputeNumeratorRhoLoop(
	rho, n int,
	scalingVector, scalingVectorRev []fr.Element,
	twiddles0 []fr.Element,
	shifters []fr.Element,
	coset, cosetExpNm1 *fr.Element,
	bn *big.Int,
	one *fr.Element,
	buf, cres []fr.Element,
	mm uint64,
	wgBuf *sync.WaitGroup,
	nbBsbGates int,
) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()
	defer s.timings.timed("detail.gpuComputeNumeratorRhoLoop.total")()
	t0 := time.Now()
	traceRho := os.Getenv("GNARK_GPU_TRACE_RHO") != ""
	var uploadPolysTime time.Duration
	var uploadMetaTime time.Duration
	var downloadPolysTime time.Duration

	npolys := len(s.x)
	elemSize := n * 32 // sizeof(Fr) = 32

	fmt.Fprintf(os.Stderr, "[GPU rho] starting: npolys=%d n=%d rho=%d\n", npolys, n, rho)

	// Ensure NTT domain is initialized
	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if err := gpu.NTTInit(logN); err != nil {
		return fmt.Errorf("NTTInit failed: %w", err)
	}

	// Allocate stream
	stream := gpu.StreamAcquire()
	if stream == nil {
		return fmt.Errorf("GPU stream create failed")
	}
	defer gpu.StreamRelease(stream)

	// Upload all polynomials to device.
	// id_ZS is a shallow clone of id_Z with shift=1 — they share the same data.
	// On GPU we make ZS point to Z's buffer so fused FFT on Z is visible to ZS.
	dPolys := make([]unsafe.Pointer, npolys)
	ownedPolys := make([]bool, npolys)
	tPhase := time.Now()
	for i := 0; i < npolys; i++ {
		if i == id_ZS {
			continue // handled below
		}
		if s.x[i] == nil {
			dPolys[i] = nil
			continue
		}
		if s.gpuCtx != nil && s.gpuCtx.n == n {
			switch i {
			case id_L:
				dPolys[i] = s.gpuCtx.dL
			case id_R:
				dPolys[i] = s.gpuCtx.dR
			case id_O:
				dPolys[i] = s.gpuCtx.dO
			case id_S1:
				dPolys[i] = s.gpuCtx.dS1
			case id_S2:
				dPolys[i] = s.gpuCtx.dS2
			case id_S3:
				dPolys[i] = s.gpuCtx.dS3
			}
			if dPolys[i] == nil {
				dPolys[i] = s.gpuCtx.getPoly(i)
			}
			if dPolys[i] != nil {
				continue
			}
		}
		dPolys[i] = gpu.Malloc(elemSize)
		if dPolys[i] == nil {
			for j := 0; j < i; j++ {
				if j != id_ZS && dPolys[j] != nil && ownedPolys[j] {
					gpu.Free(dPolys[j])
				}
			}
			return fmt.Errorf("GPU malloc failed for poly %d", i)
		}
		if s.gpuCtx != nil && s.gpuCtx.n == n {
			s.gpuCtx.mu.Lock()
			s.gpuCtx.ensurePolySlot(i + 1)
			s.gpuCtx.polyPtrs[i] = dPolys[i]
			s.gpuCtx.mu.Unlock()
			ownedPolys[i] = false
		} else {
			ownedPolys[i] = true
		}
		cp := s.x[i].Coefficients()
		if err := gpu.MemcpyH2D(dPolys[i], unsafe.Pointer(&cp[0]), elemSize); err != nil {
			return err
		}
	}
	uploadPolysTime = time.Since(tPhase)
	s.timings.add("detail.gpuRho.uploadPolys", uploadPolysTime)
	// ZS shares Z's device buffer — kernel accesses ZS[(tid+1)%n] = Z[(tid+1)%n]
	dPolys[id_ZS] = dPolys[id_Z]

	ptrArrayBytes := npolys * 8
	dPtrArray := gpu.Malloc(ptrArrayBytes)
	if dPtrArray == nil {
		for i, dp := range dPolys {
			if i == id_ZS {
				continue
			}
			if dp != nil && ownedPolys[i] {
				gpu.Free(dp)
			}
		}
		return fmt.Errorf("GPU malloc failed for poly pointer array")
	}
	defer gpu.Free(dPtrArray)
	tPhase = time.Now()
	if err := gpu.MemcpyH2D(dPtrArray, unsafe.Pointer(&dPolys[0]), ptrArrayBytes); err != nil {
		for i, dp := range dPolys {
			if i == id_ZS {
				continue
			}
			if dp != nil && ownedPolys[i] {
				gpu.Free(dp)
			}
		}
		return fmt.Errorf("poly pointer array H2D failed: %w", err)
	}
	dPtrArrayUpload := time.Since(tPhase)
	uploadMetaTime += dPtrArrayUpload
	s.timings.add("detail.gpuRho.uploadPtrArray", dPtrArrayUpload)

	defer func() {
		for i, dp := range dPolys {
			if i == id_ZS {
				continue // don't double-free (shared with Z)
			}
			if dp != nil && ownedPolys[i] {
				gpu.Free(dp)
			}
		}
	}()

	// Upload twiddles0
	var dTwiddles0 unsafe.Pointer
	if s.gpuCtx != nil && s.gpuCtx.n == n && s.gpuCtx.dTwiddles0 != nil {
		dTwiddles0 = s.gpuCtx.dTwiddles0
	} else {
		dTwiddles0 = gpu.Malloc(elemSize)
		if dTwiddles0 == nil {
			return fmt.Errorf("GPU malloc failed for twiddles0")
		}
		defer gpu.Free(dTwiddles0)
		tPhase = time.Now()
		if err := gpu.MemcpyH2D(dTwiddles0, unsafe.Pointer(&twiddles0[0]), elemSize); err != nil {
			return err
		}
		dTwiddlesUpload := time.Since(tPhase)
		uploadMetaTime += dTwiddlesUpload
		s.timings.add("detail.gpuRho.uploadTwiddles", dTwiddlesUpload)
	}

	// Upload scaling vector (will be updated at iteration 1)
	dScale := gpu.Malloc(elemSize)
	if dScale == nil {
		return fmt.Errorf("GPU malloc failed for scale")
	}
	defer gpu.Free(dScale)

	// Allocate result buffer on device
	dResult := gpu.Malloc(elemSize)
	if dResult == nil {
		return fmt.Errorf("GPU malloc failed for result")
	}
	defer gpu.Free(dResult)
	dCres := gpu.Malloc(rho * n * 32)
	if dCres == nil {
		return fmt.Errorf("GPU malloc failed for cres")
	}
	keepNumeratorResident := s.gpuCtx != nil
	// Stage 1: openings still run host-side, so the wire polys must be downloaded
	// for the CPU restore even though the numerator stays resident. Flip
	// GNARK_GPU_RESIDENT_RESTORE once the restore itself is device-resident.
	residentRestore := os.Getenv("GNARK_GPU_RESIDENT_RESTORE") != ""
	if !keepNumeratorResident {
		defer gpu.Free(dCres)
	}

	// Allocate device buffers for challenges, blinding, denominators
	dChallenges := gpu.Malloc(8 * 32) // 8 Fr values
	if dChallenges == nil {
		return fmt.Errorf("GPU malloc failed for challenges")
	}
	defer gpu.Free(dChallenges)

	dBP := gpu.Malloc(9 * 32) // 9 Fr values (bl:2 + br:2 + bo:2 + bz:3)
	if dBP == nil {
		return fmt.Errorf("GPU malloc failed for bp")
	}
	defer gpu.Free(dBP)

	dPrecompDenoms := gpu.Malloc(elemSize)
	if dPrecompDenoms == nil {
		return fmt.Errorf("GPU malloc failed for denoms")
	}
	defer gpu.Free(dPrecompDenoms)

	dCoset := gpu.Malloc(32)
	if dCoset == nil {
		return fmt.Errorf("GPU malloc failed for coset")
	}
	defer gpu.Free(dCoset)

	// Determine IFFT/FFT directions for each polynomial
	ifftDirs := make([]int, npolys)
	fftDirs := make([]int, npolys)
	for i := 0; i < npolys; i++ {
		if i == id_ZS || s.x[i] == nil {
			continue
		}
		lagReg := iop.Form{Basis: iop.Lagrange, Layout: iop.Regular}
		if s.x[i].Form == lagReg {
			ifftDirs[i] = 1 // DIF
			fftDirs[i] = 0  // DIT
		} else {
			ifftDirs[i] = 0 // DIT
			fftDirs[i] = 1  // DIF
		}
	}

	scalingVectorDomain1Rev := make([]fr.Element, n)
	w := s.domain1.Generator
	fft.BuildExpTable(w, scalingVectorDomain1Rev)
	fft.BitReverse(scalingVectorDomain1Rev)

	// Upload initial scaling vector (coset table)
	// For iteration 0, scaling is applied based on polynomial layout.
	// For LagrangeRegular: after DIF IFFT, output is BitReverse → use scalingVectorRev
	// For LagrangeBitReverse: after DIT IFFT, output is Regular → use scalingVector
	// Since all polys are the same layout, we pick one scale vector.
	// TODO: handle mixed layouts by uploading both and selecting per-poly
	if err := gpu.MemcpyH2D(dScale, unsafe.Pointer(&scalingVectorRev[0]), elemSize); err != nil {
		return err
	}

	var cs, css fr.Element
	cs.Set(&s.domain1.FrMultiplicativeGen)
	css.Square(&cs)

	for i := 0; i < rho; i++ {
		iterStart := time.Now()
		tPhase := time.Now()
		coset.Mul(coset, &shifters[i])
		cosetExpNm1.Exp(*coset, bn).Sub(cosetExpNm1, one)
		if err := gpu.MemcpyH2D(dCoset, unsafe.Pointer(coset), 32); err != nil {
			return err
		}
		if err := gpu.VecDenominators(dPrecompDenoms, dTwiddles0, dCoset, n, stream); err != nil {
			return err
		}
		denomTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.denominators", denomTime)

		// Scale blinding polynomials
		tPhase = time.Now()
		for _, q := range s.bp {
			cq := q.Coefficients()
			acc := *cosetExpNm1
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], &acc)
				acc.Mul(&acc, &shifters[i])
			}
		}
		blindScaleTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.blindScale", blindScaleTime)

		tPhase = time.Now()
		if i == 1 {
			scalingVectorRev = scalingVectorDomain1Rev

			// Re-upload scale vector
			if err := gpu.MemcpyH2D(dScale, unsafe.Pointer(&scalingVectorRev[0]), elemSize); err != nil {
				return err
			}
		}
		scaleUpdateTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.scaleUpdate", scaleUpdateTime)

		// Pack and upload blinding coefficients
		// bp layout: [bl0,bl1, br0,br1, bo0,bo1, bz0,bz1,bz2]
		var bpArr [9]fr.Element
		blCoeffs := s.bp[id_Bl].Coefficients()
		bpArr[0] = blCoeffs[0]
		if len(blCoeffs) > 1 {
			bpArr[1] = blCoeffs[1]
		}
		brCoeffs := s.bp[id_Br].Coefficients()
		bpArr[2] = brCoeffs[0]
		if len(brCoeffs) > 1 {
			bpArr[3] = brCoeffs[1]
		}
		boCoeffs := s.bp[id_Bo].Coefficients()
		bpArr[4] = boCoeffs[0]
		if len(boCoeffs) > 1 {
			bpArr[5] = boCoeffs[1]
		}
		bzCoeffs := s.bp[id_Bz].Coefficients()
		bpArr[6] = bzCoeffs[0]
		if len(bzCoeffs) > 1 {
			bpArr[7] = bzCoeffs[1]
		}
		if len(bzCoeffs) > 2 {
			bpArr[8] = bzCoeffs[2]
		}
		if err := gpu.MemcpyH2D(dBP, unsafe.Pointer(&bpArr[0]), 9*32); err != nil {
			return err
		}

		// Pack and upload challenges
		var challenges [8]fr.Element
		challenges[0] = s.alpha
		challenges[1] = s.beta
		challenges[2] = s.gamma
		challenges[3] = cs
		challenges[4] = css
		challenges[5] = *coset
		challenges[6] = *cosetExpNm1
		challenges[7] = s.domain0.CardinalityInv
		if err := gpu.MemcpyH2D(dChallenges, unsafe.Pointer(&challenges[0]), 8*32); err != nil {
			return err
		}
		uploadTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.iterationUploads", uploadTime)

		// Run GPU rho iteration: fused IFFT→scale→FFT + constraint eval + D2H
		tPhase = time.Now()
		rhoStats, err := gpu.PlonkRhoIteration(
			dPolys, dPtrArray, dScale, dTwiddles0, dBP, dChallenges, dPrecompDenoms,
			dResult,
			n, npolys, nbBsbGates,
			ifftDirs, fftDirs, id_ZS, stream,
		)
		if err != nil {
			return err
		}
		gpuIterTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.kernelAndTransfers", gpuIterTime)
		s.timings.add("detail.gpuRho.iterFusedFFT", rhoStats.FusedFFT)
		s.timings.add("detail.gpuRho.iterConstraints", rhoStats.Constraints)
		s.timings.add("detail.gpuRho.iterSync", rhoStats.Sync)
		s.timings.add("detail.gpuRho.iterResultD2H", rhoStats.ResultD2H)

		// Scatter result into the final numerator buffer on device
		tPhase = time.Now()
		if err := gpu.PlonkScatterResult(dResult, dCres, n, rho, i, mm, stream); err != nil {
			return err
		}
		scatterScheduleTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.scatterSchedule", scatterScheduleTime)

		// Inverse scale blinding polynomials
		tPhase = time.Now()
		cosetExpNm1.Inverse(cosetExpNm1)
		for _, q := range s.bp {
			cq := q.Coefficients()
			for j := 0; j < len(cq); j++ {
				cq[j].Mul(&cq[j], cosetExpNm1)
			}
		}
		blindRestoreTime := time.Since(tPhase)
		s.timings.add("detail.gpuRho.blindRestore", blindRestoreTime)

		if traceRho {
			fmt.Fprintf(os.Stderr,
				"[GPU rho iter %d] total=%v denoms=%v blind_scale=%v scale_update=%v uploads=%v gpu=%v fft=%v constraints=%v sync=%v d2h=%v scatter=%v blind_restore=%v\n",
				i, time.Since(iterStart), denomTime, blindScaleTime, scaleUpdateTime, uploadTime, gpuIterTime,
				rhoStats.FusedFFT, rhoStats.Constraints, rhoStats.Sync, rhoStats.ResultD2H,
				scatterScheduleTime, blindRestoreTime)
		}
	}

	tPhase = time.Now()
	gpu.StreamSync(stream)
	if keepNumeratorResident {
		s.gpuCtx.mu.Lock()
		if s.gpuCtx.dNumerator != nil {
			gpu.Free(s.gpuCtx.dNumerator)
		}
		s.gpuCtx.dNumerator = dCres
		s.gpuCtx.mu.Unlock()
	} else {
		if err := gpu.MemcpyD2H(unsafe.Pointer(&cres[0]), dCres, rho*n*32); err != nil {
			return err
		}
		s.timings.add("detail.gpuRho.iterResultD2H", time.Since(tPhase))
	}

	// Download the wire polys for the host-side restore/openings unless the
	// restore is itself device-resident (residentRestore).
	if !residentRestore {
		tPhase = time.Now()
		residentWires := s.residentOpenings()
		for i := 0; i < npolys; i++ {
			if i == id_ZS || s.x[i] == nil || dPolys[i] == nil {
				continue
			}
			// the wires stay device-resident for the on-device openings; don't download them
			if residentWires && (i == id_L || i == id_R || i == id_O) {
				continue
			}
			cp := s.x[i].Coefficients()
			if err := gpu.MemcpyD2H(unsafe.Pointer(&cp[0]), dPolys[i], elemSize); err != nil {
				return err
			}
			s.x[i].Basis = iop.Lagrange
			s.x[i].Layout = iop.Regular
		}
		downloadPolysTime = time.Since(tPhase)
		s.timings.add("detail.gpuRho.downloadPolys", downloadPolysTime)
	}

	if traceRho {
		fmt.Fprintf(os.Stderr,
			"[GPU rho summary] upload_polys=%v upload_meta=%v download_polys=%v total=%v\n",
			uploadPolysTime, uploadMetaTime, downloadPolysTime, time.Since(t0))
	}
	fmt.Fprintf(os.Stderr, "[GPU PLONK rho-loop] %v\n", time.Since(t0))
	return nil
}

// gpuRestoreLRO restores all device-resident polynomials from Lagrange Regular
// to Canonical Regular form with coset-inverse scaling. This replaces the CPU
// restore path (IFFT + bit-reverse + scale) and keeps data on device.
// After this call, polynomials are in Canonical Regular form both on device and
// downloaded to the host-side s.x[].Coefficients() slices.
// syncResidentPolysFromGPU refreshes host-side polynomial buffers from the
// device-resident Lagrange-Regular copies so CPU restore can proceed after a
// GPU restore failure.
// gpuEvaluateBlinded evaluates a device-resident polynomial at a point using
// GPU chunked Horner, then adds the blinding polynomial contribution on CPU.
// gpuLinearizedPoly computes the linearized polynomial on GPU.

// --- Stage 1: device-resident quotient (divideByZH + H-chunk commits) ----------

// setupGPUResidentContext activates the device-resident prover pipeline so the
// quotient numerator stays on the GPU through divideByZH and the H-chunk commits
// (no 2GB host round-trip). Gated off for statistical ZK (quotient blinding not
// yet replicated on device) and when the GPU is unavailable.
func (s *instance) setupGPUResidentContext(n int) {
	if os.Getenv("GNARK_DISABLE_GPU_RESIDENT") != "" || s.opt.StatisticalZK || !gpu.Available() {
		return
	}
	s.gpuCtx = &proverGPUContext{n: n}
}

// freeGPUContext releases all device-resident buffers held for this prove.
func (s *instance) freeGPUContext() {
	if s.gpuCtx != nil {
		s.gpuCtx.free()
		s.gpuCtx = nil
	}
}

// gpuDivideAndCommitQuotient performs divideByZH and the three H-chunk commits on
// device, reusing the rho-loop's resident numerator, then downloads the canonical
// quotient coefficients into s.h for the (still host-side) linearized polynomial.
// Returns (true,nil) if it handled the quotient; (false,nil) => CPU fallback.
func (s *instance) gpuDivideAndCommitQuotient() (bool, error) {
	if s.gpuCtx == nil || s.gpuCtx.dNumerator == nil {
		return false, nil
	}
	// Pin to one OS thread + select the device once so the device ops below don't
	// each re-bind the icicle context on a fresh thread (re-entrant LockOSThread in
	// the inner ops keeps them on this thread).
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()
	bigN := int(s.domain1.Cardinality)
	n2 := int(s.domain0.Cardinality) + 2
	dH := s.gpuCtx.dNumerator

	var shadowNum []fr.Element
	if os.Getenv("GNARK_GPU_RESIDENT_SHADOW") != "" {
		shadowNum = make([]fr.Element, bigN)
		if err := gpu.MemcpyD2H(unsafe.Pointer(&shadowNum[0]), dH, bigN*32); err != nil {
			return false, err
		}
	}

	// divideByZH = (1) * Xⁿ-1 inverse [BitReverse], (2) inverse butterflies (no 1/n),
	// (3) * cosetTableInv * CardinalityInv [natural] — replicates the CPU scale +
	// ToCanonical(bigDomain) exactly (the tested FFTInverseNoScale + coset post).
	dInvRho, err := gpuResidentInvRho(s.domain0, s.domain1)
	if err != nil {
		return false, err
	}
	if err := gpu.VecMulDevice(dH, dH, dInvRho, bigN); err != nil {
		return false, err
	}
	if err := gpu.InverseButterfliesDevice(dH, bigN); err != nil {
		return false, err
	}
	dCosetInv, err := gpuResidentCosetInvScale(s.domain1)
	if err != nil {
		return false, err
	}
	if err := gpu.VecMulDevice(dH, dH, dCosetInv, bigN); err != nil {
		return false, err
	}

	// download the quotient coefficients (h1/h2/h3 = first 3*n2 coefficients).
	hc := make([]fr.Element, 3*n2)
	if err := gpu.MemcpyD2H(unsafe.Pointer(&hc[0]), dH, 3*n2*32); err != nil {
		return false, err
	}
	s.h = iop.NewPolynomial(&hc, iop.Form{Basis: iop.Canonical, Layout: iop.Regular})

	if shadowNum != nil {
		cpuNum := iop.NewPolynomial(&shadowNum, iop.Form{Basis: iop.LagrangeCoset, Layout: iop.BitReverse})
		cpuH, derr := divideByZH(cpuNum, [2]*fft.Domain{s.domain0, s.domain1})
		if derr == nil {
			cpuHc := cpuH.Coefficients()
			mism := 0
			for i := 0; i < 3*n2 && i < len(cpuHc); i++ {
				if !hc[i].Equal(&cpuHc[i]) {
					if mism == 0 {
						var r fr.Element
						if !hc[i].IsZero() {
							r.Div(&cpuHc[i], &hc[i])
						}
						fmt.Fprintf(os.Stderr, "[RESIDENT SHADOW] first mismatch i=%d cpu=%s dev=%s ratio(cpu/dev)=%s\n", i, cpuHc[i].String(), hc[i].String(), r.String())
					}
					mism++
				}
			}
			fmt.Fprintf(os.Stderr, "[RESIDENT SHADOW] mismatches=%d of %d\n", mism, 3*n2)
		}
	}

	// DEBUG isolation: commit on host from the device-computed h. If the proof
	// verifies this way, the device divideByZH is correct and the device MSM is
	// the culprit; if it still fails, the device h itself is wrong.
	if os.Getenv("GNARK_GPU_RESIDENT_CPU_COMMIT") != "" {
		if err := commitToQuotient(s.h1(), s.h2(), s.h3(), s.proof, s.pk.Kzg); err != nil {
			return false, err
		}
		return true, nil
	}

	// commit h[i*n2 : i*n2+n2] for i=0,1,2 — async on 3 streams so the chunks
	// overlap on the GPU (same SRS base, scalars already resident in dH, no upload).
	if err := gpu.PrewarmPoints(unsafe.Pointer(&s.pk.Kzg.G1[0]), n2); err != nil {
		return false, err
	}
	gpu.DeviceSync()
	projBytes := gpu.MSMProjBytes()
	var hStreams, hProjs, hCanons [3]unsafe.Pointer
	defer func() {
		for i := 0; i < 3; i++ {
			if hCanons[i] != nil {
				gpu.Free(hCanons[i])
			}
			if hProjs[i] != nil {
				gpu.FreeHost(hProjs[i])
			}
			if hStreams[i] != nil {
				gpu.StreamDestroy(hStreams[i])
			}
		}
	}()
	for i := 0; i < 3; i++ {
		off := unsafe.Add(dH, i*n2*32)
		hStreams[i] = gpu.StreamCreate()
		hProjs[i] = gpu.MallocHost(projBytes)
		dc, err := gpu.MSMDeviceScalarsAsync(unsafe.Pointer(&s.pk.Kzg.G1[0]), off, n2, hProjs[i], hStreams[i])
		if err != nil {
			return false, err
		}
		hCanons[i] = dc
	}
	for i := 0; i < 3; i++ {
		gpu.StreamSync(hStreams[i])
	}
	for i := 0; i < 3; i++ {
		var jac curve.G1Jac
		gpu.MSMMarshalProj(hProjs[i], unsafe.Pointer(&jac))
		s.proof.H[i].FromJacobian(&jac)
	}
	return true, nil
}

var (
	residentScaleMu sync.Mutex
	dInvRhoCache    unsafe.Pointer
	dInvRhoCacheN   int
	dCosetInvCache  unsafe.Pointer
	dCosetInvCacheN int
)

// gpuResidentInvRho returns the device-resident Xⁿ-1 inverse scale vector
// S[i] = xnMinusOneInverse[bitrev(i) % rho] (BitReverse indexing), cached across
// proves (circuit-fixed).
func gpuResidentInvRho(domain0, domain1 *fft.Domain) (unsafe.Pointer, error) {
	bigN := int(domain1.Cardinality)
	residentScaleMu.Lock()
	defer residentScaleMu.Unlock()
	if dInvRhoCache != nil && dInvRhoCacheN == bigN {
		return dInvRhoCache, nil
	}
	table := evaluateXnMinusOneDomainBigCoset([2]*fft.Domain{domain0, domain1})
	rho := len(table)
	scale := make([]fr.Element, bigN)
	nn := uint64(64 - bits.TrailingZeros64(uint64(bigN)))
	for i := 0; i < bigN; i++ {
		scale[i] = table[int(bits.Reverse64(uint64(i))>>nn)%rho]
	}
	if err := uploadResidentSlice(&dInvRhoCache, &dInvRhoCacheN, scale); err != nil {
		return nil, err
	}
	return dInvRhoCache, nil
}

// gpuResidentCosetInvScale returns the device-resident coset-inverse postprocess
// vector C[i] = FrMultiplicativeGenInv^i * CardinalityInv (natural order) for the
// big domain — the cosetTableInv * CardinalityInv the CPU applies after the
// inverse butterflies. Cached across proves.
func gpuResidentCosetInvScale(domain1 *fft.Domain) (unsafe.Pointer, error) {
	bigN := int(domain1.Cardinality)
	residentScaleMu.Lock()
	defer residentScaleMu.Unlock()
	if dCosetInvCache != nil && dCosetInvCacheN == bigN {
		return dCosetInvCache, nil
	}
	scale := make([]fr.Element, bigN)
	var acc fr.Element
	acc.Set(&domain1.CardinalityInv)
	for i := 0; i < bigN; i++ {
		scale[i].Set(&acc)
		acc.Mul(&acc, &domain1.FrMultiplicativeGenInv)
	}
	if err := uploadResidentSlice(&dCosetInvCache, &dCosetInvCacheN, scale); err != nil {
		return nil, err
	}
	return dCosetInvCache, nil
}

// gpuRestoreLRO restores the device-resident wire polynomials to Canonical/Regular
// (inverse FFT + scalePowers by cs) without re-uploading them, then downloads the
// canonical coefficients into s.x for the host-side openings. Replaces the CPU
// batchApply(ToCanonical + scalePowers) when the GPU context is active.
func (s *instance) gpuRestoreLRO(cs fr.Element) error {
	n := s.gpuCtx.n
	residentWires := s.residentOpenings()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	powers := make([]fr.Element, n)
	var acc fr.Element
	acc.SetOne()
	for i := 0; i < n; i++ {
		powers[i].Set(&acc)
		acc.Mul(&acc, &cs)
	}
	dScale := gpu.Malloc(n * 32)
	if dScale == nil {
		return fmt.Errorf("gpuRestoreLRO: malloc cs-powers failed")
	}
	defer gpu.Free(dScale)
	if err := gpu.MemcpyH2D(dScale, unsafe.Pointer(&powers[0]), n*32); err != nil {
		return err
	}

	for i := 0; i < len(s.x); i++ {
		if s.x[i] == nil {
			continue
		}
		dp := s.gpuCtx.getPoly(i)
		if dp == nil {
			continue
		}
		if err := gpu.InverseFFTDevice(dp, n); err != nil {
			return err
		}
		if err := gpu.VecMulDevice(dp, dp, dScale, n); err != nil {
			return err
		}
		// keep the canonical wires device-resident for the on-device openings — skip the
		// host download (the un-coset above already left them canonical in dp).
		if residentWires && (i == id_L || i == id_R || i == id_O) {
			continue
		}
		cp := s.x[i].Coefficients()
		if err := gpu.MemcpyD2H(unsafe.Pointer(&cp[0]), dp, n*32); err != nil {
			return err
		}
		s.x[i].Basis = iop.Canonical
		s.x[i].Layout = iop.Regular
	}
	return nil
}

// gpuComputeLinearizedPoly computes the PLONK linearized polynomial on device via
// the fused kernel (no Bsb22 qcp terms). Correctness-first: uploads the inputs,
// returns the canonical result. (false => caller uses the CPU path.)
func (s *instance) gpuComputeLinearizedPoly(lZeta, rZeta, oZeta, alpha, beta, gamma, zeta, zu fr.Element, qcpZeta []fr.Element, pi2Canonical [][]fr.Element, blindedZ []fr.Element, pk *ProvingKey) ([]fr.Element, bool) {
	if s.gpuCtx == nil || !gpu.Available() {
		return nil, false
	}
	fmt.Fprintf(os.Stderr, "[LINPOLY] engaging device path: nbCommitments=%d gpuCtx=%v\n", len(s.commitmentInfo), s.gpuCtx != nil)
	n := int(s.domain0.Cardinality)
	nB := len(blindedZ)
	n2 := n + 2

	// scalars (mirror innerComputeLinearizedPoly)
	var rl fr.Element
	rl.Mul(&rZeta, &lZeta)
	var s1, s2, tmp fr.Element
	// S1(ζ) and S2(ζ) are independent O(n) Horner evaluations; overlap them on separate
	// goroutines (the GPU path used to run them serially; the CPU path already overlaps S1).
	var s1eval fr.Element
	chS1 := make(chan struct{}, 1)
	go func() {
		s1eval = s.trace.S1.Evaluate(zeta)
		close(chS1)
	}()
	tmp = s.trace.S2.Evaluate(zeta)
	tmp.Mul(&tmp, &beta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	<-chS1
	s1 = s1eval
	s1.Mul(&s1, &beta).Add(&s1, &lZeta).Add(&s1, &gamma)
	s1.Mul(&s1, &tmp).Mul(&s1, &zu).Mul(&s1, &beta).Mul(&s1, &alpha)
	var uzeta, uuzeta fr.Element
	uzeta.Mul(&zeta, &pk.Vk.CosetShift)
	uuzeta.Mul(&uzeta, &pk.Vk.CosetShift)
	s2.Mul(&beta, &zeta).Add(&s2, &lZeta).Add(&s2, &gamma)
	tmp.Mul(&beta, &uzeta).Add(&tmp, &rZeta).Add(&tmp, &gamma)
	s2.Mul(&s2, &tmp)
	tmp.Mul(&beta, &uuzeta).Add(&tmp, &oZeta).Add(&tmp, &gamma)
	s2.Mul(&s2, &tmp)
	s2.Neg(&s2).Mul(&s2, &alpha)
	var zhZeta, zetaN, zetaNP2, a2l, one, den fr.Element
	one.SetOne()
	zetaN.Exp(zeta, big.NewInt(int64(n)))
	zetaNP2.Mul(&zetaN, &zeta).Mul(&zetaNP2, &zeta)
	zhZeta.Sub(&zetaN, &one)
	den.Sub(&zeta, &one)
	den.Inverse(&den)
	a2l.Mul(&zhZeta, &den).Mul(&a2l, &alpha).Mul(&a2l, &alpha).Mul(&a2l, &s.domain0.CardinalityInv)
	scalars := []fr.Element{s1, s2, rl, lZeta, rZeta, oZeta, a2l, zhZeta}

	// canonical base Qk: use the circuit-fixed cache from Setup (skips a per-proof
	// inverse-FFT); fall back to canonicalizing per-proof for a deserialized proving key.
	qkCanon := s.pk.qkCanonical
	if qkCanon == nil {
		s.trace.Qk.ToCanonical(s.domain0).ToRegular()
		qkCanon = s.trace.Qk.Coefficients()
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()
	up := func(src []fr.Element) (unsafe.Pointer, bool) {
		d := gpu.Malloc(len(src) * 32)
		if d == nil {
			return nil, false
		}
		if err := gpu.MemcpyH2D(d, unsafe.Pointer(&src[0]), len(src)*32); err != nil {
			gpu.Free(d)
			return nil, false
		}
		return d, true
	}
	bufs := []unsafe.Pointer{}
	free := func() {
		for _, b := range bufs {
			gpu.Free(b)
		}
	}
	defer free()
	mk := func(src []fr.Element) unsafe.Pointer {
		d, ok := up(src)
		if !ok {
			return nil
		}
		bufs = append(bufs, d)
		return d
	}
	dBZ := mk(blindedZ)
	dS3 := mk(s.trace.S3.Coefficients())
	dQl := mk(s.trace.Ql.Coefficients())
	dQr := mk(s.trace.Qr.Coefficients())
	dQm := mk(s.trace.Qm.Coefficients())
	dQo := mk(s.trace.Qo.Coefficients())
	dQk := mk(qkCanon)
	// hFolded[i] = h1[i] + zNP2*h2[i] + zNP2^2*h3[i], where the shards h1/h2/h3 are
	// the three contiguous thirds of the device-resident quotient (dNumerator) — see
	// gpuDivideAndCommitQuotient, which leaves the canonical quotient in dNumerator and
	// memcpys its first 3*n2 coeffs into s.h. Non-ZK: fold straight from dNumerator at
	// its shard offsets (no host fold, no 256MB upload). ZK injects randomizers into
	// the shards (see s.h1/h2/h3), so that path keeps the host fold + upload.
	var dHF unsafe.Pointer
	if !s.opt.StatisticalZK && s.gpuCtx.dNumerator != nil {
		dHF = gpu.Malloc(n2 * 32)
		if dHF == nil {
			return nil, false
		}
		bufs = append(bufs, dHF)
		dZeta := mk([]fr.Element{zetaNP2})
		dq := s.gpuCtx.dNumerator
		if dZeta == nil || gpu.FoldQuotientDevice(dq, unsafe.Add(dq, n2*32), unsafe.Add(dq, 2*n2*32), dHF, dZeta, n2) != nil {
			return nil, false
		}
	} else {
		h1, h2, h3 := s.h1(), s.h2(), s.h3()
		hFolded := make([]fr.Element, n2)
		for i := 0; i < n2; i++ {
			var t fr.Element
			t.Mul(&h3[i], &zetaNP2).Add(&t, &h2[i]).Mul(&t, &zetaNP2).Add(&t, &h1[i])
			hFolded[i].Set(&t)
		}
		dHF = mk(hFolded)
	}
	dSc := mk(scalars)
	if dBZ == nil || dS3 == nil || dQl == nil || dQr == nil || dQm == nil || dQo == nil || dQk == nil || dHF == nil || dSc == nil {
		return nil, false
	}
	dRes := gpu.Malloc(nB * 32)
	if dRes == nil {
		return nil, false
	}
	bufs = append(bufs, dRes)
	if err := gpu.LinearizedPolyDevice(dBZ, dS3, dQl, dQr, dQm, dQo, dQk, dHF, dSc, dRes, n, nB, n2); err != nil {
		return nil, false
	}
	out := make([]fr.Element, nB)
	if err := gpu.MemcpyD2H(unsafe.Pointer(&out[0]), dRes, nB*32); err != nil {
		return nil, false
	}
	// add the Bsb22 commitment terms: linPol += sum_j qcpZeta[j] * Pi_j(X)
	for j := range qcpZeta {
		pij := pi2Canonical[j]
		qz := qcpZeta[j]
		m := len(out)
		if len(pij) < m {
			m = len(pij)
		}
		utils.Parallelize(m, func(start, end int) {
			for i := start; i < end; i++ {
				var t fr.Element
				t.Mul(&pij[i], &qz)
				out[i].Add(&out[i], &t)
			}
		})
	}
	return out, true
}
