//go:build cuda

package plonk

import (
	"fmt"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/iop"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

type restoreDebugShadow struct {
	polyIdx int
	coeffs  []fr.Element
}

type proverGPUContext struct {
	mu            sync.Mutex
	n             int
	polyPtrs      []unsafe.Pointer
	dL            unsafe.Pointer
	dR            unsafe.Pointer
	dO            unsafe.Pointer
	dS1           unsafe.Pointer
	dS2           unsafe.Pointer
	dS3           unsafe.Pointer
	dTwiddles0    unsafe.Pointer
	dNumerator    unsafe.Pointer
	dHFolded      unsafe.Pointer
	hFoldedLen    int
	dBlindedZ     unsafe.Pointer
	blindedZLen   int
	dBlindedL     unsafe.Pointer
	blindedLLen   int
	dBlindedR     unsafe.Pointer
	blindedRLen   int
	dBlindedO     unsafe.Pointer
	blindedOLen   int
	dLinearized   unsafe.Pointer
	linearizedLen int
	dInvRho       unsafe.Pointer
	invRhoLen     int
}

func (ctx *proverGPUContext) free() {
	if ctx == nil {
		return
	}
	for _, ptr := range []unsafe.Pointer{
		ctx.dL, ctx.dR, ctx.dO, ctx.dS1, ctx.dS2, ctx.dS3, ctx.dTwiddles0,
		ctx.dNumerator, ctx.dHFolded, ctx.dBlindedZ, ctx.dBlindedL, ctx.dBlindedR, ctx.dBlindedO,
		ctx.dLinearized, ctx.dInvRho,
	} {
		if ptr != nil {
			gpu.Free(ptr)
		}
	}
	ctx.dL, ctx.dR, ctx.dO = nil, nil, nil
	ctx.dS1, ctx.dS2, ctx.dS3 = nil, nil, nil
	ctx.dTwiddles0 = nil
	ctx.dNumerator = nil
	ctx.dHFolded = nil
	ctx.hFoldedLen = 0
	ctx.dBlindedZ = nil
	ctx.blindedZLen = 0
	ctx.dBlindedL = nil
	ctx.blindedLLen = 0
	ctx.dBlindedR = nil
	ctx.blindedRLen = 0
	ctx.dBlindedO = nil
	ctx.blindedOLen = 0
	ctx.dLinearized = nil
	ctx.linearizedLen = 0
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

func uploadResidentPoly(dst *unsafe.Pointer, src []fr.Element, size int) error {
	if len(src) == 0 {
		return nil
	}
	if *dst == nil {
		*dst = gpu.Malloc(size)
		if *dst == nil {
			return fmt.Errorf("GPU malloc failed for resident poly")
		}
	}
	return gpu.MemcpyH2D(*dst, unsafe.Pointer(&src[0]), size)
}

func ensureResidentPoly(dst *unsafe.Pointer, src []fr.Element, size int) error {
	if *dst != nil {
		return nil
	}
	return uploadResidentPoly(dst, src, size)
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

func releaseResidentSlice(dst *unsafe.Pointer, dstLen *int) {
	if *dst != nil {
		gpu.Free(*dst)
		*dst = nil
	}
	*dstLen = 0
}

func bestEffortUploadResidentSlice(dst *unsafe.Pointer, dstLen *int, src []fr.Element) error {
	if err := uploadResidentSlice(dst, dstLen, src); err != nil {
		if strings.Contains(err.Error(), "GPU malloc failed") {
			releaseResidentSlice(dst, dstLen)
			return nil
		}
		return err
	}
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

func (ctx *proverGPUContext) ensurePoly(id int, coeffs []fr.Element, size int) error {
	ctx.ensurePolySlot(id + 1)
	if ctx.polyPtrs[id] != nil {
		return nil
	}
	ptr := gpu.Malloc(size)
	if ptr == nil {
		return fmt.Errorf("GPU malloc failed for resident poly %d", id)
	}
	if err := gpu.MemcpyH2D(ptr, unsafe.Pointer(&coeffs[0]), size); err != nil {
		gpu.Free(ptr)
		return err
	}
	ctx.polyPtrs[id] = ptr
	return nil
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

	// If we have a resident GPU context, keep the trace on device for the
	// restore phase and later download restored canonical coefficients only once.
	// Otherwise, fall back to the original eager D2H behavior.
	if !keepNumeratorResident {
		tPhase = time.Now()
		for i := 0; i < npolys; i++ {
			if i == id_ZS || s.x[i] == nil || dPolys[i] == nil {
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
