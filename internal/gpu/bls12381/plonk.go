//go:build cuda

package gpu

/*
// Build with -tags cuda; provide the libgnark_cuda + icicle paths via the env:
//   CGO_CFLAGS="-I<gnark-cuda>/include"
//   CGO_LDFLAGS="-L<gnark-cuda>/build -L<icicle-install>/lib -L/usr/local/cuda/lib64"
#cgo LDFLAGS: -lgnark_cuda -licicle_field_bls12_381 -licicle_curve_bls12_381 -licicle_device -lcudart -lstdc++

#include <stdint.h>
#include <stdlib.h>

void gpu_stream_sync(void* stream);

int gpu_fft_scale_fft(void* d_data, void* d_scale, uint32_t log_n,
                      int ifft_dir, int fft_dir, void* stream);
int gpu_fft_scale_fft_batch(void* d_polys, uint32_t count, int skip_idx,
                            void* d_scale, uint32_t log_n,
                            int ifft_dir, int fft_dir, void* stream);
int gpu_plonk_evaluate(void** d_polys, const void* d_twiddles0,
                       const void* d_bp, const void* d_challenges,
                       const void* d_precomp_denoms,
                       uint32_t n, uint32_t npolys, uint32_t nbBsbGates,
                       void* d_result, void* stream);
int gpu_plonk_scatter_result(const void* d_src, void* d_dst, uint32_t n, uint32_t rho,
                             uint32_t iter, uint32_t shift_bits, void* stream);



*/
import "C"

import (
	"fmt"
	"math/bits"
	"unsafe"
)

// PlonkRhoIteration runs one iteration of the PLONK rho loop on GPU:
// 1. For each polynomial: fused IFFT → scale → FFT (on device, no D2H)
// 2. Constraint evaluation kernel
// 3. sync only; caller can scatter/download later
//
// dPolys: device pointers to polynomial data (already on GPU)
// dScale: device pointer to scaling vector (Fr[n], already uploaded)
// dTwiddles0: device pointer to domain twiddles
// dBP: device pointer to blinding coefficients
// dChallenges: device pointer to packed challenges
// dPrecompDenoms: device pointer to precomputed denominators
// dResult: device pointer to output buffer
// n: domain size (must be power of 2)
// npolys: number of polynomials
// nbBsbGates: custom gate count
// ifftDirs/fftDirs: per-polynomial IFFT/FFT decimation directions (0=DIT, 1=DIF)
// skipIdx: polynomial index to skip (id_ZS = 4)
func PlonkRhoIteration(
	dPolys []unsafe.Pointer,
	dPtrArray unsafe.Pointer,
	dScale unsafe.Pointer,
	dTwiddles0 unsafe.Pointer,
	dBP unsafe.Pointer,
	dChallenges unsafe.Pointer,
	dPrecompDenoms unsafe.Pointer,
	dResult unsafe.Pointer,
	n int,
	npolys int,
	nbBsbGates int,
	ifftDirs []int,
	fftDirs []int,
	skipIdx int,
	stream unsafe.Pointer,
) error {
	logN := uint32(bits.TrailingZeros64(uint64(n)))

	// Phase 1: Fused IFFT → scale → FFT for each polynomial on device
	uniformDirs := true
	var commonIFFT, commonFFT int
	firstDir := true
	for i := 0; i < npolys; i++ {
		if i == skipIdx {
			continue
		}
		if firstDir {
			commonIFFT = ifftDirs[i]
			commonFFT = fftDirs[i]
			firstDir = false
			continue
		}
		if ifftDirs[i] != commonIFFT || fftDirs[i] != commonFFT {
			uniformDirs = false
			break
		}
	}

	if uniformDirs && !firstDir {
		if C.gpu_fft_scale_fft_batch(
			dPtrArray,
			C.uint32_t(npolys),
			C.int(skipIdx),
			dScale,
			C.uint32_t(logN),
			C.int(commonIFFT),
			C.int(commonFFT),
			stream,
		) != 0 {
			return fmt.Errorf("PlonkRhoIteration: batched fused FFT failed")
		}
		C.gpu_stream_sync(stream)
	} else {
		streamCount := npolys - 1
		if streamCount > 4 {
			streamCount = 4
		}
		if streamCount < 1 {
			streamCount = 1
		}
		fftStreams := make([]unsafe.Pointer, 0, streamCount)
		fftStreams = append(fftStreams, stream)
		for i := 1; i < streamCount; i++ {
			s := StreamAcquire()
			if s == nil {
				for _, extra := range fftStreams[1:] {
					StreamRelease(extra)
				}
				return fmt.Errorf("PlonkRhoIteration: stream acquire failed")
			}
			fftStreams = append(fftStreams, s)
		}
		defer func() {
			for _, extra := range fftStreams[1:] {
				StreamRelease(extra)
			}
		}()

		launchIdx := 0
		for i := 0; i < npolys; i++ {
			if i == skipIdx {
				continue
			}
			s := fftStreams[launchIdx%len(fftStreams)]
			launchIdx++
			if C.gpu_fft_scale_fft(
				dPolys[i], dScale,
				C.uint32_t(logN),
				C.int(ifftDirs[i]), C.int(fftDirs[i]),
				s,
			) != 0 {
				return fmt.Errorf("PlonkRhoIteration: fused FFT failed for poly %d", i)
			}
		}
		for _, s := range fftStreams {
			C.gpu_stream_sync(s)
		}
	}

	// Phase 2: Constraint evaluation kernel
	if dPtrArray == nil {
		return fmt.Errorf("PlonkRhoIteration: nil ptr array")
	}

	if C.gpu_plonk_evaluate(
		(*unsafe.Pointer)(dPtrArray),
		dTwiddles0, dBP, dChallenges, dPrecompDenoms,
		C.uint32_t(n), C.uint32_t(npolys), C.uint32_t(nbBsbGates),
		dResult, stream,
	) != 0 {
		return fmt.Errorf("PlonkRhoIteration: constraint eval failed")
	}

	// Phase 3: sync only
	C.gpu_stream_sync(stream)

	return nil
}

func PlonkScatterResult(dSrc unsafe.Pointer, dDst unsafe.Pointer, n int, rho int, iter int, shiftBits uint64, stream unsafe.Pointer) error {
	if C.gpu_plonk_scatter_result(dSrc, dDst, C.uint32_t(n), C.uint32_t(rho), C.uint32_t(iter), C.uint32_t(shiftBits), stream) != 0 {
		return fmt.Errorf("PlonkScatterResult failed")
	}
	return nil
}
