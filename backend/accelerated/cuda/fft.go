//go:build cuda

package cuda

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// GPU FFT threshold: below this, CPU is faster due to GPU launch overhead.
const gpuFFTThreshold = 1 << 14 // 16K

// gpuFFT attempts GPU-accelerated forward FFT (non-coset only).
// Coset multiplication is handled by the caller before/after this.
func gpuFFT(a []fr.Element, decimation fft.Decimation, coset bool) bool {
	n := len(a)
	if n < gpuFFTThreshold || !gpu.Available() || coset {
		return false
	}
	if n&(n-1) != 0 {
		return false
	}

	mode := gpu.FFT_DIT
	if decimation == fft.DIF {
		mode = gpu.FFT_DIF
	}

	t0 := time.Now()
	err := gpu.FFT(unsafe.Pointer(&a[0]), n, false, mode)
	if err == nil {
		fmt.Fprintf(os.Stderr, "[GPU FFT fwd] n=%-8d %v\n", n, time.Since(t0))
	}
	return err == nil
}

// gpuFFTInverse attempts GPU-accelerated inverse FFT (non-coset only).
func gpuFFTInverse(a []fr.Element, decimation fft.Decimation, coset bool) bool {
	n := len(a)
	if n < gpuFFTThreshold || !gpu.Available() || coset {
		return false
	}
	if n&(n-1) != 0 {
		return false
	}

	mode := gpu.FFT_DIT
	if decimation == fft.DIF {
		mode = gpu.FFT_DIF
	}

	t0 := time.Now()
	err := gpu.FFT(unsafe.Pointer(&a[0]), n, true, mode)
	if err == nil {
		fmt.Fprintf(os.Stderr, "[GPU FFT inv] n=%-8d %v\n", n, time.Since(t0))
	}
	return err == nil
}

// GPUFFTScaleFFT performs fused IFFT → element-wise multiply → FFT on GPU.
// Eliminates one PCIe round-trip vs separate IFFT + scale + FFT calls.
func GPUFFTScaleFFT(data []fr.Element, scale []fr.Element, ifftDec fft.Decimation, fftDec fft.Decimation) bool {
	n := len(data)
	if n < gpuFFTThreshold || !gpu.Available() || len(scale) != n {
		return false
	}
	if n&(n-1) != 0 {
		return false
	}

	ifftMode := gpu.FFT_DIT
	if ifftDec == fft.DIF {
		ifftMode = gpu.FFT_DIF
	}
	fftMode := gpu.FFT_DIT
	if fftDec == fft.DIF {
		fftMode = gpu.FFT_DIF
	}

	t0 := time.Now()
	err := gpu.FFTScaleFFT(
		unsafe.Pointer(&data[0]),
		unsafe.Pointer(&scale[0]),
		n, ifftMode, fftMode,
	)
	if err == nil {
		fmt.Fprintf(os.Stderr, "[GPU FFT fused] n=%-8d %v\n", n, time.Since(t0))
	}
	return err == nil
}

// gpuFFTInverseCoset performs GPU inverse FFT WITHOUT 1/n scaling.
// The caller handles cosetTableInv * CardinalityInv multiplication after.
func gpuFFTInverseCoset(a []fr.Element, decimation fft.Decimation) bool {
	n := len(a)
	if n < gpuFFTThreshold || !gpu.Available() {
		return false
	}
	if n&(n-1) != 0 {
		return false
	}

	mode := gpu.FFT_DIT
	if decimation == fft.DIF {
		mode = gpu.FFT_DIF
	}

	t0 := time.Now()
	err := gpu.FFTInverseNoScale(unsafe.Pointer(&a[0]), n, mode)
	if err == nil {
		fmt.Fprintf(os.Stderr, "[GPU FFT coset-inv] n=%-8d %v\n", n, time.Since(t0))
	}
	return err == nil
}
