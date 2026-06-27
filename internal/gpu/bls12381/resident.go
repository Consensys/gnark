//go:build cuda

package gpu

// Device-resident primitives for the openings phase: operate in-place on device
// pointers (no H2D/D2H), so polynomials that are already on the GPU after the
// quotient rho-loop can be divided-by-Zh, restored, combined, and committed
// without round-tripping 256MB-1GB host<->device per inverse FFT. The kernels
// themselves already exist in libgnark_cuda; these are the device-pointer wrappers.

/*
#include <stdint.h>

// DIT coset inverse NTT in place: IFFT (incl 1/n) then * g^{-i} in natural order.
// This is exactly gnark's a.ToCanonical(bigDomain) for a LagrangeCoset/BitReverse
// polynomial (divideByZH).
int gpu_ntt_coset_dit(void* d_data, uint32_t log_n, int direction, void* stream);

// Element-wise r[i] = a[i] * b[i], all device-resident.
int gpu_vec_mul(void* d_r, const void* d_a, const void* d_b, uint32_t n, void* stream);

// DIT inverse-FFT butterflies in place, WITHOUT the 1/n scaling (matches
// FFTInverseNoScale). Caller applies cosetTableInv * CardinalityInv afterwards.
int gpu_ntt_dit_noscale(void* d_data, uint32_t log_n, int direction, void* stream);

// Full DIT/DIF FFT in place WITH 1/n on inverse (matches gpu.FFT / the non-coset
// FFTInverse hook).
int gpu_ntt_dit(void* d_data, uint32_t log_n, int direction, void* stream);
int gpu_ntt_dif(void* d_data, uint32_t log_n, int direction, void* stream);

// Natural-in / natural-out inverse FFT (kNN) WITH 1/n — equals gnark's
// ToCanonical(domain).ToRegular() for a non-coset Regular Lagrange poly.
int gpu_ntt(void* d_data, uint32_t log_n, int direction, void* stream);

// Fused PLONK linearized polynomial (base terms; no Bsb22 qcp terms).
int gpu_plonk_linearized_poly(const void* d_blindedZ, const void* d_s3, const void* d_ql,
    const void* d_qr, const void* d_qm, const void* d_qo, const void* d_qk, const void* d_hFolded,
    const void* d_scalars, uint32_t n, uint32_t n_blindedZ, uint32_t n_hFolded, void* d_result, void* stream);
int gpu_kzg_divide(const void* d_f, const void* d_a, const void* d_ainv, const void* d_one, uint32_t n, void* d_q, void* stream);
*/
import "C"

import (
	"fmt"
	"math/bits"
	"runtime"
	"unsafe"
)

// CosetIFFTInverseDevice performs gnark's coset inverse FFT (a.ToCanonical on the
// coset: DIT inverse FFT + 1/n + g^{-i} scaling) in place on a device-resident
// buffer of n fr.Elements. Input must be LagrangeCoset / BitReverse; output is
// Canonical / Regular — matching divideByZH's a.ToCanonical(bigDomain).ToRegular().
func CosetIFFTInverseDevice(dData unsafe.Pointer, n int) error {
	if n == 0 {
		return nil
	}
	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("CosetIFFTInverseDevice: size must be a power of 2, got %d", n)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if err := NTTInit(logN); err != nil {
		return err
	}
	if C.gpu_ntt_coset_dit(dData, C.uint32_t(logN), 1, nil) != 0 {
		return fmt.Errorf("CosetIFFTInverseDevice: kernel failed")
	}
	return nil
}

// InverseButterfliesDevice runs the DIT inverse-FFT butterflies in place on a
// device buffer WITHOUT the 1/n scaling (matches FFTInverseNoScale): BitReverse
// input -> natural output. The caller multiplies by cosetTableInv*CardinalityInv.
func InverseButterfliesDevice(dData unsafe.Pointer, n int) error {
	if n == 0 {
		return nil
	}
	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("InverseButterfliesDevice: size must be a power of 2, got %d", n)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if err := NTTInit(logN); err != nil {
		return err
	}
	if C.gpu_ntt_dit_noscale(dData, C.uint32_t(logN), 1, nil) != 0 {
		return fmt.Errorf("InverseButterfliesDevice: kernel failed")
	}
	return nil
}

// InverseFFTDevice runs the full non-coset inverse FFT (butterflies + 1/n) in
// place on a device buffer — matches gpu.FFT(inverse) / ToCanonical for a
// non-coset Lagrange poly. dif selects the DIF kernel (else DIT).
func InverseFFTDevice(dData unsafe.Pointer, n int) error {
	if n == 0 {
		return nil
	}
	logN := uint32(bits.TrailingZeros64(uint64(n)))
	if 1<<logN != n {
		return fmt.Errorf("InverseFFTDevice: size must be a power of 2, got %d", n)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if err := NTTInit(logN); err != nil {
		return err
	}
	if C.gpu_ntt(dData, C.uint32_t(logN), 1, nil) != 0 {
		return fmt.Errorf("InverseFFTDevice: kernel failed")
	}
	return nil
}

// VecMulDevice computes dR[i] = dA[i] * dB[i] in place over n device-resident
// fr.Elements (dR may alias dA).
func VecMulDevice(dR, dA, dB unsafe.Pointer, n int) error {
	if n == 0 {
		return nil
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_vec_mul(dR, dA, dB, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("VecMulDevice: kernel failed")
	}
	return nil
}

// LinearizedPolyDevice runs the fused PLONK linearized-poly kernel on resident
// inputs, writing the result (length nBlindedZ) into dResult.
func LinearizedPolyDevice(dBlindedZ, dS3, dQl, dQr, dQm, dQo, dQk, dHFolded, dScalars, dResult unsafe.Pointer, n, nBlindedZ, nHFolded int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_plonk_linearized_poly(dBlindedZ, dS3, dQl, dQr, dQm, dQo, dQk, dHFolded, dScalars,
		C.uint32_t(n), C.uint32_t(nBlindedZ), C.uint32_t(nHFolded), dResult, nil) != 0 {
		return fmt.Errorf("LinearizedPolyDevice: kernel failed")
	}
	return nil
}

// KzgDivideDevice computes q = (f - f(a))/(X - a) (n-1 coeffs) into dQ. The a^k /
// a^{-k} power tables are built on-device from the scalars dA=a, dAinv=a^{-1},
// dOne=1, so only those three field elements cross the bus (not 512MB of powers).
func KzgDivideDevice(dF, dA, dAinv, dOne, dQ unsafe.Pointer, n int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_kzg_divide(dF, dA, dAinv, dOne, C.uint32_t(n), dQ, nil) != 0 {
		return fmt.Errorf("KzgDivideDevice: kernel failed")
	}
	return nil
}
