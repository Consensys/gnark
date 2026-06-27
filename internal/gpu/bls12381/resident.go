//go:build cuda

package gpu

// Device-resident primitives for the openings phase: operate in-place on device
// pointers (no H2D/D2H), so polynomials that are already on the GPU after the
// quotient rho-loop can be divided-by-Zh, restored, combined, and committed
// without round-tripping 256MB-1GB host<->device per inverse FFT. The kernels
// themselves already exist in libgnark_cuda; these are the device-pointer wrappers.

/*
#include <stdint.h>

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

// Fold the three quotient shards: out[i] = h1[i] + z*h2[i] + z^2*h3[i], z=zeta^(n+2).
int gpu_plonk_fold_quotient(const void* d_h1, const void* d_h2, const void* d_h3, void* d_out, const void* d_zeta_n_plus_2, uint32_t n, void* stream);

// Evaluate a polynomial (canonical coeffs) at a device point; writes one Fr to host h_result.
int gpu_poly_eval(const void* d_coeffs, uint32_t n, const void* d_point, void* h_result, void* stream);
// v[i] = 0 for i<n.
int gpu_vec_set_zero(void* v, uint32_t n, void* stream);
// v[i] += a[i] * (*d_c)  for i<n.
int gpu_vec_add_scalar_mul(void* v, const void* a, const void* d_c, uint32_t n, void* stream);
*/
import "C"

import (
	"fmt"
	"math/bits"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
)

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

// FoldQuotientDevice folds the three quotient shards on-device:
//
//	dOut[i] = dH1[i] + z*dH2[i] + z^2*dH3[i],  z = zeta^(n+2) (a single device scalar dZeta).
//
// The shards are the three contiguous thirds of the device-resident quotient, so
// the caller passes dH1 = quotient base and dH2/dH3 = that base offset by n/2n
// elements — no host transfer of the (256MB) folded polynomial.
func FoldQuotientDevice(dH1, dH2, dH3, dOut, dZeta unsafe.Pointer, n int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_plonk_fold_quotient(dH1, dH2, dH3, dOut, dZeta, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("FoldQuotientDevice: kernel failed")
	}
	return nil
}

// PolyEvalDevice evaluates the n-coefficient canonical polynomial at dPoint (a device
// Fr) and returns the scalar result on the host — a chunked parallel Horner, replacing
// the sequential host Evaluate for the openings' claimed values.
func PolyEvalDevice(dCoeffs unsafe.Pointer, n int, dPoint unsafe.Pointer) (fr.Element, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	var out fr.Element
	if C.gpu_poly_eval(dCoeffs, C.uint32_t(n), dPoint, unsafe.Pointer(&out), nil) != 0 {
		return out, fmt.Errorf("PolyEvalDevice: kernel failed")
	}
	return out, nil
}

// VecSetZeroDevice zeroes the first n Fr elements of dV.
func VecSetZeroDevice(dV unsafe.Pointer, n int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_vec_set_zero(dV, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("VecSetZeroDevice: kernel failed")
	}
	return nil
}

// VecAddScalarMulDevice computes dV[i] += dA[i] * (*dC) for i<n (dC is a device Fr).
// Repeated calls with the running gamma powers fold a set of resident polynomials.
func VecAddScalarMulDevice(dV, dA, dC unsafe.Pointer, n int) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	SetDevice()
	if C.gpu_vec_add_scalar_mul(dV, dA, dC, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("VecAddScalarMulDevice: kernel failed")
	}
	return nil
}
