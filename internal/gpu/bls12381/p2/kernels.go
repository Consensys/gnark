//go:build cuda

package p2

/*
#include <stdint.h>
int gpu_ratio_copy_terms(const void* d_l, const void* d_r, const void* d_o,
                         const void* d_s1, const void* d_s2, const void* d_s3,
                         const void* d_twiddles0, const void* d_challenges,
                         uint32_t n, void* d_out_num, void* d_out_den, void* stream);
int gpu_ratio_prefix_scan(void* d_data, uint32_t n, void* stream);
int gpu_ratio_apply_inverse(void* d_coeffs, const void* d_den, uint32_t n, void* stream);
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// KzgDivide computes q = (f - f(point))/(X - point) resident, returning a fresh
// FrVector of length f.Len()-1 — the KZG opening witness polynomial. Wraps
// gpu_kzg_divide (on-device aᵏ power tables; only the scalar point crosses the
// bus). The divide uses only f[k≥1] so the claimed value f(point) is irrelevant
// here; callers compute it separately for the proof.
func (d *Device) KzgDivide(f *FrVector, point fr.Element) (*FrVector, error) {
	n := f.n
	if n < 2 {
		return nil, fmt.Errorf("p2: KzgDivide needs len>=2, got %d", n)
	}
	var ainv, one fr.Element
	ainv.Inverse(&point)
	one.SetOne()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	dA := gpu.Malloc(frBytes)
	dAinv := gpu.Malloc(frBytes)
	dOne := gpu.Malloc(frBytes)
	defer gpu.Free(dA)
	defer gpu.Free(dAinv)
	defer gpu.Free(dOne)
	if dA == nil || dAinv == nil || dOne == nil {
		return nil, fmt.Errorf("p2: KzgDivide scalar alloc failed")
	}
	if gpu.MemcpyH2D(dA, unsafe.Pointer(&point), frBytes) != nil ||
		gpu.MemcpyH2D(dAinv, unsafe.Pointer(&ainv), frBytes) != nil ||
		gpu.MemcpyH2D(dOne, unsafe.Pointer(&one), frBytes) != nil {
		return nil, fmt.Errorf("p2: KzgDivide scalar upload failed")
	}
	q, err := d.NewFrVector(n - 1)
	if err != nil {
		return nil, err
	}
	if err := gpu.KzgDivideDevice(f.ptr, dA, dAinv, dOne, q.ptr, n); err != nil {
		q.Free()
		return nil, err
	}
	return q, nil
}

// RatioBuildZ builds the PLONK permutation grand-product polynomial Z
// (Lagrange/Regular) entirely on-device, reproducing iop.BuildRatioCopyConstraint:
//
//	num[i] = Πⱼ (Pⱼ(ωⁱ) + β·uʲ·ωⁱ + γ)
//	den[i] = Πⱼ (Pⱼ(ωⁱ) + β·σ(j·n+i) + γ)
//	Z = prefixProduct(num) / prefixProduct(den)
//
// Inputs are all resident FrVectors of length n:
//   - l,r,o:        the three wire evaluations Pⱼ (Lagrange/Regular)
//   - s1,s2,s3:     σⱼ = evaluationID[permutation[i+j·n]]  (= trace.S1/S2/S3 evals)
//   - twiddles0:    evaluationID for j=0, i.e. [ω⁰,ω¹,…,ωⁿ⁻¹]
//   - challenges:   [β, γ, u, u²] with u = domain.FrMultiplicativeGen
//
// The result Z is written into z (resident). den is used as scratch.
func (d *Device) RatioBuildZ(z, l, r, o, s1, s2, s3, twiddles0 *FrVector, challenges [4]fr.Element) error {
	n := l.n
	if z.n != n {
		return fmt.Errorf("p2: RatioBuildZ size mismatch z=%d l=%d", z.n, n)
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	dch := gpu.Malloc(4 * frBytes)
	if dch == nil {
		return fmt.Errorf("p2: RatioBuildZ challenge alloc failed")
	}
	defer gpu.Free(dch)
	if err := gpu.MemcpyH2D(dch, unsafe.Pointer(&challenges[0]), 4*frBytes); err != nil {
		return err
	}

	den, err := d.NewFrVector(n)
	if err != nil {
		return err
	}
	defer den.Free()

	// num -> z, den -> den
	if C.gpu_ratio_copy_terms(l.ptr, r.ptr, o.ptr, s1.ptr, s2.ptr, s3.ptr,
		twiddles0.ptr, dch, C.uint32_t(n), z.ptr, den.ptr, nil) != 0 {
		return fmt.Errorf("p2: ratio_copy_terms failed")
	}
	if C.gpu_ratio_prefix_scan(z.ptr, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("p2: ratio_prefix_scan(num) failed")
	}
	if C.gpu_ratio_prefix_scan(den.ptr, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("p2: ratio_prefix_scan(den) failed")
	}
	if C.gpu_ratio_apply_inverse(z.ptr, den.ptr, C.uint32_t(n), nil) != 0 {
		return fmt.Errorf("p2: ratio_apply_inverse failed")
	}
	return nil
}
