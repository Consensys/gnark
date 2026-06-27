//go:build cuda

package p2

/*
#include <stdint.h>
int gpu_vec_add(void* r, const void* a, const void* b, uint32_t n, void* stream);
int gpu_vec_sub(void* r, const void* a, const void* b, uint32_t n, void* stream);
int gpu_vec_mul(void* r, const void* a, const void* b, uint32_t n, void* stream);
int gpu_vec_scalar_mul(void* v, const void* d_c, uint32_t n, void* stream);
int gpu_vec_addmul(void* v, const void* a, const void* b, uint32_t n, void* stream);
int gpu_vec_add_scalar_mul(void* v, const void* a, const void* d_c, uint32_t n, void* stream);
int gpu_vec_set_zero(void* v, uint32_t n, void* stream);
int gpu_vec_scale_by_powers(void* v, const void* d_g, uint32_t n, void* stream);
int gpu_vec_batch_invert(void* v, uint32_t n, void* stream);
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

const frBytes = fr.Bytes // 32

// FrVector is a device-resident vector of fr.Element in AoS-Montgomery layout —
// exactly the byte layout every existing shim kernel consumes (no SoA transpose).
// Element-wise ops run in place on the device; the only host traffic is the
// explicit Copy{From,To}Host.
type FrVector struct {
	ptr unsafe.Pointer // gpu_malloc(n*32)
	n   int
	dev *Device
}

// NewFrVector allocates n resident Fr elements. A finalizer backstops Free.
func (d *Device) NewFrVector(n int) (*FrVector, error) {
	if n <= 0 {
		return nil, fmt.Errorf("p2: FrVector size must be positive, got %d", n)
	}
	p := gpu.Malloc(n * frBytes)
	if p == nil {
		return nil, fmt.Errorf("p2: device alloc of %d Fr failed", n)
	}
	v := &FrVector{ptr: p, n: n, dev: d}
	runtime.SetFinalizer(v, (*FrVector).Free)
	return v, nil
}

// Free releases the device buffer. Idempotent.
func (v *FrVector) Free() {
	if v.ptr != nil {
		gpu.Free(v.ptr)
		v.ptr = nil
		runtime.SetFinalizer(v, nil)
	}
}

// Len returns the element count.
func (v *FrVector) Len() int { return v.n }

// Ptr exposes the raw device pointer for the existing resident kernels
// (MSMDeviceScalars, gpu_ntt, gpu_plonk_*, gpu_kzg_divide).
func (v *FrVector) Ptr() unsafe.Pointer { return v.ptr }

func (v *FrVector) bind() { runtime.LockOSThread(); gpu.SetDevice() }

// CopyFromHost uploads src (must be exactly Len elements).
func (v *FrVector) CopyFromHost(src []fr.Element) error {
	if len(src) != v.n {
		return fmt.Errorf("p2: CopyFromHost size mismatch %d != %d", len(src), v.n)
	}
	return gpu.MemcpyH2D(v.ptr, unsafe.Pointer(&src[0]), v.n*frBytes)
}

// CopyToHost downloads into dst (must be exactly Len elements).
func (v *FrVector) CopyToHost(dst []fr.Element) error {
	if len(dst) != v.n {
		return fmt.Errorf("p2: CopyToHost size mismatch %d != %d", len(dst), v.n)
	}
	return gpu.MemcpyD2H(unsafe.Pointer(&dst[0]), v.ptr, v.n*frBytes)
}

// uploadScalar stages a single fr.Element to a 1-element device buffer.
func uploadScalar(c fr.Element) (unsafe.Pointer, error) {
	p := gpu.Malloc(frBytes)
	if p == nil {
		return nil, fmt.Errorf("p2: scalar alloc failed")
	}
	if err := gpu.MemcpyH2D(p, unsafe.Pointer(&c), frBytes); err != nil {
		gpu.Free(p)
		return nil, err
	}
	return p, nil
}

// Mul sets v[i] = a[i]·b[i].
func (v *FrVector) Mul(a, b *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_mul(v.ptr, a.ptr, b.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_mul failed")
	}
	return nil
}

// Add sets v[i] = a[i]+b[i].
func (v *FrVector) Add(a, b *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_add(v.ptr, a.ptr, b.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_add failed")
	}
	return nil
}

// Sub sets v[i] = a[i]-b[i].
func (v *FrVector) Sub(a, b *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_sub(v.ptr, a.ptr, b.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_sub failed")
	}
	return nil
}

// AddMul sets v[i] += a[i]·b[i].
func (v *FrVector) AddMul(a, b *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_addmul(v.ptr, a.ptr, b.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_addmul failed")
	}
	return nil
}

// ScalarMul sets v[i] *= c.
func (v *FrVector) ScalarMul(c fr.Element) error {
	v.bind()
	defer runtime.UnlockOSThread()
	p, err := uploadScalar(c)
	if err != nil {
		return err
	}
	defer gpu.Free(p)
	if C.gpu_vec_scalar_mul(v.ptr, p, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_scalar_mul failed")
	}
	return nil
}

// AddScalarMul sets v[i] += a[i]·c.
func (v *FrVector) AddScalarMul(a *FrVector, c fr.Element) error {
	v.bind()
	defer runtime.UnlockOSThread()
	p, err := uploadScalar(c)
	if err != nil {
		return err
	}
	defer gpu.Free(p)
	if C.gpu_vec_add_scalar_mul(v.ptr, a.ptr, p, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_add_scalar_mul failed")
	}
	return nil
}

// SetZero zeroes the vector.
func (v *FrVector) SetZero() error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_set_zero(v.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_set_zero failed")
	}
	return nil
}

// ScaleByPowers sets v[i] *= g^i (coset shift). Powers are built on-device.
func (v *FrVector) ScaleByPowers(g fr.Element) error {
	v.bind()
	defer runtime.UnlockOSThread()
	p, err := uploadScalar(g)
	if err != nil {
		return err
	}
	defer gpu.Free(p)
	if C.gpu_vec_scale_by_powers(v.ptr, p, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_scale_by_powers failed")
	}
	return nil
}

// BatchInvert sets v[i] = 1/v[i] via Montgomery batch inversion on-device.
func (v *FrVector) BatchInvert() error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_vec_batch_invert(v.ptr, C.uint32_t(v.n), nil) != 0 {
		return fmt.Errorf("p2: vec_batch_invert failed")
	}
	return nil
}
