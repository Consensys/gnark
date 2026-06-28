//go:build cuda

// Package p2 is the device-resident orchestration layer for the BLS12-381 PLONK
// prover. It keeps field polynomials resident on the GPU as FrVector handles and
// drives the prove phases over the icicle shim (FrVector/G1MSM/RatioBuildZ/
// KzgDivide), modeled on Linea gpu/plonk2. See gnark-cuda/docs/RESIDENT_PROVER_PLAN.md.
package p2

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

const frBytes = fr.Bytes // 32

// FrVector is a device-resident vector of fr.Element in AoS-Montgomery layout —
// exactly the byte layout every shim kernel consumes (no SoA transpose). The only
// host traffic is the explicit Copy{From,To}Host.
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

// Ptr exposes the raw device pointer for the resident kernels (G1MSM, RatioBuildZ,
// KzgDivide).
func (v *FrVector) Ptr() unsafe.Pointer { return v.ptr }

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
