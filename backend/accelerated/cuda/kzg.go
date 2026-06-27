//go:build cuda

package cuda

import (
	"runtime"
	"unsafe"

	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

const gpuKzgDivideMinThreshold = 1 << 16

// gpuDividePolyByXminusA computes q = (f - f(a))/(X - a) on the GPU (q has len(f)-1
// coeffs). Returns false to fall back to the CPU synthetic division.
func gpuDividePolyByXminusA(f []fr.Element, fa, a fr.Element) ([]fr.Element, bool) {
	n := len(f)
	if n < gpuKzgDivideMinThreshold || !gpu.Available() {
		return nil, false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()

	// Only the scalars cross the bus; the n-length a^k / a^{-k} tables are built
	// on-device inside the kernel via a multiplicative prefix scan.
	var ainv, one fr.Element
	ainv.Inverse(&a)
	one.SetOne()

	dF := gpu.Malloc(n * 32)
	dA := gpu.Malloc(32)
	dAinv := gpu.Malloc(32)
	dOne := gpu.Malloc(32)
	dQ := gpu.Malloc((n - 1) * 32)
	defer func() {
		gpu.Free(dF)
		gpu.Free(dA)
		gpu.Free(dAinv)
		gpu.Free(dOne)
		gpu.Free(dQ)
	}()
	if dF == nil || dA == nil || dAinv == nil || dOne == nil || dQ == nil {
		return nil, false
	}
	if gpu.MemcpyH2D(dF, unsafe.Pointer(&f[0]), n*32) != nil ||
		gpu.MemcpyH2D(dA, unsafe.Pointer(&a), 32) != nil ||
		gpu.MemcpyH2D(dAinv, unsafe.Pointer(&ainv), 32) != nil ||
		gpu.MemcpyH2D(dOne, unsafe.Pointer(&one), 32) != nil {
		return nil, false
	}
	if err := gpu.KzgDivideDevice(dF, dA, dAinv, dOne, dQ, n); err != nil {
		return nil, false
	}
	q := make([]fr.Element, n-1)
	if gpu.MemcpyD2H(unsafe.Pointer(&q[0]), dQ, (n-1)*32) != nil {
		return nil, false
	}
	return q, true
}
