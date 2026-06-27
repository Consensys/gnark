//go:build cuda

package p2

/*
#include <stdint.h>
int gpu_ntt(void* d_data, uint32_t log_n, int direction, void* stream);
int gpu_bitreverse(void* d_data, uint32_t log_n, void* stream);
int gpu_ntt_coset(void* d_data, uint32_t log_n, int direction, void* stream);
*/
import "C"

import (
	"fmt"
	"math/bits"
	"runtime"

	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// FFTDomain is a device NTT domain of a fixed power-of-two size. It composes the
// proven icicle NTT kernels into the basis conversions the prover needs, all
// in place on resident FrVector buffers (no host round-trip).
type FFTDomain struct {
	logN uint32
	size int
	dev  *Device
}

// NewFFTDomain warms the icicle twiddle tables for size n (must be a power of 2).
func (d *Device) NewFFTDomain(n int) (*FFTDomain, error) {
	if n <= 0 || n&(n-1) != 0 {
		return nil, fmt.Errorf("p2: FFT size must be a power of 2, got %d", n)
	}
	logN := uint32(bits.TrailingZeros(uint(n)))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	gpu.SetDevice()
	if err := gpu.NTTInit(logN); err != nil {
		return nil, err
	}
	return &FFTDomain{logN: logN, size: n, dev: d}, nil
}

// Size returns the domain cardinality.
func (dm *FFTDomain) Size() int { return dm.size }

// ToCanonical converts a Lagrange/Regular vector to Canonical/Regular in place
// (inverse FFT with the 1/n scaling) — exactly iop ToCanonical(domain) for a
// non-coset Regular Lagrange polynomial. This is the selector/wire iFFT.
func (dm *FFTDomain) ToCanonical(v *FrVector) error {
	return gpu.InverseFFTDevice(v.ptr, v.n)
}

// Forward converts Canonical/Regular to Lagrange/Regular in place (forward FFT).
func (dm *FFTDomain) Forward(v *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_ntt(v.ptr, C.uint32_t(dm.logN), 0, nil) != 0 {
		return fmt.Errorf("p2: forward FFT failed")
	}
	return nil
}

// BitReverse permutes the vector in place between Regular and BitReverse layout.
func (dm *FFTDomain) BitReverse(v *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_bitreverse(v.ptr, C.uint32_t(dm.logN), nil) != 0 {
		return fmt.Errorf("p2: bit-reverse failed")
	}
	return nil
}

// CosetForward evaluates a Canonical/Regular polynomial on the coset (forward
// coset FFT) in place — the quotient-numerator evaluation step.
func (dm *FFTDomain) CosetForward(v *FrVector) error {
	v.bind()
	defer runtime.UnlockOSThread()
	if C.gpu_ntt_coset(v.ptr, C.uint32_t(dm.logN), 0, nil) != 0 {
		return fmt.Errorf("p2: coset forward FFT failed")
	}
	return nil
}

// CosetToCanonical inverts a coset evaluation back to Canonical/Regular (inverse
// coset FFT incl 1/n + g^-i) — the divideByZH post-step.
func (dm *FFTDomain) CosetToCanonical(v *FrVector) error {
	return gpu.CosetIFFTInverseDevice(v.ptr, v.n)
}
