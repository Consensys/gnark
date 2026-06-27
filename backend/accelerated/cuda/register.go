//go:build cuda

// Package cuda is the CUDA-accelerated PLONK backend for BLS12-381, built on
// libgnark_cuda (https://github.com/polytope-labs/gnark-cuda). Importing it
// (with -tags cuda) registers the GPU MSM/FFT hooks in gnark-crypto, so the
// standard plonk prover transparently runs MSMs and FFTs on the GPU; the
// device-resident quotient rho-loop is compiled into the prover under the same
// tag. Build with CGO_CFLAGS/CGO_LDFLAGS pointing at libgnark_cuda + icicle.
package cuda

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr/fft"
)

func init() {
	bls12381.RegisterGPUMultiExp(gpuMultiExp)
	fft.RegisterGPUFFT(gpuFFT, gpuFFTInverse, gpuFFTInverseCoset)
}
