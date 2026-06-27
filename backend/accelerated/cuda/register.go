//go:build cuda

// Package cuda is the CUDA-accelerated PLONK backend for BLS12-381, built on
// libgnark_cuda (https://github.com/polytope-labs/gnark-cuda).
//
// As of the device-resident rewrite, the GPU prover runs entirely through the
// backend/plonk/bls12-381 resident path (the p2 layer: FrVector, FFTDomain,
// G1MSM, the resident grand product / commit / quotient / linearize / openings),
// compiled under the same -tags cuda. The legacy gnark-crypto FFT/MSM/divide
// registration hooks are no longer installed, so the prover builds against
// upstream, unmodified gnark-crypto.
package cuda
