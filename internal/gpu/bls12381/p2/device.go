//go:build cuda

package p2

import (
	gpu "github.com/consensys/gnark/internal/gpu/bls12381"
)

// Device is the resident-prover GPU handle; its methods (NewFrVector, NewG1MSM,
// RatioBuildZ, KzgDivide) live in the sibling files. Per-stream overlap of the
// resident commits is handled directly in the prover via internal/gpu's
// async-stream MSM, not through this type.
type Device struct{}

// NewDevice selects the GPU on the calling thread and returns a Device. The cuda
// build is GPU-only: a missing/failed device surfaces at the first device op.
func NewDevice() (*Device, error) {
	gpu.SetDevice()
	return &Device{}, nil
}
